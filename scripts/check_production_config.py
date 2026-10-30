"""Validate merged production Compose invariants without printing configuration/secrets.

This is a static merge check, not certificate/CA verification or a deployment.
Use an explicit ignored environment file. No services are started or changed.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
APP_SERVICES = ("backend", "celery_worker", "celery_beat", "celery_shadow_worker")
INTERPOLATION_KEYS = {"SCYTHE_DB_PASSWORD", "POSTGRES_ROOT_PASSWORD", "REDIS_PASSWORD", "REDIS_SECURITY_PASSWORD",
                      "SANDBOX_RUNNER_SECRET", "SCYTHE_PUBLIC_HOST", "SCYTHE_PUBLIC_ORIGIN", "BACKUP_ENCRYPTION_KEY",
                      "ENVIRONMENT", "REQUIRE_REAL_CERT", "SANDBOX_IMAGE", "SHADOW_SCORING_ENABLED"}
SECRET_KEYS = ("SCYTHE_DB_PASSWORD", "POSTGRES_ROOT_PASSWORD", "REDIS_PASSWORD", "REDIS_SECURITY_PASSWORD",
               "SANDBOX_RUNNER_SECRET", "BACKUP_ENCRYPTION_KEY")


def true(value):
    return str(value).lower() in {"true", "1"}


def public_hostname(value):
    """Return a normalized public DNS hostname, or None for unsafe placeholders."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if any(char in value for char in "/:@?#*\\") or value.endswith("."):
        return None
    try:
        host = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return None
    if len(host) > 253 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in host.split(".")
    ):
        return None
    reserved_examples = ("example.com", "example.net", "example.org")
    if (host.endswith((".example", ".test", ".invalid", ".localhost"))
            or any(host == domain or host.endswith("." + domain) for domain in reserved_examples)
            or "replace-with" in host):
        return None
    return host


def validate_config(config):
    services = config.get("services", {})
    errors = []
    # Compose interpolation succeeds for short or accidentally reused secrets too;
    # reject those configurations before they can be mistaken for production-ready.
    secret_values = {}
    for service in services.values():
        env = service.get("environment", {})
        if isinstance(env, dict):
            for key in SECRET_KEYS:
                value = env.get(key)
                if value is not None:
                    secret_values.setdefault(key, value)
    # Compose exposes the database superuser password to PostgreSQL under its
    # native POSTGRES_PASSWORD name; it is intentionally not passed to app
    # containers as POSTGRES_ROOT_PASSWORD.
    postgres_password = services.get("postgres", {}).get("environment", {}).get("POSTGRES_PASSWORD")
    if postgres_password is not None:
        secret_values.setdefault("POSTGRES_ROOT_PASSWORD", postgres_password)
    for key in SECRET_KEYS:
        value = secret_values.get(key)
        if not isinstance(value, str) or len(value.encode("utf-8")) < 32:
            errors.append(f"{key}: production secret must contain at least 32 bytes")
    seen_values = {}
    for key, value in secret_values.items():
        if value in seen_values:
            errors.append(f"{key}: must be distinct from {seen_values[value]}")
        else:
            seen_values[value] = key
    for name in APP_SERVICES:
        service = services.get(name, {})
        env = service.get("environment", {})
        if env.get("ENVIRONMENT") != "production" or not true(env.get("REQUIRE_REAL_CERT")):
            errors.append(f"{name}: production mode and mandatory real TLS must be enabled")
        if str(env.get("SHADOW_SCORING_ENABLED", "")).lower() not in {"false", "0"}:
            errors.append(f"{name}: experimental shadow scoring must remain explicitly disabled")
        if len(env.get("BACKUP_ENCRYPTION_KEY") or "") < 32:
            errors.append(f"{name}: strong backup encryption key is required")
        hosts = {value.strip() for value in (env.get("ALLOWED_HOSTS") or "").split(",") if value.strip()}
        public_hosts = hosts - {"localhost", "127.0.0.1", "backend", "nginx", "0.0.0.0"}
        normalized_hosts = {public_hostname(host) for host in public_hosts}
        if "*" in hosts or len(public_hosts) != 1 or None in normalized_hosts:
            errors.append(f"{name}: explicit public hostname is required")
        origins = [value.strip() for value in (env.get("CORS_ALLOWED_ORIGINS") or "").split(",") if value.strip()]
        valid_origins = []
        for value in origins:
            try:
                parsed = urlsplit(value)
                origin_host = public_hostname(parsed.hostname)
                # CORS entries must be origins, not paths, credentials, or URL patterns.
                valid = (parsed.scheme == "https" and origin_host is not None
                         and parsed.username is None and parsed.password is None
                         and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
                         and "*" not in value and parsed.port != 0)
            except ValueError:
                valid = False
                origin_host = None
            valid_origins.append(valid and origin_host in normalized_hosts)
        if not origins or not all(valid_origins):
            errors.append(f"{name}: CORS_ALLOWED_ORIGINS must contain HTTPS origins matching the public hostname")
        if true(env.get("DEBUG")) or str(env.get("CLAMAV_FAIL_CLOSED", "true")).lower() in {"false", "0"}:
            errors.append(f"{name}: debug and fail-open malware scanning are forbidden")
    nginx = services.get("nginx", {})
    if not true(nginx.get("environment", {}).get("REQUIRE_REAL_CERT")):
        errors.append("nginx: mandatory real TLS must be enabled")
    cert_mounts = [mount for mount in nginx.get("volumes", []) if mount.get("target") == "/etc/nginx/certs"]
    if len(cert_mounts) != 1 or cert_mounts[0].get("type") != "bind" or cert_mounts[0].get("read_only") is not True:
        errors.append("nginx: exactly one read-only host certificate bind is required")
    tmpfs = nginx.get("tmpfs", [])
    paths = {value.split(":", 1)[0] for value in tmpfs}
    if "/etc/nginx/certs" in paths:
        errors.append("nginx: certificate bind must not be shadowed by tmpfs")
    if not {"/var/cache/nginx", "/var/run", "/tmp", "/var/log/nginx"}.issubset(paths):
        errors.append("nginx: required writable runtime tmpfs paths are missing")
    if nginx.get("read_only") is not True:
        errors.append("nginx: root filesystem must remain read-only")
    runner = services.get("scythe_sandbox_runner", {}).get("environment", {})
    if runner.get("ENVIRONMENT") != "production":
        errors.append("sandbox runner: production checks must be enabled")
    if not re.search(r"(?:@|^)sha256:[a-fA-F0-9]{64}$", runner.get("SANDBOX_IMAGE", "")):
        errors.append("sandbox runner: immutable sandbox image digest is required")
    return errors


def merged_config(env_file, root=ROOT):
    root = Path(root).resolve()
    environment = {key: value for key, value in os.environ.items() if key not in INTERPOLATION_KEYS}
    command = ["docker", "compose", "--profile", "*", "--project-directory", str(root), "--env-file", str(Path(env_file).resolve()),
               "-f", str(root / "docker-compose.yml"), "-f", str(root / "docker-compose.prod.yml"),
               "config", "--no-env-resolution", "--format", "json"]
    process = subprocess.run(command, capture_output=True, text=True, env=environment, check=False)
    if process.returncode != 0:
        # Compose diagnostics could contain interpolated values; never relay them.
        raise RuntimeError("Compose merge failed; check required variables and Compose support for !override/no-env-resolution")
    return json.loads(process.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        errors = validate_config(merged_config(args.env_file))
    except (OSError, RuntimeError, ValueError):
        errors = ["Production Compose configuration could not be safely validated"]
    report = {"passed": not errors, "errors": errors,
              "scope": "Static merged configuration only; real TLS identity/CA, secret escrow, restore and live workflow require separate checks"}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
