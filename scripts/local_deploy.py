"""Start or verify local SCYTHE without printing resolved Compose secrets.

This verifies infrastructure, TLS and API readiness. Model release quality is a
separate gate; a healthy stack may still return UNKNOWN for unavailable models.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from urllib.error import URLError
from urllib.request import ProxyHandler, HTTPSHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "nginx", "backend", "postgres", "redis", "redis_security", "clamav",
    "celery_worker", "celery_beat", "scythe_sandbox_runner",
    "docker_socket_proxy", "sandbox_net_holder",
}


class LocalDeploymentError(RuntimeError):
    pass


def run_docker(*args: str, timeout: int = 60, environment: dict | None = None) -> str:
    try:
        result = subprocess.run(
            ["docker", *args], cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            check=False, env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LocalDeploymentError("Docker command unavailable or timed out") from exc
    if result.returncode:
        # Compose diagnostics can contain expanded credentials. Never echo them.
        raise LocalDeploymentError(f"Docker {' '.join(args[:2])} failed; inspect Docker Desktop locally")
    return result.stdout


def compose(*args: str, timeout: int = 60, environment: dict | None = None, models: bool = False) -> str:
    profile = ("--profile", "models") if models else ()
    return run_docker("compose", "-f", "docker-compose.yml", *profile, *args,
                      timeout=timeout, environment=environment)


def release_environment(bundle: str | None, anchor: str | None) -> dict | None:
    if not bundle and not anchor:
        return None
    if not bundle or not anchor:
        raise LocalDeploymentError("Both --release-bundle and --release-checksums-sha256 are required")
    # Import the lightweight verifier directly: never import backend settings or
    # deserialize models in the deployment process.
    spec = importlib.util.spec_from_file_location(
        "scythe_release_verifier", ROOT / "containers/backend/services/model_release.py"
    )
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    try:
        root, _, _, _, _ = verifier.verify_release(bundle, anchor)
    except (ValueError, OSError, TypeError, KeyError):
        raise LocalDeploymentError("Release validation failed; no model worker will be enabled") from None
    environment = os.environ.copy()
    environment.update({
        "MODEL_RELEASE_ENABLED": "true",
        "MODEL_RELEASE_HOST_DIR": str(root),
        "MODEL_RELEASE_BUNDLE_DIR": "/opt/scythe/release",
        "MODEL_RELEASE_CHECKSUMS_SHA256": anchor,
    })
    return environment


def validate_model_config(config: dict, models: bool) -> None:
    enabled = str(config.get("services", {}).get("backend", {}).get("environment", {}).get(
        "MODEL_RELEASE_ENABLED", "false")).lower() in {"true", "1"}
    if enabled and not models:
        raise LocalDeploymentError("Model release is enabled but verified release arguments/profile are absent")
    if models and (not enabled or "celery_model_worker" not in config.get("services", {})):
        raise LocalDeploymentError("Verified release requires the enabled models worker profile")


def validate_local_config(config: dict) -> int:
    """Reject every externally published internal port or non-loopback listener."""
    https_ports = []
    for service, definition in config.get("services", {}).items():
        for port in definition.get("ports", []):
            if not isinstance(port, dict):
                raise LocalDeploymentError("Unsupported resolved Compose port format")
            try:
                loopback = ipaddress.ip_address(port.get("host_ip", "0.0.0.0")).is_loopback
            except ValueError:
                loopback = False
            if service != "nginx" or not loopback:
                raise LocalDeploymentError("Local deployment must publish only nginx on loopback")
            if port.get("target") == 443:
                https_ports.append(int(port["published"]))
    if len(https_ports) != 1:
        raise LocalDeploymentError("Expected exactly one nginx HTTPS listener")
    return https_ports[0]


def parse_status(output: str) -> list[dict]:
    """Compose releases emit either a JSON array or newline-delimited objects."""
    try:
        value = json.loads(output)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        return [json.loads(line) for line in output.splitlines() if line.strip()]


def validate_status(rows: list[dict], models: bool = False) -> list[str]:
    by_service = {row.get("Service"): row for row in rows}
    failures = []
    required = REQUIRED | ({"celery_model_worker"} if models else set())
    for service in sorted(required):
        row = by_service.get(service, {})
        state = row.get("State", "missing")
        health = row.get("Health", "")
        if state != "running" or health not in ("", "healthy") or (service == "celery_model_worker" and health != "healthy"):
            failures.append(f"{service}: {state}/{health or 'no healthcheck'}")
    return failures


def export_certificate(destination: Path, **compose_options) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    compose("cp", "nginx:/etc/nginx/certs/server.crt", str(destination), **compose_options)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def check_https(port: int, certificate: Path) -> None:
    # Trust only the exported local certificate, still checking SAN and expiry.
    context = ssl.create_default_context(cafile=str(certificate))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))
    for path in ("/health", "/"):
        try:
            with opener.open(f"https://localhost:{port}{path}", timeout=15) as response:
                if response.status != 200:
                    raise LocalDeploymentError(f"HTTPS {path} did not return 200")
        except (URLError, OSError) as exc:
            raise LocalDeploymentError(
                "Verified local HTTPS failed; inspect certificate SAN/expiry and proxy/backend health"
            ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("up", "check", "certificate"), nargs="?", default="check")
    parser.add_argument("--no-build", action="store_true", help="Reuse built images when starting")
    parser.add_argument("--wait-timeout", type=int, default=360, help="Service readiness limit in seconds")
    parser.add_argument("--release-bundle", help="Qualified immutable model-release directory")
    parser.add_argument("--release-checksums-sha256", help="Operator-pinned SHA-256 of its checksum manifest")
    args = parser.parse_args()
    certificate = ROOT / ".local" / "server.crt"
    try:
        if not (ROOT / ".env").is_file():
            raise LocalDeploymentError("Missing ignored .env; configure local secrets before starting")
        environment = release_environment(args.release_bundle, args.release_checksums_sha256)
        models = environment is not None
        compose_options = {"environment": environment, "models": models}
        run_docker("info", "--format", "{{.ServerVersion}}", environment=environment)
        config = json.loads(compose("config", "--format", "json", **compose_options))
        validate_model_config(config, models)
        port = validate_local_config(config)
        if args.command == "up":
            options = ["up", "-d", "--wait", "--wait-timeout", str(args.wait_timeout)]
            if not args.no_build:
                options.append("--build")
            compose(*options, timeout=max(1800, args.wait_timeout + 60), **compose_options)
        if args.command != "certificate":
            failures = validate_status(parse_status(compose("ps", "--all", "--format", "json", **compose_options)), models)
            if failures:
                raise LocalDeploymentError("Services not ready: " + "; ".join(failures))
        digest = export_certificate(certificate, **compose_options)
        if args.command != "certificate":
            check_https(port, certificate)
        print(json.dumps({
            "status": "certificate_exported" if args.command == "certificate" else "local_infrastructure_ready",
            "origin": f"https://localhost:{port}",
            "certificate": str(certificate), "certificate_sha256": digest,
            "model_release_quality": "qualified_bundle_verified" if models else "separate_verification_required",
            "model_worker_profile": models,
        }, indent=2))
        return 0
    except (LocalDeploymentError, ValueError, OSError) as exc:
        print(f"Local deployment check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
