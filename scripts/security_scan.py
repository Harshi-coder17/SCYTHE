"""Required local/CI scans. Missing tools/targets are failures, never clean scans."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
_tools_dir = str(ROOT / "tools")
if Path(_tools_dir).is_dir() and _tools_dir not in os.environ.get("PATH", "").split(os.pathsep):
    os.environ["PATH"] = _tools_dir + os.pathsep + os.environ.get("PATH", "")
REQUIREMENTS = ("containers/backend/requirements.txt", "containers/backend/requirements.runner.txt",
                "containers/backend/requirements.shadow.txt", "containers/sandbox/docker/requirements.txt")


def run(command, *, cwd=ROOT):
    return subprocess.run(command, cwd=cwd, check=False).returncode


def source_snapshot(destination):
    """Scan working source, including new files, without copying ignored secrets."""
    files = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT)
    for name in files.decode().split("\0"):
        if not name:
            continue
        source = ROOT / name
        if source.is_symlink() or not source.is_file():
            continue
        if not source.resolve().is_relative_to(ROOT):
            raise ValueError("Source path escapes repository")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checks", nargs="+", choices=("secrets", "sast", "deps", "images"),
                        default=["secrets", "sast", "deps", "images"])
    parser.add_argument("--output", type=Path, default=ROOT / "security-results")
    parser.add_argument("--images", nargs="+", default=["scythe-backend:latest", "scythe-celery_worker:latest",
                        "scythe-scythe_sandbox_runner:latest", "scythe-nginx:latest", "scythe-sandbox:v1.0.0"])
    parser.add_argument("--trivy-image", help="Checksum-pinned Trivy image, used if native trivy is unavailable")
    args = parser.parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []

    def record(name, command=None, error=None, cwd=ROOT):
        code = 2 if error else run(command, cwd=cwd)
        results.append({"check": name, "exit_code": code, "passed": code == 0, "error": error})
        print(f"{name}: {'PASS' if code == 0 else 'FAIL'}", flush=True)

    if "secrets" in args.checks:
        executable = os.getenv("GITLEAKS_BIN") or shutil.which("gitleaks")
        if not executable or not (ROOT / ".gitleaks.toml").is_file():
            record("secrets", error="gitleaks or repository configuration missing")
        else:
            with tempfile.TemporaryDirectory(prefix="scythe-source-scan-") as temporary:
                snapshot = Path(temporary)
                source_snapshot(snapshot)
                record("secrets", [executable, "dir", str(snapshot), "--redact=100", "--no-banner",
                                   "--config", str(ROOT / ".gitleaks.toml"), "--report-format", "json",
                                   "--report-path", str(output / "secrets.json")])
    if "sast" in args.checks:
        targets = [ROOT / "containers/backend", ROOT / "containers/sandbox/backend"]
        if not importlib.util.find_spec("bandit") or not all(p.is_dir() for p in targets):
            record("sast", error="bandit or scan target missing")
        else:
            record("sast", [sys.executable, "-m", "bandit", "-r", *map(str, targets), "-ll", "-ii",
                            "-f", "json", "-o", str(output / "sast.json")])
    if "deps" in args.checks:
        for name in REQUIREMENTS:
            target = ROOT / name
            if not importlib.util.find_spec("pip_audit") or not target.is_file():
                record(name, error="pip-audit or locked requirements missing")
                continue
            report = target.parent.name + "-" + target.name.replace(".txt", ".json")
            # OSV supports PyTorch's exact +cpu versions, which the PyPI
            # service skips because those wheels live on the vendor index.
            service = "osv" if target.name == "requirements.shadow.txt" else "pypi"
            record(name, [sys.executable, "-m", "pip_audit", "--disable-pip", "--no-deps", "-r", str(target),
                          "--vulnerability-service", service, "-f", "json", "-o", str(output / report)])
            results[-1]["vulnerability_service"] = service
            # pip-audit can exit zero while skipping unknown/local-version wheels.
            # A successful process is not evidence that every dependency was checked.
            if results[-1]["passed"]:
                try:
                    payload = json.loads((output / report).read_text(encoding="utf-8"))
                    dependencies = payload["dependencies"]
                    if not isinstance(dependencies, list) or not dependencies:
                        raise ValueError("empty or invalid dependency report")
                    if any(not isinstance(item, dict) or not item.get("name")
                           or (not item.get("skip_reason") and not isinstance(item.get("vulns"), list))
                           for item in dependencies):
                        raise ValueError("malformed dependency coverage record")
                    skipped = [item.get("name", "unknown") for item in dependencies
                               if item.get("skip_reason")]
                    if skipped:
                        raise ValueError("Dependencies not audited: " + ", ".join(skipped))
                    if any(item.get("vulns") for item in dependencies):
                        raise ValueError("Dependency report contains unresolved vulnerabilities")
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    results[-1].update(passed=False, exit_code=2, error=str(exc))
                    print(f"{name}: FAIL (audit coverage incomplete)", flush=True)
    if "images" in args.checks:
        trivy = os.getenv("TRIVY_BIN") or shutil.which("trivy")
        docker = shutil.which("docker")
        if not docker or (not trivy and (not args.trivy_image or "@sha256:" not in args.trivy_image)):
            record("images", error="Docker and native Trivy or a checksum-pinned Trivy image are required")
        else:
            for index, image in enumerate(args.images):
                exists = subprocess.run([docker, "image", "inspect", image], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL).returncode == 0
                if not exists:
                    record(image, error="Required local image missing")
                    continue
                report = f"image-{index}.json"
                scan = ["image", "--no-progress", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--exit-code", "1",
                        "--format", "json", "--timeout", "15m"]
                if trivy:
                    command = [trivy, *scan, "--output", str(output / report), image]
                else:
                    command = [docker, "run", "--rm", "--mount",
                               "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock,readonly",
                               "--mount", f"type=bind,source={output},target=/reports",
                               "-v", "scythe_trivy_cache:/root/.cache/trivy", args.trivy_image,
                               *scan, "--output", f"/reports/{report}", image]
                record(image, command)
    summary = {"timestamp": datetime.now(timezone.utc).isoformat(), "requested_checks": args.checks,
               "passed": bool(results) and all(item["passed"] for item in results), "results": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
