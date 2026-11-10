"""Lint changed Python source without shell interpolation or ignored secrets."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PREFIXES = ("containers/backend/", "containers/sandbox/backend/", "containers/sandbox/tests/", "scripts/")
SCRIPT_EXCLUDE_PREFIXES = ("scripts/train_",)


def changed_files(base=None):
    names = set()
    if base:
        subprocess.run(["git", "rev-parse", "--verify", base + "^{commit}"], cwd=ROOT,
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output = subprocess.check_output(["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", base, "--"], cwd=ROOT)
        names.update(output.decode().split("\0"))
    else:
        output = subprocess.check_output(["git", "diff", "--name-only", "--diff-filter=ACMR", "-z", "HEAD", "--"], cwd=ROOT)
        names.update(output.decode().split("\0"))
        output = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
        names.update(output.decode().split("\0"))
    return sorted(
        name
        for name in names
        if name.endswith(".py")
        and name.startswith(PREFIXES)
        and not name.startswith(SCRIPT_EXCLUDE_PREFIXES)
        and (ROOT / name).is_file()
        and (ROOT / name).resolve().is_relative_to(ROOT)
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Verified git commit/ref to compare against checkout")
    args = parser.parse_args()
    try:
        files = changed_files(args.base)
    except subprocess.CalledProcessError:
        print("Cannot establish changed-file baseline", file=sys.stderr)
        return 1
    if not files:
        print("No changed Python project files")
        return 0
    print(f"Linting {len(files)} changed Python files")
    return subprocess.run([sys.executable, "-m", "ruff", "check", *files], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
