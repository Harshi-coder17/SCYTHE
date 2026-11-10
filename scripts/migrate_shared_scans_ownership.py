"""Bounded one-time migration for legacy shared-scan volume ownership.

The default mode only lists entries carrying the previous sandbox identity.
Pass --apply while SCYTHE services are stopped to migrate those entries to
the current application/sandbox identity (10001:10001). The operation is
confined to the named Docker volume and never changes permissions.
"""

import argparse
import os
import re
import subprocess
import sys

DEFAULT_IMAGE = (
    "scythe-sandbox@sha256:e3119a08f0166226edcc2a6ba4f820a4635ec41ba6ce7616b7f8eb872b17c0f0"
)
VOLUME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def build_command(volume: str, image: str, apply: bool) -> list[str]:
    mount = f"type=volume,source={volume},target=/scans"
    if not apply:
        mount += ",readonly"
    action = (
        "find /scans -xdev \\( -uid 1001 -o -gid 1001 \\) -exec chown -h 10001:10001 {} +"
        if apply
        else "find /scans -xdev \\( -uid 1001 -o -gid 1001 \\) -print0 | tr -cd '\\0' | wc -c"
    )
    return [
        "docker", "run", "--rm", "--user", "0:0",
        "--network", "none", "--read-only", "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
        "--mount", mount,
        "--entrypoint", "sh", image, "-ec", action,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="change legacy 1001 ownership to 10001:10001")
    parser.add_argument("--volume", default=os.getenv("SHARED_SCANS_VOLUME", "scythe_shared_scans"))
    parser.add_argument("--image", default=os.getenv("SANDBOX_IMAGE", DEFAULT_IMAGE))
    args = parser.parse_args()

    if not VOLUME_RE.fullmatch(args.volume):
        parser.error("volume must be a simple Docker volume name")
    if "@sha256:" not in args.image:
        parser.error("image must be pinned by sha256 digest")
    if args.apply:
        print("Stop SCYTHE services before applying this ownership-only migration.")
        print("Only entries under the selected volume with UID 1001 or GID 1001 will be changed.")
    else:
        print("Dry run: counting legacy-owned entries without listing scan paths. Pass --apply after stopping services to migrate.")

    try:
        result = subprocess.run(build_command(args.volume, args.image, args.apply), check=False, capture_output=not args.apply, text=True)
    except FileNotFoundError:
        print("Docker CLI not found.", file=sys.stderr)
        return 127
    if result.returncode == 0 and not args.apply:
        print(f"Legacy-owned entries: {result.stdout.strip()}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
