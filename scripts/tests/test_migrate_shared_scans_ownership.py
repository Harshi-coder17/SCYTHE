from scripts.migrate_shared_scans_ownership import build_command


def test_dry_run_is_read_only_and_confined_to_named_volume():
    command = build_command("scythe_shared_scans", "scythe-sandbox@sha256:" + "a" * 64, False)
    assert "--mount" in command
    mount = command[command.index("--mount") + 1]
    assert mount == "type=volume,source=scythe_shared_scans,target=/scans,readonly"
    assert "-print0" in command[-1] and "wc -c" in command[-1]
    assert "%p" not in command[-1]  # Dry run never prints private scan paths.
    assert "chown" not in command[-1]


def test_apply_only_changes_legacy_uid_or_gid_entries():
    command = build_command("scythe_shared_scans", "scythe-sandbox@sha256:" + "a" * 64, True)
    mount = command[command.index("--mount") + 1]
    assert mount == "type=volume,source=scythe_shared_scans,target=/scans"
    assert "find /scans -xdev" in command[-1]
    assert "-uid 1001 -o -gid 1001" in command[-1]
    assert "chown -h 10001:10001" in command[-1]
