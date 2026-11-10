from pathlib import Path

import pytest

from scripts import check_digest_drift as checker


def fixture_tree(root: Path, digest: str) -> None:
    backend = root / "containers" / "backend"
    (backend / "services").mkdir(parents=True)
    (backend / ".env.example").write_text(f"SANDBOX_IMAGE={digest}\n")
    (backend / "config.py").write_text(f'SANDBOX_IMAGE: str = "{digest}"\n')
    (backend / "services/sandbox_runner_svc.py").write_text(
        f'SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "{digest}")\n'
    )
    (root / "docker-compose.yml").write_text(f"SANDBOX_IMAGE: ${{SANDBOX_IMAGE:-{digest}}}\n")


def test_relocated_backend_layout_verifies(tmp_path, monkeypatch):
    fixture_tree(tmp_path, "sha256:" + "a" * 64)
    monkeypatch.setattr(checker, "__file__", str(tmp_path / "scripts/check_digest_drift.py"))
    with pytest.raises(SystemExit) as result:
        checker.main()
    assert result.value.code == 0


def test_relocated_backend_digest_drift_fails(tmp_path, monkeypatch):
    fixture_tree(tmp_path, "sha256:" + "a" * 64)
    (tmp_path / "containers/backend/.env.example").write_text("SANDBOX_IMAGE=sha256:" + "b" * 64)
    monkeypatch.setattr(checker, "__file__", str(tmp_path / "scripts/check_digest_drift.py"))
    with pytest.raises(SystemExit) as result:
        checker.main()
    assert result.value.code == 1
