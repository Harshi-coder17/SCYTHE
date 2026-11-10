import importlib.util
from pathlib import Path
import subprocess


SPEC = importlib.util.spec_from_file_location("lint_changed", Path(__file__).parents[1] / "lint_changed.py")
lint_changed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lint_changed)


def test_changed_files_excludes_training_scripts(monkeypatch):
    outputs = iter(
        [
            b"scripts/train_30k_ultimate_visual_model.py\0scripts/security_scan.py\0\0",
            b"",
        ]
    )

    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: next(outputs))
    files = lint_changed.changed_files()

    assert "scripts/security_scan.py" in files
    assert "scripts/train_30k_ultimate_visual_model.py" not in files
