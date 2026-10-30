import base64
import io
import json
from unittest.mock import MagicMock, patch

from PIL import Image
from schemas.stage2 import Stage2Request
from services.stage2_analysis import run_stage2_analysis


def test_independent_branches_join_once_with_immutable_callback(tmp_path):
    output = io.BytesIO()
    Image.new("RGB", (8, 8)).save(output, format="PNG")
    request = Stage2Request(url="https://unlisted.example/", html="<html>fixture</html>",
                            screenshot_base64=base64.b64encode(output.getvalue()).decode())
    scan_id = "12345678-1234-4234-a234-123456789abc"
    database = MagicMock()
    database.refresh.side_effect = lambda scan: setattr(scan, "id", scan_id)
    with patch("services.stage2_analysis.settings.SHARED_DIR", str(tmp_path)), \
         patch("services.stage2_analysis.settings.TRUSTED_ALLOWLIST_DOMAINS", []), \
         patch("services.stage2_analysis.settings.SANDBOX_PRELIMINARY_THRESHOLD", 0), \
         patch("services.stage2_analysis.run_cyberintel", return_value={}), \
         patch("services.stage2_analysis.scan_file_clamav", return_value=(True, "Clean")), \
         patch("services.url_policy.validate_fetch_url", return_value=None), \
         patch("celery.chord") as chord, \
         patch("tasks.browser_features.browser_features_task.delay") as serial:
        chord.return_value.return_value.id = "join-job"
        result = run_stage2_analysis(request, MagicMock(id="user"), database)
    branches = chord.call_args.args[0]
    assert [branch.task for branch in branches] == ["tasks.browser_features", "tasks.sandbox_analysis"]
    assert all(branch.immutable and branch.kwargs == {"dispatch_next": False} for branch in branches)
    callback = chord.return_value.call_args.args[0]
    assert callback.immutable and callback.task == "tasks.consistency" and callback.args == (scan_id,)
    assert result.job_id == "join-job"
    serial.assert_not_called()
    assert (tmp_path / scan_id / "browser.png").exists()


def test_sandbox_failure_persists_before_chord_callback_and_does_not_dispatch_twice(tmp_path):
    from tasks.sandbox_analysis import sandbox_analysis_task
    scan_id = "12345678-1234-4234-a234-123456789abc"
    with patch("tasks.sandbox_analysis.settings.SHARED_DIR", str(tmp_path)), \
         patch("tasks.sandbox_analysis._mark_status"), \
         patch("tasks.sandbox_analysis._already_finalized", return_value=False), \
         patch("tasks.sandbox_analysis._call_sandbox", side_effect=TimeoutError("timeout")), \
         patch("tasks.consistency.consistency_task.delay") as dispatch:
        result = sandbox_analysis_task.run(scan_id, dispatch_next=False)
    assert result["status"] == "sandbox_analysis_failed_gracefully"
    assert json.loads((tmp_path / scan_id / "sandbox_metadata.json").read_text())["sandbox_available"] is False
    dispatch.assert_not_called()


def _browser_fixture(tmp_path, *, url="https://unlisted.example/"):
    from contextlib import ExitStack
    from types import SimpleNamespace
    from tasks import browser_features as browser
    scan_id = "12345678-1234-4234-a234-123456789abc"
    folder = tmp_path / scan_id
    folder.mkdir()
    (folder / "browser.png").write_bytes(b"fixture pixels consumed by mocked OCR")
    (folder / "browser.html").write_text("<html>fixture</html>")
    stack = ExitStack()
    stack.enter_context(patch.object(browser.settings, "SHARED_DIR", str(tmp_path)))
    stack.enter_context(patch.object(browser.settings, "TRUSTED_ALLOWLIST_DOMAINS", ["trusted.example"]))
    stack.enter_context(patch.object(browser.settings, "SANDBOX_PRELIMINARY_THRESHOLD", 0))
    stack.enter_context(patch.object(browser, "_already_finalized", return_value=False))
    stack.enter_context(patch.object(browser, "_mark_status"))
    database = stack.enter_context(patch.object(browser, "get_db_session"))
    database.return_value.__enter__.return_value.query.return_value.filter.return_value.first.return_value = SimpleNamespace(url=url)
    stack.enter_context(patch.object(browser, "extract_text", return_value="fixture"))
    stack.enter_context(patch.object(browser, "analyze_screenshot", return_value={}))
    stack.enter_context(patch.object(browser, "extract_features", return_value={}))
    sandbox = stack.enter_context(patch("tasks.sandbox_analysis.sandbox_analysis_task.delay"))
    consistency = stack.enter_context(patch("tasks.consistency.consistency_task.delay"))
    return stack, browser, scan_id, folder, sandbox, consistency


def test_browser_chord_branch_executes_without_downstream_dispatch_or_sibling_overwrite(tmp_path):
    stack, browser, scan_id, folder, sandbox, consistency = _browser_fixture(tmp_path)
    sibling = folder / "sandbox_metadata.json"
    sibling.write_text('{"sibling": "in progress"}')
    with stack:
        result = browser.browser_features_task.run(scan_id, dispatch_next=False)
    assert result["status"] == "browser_features_done"
    assert json.loads((folder / "browser_features.json").read_text())["scan_id"] == scan_id
    assert json.loads(sibling.read_text()) == {"sibling": "in progress"}
    sandbox.assert_not_called()
    consistency.assert_not_called()


def test_legacy_browser_branch_still_dispatches_exactly_one_sandbox(tmp_path):
    stack, browser, scan_id, _, sandbox, consistency = _browser_fixture(tmp_path)
    with stack:
        browser.browser_features_task.run(scan_id)
    sandbox.assert_called_once_with(scan_id)
    consistency.assert_not_called()


def test_allowlisted_legacy_browser_branch_dispatches_only_consistency(tmp_path):
    stack, browser, scan_id, folder, sandbox, consistency = _browser_fixture(tmp_path, url="https://trusted.example/")
    with stack:
        browser.browser_features_task.run(scan_id)
    sandbox.assert_not_called()
    consistency.assert_called_once_with(scan_id)
    assert json.loads((folder / "sandbox_metadata.json").read_text())["sandbox_available"] is False


def test_sandbox_success_chord_branch_does_not_dispatch_consistency(tmp_path):
    from tasks.sandbox_analysis import sandbox_analysis_task
    scan_id = "12345678-1234-4234-a234-123456789abc"
    with patch("tasks.sandbox_analysis.settings.SHARED_DIR", str(tmp_path)), \
         patch("tasks.sandbox_analysis._mark_status"), \
         patch("tasks.sandbox_analysis._already_finalized", return_value=False), \
         patch("tasks.sandbox_analysis._call_sandbox", return_value={"screenshots": {}}), \
         patch("tasks.sandbox_analysis._save_telemetry_to_postgres"), \
         patch("tasks.consistency.consistency_task.delay") as dispatch:
        sandbox_analysis_task.run(scan_id, dispatch_next=False)
    assert (tmp_path / scan_id / "sandbox_metadata.json").exists()
    dispatch.assert_not_called()


def test_sandbox_legacy_failure_continues_once_with_unavailable_metadata(tmp_path):
    from tasks.sandbox_analysis import sandbox_analysis_task
    scan_id = "12345678-1234-4234-a234-123456789abc"
    with patch("tasks.sandbox_analysis.settings.SHARED_DIR", str(tmp_path)), \
         patch("tasks.sandbox_analysis._mark_status"), \
         patch("tasks.sandbox_analysis._already_finalized", return_value=False), \
         patch("tasks.sandbox_analysis._call_sandbox", side_effect=TimeoutError("timeout")), \
         patch("tasks.consistency.consistency_task.delay") as dispatch:
        sandbox_analysis_task.run(scan_id)
    assert json.loads((tmp_path / scan_id / "sandbox_metadata.json").read_text())["sandbox_available"] is False
    dispatch.assert_called_once_with(scan_id)


def test_completed_scan_replays_do_not_execute_or_dispatch(tmp_path):
    from tasks import browser_features as browser
    from tasks import sandbox_analysis as sandbox
    scan_id = "12345678-1234-4234-a234-123456789abc"
    folder = tmp_path / scan_id
    folder.mkdir()
    (folder / "risk_report.json").write_text('{"is_placeholder":true}')
    for module, task, action in ((browser, browser.browser_features_task, "extract_text"),
                                 (sandbox, sandbox.sandbox_analysis_task, "_call_sandbox")):
        with patch.object(module.settings, "SHARED_DIR", str(tmp_path)), \
             patch.object(module, "_mark_status") as update, patch.object(module, action) as work:
            assert task.run(scan_id)["status"] == "already_finalized"
        update.assert_not_called()
        work.assert_not_called()
