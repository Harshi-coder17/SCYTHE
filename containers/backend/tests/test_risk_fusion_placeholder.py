import json
from unittest.mock import patch, MagicMock

import tasks.risk_fusion as risk_fusion_module


@patch("tasks.risk_fusion._redis_client")
@patch("tasks.risk_fusion._push_websocket_update")
@patch("tasks.risk_fusion._mark_status")
@patch("tasks.risk_fusion.get_db_session")
@patch("tasks.alert_pipeline.alert_pipeline_task.delay")
def test_risk_fusion_placeholder_suppresses_alert_dispatch(
    mock_alert_delay, mock_db_session, mock_mark_status, mock_push, mock_redis, tmp_path
):
    """
    Ensures that when risk_fusion completes and generates a HIGH/CRITICAL severity score,
    if is_placeholder=True, the alert_pipeline_task is NEVER dispatched.
    This prevents fake alerts from spamming Slack and polluting the database.
    """
    scan_id = "12345678-1234-4234-a234-123456789012"
    
    # Mock file operations via patching _scan_dir and _load_json
    with patch("tasks.risk_fusion._scan_dir", return_value=str(tmp_path)), \
         patch("tasks.risk_fusion._load_json", return_value={}), \
         patch("tasks.risk_fusion._get_cyberintel", return_value={}):
        
        # Mock RiskFusionEngine to return a HIGH severity score but with is_placeholder=True
        mock_engine = MagicMock()
        mock_engine.compute.return_value = {
            "risk_score": 85.0,
            "severity": "HIGH",
            "is_placeholder": True
        }
        
        with patch("tasks.risk_fusion.RiskFusionEngine", return_value=mock_engine):
            result = risk_fusion_module.risk_fusion_task(scan_id)
            
            # Verify the result has the severity
            assert result["severity"] == "HIGH"
            
            # Crucially, assert that alert_pipeline_task.delay was NOT called
            mock_alert_delay.assert_not_called()


@patch("tasks.risk_fusion._redis_client")
@patch("tasks.risk_fusion._push_websocket_update")
@patch("tasks.risk_fusion._mark_status")
@patch("tasks.risk_fusion.get_db_session")
@patch("tasks.alert_pipeline.alert_pipeline_task.delay")
def test_risk_fusion_real_model_dispatches_alert(
    mock_alert_delay, mock_db_session, mock_mark_status, mock_push, mock_redis, tmp_path
):
    """
    Ensures that when a real model (is_placeholder=False) generates a HIGH/CRITICAL
    severity score, the alert_pipeline_task IS correctly dispatched.
    """
    scan_id = "87654321-4321-4321-9210-210987654321"
    
    with patch("tasks.risk_fusion._scan_dir", return_value=str(tmp_path)), \
         patch("tasks.risk_fusion._load_json", return_value={}), \
         patch("tasks.risk_fusion._get_cyberintel", return_value={}):
        
        mock_engine = MagicMock()
        mock_engine.compute.return_value = {
            "risk_score": 90.0,
            "severity": "CRITICAL",
            "is_placeholder": False
        }
        
        with patch("tasks.risk_fusion.RiskFusionEngine", return_value=mock_engine):
            result = risk_fusion_module.risk_fusion_task(scan_id)
            
            assert result["severity"] == "CRITICAL"
            
            # Assert that alert_pipeline_task.delay WAS called exactly once
            mock_alert_delay.assert_called_once()


@patch("tasks.risk_fusion._redis_client")
@patch("tasks.risk_fusion._push_websocket_update")
@patch("tasks.risk_fusion._mark_status")
@patch("tasks.risk_fusion.get_db_session")
@patch("tasks.shadow_model_scoring.shadow_model_scoring_task.apply_async")
def test_shadow_dispatch_happens_after_report_and_failure_does_not_change_risk(
    mock_shadow_dispatch, mock_db_session, mock_mark_status, mock_push, mock_redis, tmp_path
):
    scan_id = "12345678-1234-4234-a234-123456789012"
    expected_report = {"risk_score": None, "severity": "UNKNOWN", "is_placeholder": True}

    def enqueue_after_report(*, args, queue):
        assert queue == "shadow"
        assert args == [scan_id]
        assert (tmp_path / "risk_report.json").is_file()
        raise RuntimeError("shadow queue is unavailable")

    mock_shadow_dispatch.side_effect = enqueue_after_report
    with patch("tasks.risk_fusion._scan_dir", return_value=str(tmp_path)), \
            patch("tasks.risk_fusion._load_json", return_value={}), \
            patch("tasks.risk_fusion._get_cyberintel", return_value={}), \
            patch("tasks.risk_fusion.settings.SHADOW_SCORING_ENABLED", True), \
            patch("tasks.risk_fusion.RiskFusionEngine") as engine:
        engine.return_value.compute.return_value = expected_report.copy()
        result = risk_fusion_module.risk_fusion_task(scan_id)

    assert result == {"scan_id": scan_id, "status": "risk_fusion_done", "severity": "UNKNOWN"}
    assert json.loads((tmp_path / "risk_report.json").read_text(encoding="utf-8")) == {
        **expected_report, "scan_id": scan_id
    }
    assert [call.args[1] for call in mock_mark_status.call_args_list] == ["risk_fusion_done"]
    mock_shadow_dispatch.assert_called_once()


@patch("tasks.risk_fusion._redis_client")
@patch("tasks.risk_fusion._push_websocket_update")
@patch("tasks.risk_fusion._mark_status")
@patch("tasks.risk_fusion.get_db_session")
@patch("tasks.shadow_model_scoring.shadow_model_scoring_task.apply_async")
def test_shadow_dispatch_is_absent_by_default(
    mock_shadow_dispatch, mock_db_session, mock_mark_status, mock_push, mock_redis, tmp_path
):
    scan_id = "12345678-1234-4234-a234-123456789012"
    with patch("tasks.risk_fusion._scan_dir", return_value=str(tmp_path)), \
            patch("tasks.risk_fusion._load_json", return_value={}), \
            patch("tasks.risk_fusion._get_cyberintel", return_value={}), \
            patch("tasks.risk_fusion.settings.SHADOW_SCORING_ENABLED", False), \
            patch("tasks.risk_fusion.RiskFusionEngine") as engine:
        engine.return_value.compute.return_value = {
            "risk_score": None, "severity": "UNKNOWN", "is_placeholder": True,
        }
        result = risk_fusion_module.risk_fusion_task(scan_id)

    assert result["status"] == "risk_fusion_done"
    mock_shadow_dispatch.assert_not_called()
