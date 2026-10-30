from unittest.mock import patch, MagicMock

import tasks.alert_pipeline as alert_pipeline_module


@patch("tasks.alert_pipeline._send_slack_notification")
@patch("tasks.alert_pipeline._update_statistics")
@patch("tasks.alert_pipeline._store_iocs")
@patch("tasks.alert_pipeline._create_incident")
@patch("tasks.alert_pipeline.get_db_session")
def test_alert_pipeline_aborts_if_placeholder(
    mock_db_session, mock_create, mock_store, mock_update, mock_slack
):
    """
    Ensures that if alert_pipeline_task is invoked directly or erroneously with
    a risk_report that has is_placeholder=True, the task aborts before touching
    the database or sending a Slack notification. (Defense-in-depth)
    """
    scan_id = "12345678-1234-4234-a234-123456789012"
    risk_report = {
        "severity": "CRITICAL",
        "risk_score": 95.0,
        "is_placeholder": True
    }
    
    result = alert_pipeline_module.alert_pipeline_task(scan_id, risk_report)
    
    # Assert it returned the abort status
    assert result["status"] == "alert_skipped"
    assert result["reason"] == "is_placeholder"
    
    # Assert database and slack functions were NOT called
    mock_create.assert_not_called()
    mock_slack.assert_not_called()


@patch("tasks.alert_pipeline._mark_status")
@patch("tasks.alert_pipeline._send_slack_notification")
@patch("tasks.alert_pipeline._update_statistics")
@patch("tasks.alert_pipeline._store_iocs")
@patch("tasks.alert_pipeline._create_incident")
@patch("tasks.alert_pipeline.get_db_session")
def test_alert_pipeline_proceeds_if_real_model(
    mock_db_session, mock_create, mock_store, mock_update, mock_slack, mock_mark_status
):
    """
    Ensures that alert_pipeline_task processes real (is_placeholder=False) reports
    and triggers DB inserts and Slack notifications.
    """
    scan_id = "87654321-4321-4321-9210-210987654321"
    risk_report = {
        "severity": "HIGH",
        "risk_score": 80.0,
        "is_placeholder": False,
        "iocs": []
    }
    
    # Setup mock DB session context manager
    mock_session_instance = MagicMock()
    mock_session_instance.query.return_value.filter.return_value.first.return_value = None
    mock_db_session.return_value.__enter__.return_value = mock_session_instance
    
    result = alert_pipeline_module.alert_pipeline_task(scan_id, risk_report)
    
    # Assert it completed successfully
    assert result["status"] == "alert_pipeline_done"
    
    # Assert that DB and Slack were engaged
    mock_create.assert_called_once()
    mock_slack.assert_called_once()


@patch("tasks.alert_pipeline._mark_status")
@patch("tasks.alert_pipeline._send_slack_notification")
@patch("tasks.alert_pipeline._create_incident")
@patch("tasks.alert_pipeline.get_db_session")
def test_alert_redelivery_does_not_duplicate_incidents_or_notifications(mock_db, create, slack, status):
    db = mock_db.return_value.__enter__.return_value
    db.query.return_value.filter.return_value.first.return_value = MagicMock()
    result = alert_pipeline_module.alert_pipeline_task("87654321-4321-4321-9210-210987654321",
            {"severity": "HIGH", "risk_score": 90, "is_placeholder": False})
    assert result["duplicate"] is True
    db.query.return_value.filter.return_value.with_for_update.assert_called_once()
    create.assert_not_called()
    slack.assert_not_called()


@patch("tasks.alert_pipeline._send_slack_notification")
@patch("tasks.alert_pipeline._create_incident")
@patch("tasks.alert_pipeline.get_db_session")
def test_cancelled_scan_does_not_create_late_incident(mock_db, create, slack):
    db = mock_db.return_value.__enter__.return_value
    scan = MagicMock(status="cancelled")
    db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = scan
    result = alert_pipeline_module.alert_pipeline_task("87654321-4321-4321-9210-210987654321",
            {"severity": "HIGH", "risk_score": 90, "is_placeholder": False})
    assert result["reason"] == "terminal_scan"
    assert scan.status == "cancelled"
    db.commit.assert_not_called()
    create.assert_not_called()
    slack.assert_not_called()
