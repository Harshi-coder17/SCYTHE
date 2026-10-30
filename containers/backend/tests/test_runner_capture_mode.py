import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from services import sandbox_runner_svc as runner


@pytest.mark.asyncio
async def test_rejected_duplicate_does_not_remove_another_active_container():
    scan_id = "12345678-1234-4234-a234-123456789abc"
    runner._active_scan_ids.add(scan_id)
    try:
        with patch.object(runner, "SANDBOX_RUNNER_SECRET", "fixture-key"), \
             patch.object(runner, "_get_semaphore", return_value=asyncio.Semaphore(2)), \
             patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as docker:
            with pytest.raises(HTTPException) as error:
                await runner.detonate(runner.DetonateRequest(scan_id=scan_id, target_url="https://example.com"), "fixture-key")
        assert error.value.status_code == 409
        docker.assert_not_called()
        assert scan_id in runner._active_scan_ids
    finally:
        runner._active_scan_ids.discard(scan_id)


def test_sandbox_uid_matches_app_shared_scan_permissions():
    from pathlib import Path

    dockerfile = Path(__file__).resolve().parents[2] / "sandbox" / "docker" / "Dockerfile"
    source = dockerfile.read_text(encoding="utf-8")
    assert runner.SANDBOX_USER == "10001:10001"
    assert runner.SANDBOX_USER_ARGS == ("--user", "10001:10001")
    assert "groupadd --gid 10001 sandbox" in source
    assert "useradd --uid 10001 --gid sandbox" in source
