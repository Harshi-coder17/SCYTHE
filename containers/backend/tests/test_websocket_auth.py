import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import main


@pytest.mark.asyncio
async def test_valid_websocket_auth_frame_resolves_active_user():
    websocket = SimpleNamespace(receive_text=AsyncMock(return_value=json.dumps({"type": "auth", "token": "fixture-token"})))
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = SimpleNamespace(is_active=True)
    manager = MagicMock()
    manager.__enter__.return_value = db
    with patch.object(main, "decode_access_token", return_value={"sub": "fixture-user"}) as decode, \
            patch.object(main, "get_db_session", return_value=manager):
        assert await main._ws_frame_auth(websocket) == "fixture-user"
    decode.assert_called_once_with("fixture-token", db=db)


@pytest.mark.asyncio
@pytest.mark.parametrize("frame", ["[]", "null", "bad-json", '{"type":"auth","token":17}', '{"type":"other"}'])
async def test_invalid_websocket_frames_fail_closed(frame):
    websocket = SimpleNamespace(receive_text=AsyncMock(return_value=frame))
    assert await main._ws_frame_auth(websocket) is None


@pytest.mark.asyncio
async def test_websocket_auth_frame_deadline_is_enforced():
    async def delayed_frame():
        await asyncio.sleep(1)
        return "{}"
    websocket = SimpleNamespace(receive_text=delayed_frame)
    with patch.object(main, "_WS_AUTH_TIMEOUT_SECONDS", 0.001):
        assert await main._ws_frame_auth(websocket) is None
