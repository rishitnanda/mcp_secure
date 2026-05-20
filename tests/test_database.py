import os
import pytest
import tempfile
import asyncio
from mcp_shield.src.database import DatabaseManager

@pytest.fixture
def temp_db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass
    for ext in ["-wal", "-shm"]:
        try:
            os.unlink(path + ext)
        except OSError:
            pass

@pytest.mark.asyncio
async def test_db_happy_path(temp_db_path):
    db_mgr = DatabaseManager(temp_db_path)
    await db_mgr.init_db()

    # Log events
    task1 = db_mgr.log_event("req-1", "tools/call", '{"code": "1+1"}', "SUCCESS", 12.5, 0, "sandbox-server")
    task2 = db_mgr.log_event("req-2", "tools/call", '{"code": "rm -rf"}', "BLOCKED", 1.2, None, "sandbox-server")
    task3 = db_mgr.log_event("req-3", "tools/call", '{"code": "import time"}', "TIMEOUT", 2000.0, -9, "sandbox-server")

    # Await database write completion
    await asyncio.gather(task1, task2, task3)

    # Check metrics
    metrics = await db_mgr.get_metrics()
    assert metrics["SUCCESS"] == 1
    assert metrics["BLOCKED"] == 1
    assert metrics["TIMEOUT"] == 1
    assert metrics["SANITIZED"] == 0

@pytest.mark.asyncio
async def test_db_unavailable_fails_gracefully():
    # An invalid directory path that will cause write failures
    invalid_path = "/nonexistent/path/telemetry.db"
    db_mgr = DatabaseManager(invalid_path)

    # init_db raises because it is a critical startup task
    with pytest.raises(Exception):
        await db_mgr.init_db()

    # log_event must execute its task and log to stderr without crashing the main pipeline
    task = db_mgr.log_event("req-4", "tools/call", "{}", "SUCCESS", 5.0, 0, "test-server")
    await task  # Awaiting the background worker completes safely without raising

    # get_metrics must catch and return zeroed stats instead of bubbling up
    metrics = await db_mgr.get_metrics()
    assert metrics["SUCCESS"] == 0
    assert metrics["BLOCKED"] == 0

@pytest.mark.asyncio
async def test_db_concurrent_stress_test(temp_db_path):
    db_mgr = DatabaseManager(temp_db_path)
    await db_mgr.init_db()

    num_writes = 100
    tasks = []
    for i in range(num_writes):
        tasks.append(
            db_mgr.log_event(
                f"req-stress-{i}",
                "tools/call",
                '{"param": "val"}',
                "SUCCESS" if i % 2 == 0 else "SANITIZED",
                15.0,
                0,
                "stress-server"
            )
        )

    await asyncio.gather(*tasks)

    metrics = await db_mgr.get_metrics()
    assert metrics["SUCCESS"] == 50
    assert metrics["SANITIZED"] == 50

