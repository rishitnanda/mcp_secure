import os
import pytest
import asyncio
import glob
import shutil
from mcp_box.src.sandbox import DockerSandbox

@pytest.fixture
def sandbox():
    return DockerSandbox()

@pytest.mark.asyncio
async def test_sandbox_clean_exec(sandbox):
    # B1: Clean execution checks exit code 0, standard logs, and success status
    print(f"\n[INFO] Running test_sandbox_clean_exec. Mock Mode: {sandbox.use_mock}")
    code = "print(42)"
    result = await sandbox.execute(code)
    
    assert result["exit_code"] == 0
    assert "42" in result["logs"]
    assert result["status"] == "success"
    assert result["duration_ms"] > 0

@pytest.mark.asyncio
async def test_sandbox_timeout_abort(sandbox):
    # B2: Execution timeout abort triggers after 2.0s hard watchdog limit
    print(f"\n[INFO] Running test_sandbox_timeout_abort. Mock Mode: {sandbox.use_mock}")
    code = "import time\ntime.sleep(5.0)"
    result = await sandbox.execute(code)
    
    assert result["exit_code"] == -1
    assert result["status"] == "timeout"
    # Duration must be within bounds of the 2.0s timeout (allowing scheduling overhead)
    assert 1800 <= result["duration_ms"] <= 3000

@pytest.mark.asyncio
async def test_sandbox_network_isolation(sandbox):
    # B3: Network access should be disabled (isolated sandbox)
    # NOTE: This is a source-code keyword check, not real network isolation.
    # Real isolation is enforced by Docker network_mode="none".
    # This mock only approximates the behaviour for CI without Docker.
    print(f"\n[INFO] Running test_sandbox_network_isolation. Mock Mode: {sandbox.use_mock}")
    code = (
        "import urllib.request\n"
        "try:\n"
        "    urllib.request.urlopen('http://google.com', timeout=1.0)\n"
        "    print('CONNECTED')\n"
        "except Exception as e:\n"
        "    print(f'FAILED: {e}')\n"
    )
    result = await sandbox.execute(code)
    assert "CONNECTED" not in result["logs"]
    assert "FAILED" in result["logs"] or "blocked" in result["logs"].lower()

@pytest.mark.asyncio
async def test_sandbox_oom_limit(sandbox):
    # B4: Allocating more than 128MB RAM should trigger OOM / crash
    # NOTE: OOM behaviour in mock mode is OS/allocator dependent.
    # Docker mem_limit="128m" provides deterministic enforcement.
    print(f"\n[INFO] Running test_sandbox_oom_limit. Mock Mode: {sandbox.use_mock}")
    code = "x = [0] * 50_000_000\nprint(len(x))"
    result = await sandbox.execute(code)
    
    assert result["status"] == "oom" or result["exit_code"] != 0

@pytest.mark.asyncio
async def test_sandbox_cleanup(sandbox):
    # B5: Verify host temporary workspace directories are deleted after run completes
    print(f"\n[INFO] Running test_sandbox_cleanup. Mock Mode: {sandbox.use_mock}")
    before_dirs = set(glob.glob("/tmp/mcp_sandbox_*"))
    
    result = await sandbox.execute("print('cleanup test')")
    assert result["exit_code"] == 0
    
    after_dirs = set(glob.glob("/tmp/mcp_sandbox_*"))
    new_dirs = after_dirs - before_dirs
    assert len(new_dirs) == 0, f"Leak detected! Remaining workspace directories: {new_dirs}"

@pytest.mark.asyncio
async def test_sandbox_readonly_fs(sandbox):
    # B6: Writing to paths outside of /workspace should be blocked
    print(f"\n[INFO] Running test_sandbox_readonly_fs. Mock Mode: {sandbox.use_mock}")
    code = (
        "try:\n"
        "    with open('/corrupt_test.txt', 'w') as f:\n"
        "        f.write('corrupt')\n"
        "    print('WRITTEN')\n"
        "except Exception as e:\n"
        "    print(f'BLOCKED: {e}')\n"
    )
    result = await sandbox.execute(code)
    assert "WRITTEN" not in result["logs"]
    assert "BLOCKED" in result["logs"] or "Read-only file system" in result["logs"]
