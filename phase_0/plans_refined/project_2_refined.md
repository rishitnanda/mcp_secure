# Project 2 Refined: `MCP-Box` (Virtualization Sandbox)

`MCP-Box` is an ephemeral containment system designed to isolate execution payloads from the host filesystem. It ensures that code run by an LLM tool cannot compromise the host computer.

---

## 🎯 1. Key Objectives & Scope

*   **Ephemeral Execution Containerization**: Spin up minimalist Linux containers (`python:3.11-alpine`) on-demand.
*   **Default Zero-Network Topology**: Prevent data exfiltration by severing outbound interfaces (`network_mode="none"`).
*   **Asynchronous Watchdog Supervisions**: Safeguard against infinite loops and resource hangs via tight timeouts.
*   **Zero-Trace Resource Cleaning**: Forcibly scrub CPU, memory, and filesystem volumes on task completion or failure.

---

## ⚙️ 2. Execution & Containment Specifications

When a code execution payload passes `MCP-Shield` validation, it is dispatched to `MCP-Box`:

```
           [Clean Payload]
                  │
                  ▼
┌─────────────────────────────────────┐
│ 1. Write script to temporary folder │
└─────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ 2. Create Docker container:         │
│    - image: python:3.11-alpine      │
│    - network_mode: "none"           │
│    - mem_limit: "128m"              │
│    - cpu_shares: 512                │
│    - read_only root filesystem      │
│    - mount temporary folder         │
│    - labels: {"mcp-sandbox": "true"}│
└─────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ 3. Execute script under watchdog:   │
│    asyncio.wait_for(timeout=2.0)    │
└─────────────────────────────────────┘
       │                      │
(Success within 2s)       (Timeout / Crash)
       │                      │
       ▼                      ▼
┌──────────────┐       ┌──────────────┐
│ Capture logs │       │ Kill container│
└──────────────┘       └──────────────┘
       │                      │
       └──────────┬───────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│ 4. Finally block:                   │
│    - container.remove(force=True)   │
│    - delete temporary folder        │
└─────────────────────────────────────┘
```

---

## 🕒 3. The Asynchronous Watchdog Engine

The watchdog prevents untrusted AI code from locking up the system event loop. It uses `asyncio` constructs:

```python
import asyncio
import docker
import os
import shutil

class DockerSandbox:
    def __init__(self, image="python:3.11-alpine", timeout=2.0):
        self.client = docker.from_env()
        self.image = image
        self.timeout = timeout

    async def execute(self, code: str) -> dict:
        # Create unique directory in host temporary space
        temp_dir = create_temp_workspace()
        write_code_file(temp_dir, code)

        container = None
        try:
            # Ephemeral container configuration
            container = self.client.containers.create(
                image=self.image,
                command="python /workspace/script.py",
                network_mode="none",
                mem_limit="128m",
                nano_cpus=1000000000, # Max 1 CPU core
                volumes={temp_dir: {"bind": "/workspace", "mode": "rw"}},
                labels={"mcp-box-sandbox": "true"},
                detach=True
            )

            # Start container asynchronously in background thread pool
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, container.start)

            # Wait for execution with hard timeout
            run_task = loop.run_in_executor(None, container.wait)
            result = await asyncio.wait_for(run_task, timeout=self.timeout)

            # Retrieve stdout/stderr
            logs = container.logs(stdout=True, stderr=True).decode("utf-8")
            exit_code = result.get("StatusCode", 0)
            return {"exit_code": exit_code, "logs": logs, "status": "success"}

        except asyncio.TimeoutError:
            if container:
                # Forcefully kill container
                await loop.run_in_executor(None, lambda: container.kill())
            return {"exit_code": -1, "logs": "Timeout limit exceeded (2000ms)", "status": "timeout"}

        except Exception as e:
            return {"exit_code": -1, "logs": f"Sandbox error: {str(e)}", "status": "error"}

        finally:
            if container:
                # Forcefully clean up container resources
                await loop.run_in_executor(None, lambda: container.remove(v=True, force=True))
            # Delete temporary workspace directories on host
            shutil.rmtree(temp_dir, ignore_errors=True)
```

---

## 🧹 4. Sandbox Daemon & Cleanup Strategies

To prevent container accumulation in production or on system crash:

1.  **Label-Based Pruning**:
    *   Every sandbox created is assigned the label `"mcp-box-sandbox": "true"`.
    *   On initialization of `MCP-Box` driver, it queries the Docker socket:
        `client.containers.list(all=True, filters={"label": "mcp-box-sandbox=true"})`
    *   It forcefully purges any matches. This cleans up dangling containers orphaned by a previous crash of the host process.
2.  **Read-Only Root Filesystem**:
    *   The container's root file system (`/`) is mounted read-only.
    *   Writing is strictly limited to `/workspace` (which is mapped to the ephemeral host directory). This prevents scripts from tampering with base system binaries inside the container image.
