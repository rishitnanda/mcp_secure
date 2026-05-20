import os
import shutil
import uuid
import logging
import docker
from typing import Dict, Any

logger = logging.getLogger("mcp_box.sandbox")

class DockerSandbox:
    def __init__(self):
        self.use_mock = False
        try:
            self.client = docker.from_env()
            self.client.ping()
            logger.info("Connected to Docker daemon successfully.")
            self._prune_containers()
        except Exception as e:
            logger.warning(
                f"Docker daemon not available: {e}. Falling back to simulated sandbox mode."
            )
            self.use_mock = True
            self.client = None

    def _prune_containers(self) -> None:
        """Kills and removes all containers labeled mcp-box-sandbox=true."""
        if self.use_mock or not self.client:
            return
        # Docker SDK operations are blocking, run synchronously in constructor
        try:
            # Filter specifically on our unique label to avoid touching host containers
            containers = self.client.containers.list(
                all=True, filters={"label": "mcp-box-sandbox=true"}
            )
            for container in containers:
                try:
                    logger.info(f"Pruning container: {container.id}")
                    container.kill()
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Error pruning containers: {e}")

    def create_temp_workspace(self) -> str:
        """Creates a uuid4 named directory in /tmp and sets permissions to 0o777."""
        temp_dir = os.path.join("/tmp", f"mcp_sandbox_{uuid.uuid4()}")
        os.makedirs(temp_dir, exist_ok=True)
        # 0o777 required: container runs as sandboxuser (uid 1000),
        # which has no special privileges on the host filesystem.
        # The mount is ephemeral and deleted in the finally block.
        os.chmod(temp_dir, 0o777)
        logger.info(f"Created temp workspace at {temp_dir}")
        return temp_dir

    def write_code_file(self, temp_dir: str, code: str) -> str:
        """Writes the python code to main.py inside the temporary directory."""
        filepath = os.path.join(temp_dir, "main.py")
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)
        logger.info(f"Wrote execution code to {filepath}")
        return filepath

    async def execute(self, code: str) -> Dict[str, Any]:
        """Executes code in the sandbox environment.
        
        Runs asynchronously by dispatching blocking Docker SDK calls to a thread pool.
        """
        if self.use_mock:
            return await self._execute_mock(code)

        import asyncio
        import time

        loop = asyncio.get_running_loop()
        temp_dir = None
        container = None
        start_time = time.time()
        
        try:
            temp_dir = self.create_temp_workspace()
            self.write_code_file(temp_dir, code)

            # Create container with resource caps and network isolated
            # nano_cpus: 1_000_000_000 (1.0 CPU core)
            # mem_limit: 128m (128MB RAM limit)
            # read_only: True (root filesystem write protection)
            # network_mode: none (no external network access)
            # user: sandboxuser (non-privileged execution)
            # volumes: bind host temp_dir to /workspace (rw)
            container = await loop.run_in_executor(
                None,
                lambda: self.client.containers.create(
                    image="mcp-box-sandbox:latest",
                    command="python3 main.py",
                    labels={"mcp-box-sandbox": "true"},
                    network_mode="none",
                    mem_limit="128m",
                    nano_cpus=1000000000,
                    read_only=True,
                    volumes={temp_dir: {"bind": "/workspace", "mode": "rw"}},
                    user="sandboxuser",
                    working_dir="/workspace"
                )
            )

            # Start container (blocking SDK call delegated to worker thread)
            await loop.run_in_executor(None, container.start)

            # Wait for execution with 2.0s hard timeout watchdog
            try:
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, container.wait),
                    timeout=2.0
                )
                exit_code = result.get("StatusCode", 0)
                status = "success" if exit_code == 0 else "failure"
                # Exit code 137 typically denotes out-of-memory killing on Linux systems
                if exit_code == 137:
                    status = "oom"
            except asyncio.TimeoutError:
                # Watchdog triggered: terminate container immediately
                try:
                    await loop.run_in_executor(None, container.kill)
                except Exception:
                    pass
                exit_code = -1
                status = "timeout"

            # Capture stdout/stderr logs
            logs_bytes = await loop.run_in_executor(None, lambda: container.logs(stdout=True, stderr=True))
            logs = logs_bytes.decode("utf-8", errors="replace")

        except Exception as e:
            logger.error(f"Sandbox container execution failed: {e}")
            exit_code = -1
            logs = f"Error: {str(e)}"
            status = "error"
        finally:
            # Clean up ephemeral resources unconditionally
            if container:
                try:
                    await loop.run_in_executor(None, lambda: container.remove(force=True))
                except Exception:
                    pass
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

        duration_ms = (time.time() - start_time) * 1000.0
        return {
            "exit_code": exit_code,
            "logs": logs,
            "status": status,
            "duration_ms": duration_ms
        }

    async def _execute_mock(self, code: str) -> Dict[str, Any]:
        """Simulates container execution using a subprocess with resource limitations.
        
        Designed for local testing/CI verification when the Docker daemon is absent.
        """
        import sys
        import subprocess
        import time
        import asyncio

        start_time = time.time()
        temp_dir = None

        try:
            temp_dir = self.create_temp_workspace()
            filepath = self.write_code_file(temp_dir, code)

            # NOTE: This is a source-code keyword check, not real network isolation.
            # Real isolation is enforced by Docker network_mode="none".
            # This mock only approximates the behaviour for CI without Docker.
            if "urllib" in code or "requests" in code or "socket" in code:
                return {
                    "exit_code": 1,
                    "logs": "[MOCK] Network connection blocked (Simulated network isolation)",
                    "status": "failure",
                    "duration_ms": (time.time() - start_time) * 1000.0
                }

            # B6 Read-only filesystem simulation: block attempts to write to root paths
            if "open(" in code and any(p in code for p in ["'/", '"/']):
                if not ("/workspace" in code or temp_dir in code):
                    return {
                        "exit_code": 1,
                        "logs": "[MOCK] OSError: [Errno 30] Read-only file system",
                        "status": "failure",
                        "duration_ms": (time.time() - start_time) * 1000.0
                    }

            # Subprocess limits implementation via resource limits
            def limit_resources():
                try:
                    import resource
                    # RLIMIT_AS caps virtual memory address space (triggers MemoryError)
                    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))
                except Exception:
                    pass

            proc = subprocess.Popen(
                [sys.executable, filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                # preexec_fn runs in child process fork before exec loading
                preexec_fn=limit_resources if os.name != 'nt' else None
            )

            loop = asyncio.get_running_loop()
            
            try:
                # We supply timeout directly to communicate to prevent thread lockups
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: proc.communicate(timeout=2.0)),
                    timeout=3.0  # outer safety net
                )
                exit_code = proc.returncode
                logs = (stdout_bytes + stderr_bytes).decode("utf-8", errors="replace")
                
                status = "success" if exit_code == 0 else "failure"
                if "MemoryError" in logs or exit_code in (137, -9):
                    status = "oom"
            except subprocess.TimeoutExpired:
                # Subprocess timed out, kill it and collect residual logs
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
                exit_code = -1
                logs = "[MOCK] TimeoutError: Execution exceeded 2.0s watchdog limit"
                status = "timeout"
            except asyncio.TimeoutError:
                # Executor timeout backup triggered
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
                exit_code = -1
                logs = "[MOCK] TimeoutError: Execution exceeded 2.0s watchdog limit"
                status = "timeout"

        except Exception as e:
            exit_code = -1
            logs = f"[MOCK] Execution error: {e}"
            status = "error"
        finally:
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

        duration_ms = (time.time() - start_time) * 1000.0
        return {
            "exit_code": exit_code,
            "logs": logs,
            "status": status,
            "duration_ms": duration_ms
        }


