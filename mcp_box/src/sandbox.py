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
        try:
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

    def execute(self, code: str) -> Dict[str, Any]:
        """Executes code in the sandbox environment."""
        if self.use_mock:
            return {"exit_code": 0, "logs": "[MOCK] Docker unavailable", "status": "mock", "duration_ms": 0.0}
        
        # TODO: Implement full docker container execution on Day 6
        raise NotImplementedError("Execution logic will be implemented on Day 6")
