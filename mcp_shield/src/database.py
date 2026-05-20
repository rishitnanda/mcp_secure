import asyncio
import time
import sys
import aiosqlite
from typing import Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str = "telemetry.db"):
        self.db_path = db_path
        self._initialized = False

    async def init_db(self):
        """Initializes the database schema and sets performance pragmas."""
        try:
            # We connect dynamically per operation to support concurrent handles
            async with aiosqlite.connect(self.db_path) as db:
                # WAL allows concurrent reads and writes without lock exception crashes
                await db.execute("PRAGMA journal_mode=WAL;")
                # NORMAL reduces sync cycles without compromising write durability in WAL mode
                await db.execute("PRAGMA synchronous=NORMAL;")
                await db.execute(
                    """
                    CREATE TABLE IF NOT EXISTS logs (
                        id TEXT PRIMARY KEY,
                        timestamp REAL,
                        method TEXT,
                        payload TEXT,
                        status TEXT,
                        duration_ms REAL,
                        exit_code INTEGER,
                        server_id TEXT
                    );
                    """
                )
                await db.commit()
            self._initialized = True
        except Exception as e:
            print(f"Database initialization failed: {e}", file=sys.stderr)
            raise e

    async def _write_log(
        self,
        request_id: str,
        method: str,
        payload: str,
        status: str,
        duration_ms: float,
        exit_code: Optional[int],
        server_id: str
    ):
        """Background worker to perform the actual write."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(
                    """
                    INSERT INTO logs (id, timestamp, method, payload, status, duration_ms, exit_code, server_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (request_id, time.time(), method, payload, status, duration_ms, exit_code, server_id)
                )
                await db.commit()
        except Exception as e:
            print(f"Async database write failed: {e}", file=sys.stderr)

    def log_event(
        self,
        request_id: str,
        method: str,
        payload: str,
        status: str,
        duration_ms: float,
        exit_code: Optional[int],
        server_id: str
    ) -> asyncio.Task:
        """Asynchronously dispatches a log write to the event loop.
        
        Returns the asyncio Task to allow waiting in tests, but in production 
        this is called without awaiting to keep the hot path non-blocking.
        """
        # Fire-and-forget task registration to avoid slowing request proxy pathways
        task = asyncio.create_task(
            self._write_log(request_id, method, payload, status, duration_ms, exit_code, server_id)
        )
        return task

    async def get_metrics(self) -> Dict[str, int]:
        """Retrieves aggregation counts by status."""
        metrics = {"SUCCESS": 0, "BLOCKED": 0, "TIMEOUT": 0, "SANITIZED": 0}
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(
                    "SELECT status, COUNT(*) FROM logs GROUP BY status;"
                ) as cursor:
                    rows = await cursor.fetchall()
                    for status, count in rows:
                        if status in metrics:
                            metrics[status] = count
                        else:
                            metrics[status] = count
        except Exception as e:
            print(f"Database metrics query failed: {e}", file=sys.stderr)
        return metrics
