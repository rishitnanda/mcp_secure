import asyncio
import os
import time
import sys
import aiosqlite
from typing import Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.getenv("MCP_SHIELD_DB_PATH", "telemetry.db")
        self._db: Optional[aiosqlite.Connection] = None
        self._initialized = False

    async def init_db(self):
        """Initializes a persistent aiosqlite connection and sets up the schema."""
        try:
            self._db = await aiosqlite.connect(self.db_path)
            await self._db.execute("PRAGMA journal_mode=WAL;")
            # NORMAL reduces sync cycles without compromising write durability in WAL mode
            await self._db.execute("PRAGMA synchronous=NORMAL;")

            await self._db.execute(
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
            await self._db.commit()
            self._initialized = True
        except Exception as e:
            print(f"Database initialization failed: {e}", file=sys.stderr)
            raise e

    async def close(self):
        """Closes the persistent database connection cleanly during lifespan shutdown."""
        if self._db:
            await self._db.close()
            self._db = None

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
        """Background worker to perform the actual write using the persistent connection."""
        if not self._db:
            return
        try:
            await self._db.execute(
                """
                INSERT INTO logs (id, timestamp, method, payload, status, duration_ms, exit_code, server_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (request_id, time.time(), method, payload, status, duration_ms, exit_code, server_id)
            )
            await self._db.commit()
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

        Guard: if init_db has not completed (possible in test isolation), returns
        a no-op task to prevent unhandled task exceptions (Problem 3).
        """
        if not self._initialized:
            # No-op guard: DB not ready, swallow silently
            return asyncio.create_task(asyncio.sleep(0))
        # Fire-and-forget task registration to avoid slowing request proxy pathways
        task = asyncio.create_task(
            self._write_log(request_id, method, payload, status, duration_ms, exit_code, server_id)
        )
        return task

    async def get_metrics(self) -> Dict[str, int]:
        """Retrieves aggregation counts by status using the persistent connection."""
        metrics = {"SUCCESS": 0, "BLOCKED": 0, "TIMEOUT": 0, "SANITIZED": 0}
        if not self._db:
            return metrics
        try:
            async with self._db.execute(
                "SELECT status, COUNT(*) FROM logs GROUP BY status;"
            ) as cursor:
                rows = await cursor.fetchall()
                for status, count in rows:
                    metrics[status] = count
        except Exception as e:
            print(f"Database metrics query failed: {e}", file=sys.stderr)
        return metrics

    async def get_logs(self, limit: int = 50) -> list:
        """Retrieves the last N logs from the database using the persistent connection."""
        if not self._db:
            return []
        try:
            self._db.row_factory = aiosqlite.Row
            async with self._db.execute(
                "SELECT id, timestamp, method, payload, status, duration_ms, exit_code, server_id FROM logs ORDER BY timestamp DESC LIMIT ?;",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(row) for row in rows]
        except Exception as e:
            print(f"Database logs query failed: {e}", file=sys.stderr)
            return []
