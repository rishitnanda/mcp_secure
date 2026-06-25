import time
from typing import List, Dict, Any, Optional

class SessionState:
    """Tracks connection-specific state and call history for provenance tracking."""
    def __init__(self, server_id: str, db_manager: Optional[Any] = None):
        self.server_id = server_id
        self.verified_capabilities: List[str] = []
        self.cert_expiry: Optional[float] = None
        
        # Provenance tracking fields
        self.call_history: List[Dict[str, Any]] = []
        self.created_at: float = time.time()
        self.last_active: float = self.created_at
        self.db_manager = db_manager
        
    def record_call(self, method: str, tool_name: Optional[str], outcome: str):
        """Records a call outcome into both in-memory history and persistent SQLite."""
        timestamp = time.time()
        self.call_history.append({
            "method": method,
            "tool_name": tool_name,
            "timestamp": timestamp,
            "outcome": outcome
        })
        self.last_active = timestamp
        
        # Persistent write-through to SQLite (non-blocking task dispatch)
        if self.db_manager:
            self.db_manager.log_session_call(self.server_id, method, tool_name, outcome)

class SessionStore:
    """
    In-memory session store keyed by session_id with TTL eviction and 
    SQLite fallback state reconstruction for fault tolerance.
    """
    def __init__(self, timeout_seconds: int = 1800, max_calls_per_session: int = 100, db_manager: Optional[Any] = None):
        self._sessions: Dict[str, SessionState] = {}
        self.timeout_seconds = timeout_seconds
        self.max_calls_per_session = max_calls_per_session
        self.db_manager = db_manager
    
    async def get_or_create(self, session_id: str) -> SessionState:
        """Returns existing session or reconstructs it from SQLite on a cold cache hit."""
        now = time.time()
        
        # Lazy eviction of in-memory sessions
        expired_keys = [
            sid for sid, state in self._sessions.items()
            if now - state.last_active > self.timeout_seconds
        ]
        for key in expired_keys:
            del self._sessions[key]
            
        if session_id not in self._sessions:
            state = SessionState(server_id=session_id, db_manager=self.db_manager)
            
            # Reconstruct historical sliding window context if SQLite manager is present
            if self.db_manager:
                history = await self.db_manager.get_session_history(session_id, self.timeout_seconds)
                if history:
                    for row in history:
                        state.call_history.append({
                            "method": row["method"],
                            "tool_name": row["tool_name"],
                            "timestamp": row["timestamp"],
                            "outcome": row["outcome"]
                        })
                    # Synchronize the active state tracking with the last known transaction
                    state.last_active = history[-1]["timestamp"]
            
            self._sessions[session_id] = state
        
        return self._sessions[session_id]

    def clear(self):
        """Clears all in-memory sessions (primarily for test execution isolation)."""
        self._sessions.clear()

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)