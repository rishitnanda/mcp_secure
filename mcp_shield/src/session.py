import time
from typing import List, Dict, Any, Optional

class SessionState:
    """Tracks connection-specific state and call history for provenance tracking."""
    def __init__(self, server_id: str):
        self.server_id = server_id
        self.verified_capabilities: List[str] = []
        self.cert_expiry: Optional[float] = None
        
        # Provenance tracking fields
        self.call_history: List[Dict[str, Any]] = []
        self.created_at: float = time.time()
        self.last_active: float = self.created_at
        
    def record_call(self, method: str, tool_name: Optional[str], outcome: str):
        """Records a call outcome into the session history."""
        self.call_history.append({
            "method": method,
            "tool_name": tool_name,
            "timestamp": time.time(),
            "outcome": outcome
        })
        self.last_active = time.time()

class SessionStore:
    """
    In-memory session store keyed by session_id with TTL eviction.
    Note: The proxy runs on asyncio. Concurrent requests interleave on the event loop, 
    so a plain dict is sufficient for state. A threading.Lock is unnecessary overhead 
    and could cause issues in an async context. If deploying with multiple workers, 
    a shared external store (e.g., Redis) should be used instead.
    """
    def __init__(self, timeout_seconds: int = 1800, max_calls_per_session: int = 100):
        self._sessions: Dict[str, SessionState] = {}
        self.timeout_seconds = timeout_seconds
        self.max_calls_per_session = max_calls_per_session
    
    def get_or_create(self, session_id: str) -> SessionState:
        """Returns existing session or creates a new one. Evicts expired sessions inline."""
        now = time.time()
        
        # Lazy eviction
        expired_keys = [
            sid for sid, state in self._sessions.items()
            if now - state.last_active > self.timeout_seconds
        ]
        for key in expired_keys:
            del self._sessions[key]
            
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(server_id=session_id)
        
        return self._sessions[session_id]

    def clear(self):
        """Clears all sessions (for testing)."""
        self._sessions.clear()

    @property
    def active_count(self) -> int:
        return len(self._sessions)
