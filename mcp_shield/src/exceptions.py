class MCPShieldException(Exception):
    """Base class for all MCP-Shield exceptions."""
    def __init__(self, message: str, stage: str):
        super().__init__(message)
        self.stage = stage

class PolicyViolationException(MCPShieldException):
    def __init__(self, message: str, matched_pattern: str):
        super().__init__(message, stage="regex")
        self.matched_pattern = matched_pattern

class ASTValidationException(MCPShieldException):
    def __init__(self, message: str, node_type: str):
        super().__init__(message, stage="ast")
        self.node_type = node_type

class NamespaceViolationException(MCPShieldException):
    def __init__(self, tool_name: str, server_id: str):
        super().__init__(f"Tool '{tool_name}' not in allowed namespace for '{server_id}'", stage="namespace")
        self.tool_name = tool_name

class CapabilityViolationException(MCPShieldException):
    def __init__(self, capability: str, server_id: str):
        super().__init__(f"Capability '{capability}' not attested for '{server_id}'", stage="attestation")
        self.capability = capability

class SequenceViolationException(MCPShieldException):
    def __init__(self, description: str, server_id: str):
        super().__init__(f"Suspicious sequence detected: {description}", stage="sequence")
        self.description = description

class MethodNotFoundException(MCPShieldException):
    def __init__(self, method: str):
        super().__init__(f"Method not found: {method}", stage="namespace")
        self.method = method

def to_jsonrpc_error(exc: Exception, request_id=None) -> dict:
    """Converts any MCPShield exception to a JSON-RPC 2.0 error dict.
    Transport-agnostic — works in both HTTP and stdio mode."""
    
    CODE_MAP = {
        PolicyViolationException:    (-32602, "Security policy violation: blocked pattern detected"),
        ASTValidationException:      (-32602, "Security policy violation: restricted AST token"),
        SequenceViolationException:  (-32602, "Security policy violation: blocked sequence detected"),
        NamespaceViolationException: (-32601, "Method not found: tool not in allowed namespace"),
        CapabilityViolationException:(-32601, "Method not found: capability not attested"),
        MethodNotFoundException:     (-32601, "Method not found"),
    }

    for exc_type, (code, default_msg) in CODE_MAP.items():
        if isinstance(exc, exc_type):
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": code,
                    "message": str(exc) or default_msg,
                    "data": {"stage": exc.stage}
                }
            }

    # Fallback for unexpected exceptions
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32603,
            "message": "Internal gateway error",
            "data": {"stage": "unknown"}
        }
    }
