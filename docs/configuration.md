# Configuration

All security policy is declarative in `config/shield_config.json`. No code changes needed to add patterns, extend tool namespaces, or adjust trust mode.

```json
{
  "trust_mode": "prompt",
  "servers": {
    "filesystem-server": {
      "allowed_tools": ["read_file", "write_file", "list_directory"],
      "sampling_allowed": false
    }
  },
  "ast_policy": {
    "blocked_modules": ["os", "sys", "subprocess", "socket", "ctypes"],
    "blocked_calls": ["eval", "exec", "getattr", "__import__"]
  }
}
```

HMAC keys are loaded from environment variables (`MCP_KEY_FILESYSTEM`, `MCP_KEY_TRUSTED`) — never stored in the config file.
