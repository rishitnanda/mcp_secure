import pytest

try:
    from mcp_shield.src.policy import PolicyEngine
    from mcp_shield.src.session import SessionState, SessionStore
    from mcp_shield.src.schemas import JSONRPCRequest
    _HAS_SHIELD = True
except ImportError:
    _HAS_SHIELD = False


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine()


@pytest.fixture(scope="module")
def store():
    return SessionStore()


def _session(server_id="filesystem-server", capabilities=None):
    s = SessionState(server_id=server_id)
    if capabilities is not None:
        s.verified_capabilities = capabilities
    return s


def _req(method="tools/call", params=None):
    return JSONRPCRequest(
        jsonrpc="2.0",
        id=1,
        method=method,
        params=params or {}
    )


def _tool_req(tool_name, arguments=None, server_id="filesystem-server"):
    return _req(
        method="tools/call",
        params={"name": tool_name, "arguments": arguments or {}}
    )


# ---------------------------------------------------------------------------
# FP-001 — Output Sanitizer: "you are now" in a deployment status message
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-001 [FALSE POSITIVE]: output_sanitizer blocks 'you are now' as a substring, "
        "but the phrase appears constantly in benign deployment and CI output. "
        "A tool returning 'Deployment complete: you are now on version 2.4.1' is flagged. "
        "Fix: narrow the rule to require 'you are now [an|a] ...' or anchor it to role-change "
        "phrasing (e.g. 'you are now an unrestricted|a different|a new persona')."
    )
)
def test_FP001_deployment_status_you_are_now(engine):
    """FP / Sanitizer: legitimate deployment status message contains 'you are now'."""
    text = "Deployment complete: you are now on version 2.4.1 of the service."
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-001: benign deployment status 'you are now on version 2.4.1' "
        "must NOT be flagged by the sanitizer."
    )


# ---------------------------------------------------------------------------
# FP-002 — Output Sanitizer: "user message:" in a chat-log export tool
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-002 [FALSE POSITIVE]: output_sanitizer blocks 'user message:' as a substring. "
        "Any tool that returns structured chat logs, support ticket exports, or audit trails "
        "will be incorrectly flagged. A customer-support MCP that surfaces 'user message: "
        "please reset my password' is blocked outright. "
        "Fix: require 'user message:' to be followed by known injection keywords, "
        "or scope the rule to role-spoofing context (e.g. preceded by a system/assistant prefix)."
    )
)
def test_FP002_chat_log_export_user_message(engine):
    """FP / Sanitizer: structured chat log export contains 'user message:' label."""
    text = (
        "Ticket #4821 transcript:\n"
        "user message: I cannot log into my account\n"
        "agent message: Let me help you reset your credentials."
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-002: chat log export with 'user message:' label must NOT be flagged."
    )

# ---------------------------------------------------------------------------
# FP-006 — AST Policy: getattr blocked in ORM model introspection
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-006 [FALSE POSITIVE]: 'getattr' is in ast_policy.blocked_calls, but it is a "
        "fundamental Python builtin used ubiquitously for legitimate dynamic dispatch. "
        "Any ORM, plugin system, dataclass accessor, or serializer uses getattr. "
        "A trusted-server executing 'value = getattr(model, field_name)' for safe "
        "record serialization is blocked. "
        "Fix: remove getattr/setattr from blocked_calls and instead flag specific dangerous "
        "combinations: getattr(os, ...), getattr(sys, ...), getattr(__builtins__, ...)."
    )
)
def test_FP003_getattr_in_orm_serializer(engine):
    """FP / AST: trusted-server submits ORM serializer code using getattr for field access."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "def serialize(model, fields):\n"
        "    return {f: getattr(model, f) for f in fields}\n"
        "result = serialize(record, ['id', 'name', 'email'])"
    )
    req = _req(
        method="tools/call",
        params={"name": "run_python", "arguments": {"code": code}}
    )
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-006: ORM field serialization using getattr on safe model fields "
        "must NOT be blocked by AST policy."
    )


# ---------------------------------------------------------------------------
# FP-007 — AST Policy: threading blocked in a legitimate data pipeline
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-007 [FALSE POSITIVE]: 'threading' is in ast_policy.blocked_modules, but "
        "concurrent processing is a standard requirement for data pipelines, web scrapers, "
        "and I/O-bound tasks. A trusted-server running a thread pool to process file chunks "
        "in parallel is blocked outright. "
        "Fix: allow threading/multiprocessing on trusted-server explicitly, or only block "
        "specific dangerous threading uses (e.g. daemon threads with os.system calls)."
    )
)
def test_FP004_threading_in_data_pipeline(engine):
    """FP / AST: trusted-server runs a thread-pool data processor."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "import threading\n"
        "results = []\n"
        "def process(chunk):\n"
        "    results.append(sum(chunk))\n"
        "threads = [threading.Thread(target=process, args=([i],)) for i in range(4)]\n"
        "for t in threads: t.start()\n"
        "for t in threads: t.join()\n"
        "print(results)"
    )
    req = _req(
        method="tools/call",
        params={"name": "run_python", "arguments": {"code": code}}
    )
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-007: data pipeline using threading for parallel chunk processing "
        "must NOT be blocked by AST policy."
    )


# ---------------------------------------------------------------------------
# FP-008 — AST Policy: urllib.parse used for URL normalization (no network I/O)
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-008 [FALSE POSITIVE]: 'urllib' is blocked wholesale in ast_policy.blocked_modules. "
        "However, urllib.parse is a pure string-manipulation library used for URL encoding, "
        "query string parsing, and path normalization — it makes zero network connections. "
        "Blocking it prevents any code that normalizes or validates URLs from running "
        "on the trusted server. "
        "Fix: only block urllib.request and urllib.urlopen (the network-I/O submodules); "
        "allow urllib.parse explicitly."
    )
)
def test_FP005_urllib_parse_url_normalization(engine):
    """FP / AST: trusted-server uses urllib.parse for query string parsing, no network I/O."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "from urllib.parse import urlencode, urlparse, parse_qs\n"
        "url = 'https://api.example.com/search?q=hello+world&limit=10'\n"
        "parsed = urlparse(url)\n"
        "params = parse_qs(parsed.query)\n"
        "print(params)"
    )
    req = _req(
        method="tools/call",
        params={"name": "run_python", "arguments": {"code": code}}
    )
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-008: urllib.parse for URL query string parsing (no network I/O) "
        "must NOT be blocked by AST policy."
    )


# ---------------------------------------------------------------------------
# FP-009 — Sequence Policy: read_file → write_file blocked for a file formatter
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-009 [FALSE POSITIVE]: the 'write_after_read_sensitive' sequence rule on "
        "filesystem-server blocks any read_file → write_file pattern as a suspected "
        "data-staging attempt. However, read-then-write is the canonical operation for "
        "every file editor, code formatter, and template renderer. A tool that reads "
        "a JSON config, reformats it, and writes it back fires this rule. "
        "Fix: require a suspicious intermediate step (e.g. resources/read or "
        "sampling/createMessage between the read and write) before blocking, or "
        "add an allowlist for known safe tool pairs."
    )
)
def test_FP006_read_write_file_for_formatter(engine, store):
    """FP / Sequence: JSON formatter reads then immediately writes the same file — benign."""
    session = store.get_or_create("FP006-server")
    session.verified_capabilities = ["tools"]

    engine.evaluate(_tool_req("read_file", {"path": "/workspace/config.json"}), "filesystem-server")
    result = engine.evaluate(
        _tool_req("write_file", {"path": "/workspace/config.json", "content": "{}"}),
        session
    )
    assert result.allowed, (
        "FP-009: read_file → write_file for a file formatter must NOT be blocked "
        "by the write_after_read_sensitive sequence rule."
    )


# ---------------------------------------------------------------------------
# FP-010 — Output Sanitizer: "new instructions:" in a CI pipeline log
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-010 [FALSE POSITIVE]: output_sanitizer blocks 'new instructions:' as a substring. "
        "CI/CD systems, runbook tools, and config management tools frequently emit structured "
        "log lines like 'new instructions: please run the database migration'. "
        "Fix: require 'new instructions:' to be paired with another injection signal "
        "(e.g. a role prefix, 'ignore', 'disregard') rather than blocking it standalone."
    )
)
def test_FP007_new_instructions_in_ci_log(engine):
    """FP / Sanitizer: CI pipeline log contains 'new instructions:' as a section header."""
    text = (
        "[Pipeline] Stage: Post-deploy\n"
        "new instructions: run smoke tests against the staging endpoint\n"
        "Command: pytest tests/smoke/ --base-url https://staging.example.com"
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-010: CI pipeline log with 'new instructions:' section header "
        "must NOT be flagged by the sanitizer."
    )


# ---------------------------------------------------------------------------
# FP-011 — Output Sanitizer: "disregard your" in a cache invalidation message
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-011 [FALSE POSITIVE]: output_sanitizer blocks 'disregard your' as a substring. "
        "Cache invalidation messages, correction notices, and user-facing warnings routinely "
        "use this phrase. A tool returning 'disregard your previous results — the index has "
        "been rebuilt' is blocked. "
        "Fix: require 'disregard your' to be followed by 'instructions', 'directives', "
        "'training', or 'system prompt' before flagging."
    )
)
def test_FP008_disregard_your_cache_invalidation(engine):
    """FP / Sanitizer: cache tool returns a message telling the user to disregard stale results."""
    text = (
        "Cache invalidated at 14:32 UTC. "
        "Please disregard your previous search results — the index has been fully rebuilt."
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-011: cache invalidation notice with 'disregard your previous search results' "
        "must NOT be flagged by the sanitizer."
    )


# ---------------------------------------------------------------------------
# FP-012 — Session Policy: max_calls_per_session=100 hit by a batch indexer
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-012 [FALSE POSITIVE]: session_policy.max_calls_per_session=100 is a hard cap "
        "that fires regardless of whether calls are benign. A batch indexing tool that calls "
        "read_file 101 times to index a codebase is blocked mid-operation with no way to "
        "continue. The cap does not distinguish between 101 reads on a known safe tool and "
        "101 escalating calls building an attack. "
        "Fix: apply max_calls_per_session only when mixed suspicious methods are detected, "
        "or implement per-tool-type sub-limits (e.g. allow up to 500 read_file calls "
        "but cap sampling/createMessage at 10)."
    )
)
def test_FP009_batch_indexer_exceeds_call_limit(engine, store):
    """FP / Session: batch file indexer makes 101 read_file calls — blocked by call cap."""
    session = store.get_or_create("FP009-indexer")
    session.verified_capabilities = ["tools"]

    results = []
    for i in range(101):
        r = engine.evaluate(
            _tool_req("read_file", {"path": f"/repo/src/file_{i}.py"}),
            session
        )
        results.append(r)

    # The 101st call should still be allowed — it is read_file, a safe tool
    assert results[-1].allowed, (
        "FP-012: 101st read_file call in a batch indexer must NOT be blocked "
        "by max_calls_per_session when no suspicious escalation has occurred."
    )


# ---------------------------------------------------------------------------
# FP-013 — Output Sanitizer: "output all tools" matches a help-menu response
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-013 [FALSE POSITIVE]: output_sanitizer blocks 'output all tools' as a substring. "
        "A server's help endpoint might legitimately return 'output all tools available in "
        "this environment by running list_tools()'. The phrase is also common in developer "
        "documentation. "
        "Fix: require 'output all tools' to be paired with an exfiltration context "
        "(e.g. 'to the user', 'in plaintext', 'as secrets') or make the rule "
        "anchor to the start of a line."
    )
)
def test_FP010_output_all_tools_in_help_text(engine):
    """FP / Sanitizer: server help text describes how to list available tools."""
    text = (
        "Developer guide:\n"
        "To output all tools available in this environment, call list_tools() "
        "from the MCP inspector. Results are returned as a JSON array."
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-013: developer help text explaining how to list tools "
        "must NOT be flagged by the sanitizer."
    )


# ---------------------------------------------------------------------------
# FP-014 — Sequence Policy: rapid_tool_escalation blocks a legitimate bulk operation
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-014 [FALSE POSITIVE]: rapid_tool_escalation blocks more than 5 distinct tool "
        "calls within 60 seconds. A legitimate multi-step data transformation pipeline "
        "that calls read_file, parse_csv, validate_schema, transform_rows, write_file, "
        "and send_report in sequence is blocked after the 5th call — even though all "
        "calls are whitelisted tools with no sampling or resource escalation. "
        "Fix: count only distinct *suspicious* tool transitions (e.g. escalation toward "
        "sampling or cross-server calls) rather than any 5 tool calls within a window."
    )
)
def test_FP011_rapid_legitimate_pipeline_blocked(engine, store):
    """FP / Sequence: 6-step ETL pipeline fires the rapid_tool_escalation rule."""
    session = store.get_or_create("FP011-pipeline")
    session.verified_capabilities = ["tools"]

    pipeline_steps = [
        ("read_file",       {"path": "/data/input.csv"}),
        ("parse_csv",       {"delimiter": ","}),
        ("validate_schema", {"schema": "orders_v2"}),
        ("transform_rows",  {"mapping": "v1_to_v2"}),
        ("write_file",      {"path": "/data/output.json"}),
        ("send_report",     {"to": "ops@example.com"}),
    ]

    results = []
    for tool_name, args in pipeline_steps:
        r = engine.evaluate(_tool_req(tool_name, args), session)
        results.append(r)

    # The 6th step (send_report) should be allowed — no sampling, no escalation
    assert results[-1].allowed, (
        "FP-014: 6th call in a legitimate ETL pipeline must NOT be blocked "
        "by the rapid_tool_escalation sequence rule."
    )


# ---------------------------------------------------------------------------
# FP-015 — AST Policy: setattr blocked in a legitimate dataclass builder
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-015 [FALSE POSITIVE]: 'setattr' is in ast_policy.blocked_calls alongside exec "
        "and eval, but setattr is a core Python builtin used in dataclasses, config loaders, "
        "mock frameworks, and every ORM. A trusted-server that dynamically assigns fields "
        "to a plain Python object for config hydration is blocked. "
        "Fix: only flag setattr when the target object is a module, class, or builtin "
        "(e.g. setattr(os, ...) or setattr(__builtins__, ...)), not arbitrary object instances."
    )
)
def test_FP012_setattr_in_config_loader(engine):
    """FP / AST: trusted-server uses setattr to hydrate a config object from a dict."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "class Config: pass\n"
        "cfg = Config()\n"
        "for key, value in {'debug': True, 'timeout': 30, 'retries': 3}.items():\n"
        "    setattr(cfg, key, value)\n"
        "print(cfg.debug, cfg.timeout)"
    )
    req = _req(
        method="tools/call",
        params={"name": "run_python", "arguments": {"code": code}}
    )
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-015: config object hydration using setattr on a plain class instance "
        "must NOT be blocked by AST policy."
    )

# ---------------------------------------------------------------------------
# FP-016 — line_start_patterns: "user:" fires on a YAML config key
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-016 [FALSE POSITIVE]: the line_start_pattern 'user:' matches any line that "
        "starts with 'user:' — including YAML/TOML config files where 'user:' is a "
        "standard key name. A tool returning a database config file with 'user: postgres' "
        "is flagged as a role-injection attempt. "
        "Fix: require 'user:' to be followed by a message body containing injection "
        "keywords, or anchor the pattern to require content after the colon that "
        "resembles a prompt (not a bare scalar value like a username)."
    )
)
def test_FP013_user_key_in_yaml_config(engine):
    """FP / line_start: YAML database config file returned by a read_file tool."""
    text = (
        "database:\n"
        "  host: db.internal\n"
        "  port: 5432\n"
        "  user: postgres\n"
        "  password: ${DB_PASS}\n"
        "  name: myapp_prod"
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-016: YAML config with 'user: postgres' key must NOT be flagged "
        "by the 'user:' line_start_pattern."
    )


# ---------------------------------------------------------------------------
# FP-017 — line_start_patterns: "assistant:" fires on a Python class definition
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-017 [FALSE POSITIVE]: the line_start_pattern 'assistant:' matches any line "
        "beginning with that word. Source code files, test fixtures, and API response "
        "schemas commonly define an 'assistant' variable or key. A tool returning a "
        "Python file that defines 'assistant: Assistant = Assistant()' or a JSON schema "
        "with an 'assistant' field will be flagged. "
        "Fix: require the line_start pattern to match 'assistant:' followed by a space "
        "and then a non-empty string that looks like prose, not a code token or scalar."
    )
)
def test_FP014_assistant_variable_in_source_code(engine):
    """FP / line_start: Python source file returned by read_file defines an 'assistant' variable."""
    text = (
        "from myapp.models import Assistant\n"
        "\n"
        "assistant: Assistant = Assistant(model='gpt-4', temperature=0.7)\n"
        "assistant.load_tools(['search', 'calculator'])\n"
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-017: Python source with 'assistant: Assistant = ...' type annotation "
        "must NOT be flagged by the 'assistant:' line_start_pattern."
    )


# ---------------------------------------------------------------------------
# FP-018 — line_start_patterns: "system:" fires on a systemd unit file
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-018 [FALSE POSITIVE]: the line_start_pattern 'system:' matches any line "
        "starting with 'system:'. Systemd unit files, Ansible playbooks, and Kubernetes "
        "manifests all use 'system:' as a section header or field name. A tool that "
        "reads /etc/systemd/system/myapp.service and returns its contents will be "
        "blocked even though the file is a plain service definition. "
        "Fix: use a more specific pattern that requires a role-like context after the "
        "colon, e.g. 'system:\\s+(you are|ignore|disregard|override)'."
    )
)
def test_FP015_system_key_in_systemd_unit(engine):
    """FP / line_start: systemd service file content returned by a filesystem tool."""
    text = (
        "[Unit]\n"
        "Description=My Application Service\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=/usr/bin/myapp --config /etc/myapp/config.yaml\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target"
    )
    # The sanitizer sees the section header '[Service]' — but also consider
    # a TOML or INI variant where 'system:' appears as a bare key
    text_ini = (
        "system: myapp-production\n"
        "environment: production\n"
        "replicas: 3"
    )
    sanitized, flagged = engine.sanitize_output(text_ini)
    assert not flagged, (
        "FP-018: INI/TOML config with 'system: myapp-production' key must NOT be "
        "flagged by the 'system:' line_start_pattern."
    )

# ---------------------------------------------------------------------------
# FP-022 — blocked_attributes: "run" fires on pytest / subprocess.run docs
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-022 [FALSE POSITIVE]: 'run' is in ast_policy.blocked_attributes, which means "
        "any attribute access ending in '.run' is blocked — including pytest.main(), "
        "unittest.TestCase.run(), Django's management command runner, and many ORMs. "
        "Code like 'result = suite.run(runner)' or 'app.run(debug=False)' (Flask) "
        "is blocked on trusted-server. The attribute 'run' is far too generic to block; "
        "the dangerous form is specifically 'subprocess.run' or 'os.system'. "
        "Fix: only block 'run' as an attribute of known dangerous objects "
        "(subprocess, os, Popen) using dataflow analysis, not any .run() call."
    )
)
def test_FP016_dot_run_in_flask_app(engine):
    """FP / AST: trusted-server runs a Flask app startup script using app.run()."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    app.run(host='0.0.0.0', port=8080, debug=False)"
    )
    req = _req("tools/call", {"name": "run_python", "arguments": {"code": code}})
    result = engine.evaluate(req, _session("trusted-server", ["execute_code"]))
    assert result.allowed, (
        "FP-022: Flask app.run() on trusted-server must NOT be blocked "
        "by the 'run' blocked_attribute rule."
    )

# ---------------------------------------------------------------------------
# FP-024 — blocked_modules: "shutil" blocked for a legitimate file copy operation
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-024 [FALSE POSITIVE]: 'shutil' is in ast_policy.blocked_modules alongside "
        "subprocess and os. While shutil.rmtree can be dangerous, shutil.copy and "
        "shutil.copyfile are the standard Python way to copy a file — more explicit "
        "and safer than open()/write() loops. A trusted-server that uses shutil.copy "
        "to back up a config file before modifying it is blocked. "
        "Fix: block only the dangerous shutil functions (rmtree, chown, move to /etc) "
        "rather than the entire module. Or allow shutil on trusted-server explicitly."
    )
)
def test_FP017_shutil_copy_for_backup(engine):
    """FP / AST: trusted-server uses shutil.copy to back up a config before editing."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "import shutil\n"
        "shutil.copy('/workspace/config.yaml', '/workspace/config.yaml.bak')\n"
        "print('Backup created: config.yaml.bak')"
    )
    req = _req("tools/call", {"name": "run_python", "arguments": {"code": code}})
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-024: shutil.copy for config file backup on trusted-server must NOT "
        "be blocked by the 'shutil' blocked_module rule."
    )


# ---------------------------------------------------------------------------
# FP-025 — blocked_modules: "signal" blocked in a graceful shutdown handler
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-025 [FALSE POSITIVE]: 'signal' is in ast_policy.blocked_modules. The Python "
        "signal module is used to register graceful shutdown handlers (SIGTERM, SIGINT) "
        "in long-running processes. Any server, worker, or daemon that wants to clean up "
        "on shutdown uses signal.signal(signal.SIGTERM, handler). This has nothing to do "
        "with privilege escalation or shell injection. "
        "Fix: remove 'signal' from blocked_modules entirely, or only block "
        "signal.raise_signal / os.kill combinations."
    )
)
def test_FP018_signal_for_graceful_shutdown(engine):
    """FP / AST: trusted-server registers a SIGTERM handler for graceful worker shutdown."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "import signal\n"
        "\n"
        "def shutdown_handler(signum, frame):\n"
        "    print('Received SIGTERM, shutting down gracefully...')\n"
        "    # flush queues, close DB connections, etc.\n"
        "\n"
        "signal.signal(signal.SIGTERM, shutdown_handler)\n"
        "print('Shutdown handler registered')"
    )
    req = _req("tools/call", {"name": "run_python", "arguments": {"code": code}})
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-025: signal.signal(SIGTERM, handler) for graceful shutdown must NOT "
        "be blocked by the 'signal' blocked_module rule."
    )


# ---------------------------------------------------------------------------
# FP-026 — blocked_calls: "compile" blocked for a template engine
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-026 [FALSE POSITIVE]: 'compile' is in ast_policy.blocked_calls alongside "
        "eval and exec. However, compile() has many legitimate uses: regex compilation "
        "(re.compile), Jinja2/Mako template compilation, and bytecode pre-compilation "
        "for performance. A trusted-server that calls re.compile(r'\\d{4}-\\d{2}-\\d{2}') "
        "to build a date-validation regex is blocked. The dangerous 'compile' is Python's "
        "builtin that compiles source strings to code objects — not re.compile. "
        "Fix: only block builtins.compile (the code-object compiler), not attribute "
        "access to any method named 'compile' (e.g. re.compile, pattern.compile)."
    )
)
def test_FP019_re_compile_for_date_validation(engine):
    """FP / AST: trusted-server uses re.compile for input validation — not code compilation."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "import re\n"
        "DATE_RE = re.compile(r'^\\d{4}-\\d{2}-\\d{2}$')\n"
        "dates = ['2024-01-15', 'not-a-date', '2023-12-31']\n"
        "valid = [d for d in dates if DATE_RE.match(d)]\n"
        "print(valid)"
    )
    req = _req("tools/call", {"name": "run_python", "arguments": {"code": code}})
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-026: re.compile() for regex date validation on trusted-server must NOT "
        "be blocked by the 'compile' blocked_call rule."
    )


# ---------------------------------------------------------------------------
# FP-027 — blocked_calls: "delattr" blocked in a dataclass cleanup utility
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-027 [FALSE POSITIVE]: 'delattr' is in ast_policy.blocked_calls. While "
        "delattr on a module or class can be dangerous, delattr on a plain instance "
        "is how Python dataclasses, serializers, and object factories remove optional "
        "fields before returning a response. A trusted-server that calls "
        "delattr(response_obj, 'internal_field') to strip private fields before "
        "serialization is a normal, safe pattern. "
        "Fix: only block delattr when the target is a module-level or class-level "
        "object (detected via type() or isinstance() checks in AST analysis), "
        "not arbitrary instance attribute deletion."
    )
)
def test_FP020_delattr_stripping_private_fields(engine):
    """FP / AST: trusted-server strips private fields from a response object before returning."""
    conn = _session(server_id="trusted-server", capabilities=["execute_code"])
    code = (
        "class APIResponse:\n"
        "    def __init__(self):\n"
        "        self.id = 42\n"
        "        self.name = 'Alice'\n"
        "        self._internal_token = 'secret'\n"
        "        self._created_at_epoch = 1700000000\n"
        "\n"
        "resp = APIResponse()\n"
        "for attr in list(vars(resp)):\n"
        "    if attr.startswith('_'):\n"
        "        delattr(resp, attr)\n"
        "print(vars(resp))  # {'id': 42, 'name': 'Alice'}"
    )
    req = _req("tools/call", {"name": "run_python", "arguments": {"code": code}})
    result = engine.evaluate(req, conn)
    assert result.allowed, (
        "FP-027: delattr() stripping private fields from a plain instance on "
        "trusted-server must NOT be blocked by the 'delattr' blocked_call rule."
    )


# ---------------------------------------------------------------------------
# FP-028 — substring_pattern: "invoke server." fires on an AWS CLI help snippet
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-028 [FALSE POSITIVE]: output_sanitizer blocks 'invoke server.' as a substring. "
        "This is intended to catch 'invoke server.tool with ...' cross-server directives, "
        "but it fires on any text containing 'invoke server.' — including AWS Lambda "
        "documentation ('invoke server.js locally with sam local invoke'), "
        "gRPC guides ('invoke server.SayHello'), and RPC framework docs. "
        "Fix: tighten the pattern to 'invoke server\\.\\w+' followed by a tool-call "
        "context keyword, or match the full original pattern "
        "'invoke server\\.\\w+\\.\\w+ with' to require the tool name."
    )
)
def test_FP021_invoke_server_in_aws_lambda_docs(engine):
    """FP / Sanitizer: AWS SAM CLI docs returned by a tool contain 'invoke server.'"""
    text = (
        "To test your Lambda function locally:\n"
        "sam local invoke server.handler --event events/test.json\n"
        "This will invoke server.handler in a Docker container simulating Lambda."
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-028: AWS SAM CLI docs with 'invoke server.handler' must NOT be "
        "flagged by the 'invoke server.' substring pattern."
    )


# ---------------------------------------------------------------------------
# FP-029 — substring_pattern: "/etc/shadow" fires in a security hardening guide
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-029 [FALSE POSITIVE]: '/etc/shadow' is blocked as a substring in all output. "
        "This is meant to catch exfiltration attempts, but it also blocks security "
        "hardening guides, compliance documentation, and sysadmin tools that describe "
        "how to properly protect /etc/shadow. A tool returning 'ensure /etc/shadow has "
        "permissions 640 and is owned by root:shadow' is educational, not malicious. "
        "Fix: only flag /etc/shadow when it appears alongside read/cat/open/exfiltration "
        "keywords, not in isolation within advisory or permissions-setting context."
    )
)
def test_FP022_etc_shadow_in_hardening_guide(engine):
    """FP / Sanitizer: security hardening report mentions /etc/shadow in a protective context."""
    text = (
        "CIS Benchmark — Linux Server Hardening:\n"
        "[ PASS ] /etc/shadow permissions: 640 (owner: root, group: shadow)\n"
        "[ PASS ] /etc/shadow is not world-readable\n"
        "Recommendation: rotate shadow passwords every 90 days."
    )
    sanitized, flagged = engine.sanitize_output(text)
    assert not flagged, (
        "FP-029: security hardening report referencing /etc/shadow in a "
        "compliance-check context must NOT be flagged by the sanitizer."
    )


# ---------------------------------------------------------------------------
# FP-030 — sequence_rule: sampling_after_resource_read fires on trusted-server
#          even though trusted-server has sampling_allowed: true
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-030 [FALSE POSITIVE]: the 'sampling_after_resource_read' sequence rule is "
        "defined under sequence_policy.default, meaning it applies to ALL servers — "
        "including trusted-server, which explicitly has sampling_allowed: true. "
        "A legitimate workflow where trusted-server reads two config resources and then "
        "calls sampling/createMessage to summarize them is blocked by the default sequence "
        "rule, even though the server is certified for sampling. "
        "Fix: sequence_policy.default rules should be skipped (or overridden) for servers "
        "that have sampling_allowed: true AND a verified capability cert, since the "
        "server-level policy already explicitly permits this flow."
    )
)
def test_FP023_trusted_server_resource_then_sampling_is_legitimate(engine, store):
    """FP / Sequence: trusted-server reads two resources then samples — a legitimate summarization flow."""
    session = store.get_or_create("FP023-trusted")
    session.verified_capabilities = ["resources", "sampling", "tools"]

    # trusted-server is explicitly sampling_allowed: true
    engine.evaluate(_req("resources/read", {"name": "config_a.json"}), session)
    engine.evaluate(_req("resources/read", {"name": "config_b.json"}), session)

    result = engine.evaluate(_req("sampling/createMessage", {}), session)
    assert result.allowed, (
        "FP-030: trusted-server reading two resources then sampling for summarization "
        "must NOT be blocked — sampling_allowed: true should exempt it from the "
        "default sampling_after_resource_read sequence rule."
    )


# ---------------------------------------------------------------------------
# FP-031 — sequence_rule: sampling_after_tool_sequence fires on coincidentally
#          same-named tools in a data science pipeline
# ---------------------------------------------------------------------------
@pytest.mark.xfail(
    reason=(
        "FP-031 [FALSE POSITIVE]: the 'sampling_after_tool_sequence' rule blocks the "
        "exact pattern [get_data, format_data, analyze, sampling/createMessage]. "
        "This name-based matching is dangerously broad — these are generic, common tool "
        "names that any data science or analytics MCP would expose. A legitimate pipeline "
        "that fetches a dataset, formats it as a dataframe, runs statistical analysis, "
        "then calls sampling to write a natural-language summary is blocked. "
        "The rule conflates tool names with attack intent. "
        "Fix: require the pattern to also observe anomalous arguments (e.g. data volume "
        "thresholds, output destinations pointing outside the workspace) rather than "
        "triggering purely on tool name sequence."
    )
)
def test_FP024_data_science_pipeline_name_collision(engine, store):
    """FP / Sequence: legitimate analytics pipeline uses get_data→format_data→analyze→sampling."""
    session = store.get_or_create("FP024-analytics")
    session.verified_capabilities = ["resources", "sampling", "tools"]

    # These are generic, sensibly-named tools in any analytics MCP
    engine.evaluate(_tool_req("get_data",     {"source": "warehouse", "table": "sales_q4"}), session)
    engine.evaluate(_tool_req("format_data",  {"as": "dataframe", "index": "date"}), session)
    engine.evaluate(_tool_req("analyze",      {"method": "linear_regression", "target": "revenue"}), session)

    # Sampling here generates a natural-language summary of the regression output
    result = engine.evaluate(_req("sampling/createMessage", {
        "messages": [{"role": "user", "content": "Summarize the regression results in plain English."}]
    }), session)

    assert result.allowed, (
        "FP-031: analytics pipeline [get_data→format_data→analyze→sampling] for "
        "natural-language summary must NOT be blocked by sampling_after_tool_sequence — "
        "the tool names are generic and the sampling intent is legitimate."
    )