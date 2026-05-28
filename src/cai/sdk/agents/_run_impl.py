from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import os
import re
import uuid
from datetime import datetime
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, cast
from urllib.parse import parse_qsl, urlparse

from openai.types.responses import (
    ResponseComputerToolCall,
    ResponseFileSearchToolCall,
    ResponseFunctionToolCall,
    ResponseFunctionWebSearch,
    ResponseOutputMessage,
    ResponseOutputText,
)
from openai.types.responses.response_computer_tool_call import (
    ActionClick,
    ActionDoubleClick,
    ActionDrag,
    ActionKeypress,
    ActionMove,
    ActionScreenshot,
    ActionScroll,
    ActionType,
    ActionWait,
)
from openai.types.responses.response_input_param import ComputerCallOutput
from openai.types.responses.response_reasoning_item import ResponseReasoningItem

from .agent import Agent, ToolsToFinalOutputResult
from .agent_output import AgentOutputSchema
from .computer import AsyncComputer, Computer
from .exceptions import AgentsException, ModelBehaviorError, UserError
from .guardrail import InputGuardrail, InputGuardrailResult, OutputGuardrail, OutputGuardrailResult
from .handoffs import Handoff, HandoffInputData
from .items import (
    HandoffCallItem,
    HandoffOutputItem,
    ItemHelpers,
    MessageOutputItem,
    ModelResponse,
    ReasoningItem,
    RunItem,
    ToolCallItem,
    ToolCallOutputItem,
    TResponseInputItem,
)
from .lifecycle import RunHooks
from .logger import logger
from .model_settings import ModelSettings
from .models.interface import ModelTracing
from .run_context import RunContextWrapper, TContext
from .stream_events import RunItemStreamEvent, StreamEvent
from .tool import ComputerTool, FunctionTool, FunctionToolResult, Tool
from .tracing import (
    SpanError,
    Trace,
    function_span,
    get_current_trace,
    guardrail_span,
    handoff_span,
    trace,
)
from .util import _coro, _error_tracing

if TYPE_CHECKING:
    from .run import RunConfig


class QueueCompleteSentinel:
    pass


QUEUE_COMPLETE_SENTINEL = QueueCompleteSentinel()

_NOT_FINAL_OUTPUT = ToolsToFinalOutputResult(is_final_output=False, final_output=None)
_AUTO_PENTEST_ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
_AUTO_PENTEST_ALLOWED_PORT = 8888
_AUTO_PENTEST_SAFE_ACTION_COUNT = 0
_AUTO_PENTEST_EXECUTED_COMMANDS: set[str] = set()
_AUTO_PENTEST_EXECUTED_CHECK_SIGNATURES: set[str] = set()
_AUTO_PENTEST_CATEGORY_COUNTS: dict[str, int] = {}
_AUTO_PENTEST_RESULTS: list[dict[str, str]] = []
_AUTO_PENTEST_RISKY_SESSION_APPROVED = False
_AUTO_PENTEST_RISKY_SESSION_DECIDED = False
_AUTO_PENTEST_ENUMERATION_MIN_CHECKS = 6
_AUTO_PENTEST_FOCUS_AREAS = [
    "security headers and cookie attributes",
    "CORS preflight and allowed methods",
    "OPTIONS and method tampering checks",
    "robots, sitemap, security.txt, and well-known metadata",
    "JavaScript asset discovery and route extraction",
    "API route discovery from static assets",
    "Swagger/OpenAPI and GraphQL discovery",
    "harmless reflected parameter probes using proof strings",
    "non-destructive SQL injection detection payloads",
    "REST parameter pollution checks",
    "path traversal probes against discovered file parameters only",
    "authentication surface discovery without default credential attempts",
    "authorization checks only with discovered object IDs",
    "BOLA/IDOR checks only when object IDs exist",
    "mass assignment checks only on discovered JSON API endpoints",
    "JWT inspection only when tokens are discovered",
    "source map and exposed build artifact checks",
    "backup/source disclosure filename checks with reasonable limits",
    "cache deception and cache header checks",
    "host header and redirect checks with in-scope hosts only",
    "CSRF signal checks on discovered state-changing forms",
    "file upload validation only on discovered upload endpoints",
    "very low-count rate-limit signal checks",
    "business logic validation using discovered workflows only",
]
_AUTO_PENTEST_CATEGORY_LIMITS = {
    "SQL Injection Bounded Checks": 3,
    "XSS Non-Executing Checks": 3,
    "Input Validation": 4,
    "SSRF Parameter Checks": 3,
    "API-specific OWASP API Top 10 Checks": 8,
}
_AUTO_PENTEST_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}
_AUTO_PENTEST_DANGEROUS_METHODS = {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
_AUTO_PENTEST_DANGEROUS_PATTERNS = [
    r"\brm\s+(-|/)",
    r"\bdel\s+",
    r"\brmdir\s+",
    r"\bformat\b",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\btaskkill\b",
    r"\bnet\s+user\b",
    r"\breg\s+(add|delete|import)\b",
    r"\bpowershell\b.*\b(remove-item|rm|del|stop-process|set-itemproperty|new-itemproperty)\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bchmod\s+777\b",
    r"\bchown\b",
    r"\bnc\b.*\s-e\s",
    r"\bncat\b.*\s-e\s",
    r"\breverse\s+shell\b",
    r"\bbrute\s*force\b",
    r"\bpassword\s*spray",
    r"\bcredential\s*stuff",
    r"\bmetadata\.google\.internal\b",
    r"\b169\.254\.169\.254\b",
]


@dataclass
class AutoPentestDecision:
    classification: str
    reason: str


@dataclass(frozen=True)
class AutoPentestTestCase:
    id: str
    name: str
    category: str
    objective: str
    risk_level: Literal["Safe", "Risky", "Blocked"]
    allowed_methods: tuple[str, ...]
    suggested_payloads: tuple[str, ...]
    tool_mapping: str
    success_indicators: tuple[str, ...]
    failure_indicators: tuple[str, ...]
    dependencies: tuple[str, ...]
    parallel: bool


_AUTO_PENTEST_TEST_CASES = [
    AutoPentestTestCase(
        "TC-000",
        "Application Entry Enumeration",
        "Recon and Endpoint Discovery",
        "Fetch the application entry point and identify real static assets and routes.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -i {target}",),
        "generic_linux_command",
        ("HTML returned", "script or link assets discovered"),
        ("connection failure",),
        (),
        False,
    ),
    AutoPentestTestCase(
        "TC-001",
        "Security Header Inspection",
        "Security Headers",
        "Inspect baseline response headers and missing browser hardening controls.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -I {target}",),
        "generic_linux_command",
        ("200/3xx response", "headers returned"),
        ("connection failure",),
        (),
        True,
    ),
    AutoPentestTestCase(
        "TC-002",
        "Robots File Discovery",
        "Recon and Endpoint Discovery",
        "Check robots.txt for intentionally published paths.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -I {target}/robots.txt",),
        "generic_linux_command",
        ("200 response", "disallow entries"),
        ("404 response",),
        (),
        True,
    ),
    AutoPentestTestCase(
        "TC-003",
        "Sitemap Discovery",
        "Recon and Endpoint Discovery",
        "Check sitemap.xml for crawled routes.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -I {target}/sitemap.xml",),
        "generic_linux_command",
        ("200 response", "urlset"),
        ("404 response",),
        (),
        True,
    ),
    AutoPentestTestCase(
        "TC-004",
        "Security Contact Discovery",
        "Recon and Endpoint Discovery",
        "Check security.txt and well-known security contact metadata.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -I {target}/security.txt", "curl -s -I {target}/.well-known/security.txt"),
        "generic_linux_command",
        ("200 response", "contact field"),
        ("404 response",),
        (),
        True,
    ),
    AutoPentestTestCase(
        "TC-020",
        "JavaScript Asset Route Extraction",
        "Recon and Endpoint Discovery",
        "Fetch discovered JS/CSS assets and extract route or API hints for later testing.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s {asset_url}",),
        "generic_linux_command",
        ("static asset returned", "route or API hint found"),
        ("404 response", "no route hints"),
        ("TC-000",),
        True,
    ),
    AutoPentestTestCase(
        "TC-005",
        "HTTP OPTIONS Method Check",
        "HTTP Methods",
        "Inspect allowed methods without changing server state.",
        "Safe",
        ("OPTIONS",),
        ("curl -s -X OPTIONS -I {target}",),
        "generic_linux_command",
        ("allow header", "204/200/405 response"),
        ("connection failure",),
        ("TC-001",),
        True,
    ),
    AutoPentestTestCase(
        "TC-006",
        "CORS Preflight Baseline",
        "CORS",
        "Check CORS behavior using a harmless origin header.",
        "Safe",
        ("OPTIONS",),
        ("curl -s -I -X OPTIONS -H 'Origin: http://localhost:8888' {target}",),
        "generic_linux_command",
        ("access-control headers", "no permissive wildcard"),
        ("connection failure",),
        ("TC-001",),
        True,
    ),
    AutoPentestTestCase(
        "TC-007",
        "Cookie Attribute Inspection",
        "Cookies and Session Attributes",
        "Inspect Set-Cookie attributes after discovered login/session flows.",
        "Safe",
        ("GET", "POST"),
        ("curl -s -i -c cai_cookies.txt {target}",),
        "generic_linux_command",
        ("HttpOnly", "Secure", "SameSite"),
        ("missing session cookies",),
        ("authenticated session if login exists",),
        False,
    ),
    AutoPentestTestCase(
        "TC-008",
        "Authentication Surface Discovery",
        "Authentication Checks",
        "Discover login, registration, logout, and password reset routes.",
        "Safe",
        ("GET", "HEAD"),
        ("crawl static assets", "inspect forms and routes"),
        "generic_linux_command",
        ("login/register route found",),
        ("no auth surface found",),
        ("TC-002", "TC-003"),
        False,
    ),
    AutoPentestTestCase(
        "TC-009",
        "Authorization Object ID Discovery",
        "Authorization / IDOR / BOLA",
        "Identify object IDs before any authorization comparison.",
        "Safe",
        ("GET",),
        ("inspect authenticated API responses",),
        "generic_linux_command",
        ("numeric or UUID object IDs discovered",),
        ("no object IDs discovered",),
        ("authenticated session"),
        False,
    ),
    AutoPentestTestCase(
        "TC-010",
        "Harmless Reflected Input Probe",
        "Input Validation",
        "Use non-executing proof strings to detect reflection.",
        "Safe",
        ("GET", "POST"),
        ("cai_reflect_probe_12345",),
        "generic_linux_command",
        ("proof string reflected",),
        ("proof string not reflected",),
        ("discovered parameter"),
        True,
    ),
    AutoPentestTestCase(
        "TC-011",
        "Non-Destructive SQLi Signal Probe",
        "SQL Injection Bounded Checks",
        "Check error/timing signals with harmless SQL metacharacters.",
        "Safe",
        ("GET", "POST"),
        ("'", "\"", "1'"),
        "generic_linux_command",
        ("SQL error signature", "response difference"),
        ("no signal",),
        ("discovered parameter"),
        True,
    ),
    AutoPentestTestCase(
        "TC-012",
        "Non-Executing XSS Reflection Probe",
        "XSS Non-Executing Checks",
        "Check output encoding with inert marker text only.",
        "Safe",
        ("GET", "POST"),
        ("cai_xss_probe_12345",),
        "generic_linux_command",
        ("marker reflected unencoded",),
        ("encoded or absent marker",),
        ("discovered parameter"),
        True,
    ),
    AutoPentestTestCase(
        "TC-013",
        "SSRF Parameter Discovery",
        "SSRF Parameter Checks",
        "Look for URL-fetching parameters without calling metadata endpoints.",
        "Safe",
        ("GET", "POST"),
        ("url=", "callback=", "next=", "redirect="),
        "generic_linux_command",
        ("URL-like parameter found",),
        ("no URL-like parameter found",),
        ("discovered endpoints"),
        False,
    ),
    AutoPentestTestCase(
        "TC-014",
        "File Upload Surface Discovery",
        "File Upload Validation",
        "Detect upload endpoints before attempting any upload validation.",
        "Safe",
        ("GET",),
        ("multipart/form-data", "type=file"),
        "generic_linux_command",
        ("upload form found",),
        ("no upload surface",),
        ("crawl complete"),
        False,
    ),
    AutoPentestTestCase(
        "TC-015",
        "Debug Exposure Check",
        "Error Handling / Debug Exposure",
        "Check common debug/build metadata paths with reasonable limits.",
        "Safe",
        ("GET", "HEAD"),
        ("curl -s -I {target}/.env", "curl -s -I {target}/debug"),
        "generic_linux_command",
        ("200 response with sensitive metadata",),
        ("404 response",),
        (),
        True,
    ),
    AutoPentestTestCase(
        "TC-016",
        "Sensitive Data Exposure Scan",
        "Sensitive Data Exposure",
        "Inspect in-scope responses for accidental secrets or PII markers.",
        "Safe",
        ("GET",),
        ("token", "secret", "password", "apiKey"),
        "generic_linux_command",
        ("secret-like string found",),
        ("no sensitive marker",),
        ("crawl complete"),
        False,
    ),
    AutoPentestTestCase(
        "TC-017",
        "Low-Count Rate Limit Signal",
        "Rate Limiting Low-Count Checks",
        "Send a tiny request burst to observe throttling signals without load testing.",
        "Risky",
        ("GET", "POST"),
        ("3-5 sequential requests maximum",),
        "generic_linux_command",
        ("429 or throttle header",),
        ("no throttle signal",),
        ("stable endpoint discovered"),
        False,
    ),
    AutoPentestTestCase(
        "TC-018",
        "Business Workflow Mapping",
        "Business Logic Safe Checks",
        "Map normal user workflows before testing business logic assumptions.",
        "Safe",
        ("GET", "POST"),
        ("authenticated navigation",),
        "generic_linux_command",
        ("workflow states found",),
        ("workflow not available",),
        ("authenticated session if app requires login"),
        False,
    ),
    AutoPentestTestCase(
        "TC-019",
        "API Inventory Check",
        "API-specific OWASP API Top 10 Checks",
        "Discover OpenAPI, GraphQL, REST, and versioned API surfaces.",
        "Safe",
        ("GET", "HEAD", "OPTIONS"),
        ("curl -s -I {target}/api", "curl -s -I {target}/swagger.json"),
        "generic_linux_command",
        ("API endpoint found", "schema found"),
        ("404 response",),
        ("TC-001",),
        True,
    ),
]
_AUTO_PENTEST_TEST_CASES_BY_ID = {test_case.id: test_case for test_case in _AUTO_PENTEST_TEST_CASES}


def _auto_pentest_parallelism() -> int:
    try:
        return max(1, int(os.getenv("CAI_AUTO_PENTEST_PARALLELISM", "1")))
    except ValueError:
        return 1


def _auto_pentest_test_case_for_index(index: int | None = None) -> AutoPentestTestCase:
    completed = _auto_pentest_safe_checks_completed() if index is None else index
    return _AUTO_PENTEST_TEST_CASES[completed % len(_AUTO_PENTEST_TEST_CASES)]


def _auto_pentest_test_case_for_command(command: str) -> AutoPentestTestCase:
    lower = command.lower()
    if " -x options" in lower or " options " in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-005"]
    if "robots.txt" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-002"]
    if "sitemap.xml" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-003"]
    if "security.txt" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-004"]
    if re.search(r"\.(?:js|css|map)(?:[?#\s]|$)", lower) or "/static/" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-020"]
    if "origin:" in lower or "access-control" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-006"]
    if "cookie" in lower or "-c " in lower or "-b " in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-007"]
    if "/api" in lower or "swagger" in lower or "graphql" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-019"]
    if ".env" in lower or "debug" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-015"]
    if "cai_reflect_probe" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-010"]
    if "cai_xss_probe" in lower:
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-012"]
    if re.search(r"['\"]|%27|%22", lower):
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-011"]
    if re.search(r"\s--head\b|\s-I(?:\s|$)", command):
        return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-001"]
    if re.search(r"\bcurl\b.*https?://(?:localhost|127\.0\.0\.1):8888/?(?:\s|$)", lower):
        if " -i" in lower or " -s " in lower:
            return _AUTO_PENTEST_TEST_CASES_BY_ID["TC-000"]
    return _auto_pentest_test_case_for_index()


def _auto_pentest_test_case_from_args(arguments: str) -> AutoPentestTestCase:
    try:
        parsed_args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError:
        return _auto_pentest_test_case_for_index()
    command = parsed_args.get("command") if isinstance(parsed_args, dict) else None
    if isinstance(command, str):
        return _auto_pentest_test_case_for_command(command)
    return _auto_pentest_test_case_for_index()


def _auto_pentest_target_from_args(arguments: str) -> str:
    try:
        parsed_args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError:
        return "unknown"
    texts = _iter_text_values(parsed_args)
    urls = [url.rstrip(").,;") for text in texts for url in _extract_urls(text)]
    return urls[0] if urls else "unknown"


def _auto_pentest_command_from_args(arguments: str) -> str:
    try:
        parsed_args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError:
        return arguments
    if isinstance(parsed_args, dict):
        command = parsed_args.get("command")
        if isinstance(command, str):
            return command
    return json.dumps(parsed_args)


def _auto_pentest_effective_risk(
    decision: AutoPentestDecision,
    command: str,
    test_case: AutoPentestTestCase,
) -> str:
    if decision.classification == "blocked":
        return "Guarded"
    if decision.classification in {"safe", "approved", "risky"}:
        return "In-scope"
    return test_case.risk_level


def _auto_pentest_compact_status_line(
    *,
    agent: Agent[Any],
    func_tool: FunctionTool,
    tool_call: ResponseFunctionToolCall,
    decision: AutoPentestDecision,
    status: str,
    summary: str = "",
) -> str:
    test_case = _auto_pentest_test_case_from_args(tool_call.arguments)
    target = _auto_pentest_target_from_args(tool_call.arguments)
    command = _auto_pentest_command_from_args(tool_call.arguments)
    risk = _auto_pentest_effective_risk(decision, command, test_case)
    decision_label = {
        "safe": "AUTO",
        "approved": "AUTO",
        "risky": "AUTO",
        "blocked": "GUARD",
        "disabled": "N/A",
    }.get(decision.classification, decision.classification.upper())
    suffix = f" | {summary}" if summary else ""
    return (
        f"[{datetime.now().strftime('%H:%M:%S')}] AUTO-PT {status.upper()} "
        f"{test_case.id} {test_case.name} | {test_case.category} | "
        f"{risk}/{decision_label} | {agent.name} | {target} | "
        f"{func_tool.name}: {command}{suffix}"
    )


def _auto_pentest_render_event(
    *,
    agent: Agent[Any],
    func_tool: FunctionTool,
    tool_call: ResponseFunctionToolCall,
    decision: AutoPentestDecision,
    status: str,
    summary: str = "",
    completed_count: int | None = None,
) -> None:
    test_case = _auto_pentest_test_case_from_args(tool_call.arguments)
    command = _auto_pentest_command_from_args(tool_call.arguments)
    risk = _auto_pentest_effective_risk(decision, command, test_case)
    decision_label = {
        "safe": "Auto-approved",
        "approved": "Auto-approved",
        "risky": "Auto-approved",
        "blocked": "Guarded",
        "disabled": "N/A",
    }.get(decision.classification, decision.classification)
    completed = (
        _auto_pentest_safe_checks_completed()
        if completed_count is None
        else completed_count
    )
    phase = (
        "Enumeration"
        if completed < _AUTO_PENTEST_ENUMERATION_MIN_CHECKS
        else "Vulnerability Testing"
    )
    next_case = _auto_pentest_test_case_for_index(completed + 1)
    upcoming_tests = [
        {
            "id": _auto_pentest_test_case_for_index(completed + index).id,
            "name": _auto_pentest_test_case_for_index(completed + index).name,
            "category": _auto_pentest_test_case_for_index(completed + index).category,
            "risk": "In-scope",
        }
        for index in range(1, 9)
    ]
    event = {
        "agent": agent.name,
        "call_id": getattr(tool_call, "call_id", None) or getattr(tool_call, "id", ""),
        "test_id": test_case.id,
        "test_name": test_case.name,
        "category": test_case.category,
        "category_completed": _AUTO_PENTEST_CATEGORY_COUNTS.get(test_case.category, 0),
        "category_limit": _auto_pentest_category_limit(test_case),
        "objective": test_case.objective,
        "target": _auto_pentest_target_from_args(tool_call.arguments),
        "tool": func_tool.name,
        "command": command,
        "payload": ", ".join(test_case.suggested_payloads[:3]),
        "indicators": ", ".join(test_case.success_indicators[:3]),
        "risk": risk,
        "decision": decision_label,
        "status": status,
        "summary": summary,
        "response": summary,
        "next_test": f"{next_case.id} {next_case.name}",
        "upcoming_tests": upcoming_tests,
        "phase": phase,
        "completed": completed,
        "total": _auto_pentest_safe_check_budget(),
        "risky_approved": _AUTO_PENTEST_RISKY_SESSION_APPROVED,
    }
    try:
        from cai.auto_pentest_ui import render_auto_pentest_event

        render_auto_pentest_event(event)
    except Exception:
        print(
            _auto_pentest_compact_status_line(
                agent=agent,
                func_tool=func_tool,
                tool_call=tool_call,
                decision=decision,
                status=status,
                summary=summary,
            )
        )


def _auto_pentest_status_line(
    *,
    agent: Agent[Any],
    func_tool: FunctionTool,
    tool_call: ResponseFunctionToolCall,
    decision: AutoPentestDecision,
    status: str,
    summary: str = "",
) -> str:
    test_case = _auto_pentest_test_case_from_args(tool_call.arguments)
    target = _auto_pentest_target_from_args(tool_call.arguments)
    command = _auto_pentest_command_from_args(tool_call.arguments)
    risk = _auto_pentest_effective_risk(decision, command, test_case)

    decision_label = {
        "safe": "Auto-approved",
        "approved": "Auto-approved",
        "risky": "Auto-approved",
        "blocked": "Guarded",
        "disabled": "N/A",
    }.get(decision.classification, decision.classification)
    next_case = _auto_pentest_test_case_for_index(_auto_pentest_safe_checks_completed() + 1)
    lines = [
        f"[{datetime.now().strftime('%H:%M:%S')}] {test_case.id} {test_case.name}",
        f"Agent: {agent.name}",
        f"Category: {test_case.category}",
        f"Target: {target}",
        f"Tool: {func_tool.name}",
        f"Command: {command}",
        f"Risk: {risk}",
        f"Decision: {decision_label}",
        f"Status: {status}",
    ]
    if summary:
        lines.append(f"Result: {summary}")
    lines.append(f"Next planned test: {next_case.id} {next_case.name}")
    return "\n".join(lines)


def _auto_pentest_result_summary(result: Any) -> str:
    text = str(result).strip().replace("\r", " ").replace("\n", " ")
    if not text:
        return "No output."
    status_match = re.search(r"\bHTTP/\S+\s+(\d{3})\b", text)
    if status_match:
        return f"HTTP {status_match.group(1)} observed."
    if len(text) > 180:
        return f"{text[:177]}..."
    return text


async def _auto_pentest_ensure_risky_session_decision() -> None:
    global _AUTO_PENTEST_RISKY_SESSION_APPROVED, _AUTO_PENTEST_RISKY_SESSION_DECIDED
    if _AUTO_PENTEST_RISKY_SESSION_DECIDED:
        return
    _AUTO_PENTEST_RISKY_SESSION_DECIDED = True
    _AUTO_PENTEST_RISKY_SESSION_APPROVED = True
    print(
        "Auto-pentest setup: all in-scope localhost:8888 app/API tests run automatically. "
        "Out-of-scope, host/filesystem-destructive, brute-force, DoS/load, malware, "
        "and metadata SSRF actions remain guarded."
    )


async def _auto_pentest_wait_for_resume_or_stop() -> AutoPentestDecision | None:
    if not _auto_pentest_enabled():
        return None
    try:
        from cai.auto_pentest_ui import get_auto_pentest_control_status
    except Exception:
        return None

    pause_notice_shown = False
    while True:
        status = get_auto_pentest_control_status()
        if status in {"stop", "stopped"}:
            return AutoPentestDecision("blocked", "Auto-pentest stopped by user.")
        if status == "paused":
            if not pause_notice_shown:
                print(
                    "Auto-pentest paused. In another terminal, write 'resume' or 'stop' "
                    "to logs/auto_pentest/control.txt."
                )
                pause_notice_shown = True
            await asyncio.sleep(1)
            continue
        return None


def _value_matches_schema_type(value: Any, expected_type: Any) -> bool:
    """Validate primitive JSON schema types used by function tool arguments."""
    if isinstance(expected_type, list):
        return any(_value_matches_schema_type(value, item) for item in expected_type)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "null":
        return value is None
    return True


def _tool_json_error_message(message: str) -> ResponseOutputMessage:
    return ResponseOutputMessage(
        id=f"fallback_tool_error_{uuid.uuid4().hex[:8]}",
        content=[ResponseOutputText(text=message, type="output_text", annotations=[])],
        role="assistant",
        type="message",
        status="completed",
    )


def _auto_pentest_enabled() -> bool:
    return os.getenv("CAI_AUTO_PENTEST_MODE", "false").lower() == "true"


def _auto_pentest_relaxed_mode() -> bool:
    return os.getenv("CAI_AUTO_PENTEST_RELAXED", "false").lower() == "true"


def _auto_pentest_agent_allowed(agent: Agent[Any]) -> bool:
    return getattr(agent, "name", "") == "Bug Bounter"


def _auto_pentest_safe_check_budget() -> int:
    try:
        return max(1, int(os.getenv("CAI_AUTO_PENTEST_SAFE_CHECK_BUDGET", "200")))
    except ValueError:
        return 200


def _auto_pentest_safe_checks_completed() -> int:
    return _AUTO_PENTEST_SAFE_ACTION_COUNT


def _auto_pentest_record_progress() -> int:
    global _AUTO_PENTEST_SAFE_ACTION_COUNT
    _AUTO_PENTEST_SAFE_ACTION_COUNT += 1
    return _AUTO_PENTEST_SAFE_ACTION_COUNT


def _auto_pentest_record_category_progress(test_case: AutoPentestTestCase) -> None:
    _AUTO_PENTEST_CATEGORY_COUNTS[test_case.category] = (
        _AUTO_PENTEST_CATEGORY_COUNTS.get(test_case.category, 0) + 1
    )


def _auto_pentest_category_limit(test_case: AutoPentestTestCase) -> int:
    try:
        default_limit = int(os.getenv("CAI_AUTO_PENTEST_CATEGORY_LIMIT", "8"))
    except ValueError:
        default_limit = 8
    env_key = re.sub(r"[^A-Z0-9]+", "_", test_case.category.upper()).strip("_")
    try:
        return int(os.getenv(f"CAI_AUTO_PENTEST_LIMIT_{env_key}", ""))
    except ValueError:
        return _AUTO_PENTEST_CATEGORY_LIMITS.get(test_case.category, default_limit)


def _auto_pentest_category_complete(test_case: AutoPentestTestCase) -> bool:
    return _AUTO_PENTEST_CATEGORY_COUNTS.get(test_case.category, 0) >= _auto_pentest_category_limit(test_case)


def _auto_pentest_budget_reached() -> bool:
    return _auto_pentest_safe_checks_completed() >= _auto_pentest_safe_check_budget()


def _auto_pentest_next_focus(completed_count: int | None = None) -> str:
    count = _auto_pentest_safe_checks_completed() if completed_count is None else completed_count
    return _AUTO_PENTEST_FOCUS_AREAS[count % len(_AUTO_PENTEST_FOCUS_AREAS)]


def _normalize_auto_pentest_command(command: str) -> str:
    return re.sub(r"\s+", " ", command.strip().lower())


def _looks_like_malformed_shell_command(command: str) -> bool:
    stripped = command.strip()
    if stripped.count("'") % 2 == 1 or stripped.count('"') % 2 == 1:
        return True
    return bool(re.search(r"https?://[^'\"\s]+\\['\"]", stripped))


def _looks_like_blind_data_extraction_sql(command: str) -> bool:
    lower = command.lower()
    return bool(
        re.search(r"\bselect\b|select%20", lower)
        or re.search(r"\bfrom\b|from%20", lower)
        or re.search(r"\b(password|admin|users)\b", lower)
    )


def _parameter_signature_for_command(command: str) -> str:
    urls = _extract_urls(command)
    if not urls:
        return _normalize_auto_pentest_command(command)
    parsed = urlparse(urls[0].rstrip(").,;'\""))
    params = sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
    path = parsed.path or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}?{','.join(params)}"


def _check_signature_for_command(test_case: AutoPentestTestCase, command: str) -> str:
    if test_case.id in {"TC-010", "TC-011", "TC-012", "TC-013"}:
        return f"{test_case.id}:{_parameter_signature_for_command(command)}"
    return f"{test_case.id}:{_normalize_auto_pentest_command(command)}"


def _is_safe_cookie_inspection_command(command: str) -> bool:
    if not re.search(r"(cookie|cookies|cookiejar|jar)", command, flags=re.IGNORECASE):
        return False
    if re.search(r"\.\.|[;&|`]|>\s*", command):
        return False
    return re.search(
        r"\b(type|cat|get-content|gc|findstr|select-string)\b",
        command,
        flags=re.IGNORECASE,
    ) is not None


def _looks_like_pre_enum_payload(command: str) -> bool:
    return any(
        marker in command
        for marker in (
            "%27",
            "%22",
            "';",
            "\";",
            "cai_reflect_probe",
            "cai_xss_probe",
            "../",
            "%2e%2e",
            "<",
            ">",
        )
    )


def _iter_text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        texts: list[str] = []
        for item in value.values():
            texts.extend(_iter_text_values(item))
        return texts
    if isinstance(value, list):
        texts = []
        for item in value:
            texts.extend(_iter_text_values(item))
        return texts
    return []


def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s'\"<>]+", text, flags=re.IGNORECASE)


def _is_allowed_scope_url(url: str) -> bool:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.hostname in _AUTO_PENTEST_ALLOWED_HOSTS and port == _AUTO_PENTEST_ALLOWED_PORT


def _has_allowed_scope_reference(texts: list[str]) -> bool:
    joined = " ".join(texts).lower()
    return (
        "http://localhost:8888" in joined
        or "http://127.0.0.1:8888" in joined
        or re.search(r"\blocalhost:8888\b", joined) is not None
        or re.search(r"\b127\.0\.0\.1:8888\b", joined) is not None
    )


def _quote_header_value(value: str) -> str:
    escaped = value.replace('"', '\\"')
    return f'"{escaped}"'


def _normalize_malformed_http_tool_payload(
    payload: dict[str, Any],
    function_map: dict[str, FunctionTool],
) -> tuple[dict[str, Any] | None, ResponseOutputMessage | None]:
    tool_name = payload.get("name")
    arguments = payload.get("arguments")
    if tool_name not in {"curl", "httpx"}:
        return payload, None
    if "generic_linux_command" not in function_map:
        return None, _tool_json_error_message(
            'Malformed tool JSON: "generic_linux_command" is not registered for this agent.'
        )
    if not isinstance(arguments, dict):
        return None, _tool_json_error_message(
            'Malformed tool JSON: "arguments" must be an object.'
        )

    url = arguments.get("url") or arguments.get("target")
    if not isinstance(url, str):
        return None, _tool_json_error_message(
            'Malformed tool JSON: curl/httpx normalization requires a string "url".'
        )
    url = url.strip()
    if not _is_allowed_scope_url(url):
        return None, _tool_json_error_message("Guarded out-of-scope action.")

    method = str(arguments.get("method", "GET")).upper()
    if method in {"TRACE", "CONNECT"}:
        return None, _tool_json_error_message("Guarded dangerous action.")

    command_parts = ["curl", "-s", "--max-time", "10"]
    if method != "GET":
        command_parts.extend(["-X", method])

    headers = arguments.get("headers")
    if isinstance(headers, dict):
        for header_name, header_value in headers.items():
            if not isinstance(header_name, str) or not isinstance(header_value, str):
                return None, _tool_json_error_message(
                    "Malformed tool JSON: headers must be string key/value pairs."
                )
            command_parts.extend(["-H", _quote_header_value(f"{header_name}: {header_value}")])
    elif headers is not None:
        return None, _tool_json_error_message(
            "Malformed tool JSON: headers must be an object when provided."
        )

    data = arguments.get("data")
    if data is not None:
        if method not in {"POST", "PUT", "PATCH"}:
            return None, _tool_json_error_message("Guarded dangerous action.")
        if not isinstance(data, str):
            return None, _tool_json_error_message(
                "Malformed tool JSON: data must be a string when provided."
            )
        if re.search(r"[;&|`]|>\s*", data):
            return None, _tool_json_error_message("Guarded dangerous action.")
        command_parts.extend(["--data", _quote_header_value(data)])

    command_parts.append(url)
    normalized = {
        "name": "generic_linux_command",
        "arguments": {"command": " ".join(command_parts)},
    }
    logger.info("Normalized malformed tool JSON to registered tool: %s -> generic_linux_command", tool_name)
    print("Normalized malformed tool JSON to registered tool")
    return normalized, None


def _classify_auto_pentest_action(tool_name: str, arguments: str) -> AutoPentestDecision:
    try:
        parsed_args = json.loads(arguments) if arguments else {}
    except json.JSONDecodeError:
        return AutoPentestDecision("blocked", "Guarded dangerous action: malformed tool arguments.")

    texts = _iter_text_values(parsed_args)
    joined = " ".join(texts)
    lower_joined = joined.lower()
    command = str(parsed_args.get("command", "")).lower() if isinstance(parsed_args, dict) else ""

    for pattern in _AUTO_PENTEST_DANGEROUS_PATTERNS:
        if re.search(pattern, lower_joined, flags=re.IGNORECASE):
            return AutoPentestDecision("blocked", "Guarded dangerous action.")

    if tool_name == "generic_linux_command" and command:
        if _looks_like_malformed_shell_command(str(parsed_args.get("command", ""))):
            return AutoPentestDecision(
                "blocked",
                "Guarded malformed shell quoting: use PowerShell-safe double-quoted URLs/data and move to the next category if this repeats.",
            )
        normalized_command = _normalize_auto_pentest_command(command)
        if normalized_command in _AUTO_PENTEST_EXECUTED_COMMANDS:
            return AutoPentestDecision(
                "blocked",
                "Guarded duplicate action: choose a different checklist category.",
            )
        if re.fullmatch(r"\s*(curl|curl\.exe|wget|wget\.exe)\s+--version\s*", command):
            return AutoPentestDecision("safe", "Auto-approved in-scope pentest action.")
        if re.fullmatch(r"\s*(where|where\.exe|where-object)\s+(curl|curl\.exe|wget|wget\.exe)\s*", command):
            return AutoPentestDecision("safe", "Auto-approved in-scope pentest action.")
        if _is_safe_cookie_inspection_command(command):
            return AutoPentestDecision("safe", "Auto-approved in-scope pentest action.")

    urls = [url.rstrip(").,;") for text in texts for url in _extract_urls(text)]
    if urls and any(not _is_allowed_scope_url(url) for url in urls):
        return AutoPentestDecision("blocked", "Guarded out-of-scope action.")

    if not urls and not _has_allowed_scope_reference(texts):
        return AutoPentestDecision("blocked", "Guarded out-of-scope action.")

    if tool_name == "generic_linux_command" and command:
        test_case = _auto_pentest_test_case_for_command(command)
        check_signature = _check_signature_for_command(test_case, command)
        if check_signature in _AUTO_PENTEST_EXECUTED_CHECK_SIGNATURES:
            return AutoPentestDecision(
                "blocked",
                f"Guarded repeated {test_case.category} check for the same endpoint/parameter; move to a different vulnerability category.",
            )
        if _auto_pentest_category_complete(test_case):
            return AutoPentestDecision(
                "blocked",
                f"Category budget reached for {test_case.category}; move to a different vulnerability category.",
            )
        if re.search(r"<\s*script\b|javascript:", command):
            return AutoPentestDecision("blocked", "Guarded dangerous action.")
        if test_case.id == "TC-011" and _looks_like_blind_data_extraction_sql(command):
            return AutoPentestDecision(
                "blocked",
                "Guarded guessed SQL data-extraction payload: SQLi category only allows bounded detection probes against discovered parameters.",
            )
        if (
            _auto_pentest_safe_checks_completed() < _AUTO_PENTEST_ENUMERATION_MIN_CHECKS
            and _looks_like_pre_enum_payload(command)
        ):
            return AutoPentestDecision(
                "blocked",
                "Guarded early payload test: complete entrypoint, asset, route, and API enumeration first.",
            )
        if re.search(r"\s-x\s+(put|patch|delete)\b", command):
            return AutoPentestDecision("risky", "Auto-approved in-scope app-layer action.")
        if re.search(r"\b(gobuster|ffuf|dirsearch|dirb)\b", command):
            return AutoPentestDecision("risky", "Auto-approved in-scope app-layer action.")
        safe_http_method = (
            re.search(r"\b(curl|wget)\b", command) is not None
            and not re.search(r"\b(nmap|masscan|sqlmap|hydra|medusa|ab|siege)\b", command)
        )
        if safe_http_method:
            return AutoPentestDecision("safe", "Auto-approved in-scope pentest action.")

    if urls or _has_allowed_scope_reference(texts):
        return AutoPentestDecision("risky", "Auto-approved in-scope app-layer action.")

    return AutoPentestDecision("blocked", "Guarded out-of-scope action.")


async def _apply_auto_pentest_policy(
    func_tool: FunctionTool, tool_call: ResponseFunctionToolCall
) -> AutoPentestDecision:
    if not _auto_pentest_enabled():
        return AutoPentestDecision("disabled", "")
    await _auto_pentest_ensure_risky_session_decision()

    decision = _classify_auto_pentest_action(func_tool.name, tool_call.arguments)
    logger.info("%s: %s", decision.reason, func_tool.name)

    if decision.classification == "safe":
        return decision
    if decision.classification == "blocked":
        print(decision.reason)
        return decision
    if decision.classification == "risky" and _auto_pentest_relaxed_mode():
        print(f"Auto-approved non-prod in-scope pentest action: {func_tool.name}")
        return AutoPentestDecision("approved", "Auto-approved non-prod in-scope pentest action.")
    if decision.classification == "risky" and _AUTO_PENTEST_RISKY_SESSION_APPROVED:
        return AutoPentestDecision("approved", "Auto-approved non-prod in-scope pentest action.")

    command = _auto_pentest_command_from_args(tool_call.arguments)
    print(
        "In-scope action was not auto-approved by policy."
    )
    print(f"In-scope command: {command}")
    return AutoPentestDecision("blocked", "In-scope action was not auto-approved.")


def _auto_pentest_continue_hint(completed_count: int) -> str:
    budget = _auto_pentest_safe_check_budget()
    next_focus = _auto_pentest_next_focus(completed_count)
    enum_remaining = max(0, _AUTO_PENTEST_ENUMERATION_MIN_CHECKS - completed_count)
    if completed_count >= budget:
        return (
            "\n\n[CAI_AUTO_PENTEST_MODE] Check budget reached. Summarize "
            "findings, evidence, and recommended next in-scope manual steps."
        )
    if enum_remaining:
        return (
            f"\n\n[CAI_AUTO_PENTEST_MODE] Checklist progress: {completed_count}/{budget}. "
            f"Enumeration phase: {enum_remaining} baseline discovery check(s) remain before "
            "payload testing. Next, enumerate real application entrypoints, static JS/CSS "
            "asset URLs from the HTML, route/API hints from those assets, robots/sitemap/"
            "security metadata, and auth forms. Use discovered URLs only; do not guess "
            "payload endpoints yet."
        )
    return (
        f"\n\n[CAI_AUTO_PENTEST_MODE] Checklist progress: {completed_count}/{budget}. "
        f"Next focus: {next_focus}. Continue automatically with exactly one next "
        "in-scope HTTP/API check for http://localhost:8888 or "
        "http://127.0.0.1:8888. Do not repeat an already executed command."
    )


def _fallback_tool_call_from_payload(
    payload: Any,
    function_map: dict[str, FunctionTool],
) -> tuple[ResponseFunctionToolCall | None, ResponseOutputMessage | None]:
    if not isinstance(payload, dict) or set(payload.keys()) != {"name", "arguments"}:
        return None, _tool_json_error_message(
            'Malformed tool JSON: expected exactly {"name": <tool>, "arguments": {...}}.'
        )

    normalized_payload, normalize_error = _normalize_malformed_http_tool_payload(
        payload, function_map
    )
    if normalize_error:
        return None, normalize_error
    payload = normalized_payload

    tool_name = payload.get("name")
    arguments = payload.get("arguments")
    if not isinstance(tool_name, str) or not isinstance(arguments, dict):
        return None, _tool_json_error_message(
            'Malformed tool JSON: "name" must be a string and "arguments" must be an object.'
        )

    tool = function_map.get(tool_name)
    if tool is None:
        return None, _tool_json_error_message(
            f'Malformed tool JSON: "{tool_name}" is not a registered tool for this agent.'
        )

    schema = tool.params_json_schema or {}
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return None, _tool_json_error_message(
            f'Malformed tool JSON: registered tool "{tool_name}" has an invalid schema.'
        )

    extra_args = sorted(set(arguments.keys()) - set(properties.keys()))
    if extra_args:
        return None, _tool_json_error_message(
            f"Malformed tool JSON: unsupported argument(s) for {tool_name}: {', '.join(extra_args)}."
        )

    for arg_name, arg_value in arguments.items():
        expected_type = properties.get(arg_name, {}).get("type")
        if expected_type and not _value_matches_schema_type(arg_value, expected_type):
            return None, _tool_json_error_message(
                f"Malformed tool JSON: argument {arg_name} does not match the registered schema."
            )

    call_id = f"fallback_{uuid.uuid4().hex[:24]}"
    return (
        ResponseFunctionToolCall(
            id=call_id,
            call_id=call_id,
            arguments=json.dumps(arguments),
            name=tool_name,
            type="function_call",
        ),
        None,
    )


def _fallback_tool_calls_from_text(
    text: str,
    function_map: dict[str, FunctionTool],
) -> tuple[list[ResponseFunctionToolCall], ResponseOutputMessage | None]:
    """Parse assistant-text tool JSON only when it matches registered tools."""
    stripped = text.strip()
    if '"name"' not in stripped and '"arguments"' not in stripped:
        return [], None

    try:
        payloads = [json.loads(stripped)] if stripped.startswith("{") else []
    except json.JSONDecodeError as exc:
        if exc.msg == "Extra data":
            payloads = []
        else:
            return [], _tool_json_error_message(
                f"Malformed tool JSON: {exc.msg} at character {exc.pos}."
            )

    if not payloads:
        decoder = json.JSONDecoder()
        for match in re.finditer(r"{", stripped):
            try:
                candidate, _ = decoder.raw_decode(stripped[match.start():])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and {"name", "arguments"}.issubset(candidate):
                payloads.append(candidate)

    tool_calls = []
    for payload in payloads:
        tool_call, error = _fallback_tool_call_from_payload(payload, function_map)
        if error:
            return [], error
        if tool_call:
            tool_calls.append(tool_call)
    return tool_calls, None


def truncate_output(output: Any, max_length: int = 10000) -> str:
    """Truncate tool output if it exceeds max_length characters.
    
    Shows first 5000 and last 5000 characters with TRUNCATED in the middle.
    """
    output_str = str(output)
    if len(output_str) <= max_length:
        return output_str
    
    # Show first 5000 and last 5000 characters
    first_part = output_str[:5000]
    last_part = output_str[-5000:]
    return f"{first_part}\n\n... TRUNCATED ...\n\n{last_part}"


@dataclass
class AgentToolUseTracker:
    agent_to_tools: list[tuple[Agent, list[str]]] = field(default_factory=list)
    """Tuple of (agent, list of tools used). Can't use a dict because agents aren't hashable."""

    def add_tool_use(self, agent: Agent[Any], tool_names: list[str]) -> None:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        if existing_data:
            existing_data[1].extend(tool_names)
        else:
            self.agent_to_tools.append((agent, tool_names))

    def has_used_tools(self, agent: Agent[Any]) -> bool:
        existing_data = next((item for item in self.agent_to_tools if item[0] == agent), None)
        return existing_data is not None and len(existing_data[1]) > 0


@dataclass
class ToolRunHandoff:
    handoff: Handoff
    tool_call: ResponseFunctionToolCall


@dataclass
class ToolRunFunction:
    tool_call: ResponseFunctionToolCall
    function_tool: FunctionTool


@dataclass
class ToolRunComputerAction:
    tool_call: ResponseComputerToolCall
    computer_tool: ComputerTool


@dataclass
class ProcessedResponse:
    new_items: list[RunItem]
    handoffs: list[ToolRunHandoff]
    functions: list[ToolRunFunction]
    computer_actions: list[ToolRunComputerAction]
    tools_used: list[str]  # Names of all tools used, including hosted tools

    def has_tools_to_run(self) -> bool:
        # Handoffs, functions and computer actions need local processing
        # Hosted tools have already run, so there's nothing to do.
        return any(
            [
                self.handoffs,
                self.functions,
                self.computer_actions,
            ]
        )


@dataclass
class NextStepHandoff:
    new_agent: Agent[Any]


@dataclass
class NextStepFinalOutput:
    output: Any


@dataclass
class NextStepRunAgain:
    pass


@dataclass
class SingleStepResult:
    original_input: str | list[TResponseInputItem]
    """The input items i.e. the items before run() was called. May be mutated by handoff input
    filters."""

    model_response: ModelResponse
    """The model response for the current step."""

    pre_step_items: list[RunItem]
    """Items generated before the current step."""

    new_step_items: list[RunItem]
    """Items generated during this current step."""

    next_step: NextStepHandoff | NextStepFinalOutput | NextStepRunAgain
    """The next step to take."""

    @property
    def generated_items(self) -> list[RunItem]:
        """Items generated during the agent run (i.e. everything generated after
        `original_input`)."""
        return self.pre_step_items + self.new_step_items


def get_model_tracing_impl(
    tracing_disabled: bool, trace_include_sensitive_data: bool
) -> ModelTracing:
    if tracing_disabled:
        return ModelTracing.DISABLED
    elif trace_include_sensitive_data:
        return ModelTracing.ENABLED
    else:
        return ModelTracing.ENABLED_WITHOUT_DATA


class RunImpl:
    @classmethod
    async def execute_tools_and_side_effects(
        cls,
        *,
        agent: Agent[TContext],
        # The original input to the Runner
        original_input: str | list[TResponseInputItem],
        # Everything generated by Runner since the original input, but before the current step
        pre_step_items: list[RunItem],
        new_response: ModelResponse,
        processed_response: ProcessedResponse,
        output_schema: AgentOutputSchema | None,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # Make a copy of the generated items
        pre_step_items = list(pre_step_items)

        new_step_items: list[RunItem] = []
        new_step_items.extend(processed_response.new_items)

        # First, lets run the tool calls - function tools and computer actions
        # Create tasks separately so we can handle partial results
        function_task = asyncio.create_task(
            cls.execute_function_tool_calls(
                agent=agent,
                tool_runs=processed_response.functions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        computer_task = asyncio.create_task(
            cls.execute_computer_actions(
                agent=agent,
                actions=processed_response.computer_actions,
                hooks=hooks,
                context_wrapper=context_wrapper,
                config=run_config,
            )
        )
        
        function_results = []
        computer_results = []
        interrupt_exception = None
        
        try:
            function_results, computer_results = await asyncio.gather(
                function_task, computer_task
            )
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            interrupt_exception = e
            
            # Try to get partial results from the tasks
            if function_task.done() and not function_task.cancelled():
                try:
                    function_results = function_task.result()
                except Exception:
                    # If the task failed, create synthetic results
                    function_results = []
                    for tool_run in processed_response.functions:
                        result = FunctionToolResult(
                            tool=tool_run.function_tool,
                            output="Tool execution interrupted",
                            run_item=ToolCallOutputItem(
                                output="Tool execution interrupted",
                                raw_item=ItemHelpers.tool_call_output_item(
                                    tool_run.tool_call, "Tool execution interrupted"
                                ),
                                agent=agent,
                            ),
                        )
                        function_results.append(result)
            else:
                # Task was cancelled or not done, create synthetic results
                function_results = []
                for tool_run in processed_response.functions:
                    result = FunctionToolResult(
                        tool=tool_run.function_tool,
                        output="Tool execution interrupted",
                        run_item=ToolCallOutputItem(
                            output="Tool execution interrupted",
                            raw_item=ItemHelpers.tool_call_output_item(
                                tool_run.tool_call, "Tool execution interrupted"
                            ),
                            agent=agent,
                        ),
                    )
                    function_results.append(result)
                    
            if computer_task.done() and not computer_task.cancelled():
                try:
                    computer_results = computer_task.result()
                except Exception:
                    computer_results = []
            else:
                computer_results = []
            
        new_step_items.extend([result.run_item for result in function_results])
        new_step_items.extend(computer_results)
        
        # Re-raise the interruption after ensuring results are added
        if interrupt_exception:
            raise interrupt_exception

        # Second, check if there are any handoffs
        if run_handoffs := processed_response.handoffs:
            return await cls.execute_handoffs(
                agent=agent,
                original_input=original_input,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                new_response=new_response,
                run_handoffs=run_handoffs,
                hooks=hooks,
                context_wrapper=context_wrapper,
                run_config=run_config,
            )

        # Third, we'll check if the tool use should result in a final output
        check_tool_use = await cls._check_for_final_output_from_tools(
            agent=agent,
            tool_results=function_results,
            context_wrapper=context_wrapper,
            config=run_config,
        )

        if check_tool_use.is_final_output:
            # If the output type is str, then let's just stringify it
            if not agent.output_type or agent.output_type is str:
                check_tool_use.final_output = str(check_tool_use.final_output)

            if check_tool_use.final_output is None:
                logger.error(
                    "Model returned a final output of None. Not raising an error because we assume"
                    "you know what you're doing."
                )

            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=check_tool_use.final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )

        # Now we can check if the model also produced a final output
        message_items = [item for item in new_step_items if isinstance(item, MessageOutputItem)]

        # We'll use the last content output as the final output
        potential_final_output_text = (
            ItemHelpers.extract_last_text(message_items[-1].raw_item) if message_items else None
        )

        # There are two possibilities that lead to a final output:
        # 1. Structured output schema => always leads to a final output
        # 2. Plain text output schema => only leads to a final output if there are no tool calls
        if output_schema and not output_schema.is_plain_text() and potential_final_output_text:
            final_output = output_schema.validate_json(potential_final_output_text)
            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=final_output,
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        elif (
            not output_schema or output_schema.is_plain_text()
        ) and not processed_response.has_tools_to_run():
            if _auto_pentest_enabled() and not _auto_pentest_budget_reached():
                completed = _auto_pentest_safe_checks_completed()
                budget = _auto_pentest_safe_check_budget()
                new_step_items.append(
                    HandoffOutputItem(
                        raw_item={
                            "role": "user",
                            "content": (
                                "[CAI_AUTO_PENTEST_MODE] Continue. "
                                f"Checklist progress: {completed}/{budget}. "
                                f"Next focus: {_auto_pentest_next_focus(completed)}. "
                                "Emit exactly one next in-scope registered tool call, "
                                "using generic_linux_command against only http://localhost:8888 "
                                "or http://127.0.0.1:8888. Do not mark checklist items "
                                "blocked, skipped, complete, or not applicable in prose; only "
                                "actual tool results count as checklist progress. "
                                "Do not repeat an already executed command, endpoint/parameter, "
                                "or vulnerability category loop. If the previous command had a "
                                "quoting or URL format error, switch to the next vulnerability category."
                            ),
                        },
                        agent=agent,
                        source_agent=agent,
                        target_agent=agent,
                    )
                )
                return SingleStepResult(
                    original_input=original_input,
                    model_response=new_response,
                    pre_step_items=pre_step_items,
                    new_step_items=new_step_items,
                    next_step=NextStepRunAgain(),
                )
            return await cls.execute_final_output(
                agent=agent,
                original_input=original_input,
                new_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                final_output=potential_final_output_text or "",
                hooks=hooks,
                context_wrapper=context_wrapper,
            )
        else:
            # If there's no final output, we can just run again
            return SingleStepResult(
                original_input=original_input,
                model_response=new_response,
                pre_step_items=pre_step_items,
                new_step_items=new_step_items,
                next_step=NextStepRunAgain(),
            )

    @classmethod
    def maybe_reset_tool_choice(
        cls, agent: Agent[Any], tool_use_tracker: AgentToolUseTracker, model_settings: ModelSettings
    ) -> ModelSettings:
        """Resets tool choice to None if the agent has used tools and the agent's reset_tool_choice
        flag is True."""

        if agent.reset_tool_choice is True and tool_use_tracker.has_used_tools(agent):
            return dataclasses.replace(model_settings, tool_choice=None)

        return model_settings

    @classmethod
    def process_model_response(
        cls,
        *,
        agent: Agent[Any],
        all_tools: list[Tool],
        response: ModelResponse,
        output_schema: AgentOutputSchema | None,
        handoffs: list[Handoff],
    ) -> ProcessedResponse:
        items: list[RunItem] = []

        run_handoffs = []
        functions = []
        computer_actions = []
        tools_used: list[str] = []
        handoff_map = {handoff.tool_name: handoff for handoff in handoffs}
        function_map = {tool.name: tool for tool in all_tools if isinstance(tool, FunctionTool)}
        computer_tool = next((tool for tool in all_tools if isinstance(tool, ComputerTool)), None)

        for output in response.output:
            if isinstance(output, ResponseOutputMessage):
                fallback_tool_calls = []
                fallback_error = None
                message_text = ItemHelpers.extract_last_text(output) if output.content else None
                if message_text:
                    fallback_tool_calls, fallback_error = _fallback_tool_calls_from_text(
                        message_text, function_map
                    )
                if fallback_error:
                    items.append(MessageOutputItem(raw_item=fallback_error, agent=agent))
                    continue
                if not fallback_tool_calls:
                    items.append(MessageOutputItem(raw_item=output, agent=agent))
                    continue
                if _auto_pentest_enabled() and len(fallback_tool_calls) > 1:
                    # Local models often emit several text JSON calls at once; process
                    # them one turn at a time so each result is fed back cleanly.
                    fallback_tool_calls = fallback_tool_calls[:1]
                for fallback_tool_call in fallback_tool_calls:
                    tools_used.append(fallback_tool_call.name)
                    items.append(ToolCallItem(raw_item=fallback_tool_call, agent=agent))
                    functions.append(
                        ToolRunFunction(
                            tool_call=fallback_tool_call,
                            function_tool=function_map[fallback_tool_call.name],
                        )
                    )
                continue
            elif isinstance(output, ResponseFileSearchToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("file_search")
            elif isinstance(output, ResponseFunctionWebSearch):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("web_search")
            elif isinstance(output, ResponseReasoningItem):
                items.append(ReasoningItem(raw_item=output, agent=agent))
            elif isinstance(output, ResponseComputerToolCall):
                items.append(ToolCallItem(raw_item=output, agent=agent))
                tools_used.append("computer_use")
                if not computer_tool:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Computer tool not found",
                            data={},
                        )
                    )
                    raise ModelBehaviorError(
                        "Model produced computer action without a computer tool."
                    )
                computer_actions.append(
                    ToolRunComputerAction(tool_call=output, computer_tool=computer_tool)
                )
            elif not isinstance(output, ResponseFunctionToolCall):
                logger.warning(f"Unexpected output type, ignoring: {type(output)}")
                continue

            # At this point we know it's a function tool call
            if not isinstance(output, ResponseFunctionToolCall):
                continue

            tools_used.append(output.name)

            # Handoffs
            if output.name in handoff_map:
                items.append(HandoffCallItem(raw_item=output, agent=agent))
                handoff = ToolRunHandoff(
                    tool_call=output,
                    handoff=handoff_map[output.name],
                )
                run_handoffs.append(handoff)
            # Regular function tool call
            else:
                if output.name not in function_map:
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Tool not found",
                            data={"tool_name": output.name},
                        )
                    )
                    raise ModelBehaviorError(f"Tool {output.name} not found in agent {agent.name}")
                items.append(ToolCallItem(raw_item=output, agent=agent))
                functions.append(
                    ToolRunFunction(
                        tool_call=output,
                        function_tool=function_map[output.name],
                    )
                )

        return ProcessedResponse(
            new_items=items,
            handoffs=run_handoffs,
            functions=functions,
            computer_actions=computer_actions,
            tools_used=tools_used,
        )

    @classmethod
    async def execute_function_tool_calls(
        cls,
        *,
        agent: Agent[TContext],
        tool_runs: list[ToolRunFunction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[FunctionToolResult]:
        safe_parallelism = _auto_pentest_parallelism() if _auto_pentest_enabled() else 1
        safe_semaphore = asyncio.Semaphore(safe_parallelism)
        risky_lock = asyncio.Lock()

        async def run_single_tool(
            func_tool: FunctionTool, tool_call: ResponseFunctionToolCall
        ) -> Any:
            with function_span(func_tool.name) as span_fn:
                if config.trace_include_sensitive_data:
                    span_fn.span_data.input = tool_call.arguments
                try:
                    if _auto_pentest_enabled() and not _auto_pentest_agent_allowed(agent):
                        return (
                            "Auto-pentest mode is restricted to the Bug Bounter agent. "
                            "Switch to /agent bug_bounter_agent to run checklist tests."
                        )
                    control_decision = await _auto_pentest_wait_for_resume_or_stop()
                    if control_decision:
                        return control_decision.reason
                    policy_decision = await _apply_auto_pentest_policy(func_tool, tool_call)
                    if _auto_pentest_enabled() and safe_parallelism > 1:
                        queued_summary = (
                            "Waiting for safe parallel slot."
                            if policy_decision.classification == "safe"
                            else policy_decision.reason
                        )
                        _auto_pentest_render_event(
                            agent=agent,
                            func_tool=func_tool,
                            tool_call=tool_call,
                            decision=policy_decision,
                            status="Queued",
                            summary=queued_summary,
                        )
                    if policy_decision.classification == "blocked":
                        if _auto_pentest_enabled():
                            _auto_pentest_render_event(
                                agent=agent,
                                func_tool=func_tool,
                                tool_call=tool_call,
                                decision=policy_decision,
                                status="Skipped",
                                summary=policy_decision.reason,
                            )
                        return policy_decision.reason

                    async def invoke_tool() -> Any:
                        if _auto_pentest_enabled():
                            _auto_pentest_render_event(
                                agent=agent,
                                func_tool=func_tool,
                                tool_call=tool_call,
                                decision=policy_decision,
                                status="Running",
                            )
                        _, _, tool_result = await asyncio.gather(
                            hooks.on_tool_start(context_wrapper, agent, func_tool),
                            (
                                agent.hooks.on_tool_start(context_wrapper, agent, func_tool)
                                if agent.hooks
                                else _coro.noop_coroutine()
                            ),
                            func_tool.on_invoke_tool(context_wrapper, tool_call.arguments),
                        )
                        return tool_result

                    if _auto_pentest_enabled() and policy_decision.classification == "safe":
                        async with safe_semaphore:
                            result = await invoke_tool()
                    elif (
                        _auto_pentest_enabled()
                        and policy_decision.classification in {"risky", "approved"}
                    ):
                        async with risky_lock:
                            result = await invoke_tool()
                    else:
                        result = await invoke_tool()

                    if policy_decision.classification in {"safe", "approved"}:
                        test_case = _auto_pentest_test_case_from_args(tool_call.arguments)
                        try:
                            parsed_args = json.loads(tool_call.arguments) if tool_call.arguments else {}
                            command = parsed_args.get("command")
                            if isinstance(command, str):
                                _AUTO_PENTEST_EXECUTED_COMMANDS.add(
                                    _normalize_auto_pentest_command(command)
                                )
                                _AUTO_PENTEST_EXECUTED_CHECK_SIGNATURES.add(
                                    _check_signature_for_command(test_case, command)
                                )
                        except Exception:
                            pass
                        _auto_pentest_record_category_progress(test_case)
                        completed_count = _auto_pentest_record_progress()
                        result_summary = _auto_pentest_result_summary(result)
                        _AUTO_PENTEST_RESULTS.append(
                            {
                                "test_case": test_case.id,
                                "tool": func_tool.name,
                                "target": _auto_pentest_target_from_args(tool_call.arguments),
                                "status": "Completed",
                                "summary": result_summary,
                            }
                        )
                        if _auto_pentest_enabled():
                            _auto_pentest_render_event(
                                agent=agent,
                                func_tool=func_tool,
                                tool_call=tool_call,
                                decision=policy_decision,
                                status="Completed",
                                summary=result_summary,
                                completed_count=completed_count,
                            )
                        result = f"{result}{_auto_pentest_continue_hint(completed_count)}"

                    await asyncio.gather(
                        hooks.on_tool_end(context_wrapper, agent, func_tool, result),
                        (
                            agent.hooks.on_tool_end(context_wrapper, agent, func_tool, result)
                            if agent.hooks
                            else _coro.noop_coroutine()
                        ),
                    )
                except Exception as e:
                    if _auto_pentest_enabled():
                        _auto_pentest_render_event(
                            agent=agent,
                            func_tool=func_tool,
                            tool_call=tool_call,
                            decision=AutoPentestDecision("blocked", "Tool execution failed."),
                            status="Failed",
                            summary=str(e),
                        )
                    _error_tracing.attach_error_to_current_span(
                        SpanError(
                            message="Error running tool",
                            data={"tool_name": func_tool.name, "error": str(e)},
                        )
                    )
                    if isinstance(e, AgentsException):
                        raise e
                    raise UserError(f"Error running tool {func_tool.name}: {e}") from e

                if config.trace_include_sensitive_data:
                    span_fn.span_data.output = result
            return result

        tasks = []
        for tool_run in tool_runs:
            function_tool = tool_run.function_tool
            tasks.append(asyncio.create_task(run_single_tool(function_tool, tool_run.tool_call)))

        try:
            results = await asyncio.gather(*tasks)
        except (KeyboardInterrupt, asyncio.CancelledError) as e:
            # When interrupted, return partial results with error messages
            results = []
            for i, task in enumerate(tasks):
                if task.done() and not task.cancelled():
                    try:
                        results.append(task.result())
                    except Exception:
                        results.append("Tool execution interrupted")
                else:
                    results.append("Tool execution interrupted")
            
            # Re-raise the exception after collecting results
            raise e

        return [
            FunctionToolResult(
                tool=tool_run.function_tool,
                output=result,
                run_item=ToolCallOutputItem(
                    output=result,
                    raw_item=ItemHelpers.tool_call_output_item(tool_run.tool_call, truncate_output(result)),
                    agent=agent,
                ),
            )
            for tool_run, result in zip(tool_runs, results)
        ]

    @classmethod
    async def execute_computer_actions(
        cls,
        *,
        agent: Agent[TContext],
        actions: list[ToolRunComputerAction],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> list[RunItem]:
        results: list[RunItem] = []
        # Need to run these serially, because each action can affect the computer state
        for action in actions:
            results.append(
                await ComputerAction.execute(
                    agent=agent,
                    action=action,
                    hooks=hooks,
                    context_wrapper=context_wrapper,
                    config=config,
                )
            )

        return results

    @classmethod
    async def execute_handoffs(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        new_response: ModelResponse,
        run_handoffs: list[ToolRunHandoff],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        run_config: RunConfig,
    ) -> SingleStepResult:
        # If there is more than one handoff, add tool responses that reject those handoffs
        multiple_handoffs = len(run_handoffs) > 1
        if multiple_handoffs:
            output_message = "Multiple handoffs detected, ignoring this one."
            new_step_items.extend(
                [
                    ToolCallOutputItem(
                        output=output_message,
                        raw_item=ItemHelpers.tool_call_output_item(
                            handoff.tool_call, output_message
                        ),
                        agent=agent,
                    )
                    for handoff in run_handoffs[1:]
                ]
            )

        actual_handoff = run_handoffs[0]
        with handoff_span(from_agent=agent.name) as span_handoff:
            handoff = actual_handoff.handoff
            new_agent: Agent[Any] = await handoff.on_invoke_handoff(
                context_wrapper, actual_handoff.tool_call.arguments
            )
            span_handoff.span_data.to_agent = new_agent.name
            if multiple_handoffs:
                requested_agents = [handoff.handoff.agent_name for handoff in run_handoffs]
                span_handoff.set_error(
                    SpanError(
                        message="Multiple handoffs requested",
                        data={
                            "requested_agents": requested_agents,
                        },
                    )
                )

            # Append a tool output item for the handoff
            new_step_items.append(
                HandoffOutputItem(
                    agent=agent,
                    raw_item=ItemHelpers.tool_call_output_item(
                        actual_handoff.tool_call,
                        handoff.get_transfer_message(new_agent),
                    ),
                    source_agent=agent,
                    target_agent=new_agent,
                )
            )

            # Execute handoff hooks
            await asyncio.gather(
                hooks.on_handoff(
                    context=context_wrapper,
                    from_agent=agent,
                    to_agent=new_agent,
                ),
                (
                    agent.hooks.on_handoff(
                        context_wrapper,
                        agent=new_agent,
                        source=agent,
                    )
                    if agent.hooks
                    else _coro.noop_coroutine()
                ),
            )

            # If there's an input filter, filter the input for the next agent
            input_filter = handoff.input_filter or (
                run_config.handoff_input_filter if run_config else None
            )
            if input_filter:
                logger.debug("Filtering inputs for handoff")
                handoff_input_data = HandoffInputData(
                    input_history=tuple(original_input)
                    if isinstance(original_input, list)
                    else original_input,
                    pre_handoff_items=tuple(pre_step_items),
                    new_items=tuple(new_step_items),
                )
                if not callable(input_filter):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter",
                            data={"details": "not callable()"},
                        ),
                    )
                    raise UserError(f"Invalid input filter: {input_filter}")
                filtered = input_filter(handoff_input_data)
                if not isinstance(filtered, HandoffInputData):
                    _error_tracing.attach_error_to_span(
                        span_handoff,
                        SpanError(
                            message="Invalid input filter result",
                            data={"details": "not a HandoffInputData"},
                        ),
                    )
                    raise UserError(f"Invalid input filter result: {filtered}")

                original_input = (
                    filtered.input_history
                    if isinstance(filtered.input_history, str)
                    else list(filtered.input_history)
                )
                pre_step_items = list(filtered.pre_handoff_items)
                new_step_items = list(filtered.new_items)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepHandoff(new_agent),
        )

    @classmethod
    async def execute_final_output(
        cls,
        *,
        agent: Agent[TContext],
        original_input: str | list[TResponseInputItem],
        new_response: ModelResponse,
        pre_step_items: list[RunItem],
        new_step_items: list[RunItem],
        final_output: Any,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
    ) -> SingleStepResult:
        # Run the on_end hooks
        await cls.run_final_output_hooks(agent, hooks, context_wrapper, final_output)

        return SingleStepResult(
            original_input=original_input,
            model_response=new_response,
            pre_step_items=pre_step_items,
            new_step_items=new_step_items,
            next_step=NextStepFinalOutput(final_output),
        )

    @classmethod
    async def run_final_output_hooks(
        cls,
        agent: Agent[TContext],
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        final_output: Any,
    ):
        await asyncio.gather(
            hooks.on_agent_end(context_wrapper, agent, final_output),
            agent.hooks.on_end(context_wrapper, agent, final_output)
            if agent.hooks
            else _coro.noop_coroutine(),
        )

    @classmethod
    async def run_single_input_guardrail(
        cls,
        agent: Agent[Any],
        guardrail: InputGuardrail[TContext],
        input: str | list[TResponseInputItem],
        context: RunContextWrapper[TContext],
    ) -> InputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent, input, context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    async def run_single_output_guardrail(
        cls,
        guardrail: OutputGuardrail[TContext],
        agent: Agent[Any],
        agent_output: Any,
        context: RunContextWrapper[TContext],
    ) -> OutputGuardrailResult:
        with guardrail_span(guardrail.get_name()) as span_guardrail:
            result = await guardrail.run(agent=agent, agent_output=agent_output, context=context)
            span_guardrail.span_data.triggered = result.output.tripwire_triggered
            return result

    @classmethod
    def stream_step_result_to_queue(
        cls,
        step_result: SingleStepResult,
        queue: asyncio.Queue[StreamEvent | QueueCompleteSentinel],
    ):
        for item in step_result.new_step_items:
            if isinstance(item, MessageOutputItem):
                event = RunItemStreamEvent(item=item, name="message_output_created")
            elif isinstance(item, HandoffCallItem):
                event = RunItemStreamEvent(item=item, name="handoff_requested")
            elif isinstance(item, HandoffOutputItem):
                event = RunItemStreamEvent(item=item, name="handoff_occured")
            elif isinstance(item, ToolCallItem):
                event = RunItemStreamEvent(item=item, name="tool_called")
            elif isinstance(item, ToolCallOutputItem):
                event = RunItemStreamEvent(item=item, name="tool_output")
            elif isinstance(item, ReasoningItem):
                event = RunItemStreamEvent(item=item, name="reasoning_item_created")
            else:
                logger.warning(f"Unexpected item type: {type(item)}")
                event = None

            if event:
                queue.put_nowait(event)

    @classmethod
    async def _check_for_final_output_from_tools(
        cls,
        *,
        agent: Agent[TContext],
        tool_results: list[FunctionToolResult],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> ToolsToFinalOutputResult:
        """Returns (i, final_output)."""
        if not tool_results:
            return _NOT_FINAL_OUTPUT

        if agent.tool_use_behavior == "run_llm_again":
            return _NOT_FINAL_OUTPUT
        elif agent.tool_use_behavior == "stop_on_first_tool":
            return ToolsToFinalOutputResult(
                is_final_output=True, final_output=tool_results[0].output
            )
        elif isinstance(agent.tool_use_behavior, dict):
            names = agent.tool_use_behavior.get("stop_at_tool_names", [])
            for tool_result in tool_results:
                if tool_result.tool.name in names:
                    return ToolsToFinalOutputResult(
                        is_final_output=True, final_output=tool_result.output
                    )
            return ToolsToFinalOutputResult(is_final_output=False, final_output=None)
        elif callable(agent.tool_use_behavior):
            if inspect.iscoroutinefunction(agent.tool_use_behavior):
                return await cast(
                    Awaitable[ToolsToFinalOutputResult],
                    agent.tool_use_behavior(context_wrapper, tool_results),
                )
            else:
                return cast(
                    ToolsToFinalOutputResult, agent.tool_use_behavior(context_wrapper, tool_results)
                )

        logger.error(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")
        raise UserError(f"Invalid tool_use_behavior: {agent.tool_use_behavior}")


class TraceCtxManager:
    """Creates a trace only if there is no current trace, and manages the trace lifecycle."""

    def __init__(
        self,
        workflow_name: str,
        trace_id: str | None,
        group_id: str | None,
        metadata: dict[str, Any] | None,
        disabled: bool,
    ):
        self.trace: Trace | None = None
        self.workflow_name = workflow_name
        self.trace_id = trace_id
        self.group_id = group_id
        self.metadata = metadata
        self.disabled = disabled

    def __enter__(self) -> TraceCtxManager:
        current_trace = get_current_trace()
        if not current_trace:
            self.trace = trace(
                workflow_name=self.workflow_name,
                trace_id=self.trace_id,
                group_id=self.group_id,
                metadata=self.metadata,
                disabled=self.disabled,
            )
            self.trace.start(mark_as_current=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.trace:
            self.trace.finish(reset_current=True)


class ComputerAction:
    @classmethod
    async def execute(
        cls,
        *,
        agent: Agent[TContext],
        action: ToolRunComputerAction,
        hooks: RunHooks[TContext],
        context_wrapper: RunContextWrapper[TContext],
        config: RunConfig,
    ) -> RunItem:
        output_func = (
            cls._get_screenshot_async(action.computer_tool.computer, action.tool_call)
            if isinstance(action.computer_tool.computer, AsyncComputer)
            else cls._get_screenshot_sync(action.computer_tool.computer, action.tool_call)
        )

        _, _, output = await asyncio.gather(
            hooks.on_tool_start(context_wrapper, agent, action.computer_tool),
            (
                agent.hooks.on_tool_start(context_wrapper, agent, action.computer_tool)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
            output_func,
        )

        await asyncio.gather(
            hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output),
            (
                agent.hooks.on_tool_end(context_wrapper, agent, action.computer_tool, output)
                if agent.hooks
                else _coro.noop_coroutine()
            ),
        )

        # TODO: don't send a screenshot every single time, use references
        image_url = f"data:image/png;base64,{output}"
        return ToolCallOutputItem(
            agent=agent,
            output=image_url,
            raw_item=ComputerCallOutput(
                call_id=action.tool_call.call_id,
                output={
                    "type": "computer_screenshot",
                    "image_url": image_url,
                },
                type="computer_call_output",
            ),
        )

    @classmethod
    async def _get_screenshot_sync(
        cls,
        computer: Computer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            computer.screenshot()
        elif isinstance(action, ActionScroll):
            computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            computer.type(action.text)
        elif isinstance(action, ActionWait):
            computer.wait()

        return computer.screenshot()

    @classmethod
    async def _get_screenshot_async(
        cls,
        computer: AsyncComputer,
        tool_call: ResponseComputerToolCall,
    ) -> str:
        action = tool_call.action
        if isinstance(action, ActionClick):
            await computer.click(action.x, action.y, action.button)
        elif isinstance(action, ActionDoubleClick):
            await computer.double_click(action.x, action.y)
        elif isinstance(action, ActionDrag):
            await computer.drag([(p.x, p.y) for p in action.path])
        elif isinstance(action, ActionKeypress):
            await computer.keypress(action.keys)
        elif isinstance(action, ActionMove):
            await computer.move(action.x, action.y)
        elif isinstance(action, ActionScreenshot):
            await computer.screenshot()
        elif isinstance(action, ActionScroll):
            await computer.scroll(action.x, action.y, action.scroll_x, action.scroll_y)
        elif isinstance(action, ActionType):
            await computer.type(action.text)
        elif isinstance(action, ActionWait):
            await computer.wait()

        return await computer.screenshot()
