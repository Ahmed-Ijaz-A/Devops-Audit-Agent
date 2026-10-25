"""Explicit LLM-to-tool control loop. No agent framework is used."""

from __future__ import annotations

import json
import re
import sys
import time
from typing import Any

from llm import Conversation, LLMSettings, Turn, make_client, new_conversation
from prompts import SYSTEM_PROMPT
from tools import RUN_PYTEST_SCHEMA, TOOL_SCHEMAS, GitRepository, redact_secrets

MAX_TOOL_CALLS = 40
MAX_REQUESTS = MAX_TOOL_CALLS + 5
MAX_REPORT_FINDINGS = 100
MAX_REPAIR_ATTEMPTS = 2
RATE_LIMIT_WAITS = (20, 40, 60)
DEFAULT_TIME_LIMIT_SECONDS = 900
# Older tool output is replaced by a short stub beyond this many characters, keeping requests small on free tiers.
MAX_TOOL_OUTPUT_CONTEXT_CHARS = 120_000


ALLOWED_CATEGORIES = {
    "repository_hygiene", "dependency_management", "code_quality", "testing",
    "ci_cd", "security", "configuration", "collaboration", "build_release",
}
CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene", "repository": "repository_hygiene",
    "dependencies": "dependency_management", "dependency": "dependency_management",
    "quality": "code_quality", "tests": "testing", "test": "testing",
    "ci": "ci_cd", "cicd": "ci_cd", "github_actions": "ci_cd", "github_actions_ci": "ci_cd",
    "config": "configuration", "build": "build_release", "release": "build_release",
    "build_and_release": "build_release",
}
ALLOWED_SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_ALIASES = {"blocker": "critical", "major": "high", "moderate": "medium", "minor": "low", "info": "low", "informational": "low"}
CATEGORY_PREFIXES = {
    "repository_hygiene": "HYG", "dependency_management": "DEP", "code_quality": "CQ", "testing": "TEST",
    "ci_cd": "CI", "security": "SEC", "configuration": "CFG", "collaboration": "COL", "build_release": "BLD",
}
TEXT_FIELDS = ("rule_id", "description", "evidence", "recommendation")
REPORT_FIELDS = ("rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation")


class AgentError(RuntimeError):
    """Raised when the LLM loop returns unusable results."""


def _make_client(settings: LLMSettings) -> Any:
    """Load the provider SDK only for a real audit, not for local unit tests."""
    try:
        return make_client(settings)
    except ImportError as exc:
        raise AgentError("OpenAI SDK is missing. Install dependencies with: python -m pip install -r requirements.txt") from exc


def _is_transient(exc: Exception) -> bool:
    name = type(exc).__name__
    if name == "RateLimitError":
        return not _is_billing_error(exc)
    return name in {"InternalServerError", "APITimeoutError", "APIConnectionError"}


def _request_with_retry(
    conversation: Conversation, tool_choice: str, settings: LLMSettings, fallbacks: list[str], notes: list[str],
) -> Turn:
    """Wait out rate limits and overloads (common on free tiers) beyond the SDK's short retries, then try fallback models."""
    while True:
        for wait in (*RATE_LIMIT_WAITS, None):
            try:
                return conversation.request(tool_choice)
            except Exception as exc:
                transient = _is_transient(exc)
                if transient and wait is not None:
                    reason = "rate limited" if type(exc).__name__ == "RateLimitError" else "temporarily unavailable"
                    print(f"{settings.provider} model {conversation.model} {reason}; waiting {wait}s before retrying.", file=sys.stderr)
                    time.sleep(wait)
                    continue
                if fallbacks and (transient or type(exc).__name__ == "NotFoundError"):
                    previous, conversation.model = conversation.model, fallbacks.pop(0)
                    notes.append(f"switched model from {previous} to {conversation.model} ({type(exc).__name__})")
                    print(f"Switching to fallback model {conversation.model}.", file=sys.stderr)
                    break
                # Avoid dumping provider exception bodies or request details into the CLI.
                raise _translate_provider_error(exc, conversation.model, settings.provider) from exc


def _error_body(exc: Exception) -> dict[str, Any]:
    """The provider's error object; Gemini wraps it in a one-element list."""
    body = getattr(exc, "body", None)
    if isinstance(body, list) and body:
        body = body[0]
    if isinstance(body, dict):
        error = body.get("error", body)
        if isinstance(error, dict):
            return error
    return {}


def _provider_error_metadata(exc: Exception) -> tuple[str | None, str | None]:
    """Extract only the provider's short machine-readable error code and type."""
    error = _error_body(exc)
    code = getattr(exc, "code", None) or error.get("code")
    error_type = getattr(exc, "type", None) or error.get("type") or error.get("status")
    return (code if isinstance(code, str) else None, error_type if isinstance(error_type, str) else None)


def _provider_message(exc: Exception) -> str:
    """A short, redacted provider message so users can diagnose 400/401/403 errors."""
    message = _error_body(exc).get("message")
    if not isinstance(message, str):
        message = getattr(exc, "message", None) or str(exc)
    return redact_secrets(" ".join(str(message).split()))[:300]


BILLING_CODES = {
    "insufficient_quota", "credit_balance_exhausted", "organization_spend_limit_exceeded",
    "project_spend_limit_exceeded", "organization_usage_limit_exceeded",
}


def _is_billing_error(exc: Exception) -> bool:
    code, error_type = _provider_error_metadata(exc)
    return code in BILLING_CODES or error_type == "insufficient_quota"


def _translate_provider_error(exc: Exception, model: str, provider: str = "openai") -> AgentError:
    name = type(exc).__name__
    code, error_type = _provider_error_metadata(exc)
    detail = _provider_message(exc)
    if name == "NotFoundError" or code == "model_not_found":
        return AgentError(
            f"Model '{model}' was not found or is not enabled for your {provider} account. "
            f"Set LLM_MODEL to a model ID your provider lists. Provider said: {detail}"
        )
    if name == "AuthenticationError":
        return AgentError(f"{provider} rejected the API key (401). Check the key for LLM_PROVIDER={provider}. Provider said: {detail}")
    if name == "PermissionDeniedError":
        return AgentError(f"Your {provider} key cannot use '{model}' (403). Provider said: {detail}")
    if name == "RateLimitError":
        if _is_billing_error(exc):
            hint = (
                "Check API Platform billing, available credits, and project or organization spend limits. ChatGPT billing is separate. "
                "For a free alternative, set LLM_PROVIDER=gemini (see README)."
                if provider == "openai" else "Check your provider's billing or free-tier quota."
            )
            return AgentError(f"{provider} API quota/billing limit reached ({code or error_type}). {hint}")
        if code in {"rate_limit_exceeded", "slow_down"} or error_type == "rate_limit_error":
            return AgentError(
                f"{provider} request rate limit reached ({code or error_type}) after automatic retries. Wait before "
                f"retrying, or set LLM_MIN_INTERVAL to space requests out. Provider said: {detail}"
            )
        return AgentError(
            f"{provider} rejected the request under a rate or quota limit ({code or error_type or 'no error code'}). "
            f"Free tiers also have a daily request limit; wait and retry, or set LLM_MIN_INTERVAL. Provider said: {detail}"
        )
    if name in {"APITimeoutError", "APIConnectionError"}:
        return AgentError(f"Could not reach the {provider} API ({name}) after retries. Check network access and retry.")
    if name == "InternalServerError":
        return AgentError(
            f"{provider} is overloaded or temporarily failing for '{model}' after repeated retries. Try again later, or set "
            f"LLM_MODEL (or LLM_FALLBACK_MODELS) to another model your provider lists. Provider said: {detail}"
        )
    return AgentError(f"LLM request failed ({name}{', ' + code if code else ''}): {detail}")


def _json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object, tolerating a surrounding markdown fence or leading/trailing prose."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"\A```(?:json)?\s*|\s*```\Z", "", cleaned, flags=re.IGNORECASE)
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start < 0 or end <= start:
            raise
        value = json.loads(cleaned[start:end + 1])
    if not isinstance(value, dict):
        raise AgentError("The model's final response was not a JSON object.")
    return value


def _normalize_category(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    key = re.sub(r"[^a-z0-9]+", "_", value.strip().casefold()).strip("_")
    key = CATEGORY_ALIASES.get(key, key)
    return key if key in ALLOWED_CATEGORIES else None


def _normalize_severity(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    key = value.strip().casefold()
    key = SEVERITY_ALIASES.get(key, key)
    return key if key in ALLOWED_SEVERITIES else None


def _normalize_rule_id(value: Any, category: str) -> str:
    """PREFIX-NNN; a missing or garbled id becomes the category's catch-all PREFIX-099."""
    match = re.search(r"([A-Za-z]{2,6})\s*-?\s*(\d{1,4})", value if isinstance(value, str) else "")
    if match:
        return f"{match.group(1).upper()}-{int(match.group(2)):03d}"
    return f"{CATEGORY_PREFIXES[category]}-099"


def _evidence_steps(value: Any, evidence_steps: set[int]) -> list[int]:
    """The cited step numbers that refer to tool calls which actually ran and returned a result."""
    if not isinstance(value, list):
        value = [value]
    steps = []
    for item in value:
        if isinstance(item, str):
            item = re.sub(r"\D", "", item)
            item = int(item) if item else None
        if isinstance(item, int) and not isinstance(item, bool) and item in evidence_steps and item not in steps:
            steps.append(item)
    return steps


def _validate_report(
    raw: dict[str, Any], repo_url: str, repo: GitRepository, notes: list[str] | None = None,
    evidence_steps: set[int] | None = None, citations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Normalize findings. Unusable or unsupported findings are dropped and bad locations nulled rather than failing the audit.

    When evidence_steps is given, every finding must cite at least one of those tool-result steps in evidence_refs.
    """
    notes = notes if notes is not None else []
    violations = raw.get("violations")
    if not isinstance(violations, list):
        raise AgentError("The model's final JSON must contain a violations array.")

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, int | None, str]] = set()

    for index, item in enumerate(violations):
        if not isinstance(item, dict):
            notes.append(f"finding {index}: dropped, not an object")
            continue
        finding: dict[str, Any] = {
            "rule_id": item.get("rule_id"),
            "category": _normalize_category(item.get("category")),
            "severity": _normalize_severity(item.get("severity")),
            "file": item.get("file"),
            "line": item.get("line"),
            "description": item.get("description"),
            "evidence": item.get("evidence"),
            "recommendation": item.get("recommendation"),
        }
        if finding["category"] is None or finding["severity"] is None:
            notes.append(f"finding {index}: dropped, unsupported category or severity")
            continue
        finding["rule_id"] = _normalize_rule_id(finding["rule_id"], finding["category"])
        if any(not isinstance(finding[key], str) or not finding[key].strip() for key in TEXT_FIELDS):
            notes.append(f"finding {index}: dropped, missing text field")
            continue
        for key in TEXT_FIELDS:
            finding[key] = redact_secrets(finding[key].strip())
        refs: list[int] = []
        if evidence_steps is not None:
            refs = _evidence_steps(item.get("evidence_refs"), evidence_steps)
            if not refs:
                notes.append(f"finding {index} ({finding['rule_id']}): dropped, no evidence_refs to a tool result that ran")
                continue

        if isinstance(finding["file"], str) and finding["file"].strip():
            path = finding["file"].strip().replace("\\", "/").removeprefix("./")
            if repo.has_file(path):
                finding["file"] = path
            else:
                notes.append(f"finding {index}: file not tracked, set file/line to null")
                finding["file"] = None
        else:
            finding["file"] = None

        line = finding["line"]
        if isinstance(line, str) and line.strip().isdigit():
            line = int(line.strip())
        if finding["file"] is None or isinstance(line, bool) or not isinstance(line, int) or line < 1:
            line = None
        elif line > repo.line_count(finding["file"]):
            notes.append(f"finding {index}: line {line} beyond end of {finding['file']}, set to null")
            line = None
        finding["line"] = line

        description_key = " ".join(re.findall(r"[a-z0-9]+", finding["description"].casefold()))
        location_key = (finding["rule_id"], finding["file"], finding["line"], "")
        text_key = ("", finding["file"], None, description_key)
        if location_key in seen or text_key in seen:
            notes.append(f"finding {index} ({finding['rule_id']}): dropped, duplicate of an earlier finding")
            continue
        seen.update({location_key, text_key})
        normalized.append(finding)
        if citations is not None:
            citations.append({"rule_id": finding["rule_id"], "file": finding["file"], "line": finding["line"], "evidence_refs": refs})
        if len(normalized) >= MAX_REPORT_FINDINGS:
            notes.append("report truncated at the findings limit")
            break
    rank = {severity: position for position, severity in enumerate(ALLOWED_SEVERITIES)}
    normalized.sort(key=lambda v: (rank[v["severity"]], v["file"] or "", v["line"] or 0, v["rule_id"]))
    return {"repository": repo_url, "violations": [{field: v[field] for field in REPORT_FIELDS} for v in normalized]}


def run_agent(
    repo_url: str, repo: GitRepository, *, settings: LLMSettings, enable_pytest: bool = False,
    time_limit: float = DEFAULT_TIME_LIMIT_SECONDS, clock: Any = time.monotonic,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run bounded model-directed inspection and return report plus trace."""
    client = _make_client(settings)
    tools = TOOL_SCHEMAS + ([RUN_PYTEST_SCHEMA] if enable_pytest else [])
    offered = {tool["name"] for tool in tools}
    conversation = new_conversation(
        settings.api, client, settings.model, tools, SYSTEM_PROMPT,
        f"Inspect this public repository: {repo_url}. Begin by observing its file structure, then investigate relevant areas dynamically. "
        "Tool results are labelled [step N]; cite those numbers in evidence_refs.",
        settings.min_interval,
    )
    trace: dict[str, Any] = {
        "repository": repo_url, "provider": settings.provider, "model": settings.model,
        "tools_offered": sorted(offered), "tool_calls": [], "notes": [], "citations": [],
    }
    fallbacks = [model for model in settings.fallback_models if model != settings.model]
    deadline = clock() + time_limit
    tool_count = 0
    repairs = 0
    finalizing = False
    evidence_steps: set[int] = set()  # steps whose tool ran and returned a result (not an error)
    seen_calls: dict[str, int] = {}

    for request_number in range(1, MAX_REQUESTS + 1):
        if not finalizing:
            reason = None
            if tool_count >= MAX_TOOL_CALLS or request_number == MAX_REQUESTS:
                reason = "tool budget reached"
            elif clock() > deadline:
                reason = f"time limit of {time_limit:.0f}s reached"
            if reason:
                # Budget exhausted: ask for the report from the evidence gathered so far instead of failing.
                finalizing = True
                trace["notes"].append(f"{reason}; requested final report")
                conversation.add_user("The inspection budget is exhausted. Do not call more tools. Return the final JSON report now, using only evidence already gathered.")
        tool_choice = "none" if finalizing else ("required" if tool_count == 0 else "auto")
        turn = _request_with_retry(conversation, tool_choice, settings, fallbacks, trace["notes"])

        calls = turn.calls
        if not calls:
            text = turn.text
            notes: list[str] = []
            citations: list[dict[str, Any]] = []
            try:
                if not text:
                    raise AgentError("The model returned neither tool calls nor a final report.")
                raw = _json_object(text)
                report = _validate_report(raw, repo_url, repo, notes, evidence_steps, citations)
                submitted = raw.get("violations") or []
                if submitted and not report["violations"] and any("evidence_refs" in note for note in notes):
                    raise AgentError(
                        "every finding was discarded because none cited evidence_refs from the [step N] labels of tool results that ran. "
                        "Add evidence_refs to each finding you can support, and drop the rest."
                    )
            except (AgentError, ValueError) as exc:
                repairs += 1
                if repairs > MAX_REPAIR_ATTEMPTS or request_number == MAX_REQUESTS:
                    raise AgentError(f"The model did not produce a valid report: {exc}") from exc
                trace["notes"].append(f"final report rejected ({exc}); asked model to correct it")
                if text:
                    conversation.add_assistant(text)
                conversation.add_user(f"Your final answer was invalid: {exc} Respond with only the JSON object {{\"violations\": [...]}} following the required schema.")
                finalizing = True
                continue
            trace["notes"].extend(notes)
            trace["citations"] = citations
            trace["tool_call_count"] = tool_count
            trace["final_model"] = conversation.model
            return report, trace

        for call in calls:
            arguments: dict[str, Any] = {}
            step = len(trace["tool_calls"]) + 1
            if tool_count >= MAX_TOOL_CALLS or finalizing:
                # Every function call needs an output item, or the next request is rejected.
                result: Any = {"error": "tool budget exhausted; return the final report"}
            else:
                tool_count += 1
                try:
                    arguments = json.loads(call.arguments)
                    if not isinstance(arguments, dict):
                        raise ValueError("tool arguments must be a JSON object")
                    if call.name not in offered:
                        raise ValueError(f"tool '{call.name}' is not available in this run")
                    key = f"{call.name}:{json.dumps(arguments, sort_keys=True)}"
                    if key in seen_calls:
                        result = {"error": f"duplicate of step {seen_calls[key]}; the result is unchanged. Use other arguments or another tool."}
                    else:
                        seen_calls[key] = step
                        result = repo.dispatch(call.name, arguments)
                        if not (isinstance(result, dict) and result.get("available") is False):
                            evidence_steps.add(step)
                except Exception as exc:  # Return tool-level errors to the agent for interpretation.
                    result = {"error": str(exc)}
            safe_result = redact_secrets(json.dumps(result, ensure_ascii=False, default=str))
            safe_arguments = redact_secrets(json.dumps(arguments, ensure_ascii=False))
            trace["tool_calls"].append({"step": step, "name": call.name, "arguments": safe_arguments, "result": safe_result})
            conversation.add_tool_output(call.call_id, f"[step {step}] {safe_result}", f"{call.name} {safe_arguments}")
        conversation.compact(MAX_TOOL_OUTPUT_CONTEXT_CHARS)

    raise AgentError(f"Inspection stopped after the {MAX_REQUESTS}-request safety limit without a final report.")
