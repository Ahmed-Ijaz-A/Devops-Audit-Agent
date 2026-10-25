"""LLM provider settings and conversation adapters (OpenAI Responses API or OpenAI-compatible Chat Completions)."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

PROVIDERS: dict[str, dict[str, Any]] = {
    "openai": {"api": "responses", "base_url": None, "key_env": "OPENAI_API_KEY", "default_model": "gpt-6-luna"},
    "gemini": {"api": "chat", "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/", "key_env": "GEMINI_API_KEY", "default_model": "gemini-3.8-flash"},
    "groq": {"api": "chat", "base_url": "https://api.groq.com/openai/v1", "key_env": "GROQ_API_KEY", "default_model": None},
    "openrouter": {"api": "chat", "base_url": "https://openrouter.ai/api/v1", "key_env": "OPENROUTER_API_KEY", "default_model": None},
    "ollama": {"api": "chat", "base_url": "http://localhost:11434/v1", "key_env": None, "default_model": None},
}
PLACEHOLDER_KEYS = {"", "replace-me", "your-api-key", "changeme"}


@dataclass(frozen=True)
class LLMSettings:
    provider: str
    api: str
    model: str
    api_key: str
    base_url: str | None
    min_interval: float = 0.0
    fallback_models: tuple[str, ...] = ()


def resolve_settings(env: Mapping[str, str] = os.environ) -> LLMSettings:
    """Read provider settings from environment variables; raise ValueError with a fix when incomplete."""
    provider = env.get("LLM_PROVIDER", "openai").strip().lower() or "openai"
    if provider not in PROVIDERS:
        raise ValueError(f"LLM_PROVIDER must be one of: {', '.join(PROVIDERS)}.")
    preset = PROVIDERS[provider]
    api = env.get("LLM_API", preset["api"]).strip().lower()
    if api not in {"responses", "chat"}:
        raise ValueError("LLM_API must be 'responses' or 'chat'.")

    key_env = preset["key_env"]
    api_key = env.get("LLM_API_KEY") or (env.get(key_env) if key_env else None) or ""
    if key_env is None:
        api_key = api_key or "ollama"  # Local servers ignore the key, but the SDK requires one.
    if api_key.strip() in PLACEHOLDER_KEYS:
        raise ValueError(f"Set {key_env or 'LLM_API_KEY'} (environment variable or .env file) for LLM_PROVIDER={provider}.")

    model = env.get("LLM_MODEL") or (env.get("OPENAI_MODEL") if provider == "openai" else None) or preset["default_model"]
    if not model:
        raise ValueError(f"Set LLM_MODEL to a tool-calling model available from {provider}.")
    try:
        min_interval = float(env.get("LLM_MIN_INTERVAL", "0") or 0)
    except ValueError as exc:
        raise ValueError("LLM_MIN_INTERVAL must be a number of seconds.") from exc
    fallback_models = tuple(name.strip() for name in env.get("LLM_FALLBACK_MODELS", "").split(",") if name.strip())
    for name in (model, *fallback_models):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", name):
            raise ValueError(f"'{name}' is not a valid model ID. Use an ID exactly as your provider lists it (check LLM_MODEL and LLM_FALLBACK_MODELS).")
    return LLMSettings(
        provider, api, model, api_key.strip(), env.get("LLM_BASE_URL") or preset["base_url"], max(0.0, min_interval), fallback_models,
    )


@dataclass
class ToolCall:
    call_id: str
    name: str
    arguments: str


@dataclass
class Turn:
    calls: list[ToolCall]
    text: str


class Conversation:
    """Message history plus one request method; subclasses speak one provider API."""

    def __init__(self, client: Any, model: str, tools: list[dict[str, Any]], system: str, user: str, min_interval: float = 0.0):
        self.client = client
        self.model = model
        self.tools = tools
        self.min_interval = min_interval
        self._last_request = 0.0
        self._labels: dict[int, str] = {}
        self.items: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def request(self, tool_choice: str) -> Turn:
        # Free tiers allow only a few requests per minute; spacing requests avoids most 429s.
        wait = self._last_request + self.min_interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            return self._request(tool_choice)
        finally:
            self._last_request = time.monotonic()

    def _request(self, tool_choice: str) -> Turn:
        raise NotImplementedError

    def add_user(self, text: str) -> None:
        self.items.append({"role": "user", "content": text})

    def add_assistant(self, text: str) -> None:
        self.items.append({"role": "assistant", "content": text})

    def add_tool_output(self, call_id: str, output: str, label: str = "") -> None:
        item = self._tool_output_item(call_id, output)
        self._labels[id(item)] = label
        self.items.append(item)

    def _tool_output_item(self, call_id: str, output: str) -> dict[str, Any]:
        raise NotImplementedError

    _OUTPUT_KEY = "content"

    def _is_tool_output(self, item: dict[str, Any]) -> bool:
        raise NotImplementedError

    def compact(self, limit: int) -> int:
        """Replace the oldest tool outputs with one-line stubs until they fit in `limit` characters.

        Outputs of the latest batch are kept: the model has not seen them yet. Returns the number stubbed.
        """
        outputs = [item for item in self.items if self._is_tool_output(item)]
        total = sum(len(item[self._OUTPUT_KEY]) for item in outputs)
        latest = len(self.items)
        while latest > 0 and self._is_tool_output(self.items[latest - 1]):
            latest -= 1
        stubbed = 0
        for item in self.items[:latest]:
            if total <= limit:
                break
            if not self._is_tool_output(item) or item[self._OUTPUT_KEY].endswith(OMITTED_SUFFIX):
                continue
            content = item[self._OUTPUT_KEY]
            step_label = content.split("]", 1)[0] + "]" if content.startswith("[step ") else ""
            stub = f"{step_label} {self._labels.get(id(item), 'earlier call')} {OMITTED_SUFFIX}".strip()
            total -= len(content) - len(stub)
            item[self._OUTPUT_KEY] = stub
            stubbed += 1
        return stubbed


OMITTED_SUFFIX = "(output omitted to save context; repeat the call with different arguments if you need it again)"


class ResponsesConversation(Conversation):
    """OpenAI Responses API."""

    def _request(self, tool_choice: str) -> Turn:
        response = self.client.responses.create(model=self.model, input=self.items, tools=self.tools, tool_choice=tool_choice)
        calls = [item for item in response.output if getattr(item, "type", None) == "function_call"]
        if calls:
            self.items.extend(item.model_dump(exclude_none=True) for item in response.output)
        return Turn([ToolCall(call.call_id, call.name, call.arguments) for call in calls], response.output_text or "")

    _OUTPUT_KEY = "output"

    def _tool_output_item(self, call_id: str, output: str) -> dict[str, Any]:
        return {"type": "function_call_output", "call_id": call_id, "output": output}

    def _is_tool_output(self, item: dict[str, Any]) -> bool:
        return item.get("type") == "function_call_output"


class ChatConversation(Conversation):
    """OpenAI-compatible Chat Completions (Gemini, Groq, OpenRouter, Ollama, ...)."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.tools = [_chat_tool(tool) for tool in self.tools]
        self._send_tool_choice = True

    def _request(self, tool_choice: str) -> Turn:
        kwargs: dict[str, Any] = {"model": self.model, "messages": self.items, "tools": self.tools}
        if self._send_tool_choice:
            kwargs["tool_choice"] = tool_choice
        try:
            response = self.client.chat.completions.create(**kwargs)
        except Exception as exc:
            # Some compatible servers reject tool_choice values; retry once without it and stop sending it.
            if not self._send_tool_choice or type(exc).__name__ != "BadRequestError" or "tool_choice" not in str(exc):
                raise
            self._send_tool_choice = False
            kwargs.pop("tool_choice")
            response = self.client.chat.completions.create(**kwargs)
        if not response.choices:
            return Turn([], "")
        message = response.choices[0].message
        tool_calls = [call for call in (message.tool_calls or []) if getattr(call, "type", "function") == "function"]
        if tool_calls:
            assistant: dict[str, Any] = {"role": "assistant", "tool_calls": [call.model_dump(exclude_none=True) for call in tool_calls]}
            if message.content:
                assistant["content"] = message.content
            self.items.append(assistant)
        return Turn([ToolCall(call.id, call.function.name, call.function.arguments or "{}") for call in tool_calls], message.content or "")

    def _tool_output_item(self, call_id: str, output: str) -> dict[str, Any]:
        return {"role": "tool", "tool_call_id": call_id, "content": output}

    def _is_tool_output(self, item: dict[str, Any]) -> bool:
        return item.get("role") == "tool"


def _chat_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Convert a Responses-style tool schema into the most widely accepted Chat Completions form."""
    function: dict[str, Any] = {"name": tool["name"], "description": tool["description"]}
    parameters = tool.get("parameters") or {}
    if parameters.get("properties"):
        function["parameters"] = {key: value for key, value in parameters.items() if key != "additionalProperties"}
    return {"type": "function", "function": function}


def make_client(settings: LLMSettings) -> Any:
    from openai import OpenAI

    # The SDK retries timeouts, 429 rate limits, and 5xx errors with backoff (honouring Retry-After).
    return OpenAI(api_key=settings.api_key, base_url=settings.base_url, timeout=180.0, max_retries=5)


def new_conversation(api: str, client: Any, model: str, tools: list[dict[str, Any]], system: str, user: str, min_interval: float = 0.0) -> Conversation:
    adapter = ChatConversation if api == "chat" else ResponsesConversation
    return adapter(client, model, tools, system, user, min_interval)
