import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_loop import run_agent
from llm import LLMSettings, resolve_settings
from tools import GitRepository


class SettingsTests(unittest.TestCase):
    def test_defaults_to_openai(self):
        settings = resolve_settings({"OPENAI_API_KEY": "sk-test", "OPENAI_MODEL": "some-model"})
        self.assertEqual((settings.provider, settings.api, settings.model, settings.base_url), ("openai", "responses", "some-model", None))

    def test_gemini_uses_chat_completions_endpoint(self):
        settings = resolve_settings({"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "key", "LLM_MIN_INTERVAL": "6"})
        self.assertEqual(settings.api, "chat")
        self.assertIn("generativelanguage.googleapis.com", settings.base_url)
        self.assertEqual(settings.min_interval, 6.0)

    def test_parses_fallback_models(self):
        settings = resolve_settings({"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "key", "LLM_FALLBACK_MODELS": " a-model, b-model ,"})
        self.assertEqual(settings.fallback_models, ("a-model", "b-model"))

    def test_rejects_placeholder_model_names(self):
        with self.assertRaisesRegex(ValueError, "not a valid model ID"):
            resolve_settings({"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "key", "LLM_FALLBACK_MODELS": "<model-2>"})

    def test_ollama_needs_no_key_but_needs_a_model(self):
        with self.assertRaisesRegex(ValueError, "LLM_MODEL"):
            resolve_settings({"LLM_PROVIDER": "ollama"})
        self.assertEqual(resolve_settings({"LLM_PROVIDER": "ollama", "LLM_MODEL": "qwen3"}).api_key, "ollama")

    def test_rejects_missing_or_placeholder_key_and_unknown_provider(self):
        for env in ({"LLM_PROVIDER": "gemini"}, {"LLM_PROVIDER": "gemini", "GEMINI_API_KEY": "replace-me"}, {"LLM_PROVIDER": "nope"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                resolve_settings(env)


def chat_response(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class ToolCallObject(SimpleNamespace):
    def model_dump(self, **kwargs):
        return {"id": self.id, "type": "function", "function": {"name": self.function.name, "arguments": self.function.arguments}}


def tool_call(call_id, name, arguments):
    return ToolCallObject(id=call_id, type="function", function=SimpleNamespace(name=name, arguments=arguments))


class ChatCompletionsLoopTests(unittest.TestCase):
    def test_runs_tool_loop_over_chat_completions(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._files = ["README.md"]
        repo._git = lambda *args, **kwargs: "# Project\n"
        repo.dispatch = lambda name, args: {"files": ["README.md"]}
        responses = [
            chat_response(SimpleNamespace(content=None, tool_calls=[tool_call("c1", "list_files", "{}")])),
            chat_response(SimpleNamespace(content='{"violations": []}', tool_calls=None)),
        ]
        requests = []

        def create(**kwargs):
            requests.append(json.loads(json.dumps(kwargs)))
            return responses.pop(0)

        client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
        settings = LLMSettings(provider="gemini", api="chat", model="m", api_key="k", base_url="https://example.invalid/")
        with patch("agent_loop._make_client", return_value=client):
            report, trace = run_agent(repo.url, repo, settings=settings)

        self.assertEqual(report["violations"], [])
        self.assertEqual(trace["tool_calls"][0]["name"], "list_files")
        first_tools = {tool["function"]["name"]: tool["function"] for tool in requests[0]["tools"]}
        self.assertNotIn("parameters", first_tools["list_files"])
        self.assertNotIn("additionalProperties", first_tools["read_file"]["parameters"])
        self.assertEqual(requests[0]["tool_choice"], "required")
        roles = [message["role"] for message in requests[1]["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant", "tool"])
        self.assertEqual(requests[1]["messages"][3]["tool_call_id"], "c1")


if __name__ == "__main__":
    unittest.main()


class CompactionTests(unittest.TestCase):
    def test_stubs_oldest_outputs_but_keeps_latest_batch(self):
        from llm import OMITTED_SUFFIX, ChatConversation

        conversation = ChatConversation(None, "m", [], "system", "user")
        for step in range(1, 4):
            conversation.items.append({"role": "assistant", "tool_calls": []})
            conversation.add_tool_output(f"c{step}", f"[step {step}] " + "x" * 1000, f"read_file {step}")
        stubbed = conversation.compact(1500)
        contents = [item["content"] for item in conversation.items if item.get("role") == "tool"]
        self.assertEqual(stubbed, 2)
        self.assertTrue(contents[0].startswith("[step 1] read_file 1") and contents[0].endswith(OMITTED_SUFFIX))
        self.assertTrue(contents[2].startswith("[step 3] xxx"))

    def test_does_nothing_under_the_limit(self):
        from llm import ResponsesConversation

        conversation = ResponsesConversation(None, "m", [], "system", "user")
        conversation.add_tool_output("c1", "[step 1] small", "list_files")
        self.assertEqual(conversation.compact(10_000), 0)
