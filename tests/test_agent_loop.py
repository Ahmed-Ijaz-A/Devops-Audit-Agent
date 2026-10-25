import json
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_loop import MAX_TOOL_CALLS, RATE_LIMIT_WAITS, AgentError, _json_object, _validate_report, run_agent
from llm import LLMSettings
from tools import GitRepository

SETTINGS = LLMSettings(provider="openai", api="responses", model="test-model", api_key="test", base_url=None)


class Item:
    type = "function_call"

    def __init__(self, name, arguments, call_id):
        self.name = name
        self.arguments = arguments
        self.call_id = call_id

    def model_dump(self, **kwargs):
        return {"type": self.type, "name": self.name, "arguments": self.arguments, "call_id": self.call_id}


class Response:
    def __init__(self, output=(), output_text=""):
        self.output = list(output)
        self.output_text = output_text


def fake_client(responses, requests=None):
    class FakeResponses:
        def create(self, **kwargs):
            if requests is not None:
                requests.append(kwargs)
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    return type("FakeClient", (), {"responses": FakeResponses()})()


def finding(**overrides):
    value = {
        "rule_id": "SEC-001", "category": "security", "severity": "high",
        "file": "config.py", "line": 1, "description": "Credential risk",
        "evidence": "API_KEY is hardcoded", "recommendation": "Use a secret store",
    }
    value.update(overrides)
    return value


class ReportValidationTests(unittest.TestCase):
    def setUp(self):
        self.repo = GitRepository("https://github.com/example/project", Path("."))
        self.repo._files = ["config.py"]
        self.repo._git = lambda *args, **kwargs: "API_KEY = os.getenv('API_KEY')\n"

    def test_accepts_empty_report(self):
        self.assertEqual(_validate_report({"violations": []}, self.repo.url, self.repo)["violations"], [])

    def test_rejects_report_without_violations_array(self):
        with self.assertRaises(AgentError):
            _validate_report({"findings": []}, self.repo.url, self.repo)

    def test_drops_finding_missing_required_text(self):
        notes = []
        report = _validate_report({"violations": [{"rule_id": "SEC-1"}, finding()]}, self.repo.url, self.repo, notes)
        self.assertEqual(len(report["violations"]), 1)
        self.assertTrue(notes)

    def test_nulls_line_beyond_end_of_file(self):
        report = _validate_report({"violations": [finding(line=8)]}, self.repo.url, self.repo)
        self.assertEqual(report["violations"][0]["file"], "config.py")
        self.assertIsNone(report["violations"][0]["line"])

    def test_nulls_untracked_file(self):
        report = _validate_report({"violations": [finding(file="missing.py", line=3)]}, self.repo.url, self.repo)
        self.assertIsNone(report["violations"][0]["file"])
        self.assertIsNone(report["violations"][0]["line"])

    def test_normalizes_category_and_severity(self):
        report = _validate_report({"violations": [finding(category="CI/CD", severity="HIGH")]}, self.repo.url, self.repo)
        self.assertEqual(report["violations"][0]["category"], "ci_cd")
        self.assertEqual(report["violations"][0]["severity"], "high")

    def test_removes_duplicates_and_outputs_all_fields(self):
        report = _validate_report({"violations": [finding(), finding()]}, self.repo.url, self.repo)
        self.assertEqual(len(report["violations"]), 1)
        self.assertEqual(
            set(report["violations"][0]),
            {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"},
        )

    def test_parses_json_and_rejects_non_object(self):
        self.assertEqual(_json_object('{"violations": []}'), {"violations": []})
        self.assertEqual(_json_object('Here it is:\n{"violations": []}'), {"violations": []})
        with self.assertRaises((AgentError, ValueError)):
            _json_object("[]")


class AgentLoopTests(unittest.TestCase):
    def setUp(self):
        self.repo = GitRepository("https://github.com/example/project", Path("."))
        self.repo._files = ["config.py"]
        self.repo._git = lambda *args, **kwargs: "API_KEY = os.getenv('API_KEY')\n"
        self.repo.dispatch = lambda name, args: {"files": ["config.py"]} if name == "list_files" else {"path": args["path"], "content": "1: safe"}

    def test_agent_uses_follow_up_tool_calls_before_final_report(self):
        responses = [
            Response([Item("list_files", "{}", "call-1")]),
            Response([Item("read_file", '{"path":"config.py"}', "call-2")]),
            Response(output_text='{"violations": []}'),
        ]
        with patch("agent_loop._make_client", return_value=fake_client(responses)):
            report, trace = run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertEqual(report["violations"], [])
        self.assertEqual([call["name"] for call in trace["tool_calls"]], ["list_files", "read_file"])

    def test_asks_model_to_repair_invalid_final_json(self):
        requests = []
        responses = [
            Response([Item("list_files", "{}", "call-1")]),
            Response(output_text="I found no problems."),
            Response(output_text='{"violations": []}'),
        ]
        with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
            report, _ = run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertEqual(report["violations"], [])
        self.assertEqual(requests[-1]["tool_choice"], "none")

    def test_forces_final_report_when_tool_budget_is_exhausted(self):
        requests = []
        responses = [Response([Item("list_files", "{}", f"call-{i}")]) for i in range(MAX_TOOL_CALLS)]
        responses.append(Response(output_text='{"violations": []}'))
        with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
            report, trace = run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertEqual(report["violations"], [])
        self.assertEqual(trace["tool_call_count"], MAX_TOOL_CALLS)
        self.assertEqual(requests[-1]["tool_choice"], "none")

    def test_run_pytest_is_offered_only_when_enabled(self):
        for enabled in (False, True):
            requests = []
            responses = [Response([Item("run_pytest", "{}", "call-1")]), Response(output_text='{"violations": []}')]
            self.repo.dispatch = lambda name, args: {"available": True, "exit_code": 0}
            with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
                _, trace = run_agent(self.repo.url, self.repo, settings=SETTINGS, enable_pytest=enabled)
            offered = [tool["name"] for tool in requests[0]["tools"]]
            self.assertEqual("run_pytest" in offered, enabled)
            self.assertEqual("not available" in trace["tool_calls"][0]["result"], not enabled)

    def test_tool_errors_are_returned_to_the_model(self):
        responses = [
            Response([Item("read_file", '{"path":"../etc/passwd"}', "call-1")]),
            Response(output_text='{"violations": []}'),
        ]
        self.repo.dispatch = GitRepository.dispatch.__get__(self.repo)
        with patch("agent_loop._make_client", return_value=fake_client(responses)):
            _, trace = run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertIn("error", trace["tool_calls"][0]["result"])

    def test_explains_quota_rate_limit_separately(self):
        class RateLimitError(Exception):
            code = "insufficient_quota"
            type = "insufficient_quota"

        with patch("agent_loop._make_client", return_value=fake_client([RateLimitError()])):
            with self.assertRaisesRegex(AgentError, "quota/billing limit reached"):
                run_agent(self.repo.url, self.repo, settings=SETTINGS)

        RateLimitError.code = "rate_limit_exceeded"
        RateLimitError.type = "rate_limit_error"
        errors = [RateLimitError() for _ in range(len(RATE_LIMIT_WAITS) + 1)]
        with patch("agent_loop._make_client", return_value=fake_client(errors)), patch("agent_loop.time.sleep") as sleep:
            with self.assertRaisesRegex(AgentError, "request rate limit reached"):
                run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertEqual(sleep.call_count, len(RATE_LIMIT_WAITS))

    def test_switches_to_fallback_model_when_overloaded(self):
        class InternalServerError(Exception):
            body = {"message": "This model is currently experiencing high demand."}

        requests = []
        overloads = [InternalServerError() for _ in range(len(RATE_LIMIT_WAITS) + 1)]
        responses = [*overloads, Response([Item("list_files", "{}", "call-1")]), Response(output_text='{"violations": []}')]
        settings = LLMSettings("gemini", "responses", "busy-model", "k", None, fallback_models=("spare-model",))
        with patch("agent_loop._make_client", return_value=fake_client(responses, requests)), patch("agent_loop.time.sleep"):
            report, trace = run_agent(self.repo.url, self.repo, settings=settings)
        self.assertEqual(report["violations"], [])
        self.assertEqual(requests[-1]["model"], "spare-model")
        self.assertEqual(trace["final_model"], "spare-model")
        self.assertTrue(any("switched model" in note for note in trace["notes"]))

    def test_overload_without_fallback_explains_what_to_do(self):
        class InternalServerError(Exception):
            body = {"message": "This model is currently experiencing high demand."}

        errors = [InternalServerError() for _ in range(len(RATE_LIMIT_WAITS) + 1)]
        with patch("agent_loop._make_client", return_value=fake_client(errors)), patch("agent_loop.time.sleep"):
            with self.assertRaisesRegex(AgentError, "LLM_FALLBACK_MODELS"):
                run_agent(self.repo.url, self.repo, settings=SETTINGS)

    def test_waits_out_a_temporary_rate_limit(self):
        class RateLimitError(Exception):
            code = "rate_limit_exceeded"

        responses = [RateLimitError(), Response([Item("list_files", "{}", "call-1")]), Response(output_text='{"violations": []}')]
        with patch("agent_loop._make_client", return_value=fake_client(responses)), patch("agent_loop.time.sleep"):
            report, _ = run_agent(self.repo.url, self.repo, settings=SETTINGS)
        self.assertEqual(report["violations"], [])

    def test_reports_provider_message_for_bad_requests(self):
        class BadRequestError(Exception):
            body = {"message": "Unsupported parameter: 'tool_choice'.", "code": "unsupported_parameter"}

        with patch("agent_loop._make_client", return_value=fake_client([BadRequestError()])):
            with self.assertRaisesRegex(AgentError, "Unsupported parameter"):
                run_agent(self.repo.url, self.repo, settings=SETTINGS)


def report_text(*findings):
    return json.dumps({"violations": list(findings)})


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.repo = GitRepository("https://github.com/example/project", Path("."))
        self.repo._files = ["config.py"]
        self.repo._git = lambda *args, **kwargs: "API_KEY = 'x'\n"
        self.repo.dispatch = lambda name, args: {"path": "config.py", "content": "1: API_KEY = '[REDACTED]'"}

    def run_with(self, responses, **kwargs):
        requests = []
        with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
            report, trace = run_agent(self.repo.url, self.repo, settings=SETTINGS, **kwargs)
        return report, trace, requests

    def test_tool_results_are_labelled_with_steps(self):
        _, trace, requests = self.run_with([
            Response([Item("read_file", '{"path":"config.py"}', "c1")]),
            Response(output_text=report_text(finding(evidence_refs=[1]))),
        ])
        outputs = [item for item in requests[1]["input"] if item.get("type") == "function_call_output"]
        self.assertTrue(outputs[0]["output"].startswith("[step 1] "))
        self.assertEqual(trace["tool_calls"][0]["step"], 1)

    def test_keeps_cited_findings_and_drops_uncited_ones(self):
        report, trace, _ = self.run_with([
            Response([Item("read_file", '{"path":"config.py"}', "c1")]),
            Response(output_text=report_text(
                finding(evidence_refs=[1]),
                finding(rule_id="CFG-001", category="configuration", description="Other", evidence_refs=[7]),
            )),
        ])
        self.assertEqual([v["rule_id"] for v in report["violations"]], ["SEC-001"])
        self.assertNotIn("evidence_refs", report["violations"][0])
        self.assertEqual(trace["citations"][0]["evidence_refs"], [1])
        self.assertTrue(any("no evidence_refs" in note for note in trace["notes"]))

    def test_asks_for_evidence_refs_when_every_finding_lacks_them(self):
        report, _, requests = self.run_with([
            Response([Item("read_file", '{"path":"config.py"}', "c1")]),
            Response(output_text=report_text(finding())),
            Response(output_text=report_text(finding(evidence_refs=["step 1"]))),
        ])
        self.assertEqual(len(report["violations"]), 1)
        self.assertIn("evidence_refs", requests[-1]["input"][-1]["content"])

    def test_error_results_cannot_be_cited(self):
        self.repo.dispatch = GitRepository.dispatch.__get__(self.repo)
        report, _, _ = self.run_with([
            Response([Item("read_file", '{"path":"missing.py"}', "c1")]),
            Response(output_text=report_text(finding(evidence_refs=[1]))),
            Response(output_text=report_text()),
        ])
        self.assertEqual(report["violations"], [])

    def test_repeated_identical_call_is_not_run_again(self):
        calls = []
        self.repo.dispatch = lambda name, args: calls.append(name) or {"content": "1: x"}
        _, trace, _ = self.run_with([
            Response([Item("read_file", '{"path":"config.py"}', "c1")]),
            Response([Item("read_file", '{"path": "config.py"}', "c2")]),
            Response(output_text=report_text()),
        ])
        self.assertEqual(calls, ["read_file"])
        self.assertIn("duplicate of step 1", trace["tool_calls"][1]["result"])

    def test_time_limit_forces_final_report(self):
        ticks = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0])
        report, trace, requests = self.run_with([
            Response([Item("read_file", '{"path":"config.py"}', "c1")]),
            Response(output_text=report_text()),
        ], time_limit=10, clock=lambda: next(ticks))
        self.assertEqual(requests[-1]["tool_choice"], "none")
        self.assertTrue(any("time limit" in note for note in trace["notes"]))

    def test_normalizes_rule_ids_severity_aliases_and_sorts(self):
        repo = self.repo
        report = _validate_report({"violations": [
            finding(rule_id="hyg 1", category="repository_hygiene", severity="minor", description="Low one"),
            finding(rule_id="garbled", severity="blocker", description="Critical one"),
        ]}, repo.url, repo)
        self.assertEqual([(v["rule_id"], v["severity"]) for v in report["violations"]], [("SEC-099", "critical"), ("HYG-001", "low")])


if __name__ == "__main__":
    unittest.main()
