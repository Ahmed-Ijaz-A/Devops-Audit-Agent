import unittest
from pathlib import Path
from unittest.mock import patch

from agent_loop import MAX_TOOL_CALLS, AgentError, _json_object, _validate_report, run_agent
from tools import GitRepository


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
            report, trace = run_agent(self.repo.url, self.repo, api_key="test", model="test-model")
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
            report, _ = run_agent(self.repo.url, self.repo, api_key="test", model="test-model")
        self.assertEqual(report["violations"], [])
        self.assertEqual(requests[-1]["tool_choice"], "none")

    def test_forces_final_report_when_tool_budget_is_exhausted(self):
        requests = []
        responses = [Response([Item("list_files", "{}", f"call-{i}")]) for i in range(MAX_TOOL_CALLS)]
        responses.append(Response(output_text='{"violations": []}'))
        with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
            report, trace = run_agent(self.repo.url, self.repo, api_key="test", model="test-model")
        self.assertEqual(report["violations"], [])
        self.assertEqual(trace["tool_call_count"], MAX_TOOL_CALLS)
        self.assertEqual(requests[-1]["tool_choice"], "none")

    def test_run_pytest_is_offered_only_when_enabled(self):
        for enabled in (False, True):
            requests = []
            responses = [Response([Item("run_pytest", "{}", "call-1")]), Response(output_text='{"violations": []}')]
            self.repo.dispatch = lambda name, args: {"available": True, "exit_code": 0}
            with patch("agent_loop._make_client", return_value=fake_client(responses, requests)):
                _, trace = run_agent(self.repo.url, self.repo, api_key="test", model="test-model", enable_pytest=enabled)
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
            _, trace = run_agent(self.repo.url, self.repo, api_key="test", model="test-model")
        self.assertIn("error", trace["tool_calls"][0]["result"])

    def test_explains_quota_rate_limit_separately(self):
        class RateLimitError(Exception):
            code = "insufficient_quota"
            type = "insufficient_quota"

        with patch("agent_loop._make_client", return_value=fake_client([RateLimitError()])):
            with self.assertRaisesRegex(AgentError, "quota/billing limit reached"):
                run_agent(self.repo.url, self.repo, api_key="test", model="test-model")

        RateLimitError.code = "rate_limit_exceeded"
        RateLimitError.type = "rate_limit_error"
        with patch("agent_loop._make_client", return_value=fake_client([RateLimitError()])):
            with self.assertRaisesRegex(AgentError, "request rate limit reached"):
                run_agent(self.repo.url, self.repo, api_key="test", model="test-model")

    def test_reports_provider_message_for_bad_requests(self):
        class BadRequestError(Exception):
            body = {"message": "Unsupported parameter: 'tool_choice'.", "code": "unsupported_parameter"}

        with patch("agent_loop._make_client", return_value=fake_client([BadRequestError()])):
            with self.assertRaisesRegex(AgentError, "Unsupported parameter"):
                run_agent(self.repo.url, self.repo, api_key="test", model="test-model")


if __name__ == "__main__":
    unittest.main()
