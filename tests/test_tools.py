import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import GitRepository, RepositoryError, normalize_github_url, redact_secrets, summarize_workflow


class UrlTests(unittest.TestCase):
    def test_normalizes_public_repository_url(self):
        self.assertEqual(
            normalize_github_url("https://github.com/example/project.git"),
            "https://github.com/example/project",
        )

    def test_rejects_non_github_and_extra_path(self):
        for value in ("http://github.com/a/b", "https://example.com/a/b", "https://github.com/a/b/tree/main"):
            with self.subTest(value=value), self.assertRaises(RepositoryError):
                normalize_github_url(value)


class RedactionTests(unittest.TestCase):
    def test_masks_literal_credentials(self):
        self.assertNotIn("supersecret", redact_secrets('API_TOKEN="supersecret"'))

    def test_masks_prefixed_keys_and_json_keys(self):
        for text in ('DB_PASSWORD="hunter2"', "NPM_TOKEN: hunter2", 'aws_secret_access_key = "hunter2"', '{"password": "hunter2"}'):
            with self.subTest(text=text):
                self.assertNotIn("hunter2", redact_secrets(text))

    def test_preserves_environment_variable_lookup(self):
        self.assertIn("os.getenv", redact_secrets("api_key = os.getenv('API_KEY')"))

    def test_preserves_placeholders_and_code(self):
        self.assertIn("your-api-key", redact_secrets("OPENAI_API_KEY=your-api-key"))
        self.assertIn("request.headers", redact_secrets("token = request.headers.get('X-Token')"))
        self.assertIn("secrets.NPM_TOKEN", redact_secrets("NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"))


class PathTests(unittest.TestCase):
    def test_rejects_paths_outside_repository(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._files = ["README.md"]
        for path in ("../secret", "/etc/passwd", "folder/../../secret"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                repo.read_file(path)

    def test_requires_a_tracked_file(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._files = ["README.md"]
        with self.assertRaises(ValueError):
            repo.read_file("missing.txt")

    def test_read_file_returns_line_numbers_and_redacts_credentials(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._files = ["config.py"]
        repo._git = lambda *args, **kwargs: 'API_TOKEN = "real-secret-value"\nAPI_KEY = os.getenv("API_KEY")\n'
        result = repo.read_file("config.py")
        self.assertIn("1: API_TOKEN = \"[REDACTED]", result["content"])
        self.assertIn("os.getenv", result["content"])
        self.assertNotIn("real-secret-value", result["content"])

    def test_search_finds_file_and_line(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "HEAD:config.py\x001\x00DEBUG = True\nHEAD:.vscode/settings.json\x004\x00\"debug\": true\n"
        result = repo.search_code("DEBUG")
        self.assertEqual(result["matches"][0]["file"], "config.py")
        self.assertEqual(result["matches"][0]["line"], 1)
        self.assertEqual(result["matches"][1]["file"], ".vscode/settings.json")

    def test_search_never_reveals_dotenv_values(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "HEAD:.env\x002\x00DB_HOST=prod-db.internal\n"
        result = repo.search_code("DB_HOST")
        self.assertEqual(result["matches"][0]["file"], ".env")
        self.assertNotIn("prod-db", result["matches"][0]["text"])

    def test_git_log_includes_changed_files(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "\x1eabc\x1f2024-01-01T00:00:00+00:00\x1fRemove .env\n\n.env\n"
        commit = repo.git_log()["commits"][0]
        self.assertEqual(commit["subject"], "Remove .env")
        self.assertEqual(commit["files_changed"], [".env"])


WORKFLOW = """name: CI
on:
  pull_request_target:
    branches: [main]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@0123456789abcdef0123456789abcdef01234567
        with:
          password: hunter2
      - run: pytest || true
        continue-on-error: true
"""


class WorkflowTests(unittest.TestCase):
    def test_summarizes_triggers_permissions_and_steps(self):
        summary = summarize_workflow(".github/workflows/ci.yml", WORKFLOW)
        self.assertIn("pull_request_target", summary["triggers"])
        self.assertEqual(summary["permissions"], "write-all")
        steps = summary["jobs"][0]["steps"]
        self.assertEqual(steps[0]["pinned"], "tag/branch 'v4'")
        self.assertEqual(steps[1]["pinned"], "full commit SHA")
        self.assertTrue(steps[2]["continue-on-error"])
        lines = {item["line"] for item in summary["notable_lines"]}
        self.assertTrue({3, 5, 12, 16, 17} <= lines)

    def test_never_reveals_literal_workflow_secrets(self):
        self.assertNotIn("hunter2", json.dumps(summarize_workflow(".github/workflows/ci.yml", WORKFLOW)))

    def test_reports_parse_errors(self):
        self.assertIn("parse_error", summarize_workflow(".github/workflows/bad.yml", "on: [push\njobs: {"))

    def test_inspect_workflows_reads_only_workflow_files(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._files = [".github/workflows/ci.yml", ".github/dependabot.yml", "README.md"]
        repo._git = lambda *args, **kwargs: WORKFLOW
        result = repo.inspect_workflows()
        self.assertEqual(result["workflow_count"], 1)
        self.assertEqual(result["workflows"][0]["path"], ".github/workflows/ci.yml")


def make_git_repo(root: Path, files: dict[str, str]) -> GitRepository:
    source = root / "source"
    source.mkdir()
    for name, content in files.items():
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(content, encoding="utf-8")
    for command in (["init", "-q"], ["add", "."], ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-C", str(source), *command], check=True, capture_output=True)
    return GitRepository("https://github.com/example/project", source)


@unittest.skipUnless(shutil.which("git"), "git is required")
class StaticAnalysisTests(unittest.TestCase):
    def test_run_ruff_reports_issues_without_touching_repository(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = make_git_repo(Path(temp), {"app.py": "import os\nprint(undefined_name)\n"})
            result = repo.run_ruff()
            self.assertTrue(result["available"])
            self.assertIn("F821", result["issues_by_code"])
            self.assertIn({"file": "app.py", "line": 2}, [{"file": i["file"], "line": i["line"]} for i in result["sample"]])
            status = subprocess.run(["git", "-C", str(repo.path), "status", "--porcelain"], capture_output=True, text=True, check=True)
            self.assertEqual(status.stdout, "")
            self.assertEqual([p.name for p in Path(temp).iterdir()], ["source"])

    def test_run_pytest_reports_unavailable_docker(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        with patch("tools.shutil.which", return_value=None):
            self.assertFalse(repo.run_pytest()["available"])


if __name__ == "__main__":
    unittest.main()
