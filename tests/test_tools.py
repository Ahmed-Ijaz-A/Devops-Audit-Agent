import unittest
from pathlib import Path

from tools import GitRepository, RepositoryError, normalize_github_url, redact_secrets


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

    def test_preserves_environment_variable_lookup(self):
        self.assertIn("os.getenv", redact_secrets("api_key = os.getenv('API_KEY')"))


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
        repo._git = lambda *args, **kwargs: 'API_TOKEN = "real-secret-value"\nAPI_KEY = os.getenv("API_KEY")\n'  # noqa: E731
        result = repo.read_file("config.py")
        self.assertIn("1: API_TOKEN = \"[REDACTED]", result["content"])
        self.assertIn("os.getenv", result["content"])
        self.assertNotIn("real-secret-value", result["content"])

    def test_search_finds_file_and_line(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "HEAD:config.py\x001\x00DEBUG = True\nHEAD:.vscode/settings.json\x004\x00\"debug\": true\n"  # noqa: E731
        result = repo.search_code("DEBUG")
        self.assertEqual(result["matches"][0]["file"], "config.py")
        self.assertEqual(result["matches"][0]["line"], 1)
        self.assertEqual(result["matches"][1]["file"], ".vscode/settings.json")

    def test_search_never_reveals_dotenv_values(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "HEAD:.env\x002\x00DB_HOST=prod-db.internal\n"  # noqa: E731
        result = repo.search_code("DB_HOST")
        self.assertEqual(result["matches"][0]["file"], ".env")
        self.assertNotIn("prod-db", result["matches"][0]["text"])

    def test_git_log_includes_changed_files(self):
        repo = GitRepository("https://github.com/example/project", Path("."))
        repo._git = lambda *args, **kwargs: "\x1eabc\x1f2024-01-01T00:00:00+00:00\x1fRemove .env\n\n.env\n"  # noqa: E731
        commit = repo.git_log()["commits"][0]
        self.assertEqual(commit["subject"], "Remove .env")
        self.assertEqual(commit["files_changed"], [".env"])


if __name__ == "__main__":
    unittest.main()
