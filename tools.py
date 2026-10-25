"""Read-only GitHub repository access and inspection tools."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

MAX_FILE_BYTES = 80_000
MAX_SEARCH_MATCHES = 100
MAX_LOG_COMMITS = 40
MAX_LOG_FILES_PER_COMMIT = 25
GIT_TIMEOUT_SECONDS = 90
DOTENV_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.staging", ".env.test"}

TOOL_SCHEMAS = [
    {"type": "function", "name": "list_files", "description": "List tracked repository paths and identify common project/configuration files.", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "read_file", "description": "Read one tracked text file, with line numbers. Secrets are redacted and large files are capped.", "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "Repository-relative path from list_files"}}, "required": ["path"], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "search_code", "description": "Search all tracked text files (including dotfiles and .github) for a literal case-insensitive pattern; results include file and line.", "parameters": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Literal search text, maximum 200 characters"}}, "required": ["pattern"], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "git_log", "description": "Inspect the 20 most recent commits: hash, date, subject, and changed file paths (useful for files committed then removed).", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
]

SECRET_PATTERNS = [
    re.compile(r"(?i)(\b(?:api[_-]?(?:key|token)|access[_-]?key|auth[_-]?token|token|secret|password|passwd|client[_-]?secret|private[_-]?key|database[_-]?url|connection[_-]?string)\b\s*[:=]\s*)(['\"]?)([^\s'\",;]+)"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?im)(\b(?:proxy-)?authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
]


class RepositoryError(RuntimeError):
    """Raised for invalid repository URLs or Git access failures."""


def _is_dotenv(path: str) -> bool:
    return PurePosixPath(path).name.lower() in DOTENV_NAMES


def redact_secrets(value: str) -> str:
    """Mask likely credential values before model, trace, or report use."""
    text = value
    assignment_pattern = SECRET_PATTERNS[0]
    environment_refs = ("os.environ", "os.getenv", "getenv", "process.env", "env", "none", "null")
    def mask_assignment(match: re.Match[str]) -> str:
        candidate = match.group(3).strip().strip("'\"").casefold()
        if candidate.startswith(environment_refs) or candidate.startswith("${"):
            return match.group(0)
        return match.group(1) + match.group(2) + "[REDACTED]"
    text = assignment_pattern.sub(mask_assignment, text)
    for pattern in SECRET_PATTERNS[1:]:
        if "PRIVATE KEY" in pattern.pattern:
            text = pattern.sub(lambda match: "[REDACTED PRIVATE KEY]" + "\n" * match.group(0).count("\n"), text)
        elif "authorization" in pattern.pattern:
            text = pattern.sub(lambda match: match.group(1) + "[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text


def normalize_github_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.port or parsed.username or parsed.password:
        raise RepositoryError("Repository URL must be an HTTPS URL on github.com.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2 or any(part in {".", ".."} for part in parts):
        raise RepositoryError("Use a repository URL in the form https://github.com/owner/name.")
    owner, name = parts
    name = name.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise RepositoryError("Repository owner or name contains unsupported characters.")
    if parsed.query or parsed.fragment:
        raise RepositoryError("Repository URL must not include a query string or fragment.")
    return f"https://github.com/{owner}/{name}"


class GitRepository:
    """A no-checkout clone inspected only through read-only Git plumbing."""

    def __init__(self, url: str, path: Path):
        self.url = url
        self.path = path
        self._files: list[str] | None = None

    @classmethod
    def clone(cls, url: str, path: Path) -> "GitRepository":
        path.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_LFS_SKIP_SMUDGE"] = "1"
        command = ["git", "-c", "credential.helper=", "-c", "protocol.ext.allow=never", "clone", "--quiet", "--depth", "100", "--no-checkout", url, str(path)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=GIT_TIMEOUT_SECONDS, env=env, check=False)
        except FileNotFoundError as exc:
            raise RepositoryError("Git is required but was not found on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise RepositoryError("Repository download timed out.") from exc
        if result.returncode:
            message = redact_secrets(result.stderr.strip())[-1200:]
            raise RepositoryError(f"Could not clone public repository: {message or 'Git returned an error.'}")
        return cls(url, path)

    def _git(self, *args: str, timeout: int = GIT_TIMEOUT_SECONDS, ok_codes: tuple[int, ...] = (0,)) -> str:
        command = ["git", "-C", str(self.path), *args]
        env = os.environ.copy()
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_LFS_SKIP_SMUDGE"] = "1"
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout, env=env, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RepositoryError(f"Git operation timed out: {args[0]}") from exc
        if result.returncode not in ok_codes:
            message = redact_secrets(result.stderr.decode("utf-8", "replace").strip())[-1000:]
            raise RepositoryError(message or f"Git operation failed: {args[0]}")
        return result.stdout.decode("utf-8", "replace")

    def list_files(self) -> dict[str, Any]:
        output = self._git("ls-tree", "-r", "--name-only", "-z", "HEAD")
        self._files = [item.decode("utf-8", "replace") for item in output.encode("utf-8", "surrogateescape").split(b"\0") if item]
        names = self._files[:3000]
        return {"count": len(self._files), "truncated": len(self._files) > len(names), "files": names}

    def _tracked_path(self, raw_path: str) -> str:
        path = raw_path.replace("\\", "/")
        parsed = PurePosixPath(path)
        if not path or parsed.is_absolute() or any(part in {"..", "."} for part in parsed.parts):
            raise ValueError("path must be a safe repository-relative path")
        if not self.has_file(path):
            raise ValueError("path is not a tracked repository file")
        return path

    def has_file(self, path: str) -> bool:
        try:
            normalized = self._tracked_path_basic(path)
        except ValueError:
            return False
        if self._files is None:
            self.list_files()
        return normalized in (self._files or [])

    @staticmethod
    def _tracked_path_basic(path: str) -> str:
        value = path.replace("\\", "/")
        parsed = PurePosixPath(value)
        if not value or parsed.is_absolute() or any(part in {"..", "."} for part in parsed.parts):
            raise ValueError("invalid repository path")
        return value

    def read_file(self, path: str) -> dict[str, Any]:
        safe_path = self._tracked_path(path)
        raw = self._git("show", f"HEAD:{safe_path}").encode("utf-8", "surrogateescape")
        if b"\0" in raw[:8192]:
            raise ValueError("binary files are not supported")
        truncated = len(raw) > MAX_FILE_BYTES
        content = raw[:MAX_FILE_BYTES].decode("utf-8", "replace")
        # Never reveal dotenv file values to the model.
        if _is_dotenv(safe_path):
            lines = [f"{i}: {line.split('=', 1)[0]}=[REDACTED]" if "=" in line else f"{i}: [REDACTED]" for i, line in enumerate(content.splitlines(), 1)]
        else:
            content = redact_secrets(content)
            lines = [f"{i}: {line}" for i, line in enumerate(content.splitlines(), 1)]
        return {"path": safe_path, "truncated": truncated, "content": "\n".join(lines)}

    def line_count(self, path: str) -> int:
        safe_path = self._tracked_path(path)
        raw = self._git("show", f"HEAD:{safe_path}").encode("utf-8", "surrogateescape")
        return raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0)

    def search_code(self, pattern: str) -> dict[str, Any]:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 200:
            raise ValueError("pattern must contain 1 to 200 characters")
        # git grep searches every tracked text file (dotfiles included) in one process; exit code 1 means no match.
        output = self._git("grep", "-z", "-n", "-I", "-i", "-F", "-e", pattern, "HEAD", "--", timeout=60, ok_codes=(0, 1))
        matches: list[dict[str, Any]] = []
        truncated = False
        for record in output.split("\n"):
            fields = record.split("\0", 2)
            if len(fields) != 3 or not fields[1].isdigit():
                continue
            path = fields[0].removeprefix("HEAD:")
            text = "[REDACTED]" if _is_dotenv(path) else redact_secrets(fields[2])
            matches.append({"file": path, "line": int(fields[1]), "text": text.strip()[:400]})
            if len(matches) >= MAX_SEARCH_MATCHES:
                truncated = True
                break
        return {"matches": matches, "match_count": len(matches), "truncated": truncated}

    def git_log(self, limit: int = 20) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LOG_COMMITS:
            raise ValueError(f"limit must be between 1 and {MAX_LOG_COMMITS}")
        output = self._git("log", f"-{limit}", "--date=iso-strict", "--format=%x1e%H%x1f%ad%x1f%s", "--name-only", timeout=30)
        commits = []
        for block in output.split("\x1e"):
            header, _, names = block.partition("\n")
            fields = header.split("\x1f", 2)
            if len(fields) == 3:
                changed = [name for name in names.splitlines() if name.strip()]
                commits.append({
                    "hash": fields[0], "date": fields[1], "subject": redact_secrets(fields[2]),
                    "files_changed": changed[:MAX_LOG_FILES_PER_COMMIT],
                    "files_changed_total": len(changed),
                })
        return {"commits": commits}

    def dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "list_files":
            if args:
                raise ValueError("list_files takes no arguments")
            return self.list_files()
        if name == "read_file":
            return self.read_file(args["path"])
        if name == "search_code":
            return self.search_code(args["pattern"])
        if name == "git_log":
            if args:
                raise ValueError("git_log takes no arguments")
            return self.git_log()
        raise ValueError(f"Unknown tool: {name}")
