"""Read-only GitHub repository access and inspection tools."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import uuid
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import yaml

MAX_FILE_BYTES = 80_000
MAX_SEARCH_MATCHES = 100
MAX_FLAGGED_FILES = 50
MAX_HISTORY_COMMITS = 100
MAX_HISTORY_MATCHES = 40
MAX_LOG_COMMITS = 40
MAX_LOG_FILES_PER_COMMIT = 25
GIT_TIMEOUT_SECONDS = 90
DOTENV_NAMES = {".env", ".env.local", ".env.development", ".env.production", ".env.staging", ".env.test"}
MAX_EXPORT_BYTES = 200_000_000
MAX_WORKFLOWS = 20
MAX_NOTABLE_LINES = 40
RUFF_TIMEOUT_SECONDS = 120
RUFF_CONFIG_NAMES = {"pyproject.toml", "ruff.toml", ".ruff.toml"}
PYTEST_IMAGE = "python:3.12-slim"
PYTEST_INSTALL_TIMEOUT_SECONDS = 600
PYTEST_RUN_TIMEOUT_SECONDS = 300
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# Workflow lines worth showing the model with exact line numbers; the model decides whether each is a defect.
NOTABLE_WORKFLOW_LINE = re.compile(
    r"pull_request_target|workflow_run|permissions|write-all|continue-on-error|\|\|\s*true|"
    r"\bif:\s*(?:false|\$\{\{\s*false)|\$\{\{\s*github\.(?:event|head_ref)|secrets\.|"
    r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh|--no-verify|echo\b.*\$\{\{|"
    r"set\s+-x|ACTIONS_ALLOW_UNSECURE|ref:\s*\$\{\{|auto-?merge|--admin",
    re.IGNORECASE,
)

TOOL_SCHEMAS = [
    {"type": "function", "name": "list_files", "description": "List tracked repository paths. 'flagged' lists tracked paths that are commonly not meant to be committed (caches, env files, editor settings, keys), with the reason; verify before reporting.", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "read_file", "description": "Read one tracked text file, with line numbers. Secrets are redacted and large files are capped.", "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "Repository-relative path from list_files"}}, "required": ["path"], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "search_code", "description": "Case-insensitive search of all tracked text files (including dotfiles and .github); results include file and line. Set regex=true to use an extended regular expression such as (password|secret|token)\\s*[:=].", "parameters": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Search text or regular expression, maximum 200 characters"}, "regex": {"type": "boolean", "description": "true to treat pattern as an extended regular expression, false for literal text"}}, "required": ["pattern", "regex"], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "search_history", "description": "Search the diffs of recent commits for a case-insensitive extended regular expression. Shows lines that commits added or removed, so it finds credentials deleted from the code that remain in git history.", "parameters": {"type": "object", "properties": {"pattern": {"type": "string", "description": "Extended regular expression, maximum 200 characters, e.g. (password|secret|token|api_?key)\\s*[:=]"}}, "required": ["pattern"], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "git_log", "description": "Inspect the 20 most recent commits: hash, date, subject, and changed file paths (useful for files committed then removed).", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "inspect_workflows", "description": "Parse every GitHub Actions workflow: triggers, permissions, jobs, steps, action pinning, referenced secret names, and notable lines with line numbers.", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
    {"type": "function", "name": "run_ruff", "description": "Run the ruff linter statically over the repository's Python files (no code is executed). Uses the repository's ruff configuration when present, otherwise ruff defaults.", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True},
]

RUN_PYTEST_SCHEMA = {"type": "function", "name": "run_pytest", "description": "Install the repository's dependencies and run its test suite with pytest inside an isolated Docker container (tests run with networking disabled). Slow; call at most once, after confirming tests exist.", "parameters": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}, "strict": True}

SECRET_PATTERNS = [
    # Key may carry a prefix/suffix (DB_PASSWORD, NPM_TOKEN, aws_secret_access_key) and a closing quote (JSON keys).
    re.compile(r"(?i)(\b[\w.-]*?(?:api[_-]?(?:key|token)|access[_-]?key|auth[_-]?token|token|secret|password|passwd|pwd|client[_-]?secret|private[_-]?key|database[_-]?url|connection[_-]?string)[\w.-]*['\"]?\s*[:=]\s*)(['\"]?)([^\s'\",;]+)"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?im)(\b(?:proxy-)?authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:[^\s/@]+@[^\s]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
]


# Obvious placeholder values are shown so the model can tell an example file from a leaked credential.
PLACEHOLDER = re.compile(
    r"^(?:<[^>]*>|x{3,}|\*{3,}|\.{3}|change[-_]?me|replace[-_]?me|your[-_].*|my[-_].*|example.*|dummy.*|"
    r"placeholder.*|todo|tbd|secret|password|token|test|fake.*|sample.*|insert[-_].*|put[-_].*|enter[-_].*)$"
)


class RepositoryError(RuntimeError):
    """Raised for invalid repository URLs or Git access failures."""


def _is_dotenv(path: str) -> bool:
    return PurePosixPath(path).name.lower() in DOTENV_NAMES


ENV_TEMPLATE_SUFFIXES = {"example", "sample", "template", "dist", "default", "defaults"}
TOOL_CACHE_DIRS = {".pytest_cache", ".ruff_cache", ".mypy_cache", ".tox", ".nox", ".hypothesis", ".ipynb_checkpoints"}


def tracked_file_concern(path: str) -> str | None:
    """A reason this tracked path is often committed by mistake, or None. A hint for the model, not a verdict."""
    parts = PurePosixPath(path).parts
    name = parts[-1]
    lower = name.lower()
    suffix = PurePosixPath(lower).suffix
    directories = set(parts[:-1])
    if "__pycache__" in directories or suffix in {".pyc", ".pyo"}:
        return "Python bytecode cache"
    if "node_modules" in directories:
        return "installed dependencies"
    if directories & {".venv", "venv"} or lower == "pyvenv.cfg":
        return "virtual environment"
    if lower in {".ds_store", "thumbs.db", "desktop.ini"}:
        return "operating-system metadata file"
    if lower == ".env" or (lower.startswith(".env.") and lower.rsplit(".", 1)[-1] not in ENV_TEMPLATE_SUFFIXES):
        return "environment file (may contain secrets)"
    if suffix in {".log", ".tmp", ".swp", ".swo", ".bak", ".orig"} or lower.endswith("~"):
        return "temporary, backup, or log file"
    if directories & TOOL_CACHE_DIRS or lower in {".coverage", "coverage.xml"}:
        return "tool cache or coverage output"
    if directories & {".idea", ".vscode"}:
        return "local editor settings (sometimes shared on purpose)"
    if any(p.endswith(".egg-info") for p in parts) or (parts[0] in {"dist", "build"} and len(parts) > 1):
        return "build output"
    if suffix in {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} or lower in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}:
        return "private key or certificate (could be a test fixture)"
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return "local database file"
    return None


def redact_secrets(value: str) -> str:
    """Mask likely credential values before model, trace, or report use."""
    text = value
    assignment_pattern = SECRET_PATTERNS[0]
    environment_refs = ("os.environ", "os.getenv", "getenv", "process.env", "env", "none", "null", "true", "false")
    def mask_assignment(match: re.Match[str]) -> str:
        candidate = match.group(3).strip().strip("'\"").casefold()
        # GitHub Actions permission values (id-token: write, contents: read) are settings, not secrets.
        if candidate in {"read", "write", "none", "read-all", "write-all"}:
            return match.group(0)
        if candidate.startswith(environment_refs) or candidate.startswith(("${", "$", "%(", "{{")) or PLACEHOLDER.match(candidate):
            return match.group(0)
        # An unquoted value that is code (a call, attribute, or subscript) is not a literal credential.
        if not match.group(2) and re.match(r"[a-z_][\w]*(?:[.(\[])", candidate):
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
    def clone(cls, url: str, path: Path) -> GitRepository:
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
        return self._git_bytes(*args, timeout=timeout, ok_codes=ok_codes).decode("utf-8", "replace")

    def _git_bytes(self, *args: str, timeout: int = GIT_TIMEOUT_SECONDS, ok_codes: tuple[int, ...] = (0,)) -> bytes:
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
        return result.stdout

    def list_files(self) -> dict[str, Any]:
        output = self._git("ls-tree", "-r", "--name-only", "-z", "HEAD")
        self._files = [item.decode("utf-8", "replace") for item in output.encode("utf-8", "surrogateescape").split(b"\0") if item]
        names = self._files[:3000]
        flagged = [{"path": path, "reason": reason} for path in self._files if (reason := tracked_file_concern(path))]
        return {
            "count": len(self._files), "truncated": len(self._files) > len(names), "files": names,
            "flagged": flagged[:MAX_FLAGGED_FILES], "flagged_total": len(flagged),
        }

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

    def search_code(self, pattern: str, regex: bool = False) -> dict[str, Any]:
        if not isinstance(pattern, str) or not pattern or len(pattern) > 200:
            raise ValueError("pattern must contain 1 to 200 characters")
        # git grep searches every tracked text file (dotfiles included) in one process; exit code 1 means no match.
        mode = "-E" if regex else "-F"
        try:
            output = self._git("grep", "-z", "-n", "-I", "-i", mode, "-e", pattern, "HEAD", "--", timeout=60, ok_codes=(0, 1))
        except RepositoryError as exc:
            raise ValueError(f"search failed (check the regular expression): {exc}") from exc
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

    def search_history(self, pattern: str) -> dict[str, Any]:
        """Lines matching a regex that commits added (+) or removed (-), including values later deleted from the code."""
        if not isinstance(pattern, str) or not pattern or len(pattern) > 200:
            raise ValueError("pattern must contain 1 to 200 characters")
        try:
            matcher = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"invalid regular expression: {exc}") from exc
        try:
            output = self._git(
                "log", f"-{MAX_HISTORY_COMMITS}", "-E", "-i", f"-G{pattern}", "-p", "-U0", "--no-color", "--no-ext-diff",
                "--no-textconv", "--date=short", "--format=\x1e%h %ad", timeout=60,
            )
        except RepositoryError as exc:
            raise ValueError(f"history search failed (check the regular expression): {exc}") from exc
        matches: list[dict[str, Any]] = []
        commit, path = "", ""
        for line in output.split("\n"):
            if line.startswith("\x1e"):
                commit = line[1:].strip()
            elif line.startswith("+++ "):
                path = line[4:].removeprefix("b/")
            elif line.startswith("--- ") or line.startswith("@@"):
                continue
            elif line[:1] in "+-" and line and matcher.search(line[1:]):
                text = "[REDACTED]" if _is_dotenv(path) else redact_secrets(line[1:].strip())
                matches.append({"commit": commit, "file": path, "change": "added" if line[0] == "+" else "removed", "text": text[:300]})
                if len(matches) >= MAX_HISTORY_MATCHES:
                    break
        present = set(self._files if self._files is not None else self.list_files()["files"])
        for match in matches:
            match["file_still_tracked"] = match["file"] in present
        return {
            "commits_searched": f"up to {MAX_HISTORY_COMMITS} most recent (clone history is limited)",
            "matches": matches, "truncated": len(matches) >= MAX_HISTORY_MATCHES,
            "note": "'removed' lines no longer exist at HEAD but remain readable in git history.",
        }

    def inspect_workflows(self) -> dict[str, Any]:
        files = self._files if self._files is not None else self.list_files()["files"]
        paths = [
            path for path in files
            if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))
        ]
        workflows = []
        for path in paths[:MAX_WORKFLOWS]:
            text = self._git("show", f"HEAD:{path}")
            workflows.append(summarize_workflow(path, text))
        return {"workflow_count": len(paths), "truncated": len(paths) > MAX_WORKFLOWS, "workflows": workflows}

    def export_tree(self, dest: Path, include: Any = None) -> int:
        """Write HEAD's regular files into dest (never the target repository). Returns files written."""
        archive = self._git_bytes("archive", "--format=tar", "HEAD", timeout=GIT_TIMEOUT_SECONDS)
        dest.mkdir(parents=True, exist_ok=True)
        written = total = 0
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            for member in tar:
                # Regular files only: symlinks and devices could point outside the export directory.
                if not member.isfile():
                    continue
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or (include and not include(member.name)):
                    continue
                total += member.size
                if total > MAX_EXPORT_BYTES:
                    raise RepositoryError("Repository is too large to export for analysis.")
                target = dest.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is not None:
                    target.write_bytes(source.read())
                    written += 1
        return written

    def _scratch_dir(self, label: str) -> Path:
        # A sibling of the private clone, inside the temporary directory agent.py removes afterwards.
        return self.path.parent / f"{label}-{uuid.uuid4().hex[:8]}"

    def run_ruff(self) -> dict[str, Any]:
        workdir = self._scratch_dir("ruff")
        try:
            count = self.export_tree(
                workdir,
                include=lambda name: name.endswith((".py", ".pyi")) or PurePosixPath(name).name in RUFF_CONFIG_NAMES,
            )
            if not any(workdir.rglob("*.py")):
                return {"available": True, "python_files": 0, "note": "No Python files to lint."}
            has_config = any(
                (workdir / name).is_file() and (name != "pyproject.toml" or "[tool.ruff" in (workdir / name).read_text("utf-8", "replace"))
                for name in RUFF_CONFIG_NAMES
            )
            # Without a repository config, --isolated keeps any ruff config on the auditing machine out of the result.
            result = _run_ruff_process(workdir, isolated=not has_config)
            if result is None:
                return {"available": False, "reason": "ruff is not installed in the agent environment."}
            config_note = "repository ruff configuration" if has_config else "ruff default rules (no repository ruff configuration)"
            if result.returncode not in (0, 1) and has_config:
                # The repository's config may target another ruff version; fall back so the check is still available.
                result = _run_ruff_process(workdir, isolated=True) or result
                config_note = "ruff default rules (repository configuration could not be loaded)"
            if result.returncode not in (0, 1):
                return {"available": False, "reason": "ruff failed: " + redact_secrets(result.stderr.strip())[-400:]}
            issues = json.loads(result.stdout or "[]")
        except subprocess.TimeoutExpired:
            return {"available": False, "reason": f"ruff timed out after {RUFF_TIMEOUT_SECONDS}s."}
        except (OSError, ValueError, RepositoryError) as exc:
            return {"available": False, "reason": f"ruff could not run: {exc}"}
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        by_code = Counter(issue.get("code") or "syntax-error" for issue in issues)
        sample = [
            {
                "file": Path(issue["filename"]).resolve().relative_to(workdir.resolve()).as_posix()
                if Path(issue["filename"]).is_absolute() else issue["filename"],
                "line": (issue.get("location") or {}).get("row"),
                "code": issue.get("code") or "syntax-error",
                "message": redact_secrets(issue.get("message", ""))[:200],
            }
            for issue in issues[:30]
        ]
        return {
            "available": True, "python_files": count, "config": config_note,
            "issue_count": len(issues), "issues_by_code": dict(by_code.most_common(20)), "sample": sample,
        }

    def run_pytest(self) -> dict[str, Any]:
        """Run tests in Docker: install deps with network, then test with --network none, no capabilities."""
        docker = shutil.which("docker")
        if not docker:
            return {"available": False, "reason": "Docker is not installed; tests were not executed."}
        ping = _docker([docker, "info", "--format", "{{.ServerVersion}}"], timeout=30)
        if ping is None or ping.returncode:
            return {"available": False, "reason": "Docker daemon is not running; tests were not executed."}

        workdir = self._scratch_dir("pytest")
        tag = uuid.uuid4().hex[:12]
        container, image = f"devops-audit-{tag}", f"devops-audit-tests:{tag}"
        limits = ["--memory", "2g", "--cpus", "2", "--pids-limit", "512", "--security-opt", "no-new-privileges"]
        install_script = (
            "set -u; cd /work; "
            "python -m pip install -q --disable-pip-version-check pytest >/dev/null 2>&1; "
            "status=0; "
            "for f in requirements.txt requirements-dev.txt requirements-test.txt requirements/dev.txt requirements/test.txt; do "
            "  if [ -f \"$f\" ]; then python -m pip install -q --disable-pip-version-check -r \"$f\" || status=1; fi; done; "
            "if [ -f pyproject.toml ] || [ -f setup.py ] || [ -f setup.cfg ]; then "
            "  python -m pip install -q --disable-pip-version-check '.[test]' 2>/dev/null "
            "  || python -m pip install -q --disable-pip-version-check '.[dev]' 2>/dev/null "
            "  || python -m pip install -q --disable-pip-version-check . || status=1; fi; "
            "exit $status"
        )
        try:
            self.export_tree(workdir)
            created = _docker([docker, "create", "--name", container, *limits, "-w", "/work", PYTEST_IMAGE, "sh", "-c", install_script], timeout=PYTEST_INSTALL_TIMEOUT_SECONDS)
            if created is None or created.returncode:
                return {"available": False, "reason": "Could not create the test container: " + _tail(created)}
            copied = _docker([docker, "cp", f"{workdir}{os.sep}.", f"{container}:/work"], timeout=120)
            if copied is None or copied.returncode:
                return {"available": False, "reason": "Could not copy the repository into the container: " + _tail(copied)}
            installed = _docker([docker, "start", "-a", container], timeout=PYTEST_INSTALL_TIMEOUT_SECONDS)
            if installed is None:
                return {"available": False, "reason": "Dependency installation timed out; tests were not executed."}
            committed = _docker([docker, "commit", container, image], timeout=120)
            if committed is None or committed.returncode:
                return {"available": False, "reason": "Could not snapshot the test container: " + _tail(committed)}
            ran = _docker(
                [docker, "run", "--rm", "--network", "none", "--cap-drop", "ALL", *limits, "-w", "/work", image,
                 "python", "-m", "pytest", "-q", "-rf", "--no-header", "-p", "no:cacheprovider"],
                timeout=PYTEST_RUN_TIMEOUT_SECONDS,
            )
            if ran is None:
                return {"available": True, "dependencies_installed": installed.returncode == 0, "timed_out": True,
                        "note": f"pytest did not finish within {PYTEST_RUN_TIMEOUT_SECONDS}s."}
        except (OSError, RepositoryError) as exc:
            return {"available": False, "reason": f"Tests could not be run: {exc}"}
        finally:
            _docker([docker, "rm", "-f", container], timeout=60)
            _docker([docker, "rmi", "-f", image], timeout=60)
            shutil.rmtree(workdir, ignore_errors=True)

        output = redact_secrets(ran.stdout + ran.stderr)
        summary = next((line.strip("= ").strip() for line in reversed(output.splitlines()) if line.strip()), "")
        return {
            "available": True,
            "dependencies_installed": installed.returncode == 0,
            "exit_code": ran.returncode,
            "meaning": PYTEST_EXIT_CODES.get(ran.returncode, "unexpected exit code"),
            "summary": summary[:300],
            "output_tail": output[-4000:],
            "note": "If dependencies_installed is false, failures may come from the sandbox, not the repository.",
        }

    def dispatch(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "list_files":
            if args:
                raise ValueError("list_files takes no arguments")
            return self.list_files()
        if name == "read_file":
            return self.read_file(args["path"])
        if name == "search_code":
            return self.search_code(args["pattern"], bool(args.get("regex", False)))
        if name == "search_history":
            return self.search_history(args["pattern"])
        no_argument_tools = {
            "git_log": self.git_log,
            "inspect_workflows": self.inspect_workflows,
            "run_ruff": self.run_ruff,
            "run_pytest": self.run_pytest,
        }
        if name in no_argument_tools:
            if args:
                raise ValueError(f"{name} takes no arguments")
            return no_argument_tools[name]()
        raise ValueError(f"Unknown tool: {name}")


PYTEST_EXIT_CODES = {
    0: "all tests passed", 1: "some tests failed", 2: "test run interrupted or collection errors",
    3: "internal pytest error", 4: "pytest usage error", 5: "no tests were collected",
}


def _run_ruff_process(workdir: Path, *, isolated: bool) -> subprocess.CompletedProcess[str] | None:
    command = [sys.executable, "-m", "ruff", "check", "--output-format", "json", "--no-cache", "--exit-zero", "."]
    if isolated:
        command.insert(4, "--isolated")
    try:
        result = subprocess.run(command, cwd=workdir, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=RUFF_TIMEOUT_SECONDS, check=False)
    except FileNotFoundError:
        return None
    if "No module named ruff" in result.stderr:
        return None
    return result


def _docker(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _tail(result: subprocess.CompletedProcess[str] | None) -> str:
    if result is None:
        return "timed out"
    return redact_secrets((result.stderr or result.stdout).strip())[-300:] or "no output"


def summarize_workflow(path: str, text: str) -> dict[str, Any]:
    """Structured facts about one GitHub Actions workflow, for the model to interpret."""
    lines = text.splitlines()
    notable = [
        {"line": number, "text": redact_secrets(line.strip())[:200]}
        for number, line in enumerate(lines, 1)
        if NOTABLE_WORKFLOW_LINE.search(line) and not line.lstrip().startswith("#")
    ]
    summary: dict[str, Any] = {
        "path": path,
        "line_count": len(lines),
        "secrets_referenced": sorted(set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))),
        "notable_lines": notable[:MAX_NOTABLE_LINES],
    }
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        summary["parse_error"] = str(exc).splitlines()[0][:200]
        return summary
    if not isinstance(document, dict):
        summary["parse_error"] = "workflow is not a YAML mapping"
        return summary
    # PyYAML follows YAML 1.1, where the bare key `on` parses as boolean True.
    triggers = document.get("on", document.get(True))
    summary["name"] = document.get("name")
    summary["triggers"] = _describe_triggers(triggers)
    summary["permissions"] = document.get("permissions", "not set (repository default applies)")
    summary["concurrency"] = document.get("concurrency")
    jobs = document.get("jobs") if isinstance(document.get("jobs"), dict) else {}
    summary["jobs"] = [_describe_job(job_id, job) for job_id, job in list(jobs.items())[:15] if isinstance(job, dict)]
    return summary


def _describe_triggers(triggers: Any) -> Any:
    if isinstance(triggers, str):
        return {triggers: None}
    if isinstance(triggers, list):
        return {str(event): None for event in triggers}
    if not isinstance(triggers, dict):
        return triggers
    described: dict[str, Any] = {}
    for event, config in triggers.items():
        if isinstance(config, dict):
            keep = ("branches", "branches-ignore", "paths", "paths-ignore", "tags", "types", "workflows", "cron")
            described[str(event)] = {key: config[key] for key in keep if key in config} or "configured"
        elif isinstance(config, list) and event == "schedule":
            described[str(event)] = [item.get("cron") for item in config if isinstance(item, dict)]
        else:
            described[str(event)] = config
    return described


def _describe_job(job_id: str, job: dict[str, Any]) -> dict[str, Any]:
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    described_steps = []
    for step in steps[:40]:
        if not isinstance(step, dict):
            continue
        item: dict[str, Any] = {"name": step.get("name")}
        uses = step.get("uses")
        if isinstance(uses, str):
            item["uses"] = uses
            if uses.startswith(("./", "docker://")):
                item["pinned"] = "local or docker reference"
            else:
                ref = uses.partition("@")[2]
                item["pinned"] = "full commit SHA" if FULL_SHA.match(ref) else (f"tag/branch '{ref}'" if ref else "no ref")
        if isinstance(step.get("run"), str):
            item["run"] = redact_secrets(step["run"].strip())[:300]
        if isinstance(step.get("with"), dict):
            item["with"] = {key: _redacted_value(key, value) for key, value in step["with"].items()}
        if isinstance(step.get("env"), dict):
            item["env"] = {key: _redacted_value(key, value) for key, value in step["env"].items()}
        for key in ("if", "continue-on-error", "shell", "working-directory"):
            if key in step:
                item[key] = step[key]
        described_steps.append(item)
    described: dict[str, Any] = {"id": job_id, "steps": described_steps}
    for key in ("name", "runs-on", "needs", "if", "permissions", "environment", "continue-on-error", "uses", "strategy", "timeout-minutes"):
        if key in job:
            described[key] = job[key]
    if isinstance(job.get("env"), dict):
        described["env"] = {key: _redacted_value(key, value) for key, value in job["env"].items()}
    if "secrets" in job:
        described["secrets"] = job["secrets"] if isinstance(job["secrets"], str) else {key: _redacted_value(key, value) for key, value in job["secrets"].items()} if isinstance(job["secrets"], dict) else "configured"
    return described


def _redacted_value(key: Any, value: Any) -> str:
    """Show expressions such as ${{ secrets.X }} but mask literal values under credential-like keys."""
    text = str(value)
    if "${{" in text:
        return redact_secrets(text)[:160]
    masked = redact_secrets(f"{key}: {text}")
    return masked.split(": ", 1)[1][:160] if ": " in masked else "[REDACTED]"
