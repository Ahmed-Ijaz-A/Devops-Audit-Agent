"""Command line entry point for the DevOps repository auditing agent."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from agent_loop import DEFAULT_TIME_LIMIT_SECONDS, AgentError, run_agent
from llm import resolve_settings
from tools import GitRepository, RepositoryError, normalize_github_url


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a public GitHub repository for DevOps issues.")
    parser.add_argument("--repo", required=True, help="Public GitHub repository URL")
    parser.add_argument("--output", required=True, help="Path for the JSON report")
    parser.add_argument("--trace-output", help="Optional path for a redacted tool-call trace")
    parser.add_argument(
        "--sandbox-tests", action="store_true",
        help="Offer the run_pytest tool, which runs the repository's tests in an isolated Docker container (requires Docker)",
    )
    parser.add_argument(
        "--time-limit", type=float, default=DEFAULT_TIME_LIMIT_SECONDS,
        help=f"Seconds of investigation before the agent must report from the evidence it has (default {DEFAULT_TIME_LIMIT_SECONDS})",
    )
    return parser.parse_args()


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from a local .env file without overriding variables already set."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        key, value = key.strip(), value.strip().strip("'\"")
        if key and value and key not in os.environ:
            os.environ[key] = value


def main() -> int:
    args = parse_args()
    load_dotenv(Path(__file__).resolve().parent / ".env")
    load_dotenv(Path.cwd() / ".env")
    try:
        settings = resolve_settings()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Using {settings.provider} model {settings.model}", file=sys.stderr)
    try:
        repo_url = normalize_github_url(args.repo)
        output_path = Path(args.output).expanduser().resolve()
        trace_path = Path(args.trace_output).expanduser().resolve() if args.trace_output else Path(str(output_path) + ".trace.json")
        if output_path == trace_path:
            raise AgentError("Report and trace output paths must be different.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        trace_path.parent.mkdir(parents=True, exist_ok=True)

        # Git marks pack files read-only, which can make cleanup fail on Windows; that must not fail a finished audit.
        with tempfile.TemporaryDirectory(prefix="devops-audit-", ignore_cleanup_errors=True) as temp_dir:
            repo = GitRepository.clone(repo_url, Path(temp_dir) / "repository")
            report, trace = run_agent(
                repo_url, repo, settings=settings, enable_pytest=args.sandbox_tests, time_limit=args.time_limit,
            )

        write_json_atomic(output_path, report)
        write_json_atomic(trace_path, trace)
        print(f"Audit complete: {len(report['violations'])} violation(s) written to {output_path}", file=sys.stderr)
        print(f"Tool trace: {trace_path}", file=sys.stderr)
        return 0
    except (AgentError, RepositoryError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Error: interrupted; no report was written.", file=sys.stderr)
        return 130


def write_json_atomic(path: Path, value: object) -> None:
    """Write to a temporary file and rename it, so an interrupted run never leaves a half-written report."""
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temp_name, path)
    except BaseException:
        Path(temp_name).unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
