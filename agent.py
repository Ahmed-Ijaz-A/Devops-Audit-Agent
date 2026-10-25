"""Command line entry point for the DevOps repository auditing agent."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from agent_loop import AgentError, run_agent
from tools import GitRepository, RepositoryError, normalize_github_url


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit a public GitHub repository for DevOps issues.")
    parser.add_argument("--repo", required=True, help="Public GitHub repository URL")
    parser.add_argument("--output", required=True, help="Path for the JSON report")
    parser.add_argument("--trace-output", help="Optional path for a redacted tool-call trace")
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
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key == "replace-me":
        print("Error: set OPENAI_API_KEY (environment variable or .env file) before running the agent.", file=sys.stderr)
        return 2
    model = os.getenv("OPENAI_MODEL", "gpt-6-luna")
    try:
        repo_url = normalize_github_url(args.repo)
        output_path = Path(args.output).expanduser().resolve()
        trace_path = Path(args.trace_output).expanduser().resolve() if args.trace_output else Path(str(output_path) + ".trace.json")
        if output_path == trace_path:
            raise AgentError("Report and trace output paths must be different.")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        trace_path.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="devops-audit-") as temp_dir:
            repo = GitRepository.clone(repo_url, Path(temp_dir) / "repository")
            report, trace = run_agent(repo_url, repo, api_key=api_key, model=model)

        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        trace_path.write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Audit complete: {output_path}", file=sys.stderr)
        print(f"Tool trace: {trace_path}", file=sys.stderr)
        return 0
    except (AgentError, RepositoryError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
