# DevOps Repository Auditing Agent

A Python tool-calling agent that inspects public GitHub repositories for evidence-backed DevOps issues. The LLM chooses inspection tools dynamically and can request follow-up calls; this is a hand-built loop with no orchestration framework.

## Requirements

- Python 3.10 or newer
- Git installed and available on `PATH`
- An OpenAI API key with access to the model selected in `OPENAI_MODEL`
- Network access to GitHub and the OpenAI API

Repository file contents selected by the agent are sent to the configured OpenAI model. Use this only for public repositories and content suitable for that service. Likely credentials are redacted before model input, traces, and reports, but automated redaction cannot guarantee detection of every secret.

## Install

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Set the API key in your shell, or copy `.env.example` to `.env` and fill it in (`.env` is git-ignored and is read automatically; shell variables take precedence). Do not put a real key in `.env.example` or commit it.

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-6-luna"
```

You can choose another model available to your account by setting `OPENAI_MODEL`. The default is `gpt-6-luna`.

## Run

```powershell
python agent.py --repo https://github.com/owner/repository --output report.json
```

The command writes the required report to `report.json` and a redacted tool-call trace to `report.json.trace.json`. To choose another trace path:

```powershell
python agent.py --repo https://github.com/owner/repository --output report.json --trace-output audit-trace.json
```

The report has a `repository` URL and a `violations` array. Each finding contains `rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and `recommendation`. File and line are JSON `null` when inapplicable. A successful audit with no supported issues produces an empty array. Fatal setup, download, model, or report errors exit nonzero and print a useful message to stderr.

`sample_report.json` demonstrates the output shape with an empty findings list. Replace it with the output of a real agent run before submission; no live model call is performed as part of setup.

## Architecture

1. `agent.py` validates inputs, clones the public repository into a temporary directory, and manages output files.
2. `tools.py` exposes `list_files`, `read_file`, `search_code` (via `git grep` over every tracked text file, dotfiles included), and `git_log` (recent commits with changed paths). The clone uses `--no-checkout`; inspection uses read-only Git commands and never executes repository code.
3. `agent_loop.py` sends the system instructions and tool schemas to the model through the OpenAI Responses API. It executes the model's tool calls, returns results (including tool errors) to the model, and continues until the model produces a report. The loop is bounded to 40 tool calls; when the budget is reached the model is told to stop calling tools and report from the evidence gathered so far. Timeouts, 429 rate limits and 5xx errors are retried with backoff by the SDK.
4. The final JSON is validated. If it is not valid JSON, the model is asked to correct it (up to two times). Findings with an unsupported category/severity or missing text are dropped; a file not tracked in the repository, or a line past the end of the file, is set to `null` instead of failing the audit. Duplicates are removed, and every adjustment is recorded in the trace's `notes`.

Repository files and commit messages are untrusted data. The system prompt tells the model to treat them as evidence, not instructions. Optional test runners, linters, submodules, and repository build scripts are not executed.

## Tests

Run the test suite with:

```powershell
python -m unittest discover -s tests -v
```

The tests use local temporary data and mocked model/tool boundaries; they do not need a live API key or run code from an inspected repository.

## Limitations

- The audit is limited to files available from the public repository's default branch and the most recent 100 commits.
- Search and file output have size limits. Very large repositories may be only partially searched.
- Secret detection is pattern-based and may miss credentials. Remote GitHub settings such as branch protection cannot be inferred from repository contents.
- The LLM may miss issues or make mistakes. Review findings before acting on recommendations.
