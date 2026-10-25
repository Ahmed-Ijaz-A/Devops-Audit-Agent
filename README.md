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

### Optional: run the target's tests in a sandbox

```powershell
python agent.py --repo https://github.com/owner/repository --output report.json --sandbox-tests
```

`--sandbox-tests` offers the agent a `run_pytest` tool. It needs Docker running. The repository is copied into a `python:3.12-slim` container, where its dependencies are installed (with network access). Its tests then run in a snapshot of that container with networking disabled, all Linux capabilities dropped, `no-new-privileges`, and limits of 2 GB memory, 2 CPUs and 512 processes. The container and image are removed afterwards. Without the flag, no repository code is executed. If Docker is unavailable, the tool reports that the check was not performed, and the agent does not report test results.

The report has a `repository` URL and a `violations` array. Each finding contains `rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and `recommendation`. File and line are JSON `null` when inapplicable. A successful audit with no supported issues produces an empty array. Fatal setup, download, model, or report errors exit nonzero and print a useful message to stderr.

`sample_report.json` demonstrates the output shape with an empty findings list. Replace it with the output of a real agent run before submission; no live model call is performed as part of setup.

## Architecture

1. `agent.py` validates inputs, clones the public repository into a temporary directory, and manages output files.
2. `tools.py` implements the inspection tools. The clone uses `--no-checkout`, so the target repository's files are only read through Git.

   | Tool | What it does |
   |---|---|
   | `list_files()` | Tracked paths at `HEAD`. |
   | `read_file(path)` | One tracked text file with line numbers; credentials and all `.env` values are redacted. |
   | `search_code(pattern)` | Case-insensitive literal `git grep` over every tracked text file, including dotfiles and `.github/`. |
   | `git_log()` | The 20 most recent commits with the files each one changed. |
   | `inspect_workflows()` | Parses each GitHub Actions workflow into triggers, permissions, jobs, steps, action pinning (SHA vs tag), referenced secret names, and notable lines with line numbers (`pull_request_target`, `continue-on-error`, `\|\| true`, `curl \| sh`, …). Literal secret values are masked. |
   | `run_ruff()` | Static lint of the Python files using the repository's ruff configuration, or ruff defaults in isolated mode when there is none. Source is exported to a temporary directory; nothing is executed. |
   | `run_pytest()` | Only with `--sandbox-tests`; see above. |

   Tools that cannot run (for example, no Docker) return `available: false`, and the model is instructed not to report a result for that check.
3. `agent_loop.py` sends the system instructions and tool schemas to the model through the OpenAI Responses API. It executes the model's tool calls, returns results (including tool errors) to the model, and continues until the model produces a report. The loop is bounded to 40 tool calls; when the budget is reached the model is told to stop calling tools and report from the evidence gathered so far. Timeouts, 429 rate limits and 5xx errors are retried with backoff by the SDK.
4. The final JSON is validated. If it is not valid JSON, the model is asked to correct it (up to two times). Findings with an unsupported category/severity or missing text are dropped; a file not tracked in the repository, or a line past the end of the file, is set to `null` instead of failing the audit. Duplicates are removed, and every adjustment is recorded in the trace's `notes`.

Repository files and commit messages are untrusted data. The system prompt tells the model to treat them as evidence, not instructions. Repository code, build scripts, and submodules are never executed outside the opt-in Docker sandbox.

## Tests

Run the test suite with:

```powershell
python -m unittest discover -s tests -v
python -m ruff check .
```

The tests use local temporary Git repositories and mocked model/tool boundaries; they do not need a live API key, network access, or Docker. GitHub Actions (`.github/workflows/ci.yml`) runs lint and tests on Python 3.10 and 3.12 for every push to `main` and every pull request.

## Limitations

- The audit is limited to files available from the public repository's default branch and the most recent 100 commits.
- Search and file output have size limits. Very large repositories may be only partially searched.
- Secret detection is pattern-based and may miss credentials. Remote GitHub settings such as branch protection cannot be inferred from repository contents.
- The LLM may miss issues or make mistakes. Review findings before acting on recommendations.
