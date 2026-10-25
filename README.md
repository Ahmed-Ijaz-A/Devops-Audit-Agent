# DevOps Repository Auditing Agent

A Python tool-calling agent that inspects public GitHub repositories for evidence-backed DevOps issues. The LLM chooses inspection tools dynamically and can request follow-up calls; this is a hand-built loop with no orchestration framework.

## Requirements

- Python 3.10 or newer
- Git installed and available on `PATH`
- An API key for one supported LLM provider (OpenAI, Google Gemini, Groq, OpenRouter), or a local Ollama server
- Network access to GitHub and the chosen provider

Repository file contents selected by the agent are sent to the configured LLM provider. Use this only for public repositories and content suitable for that service. Likely credentials are redacted before model input, traces, and reports, but automated redaction cannot guarantee detection of every secret.

## Install

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Configure the LLM provider

Set variables in your shell, or copy `.env.example` to `.env` and fill it in. `.env` is git-ignored and read automatically, and shell variables take precedence. Do not put a real key in `.env.example` or commit it.

| `LLM_PROVIDER` | Key variable | API used | Default model |
|---|---|---|---|
| `openai` (default) | `OPENAI_API_KEY` | Responses API | `gpt-6-luna` (or `OPENAI_MODEL`) |
| `gemini` | `GEMINI_API_KEY` | OpenAI-compatible Chat Completions | `gemini-3.8-flash` |
| `groq` | `GROQ_API_KEY` | OpenAI-compatible Chat Completions | set `LLM_MODEL` |
| `openrouter` | `OPENROUTER_API_KEY` | OpenAI-compatible Chat Completions | set `LLM_MODEL` |
| `ollama` | none | OpenAI-compatible Chat Completions at `http://localhost:11434/v1` | set `LLM_MODEL` |

Optional variables: `LLM_MODEL` overrides the model, `LLM_BASE_URL` points at another OpenAI-compatible server, `LLM_API_KEY` overrides the key, and `LLM_MIN_INTERVAL` sets the minimum seconds between requests. All providers are called through the `openai` Python SDK; no agent framework is involved.

OpenAI (paid):

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-6-luna"
```

Google Gemini (has a free tier; create a key at https://aistudio.google.com/apikey):

```powershell
$env:LLM_PROVIDER = "gemini"
$env:GEMINI_API_KEY = "your-gemini-key"
$env:LLM_MIN_INTERVAL = "6"   # stay under free-tier requests-per-minute limits
```

If a model ID is not found, pick one from the provider's current model list and set `LLM_MODEL`. Free tiers have per-minute and daily limits, and popular models are sometimes overloaded (HTTP 503). The agent spaces requests out by `LLM_MIN_INTERVAL`. On a rate limit, overload, or connection failure, it waits 20, 40 and 60 seconds and retries. It then switches to the next model in `LLM_FALLBACK_MODELS` (comma-separated), if set, before giving up. Model switches are recorded in the trace.

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
   | `list_files()` | Tracked paths at `HEAD`, plus `flagged` paths that are often committed by mistake (bytecode, env files, logs, editor settings, keys, build output) with the reason. Flags are hints for the model to verify, not findings. |
   | `read_file(path)` | One tracked text file with line numbers; credentials and all `.env` values are redacted. |
   | `search_code(pattern, regex)` | Case-insensitive `git grep` over every tracked text file, including dotfiles and `.github/`, as literal text or an extended regular expression. |
   | `search_history(pattern)` | Searches the diffs of the last 100 commits for a regular expression and reports lines that were added or removed, so credentials deleted from the code but still in git history are found. Values are redacted. |
   | `git_log()` | The 20 most recent commits with the files each one changed. |
   | `inspect_workflows()` | Parses each GitHub Actions workflow into triggers, permissions, jobs, steps, action pinning (SHA vs tag), referenced secret names, and notable lines with line numbers (`pull_request_target`, `continue-on-error`, `\|\| true`, `curl \| sh`, …). Literal secret values are masked. |
   | `run_ruff()` | Static lint of the Python files using the repository's ruff configuration, or ruff defaults in isolated mode when there is none. Source is exported to a temporary directory; nothing is executed. |
   | `run_pytest()` | Only with `--sandbox-tests`; see above. |

   Tools that cannot run (for example, no Docker) return `available: false`, and the model is instructed not to report a result for that check.
3. `llm.py` holds provider settings and two small conversation adapters, one for the OpenAI Responses API and one for OpenAI-compatible Chat Completions. Each keeps the message history and converts tool calls and results to its API's format.
4. `prompts.py` holds the system prompt: how to investigate (survey, hunt, verify, review), a rule catalogue with a default severity per rule, a list of acceptable alternatives and other things not to report, and the output format.
5. `agent_loop.py` sends the system instructions and tool schemas to the model through the chosen adapter. It executes the model's tool calls and returns each result (including tool errors), labelled `[step N]`, to the model. It continues until the model produces a report. Guards:
   - An identical repeated call is answered with a pointer to the earlier step instead of running again.
   - When tool output exceeds about 120,000 characters, the oldest outputs are replaced with one-line stubs; the latest batch is always kept.
   - The investigation is bounded to 40 tool calls and `--time-limit` seconds (default 900). When either is reached, the model must report from the evidence gathered so far.
6. The final JSON is validated:
   - Every finding must cite, in `evidence_refs`, the `[step N]` of at least one tool call that actually ran and returned a result; uncited findings are dropped as unsupported. If every finding lacks citations, the model is asked once to add them.
   - Invalid JSON is sent back for correction (up to two times).
   - Findings with an unsupported category/severity or missing text are dropped. Rule IDs are normalised to `PREFIX-NNN` and severity synonyms are mapped. A file not tracked in the repository, or a line past the end of the file, is set to `null`.
   - Duplicates (same rule and location, or same description for the same file) are removed, and findings are sorted by severity.
   - Every adjustment is recorded in the trace's `notes`, and each kept finding's citations in the trace's `citations`. The report keeps only the required fields and is written atomically.

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
