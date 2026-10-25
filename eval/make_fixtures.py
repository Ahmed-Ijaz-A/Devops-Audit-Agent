"""Generate three local Git repositories with known DevOps defects, plus an answer key for each.

    python eval/make_fixtures.py --out ../audit-fixtures

Repositories (mirroring the hidden evaluation):
  devops-fixture-obvious  - obvious problems (missing README, hardcoded key, committed .env, ...)
  devops-fixture-subtle   - subtler CI, security, and configuration defects, including a secret left in git history
  devops-fixture-healthy  - a well-maintained project with false-positive traps (placeholders, test tokens)

Answer keys are written to eval/keys/<name>.json with line numbers resolved from the generated files. All credential
values are fake and use generic formats.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent / "keys"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "Fixture Bot", "GIT_AUTHOR_EMAIL": "fixtures@example.com",
    "GIT_COMMITTER_NAME": "Fixture Bot", "GIT_COMMITTER_EMAIL": "fixtures@example.com",
}

# ---------------------------------------------------------------------------------------------------------------
# A: obvious defects
# ---------------------------------------------------------------------------------------------------------------
OBVIOUS_FILES = {
    "app.py": '''from flask import Flask, jsonify, request

import config
from inventory import Inventory

app = Flask(__name__)
store = Inventory(config.DATABASE_PATH)


@app.route("/items", methods=["GET"])
def list_items():
    return jsonify(store.all())


@app.route("/items", methods=["POST"])
def add_item():
    payload = request.get_json()
    store.add(payload["name"], payload.get("quantity", 0))
    return jsonify({"status": "ok"}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
''',
    "config.py": '''DATABASE_PATH = "inventory.db"
UPLOAD_DIR = "C:\\\\Users\\\\jdoe\\\\projects\\\\inventory-service\\\\uploads"
PAYMENT_API_URL = "https://payments.example.com/v1"
PAYMENT_API_KEY = "a8f5f167f44f4964e6c998dee827110c"
''',
    "inventory.py": '''import sqlite3


class Inventory:
    def __init__(self, path):
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute("CREATE TABLE IF NOT EXISTS items (name TEXT PRIMARY KEY, quantity INTEGER)")

    def all(self):
        rows = self.connection.execute("SELECT name, quantity FROM items").fetchall()
        return [{"name": name, "quantity": quantity} for name, quantity in rows]

    def add(self, name, quantity):
        self.connection.execute("INSERT OR REPLACE INTO items VALUES (?, ?)", (name, quantity))
        self.connection.commit()
''',
    "requirements.txt": "flask\nrequests\nsqlalchemy\n",
    ".env": "DB_PASSWORD=Vx7q2Lm9Rt4wPz8\nSESSION_SECRET=3c9e1f7a2b8d4e6f0a1b\n",
}
OBVIOUS_BINARY = {"__pycache__/config.cpython-311.pyc": bytes.fromhex("a70d0d0a00000000") + b"\x00" * 64}
OBVIOUS_KEY = [
    {"id": "missing-readme", "categories": ["repository_hygiene", "collaboration"], "file": None, "keywords": ["readme"]},
    {"id": "missing-gitignore", "categories": ["repository_hygiene"], "file": None, "keywords": ["gitignore"]},
    {"id": "tracked-bytecode", "categories": ["repository_hygiene"], "file": "__pycache__/config.cpython-311.pyc", "file_optional": True,
     "keywords": ["pycache", "pyc", "bytecode", "compiled"]},
    {"id": "hardcoded-api-key", "categories": ["security"], "file": "config.py", "find": ["PAYMENT_API_KEY"]},
    {"id": "committed-env-file", "categories": ["security", "configuration", "repository_hygiene"], "file": ".env"},
    {"id": "machine-specific-path", "categories": ["configuration"], "file": "config.py", "find": ["UPLOAD_DIR"]},
    {"id": "debug-mode", "categories": ["security", "configuration"], "file": "app.py", "find": ["debug=True"]},
    {"id": "unpinned-dependencies", "categories": ["dependency_management"], "file": "requirements.txt"},
    {"id": "no-tests", "categories": ["testing"], "file": None, "keywords": ["test"]},
    {"id": "no-linting", "categories": ["code_quality"], "file": None, "keywords": ["lint", "format", "ruff", "flake8"]},
    # Defensible but not required: reporting these is neither rewarded nor penalised.
    {"id": "no-ci", "categories": ["ci_cd", "testing", "build_release"], "file": None, "optional": True,
     "keywords": ["ci", "continuous", "workflow", "pipeline", "github actions"]},
]

# ---------------------------------------------------------------------------------------------------------------
# B: subtle defects
# ---------------------------------------------------------------------------------------------------------------
SUBTLE_SETTINGS_V1 = '''import os

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_USER = os.environ.get("SMTP_USER", "billing")
SMTP_PASSWORD = "Rk4vP9zLq2wX7mTe"
'''
SUBTLE_FILES = {
    "README.md": '''# billing-api

Invoice calculation service.

## Development

```bash
python -m venv .venv
pip install -e ".[dev]"
pytest
ruff check .
```

Configuration is read from environment variables (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`).
''',
    ".gitignore": "__pycache__/\n*.py[cod]\n.venv/\n.env\ndist/\nbuild/\n*.egg-info/\n.pytest_cache/\n.ruff_cache/\n",
    "pyproject.toml": '''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "billing-api"
version = "1.4.0"
requires-python = ">=3.10"
dependencies = [
    "requests>=2.31,<3",
    "pydantic>=2.5,<3",
]

[project.optional-dependencies]
dev = ["pytest>=8", "ruff>=0.5"]

[tool.ruff]
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
''',
    "requirements.txt": "requests==2.25.1\npydantic==1.10.13\n",
    "billing/__init__.py": '"""Invoice calculations."""\n',
    "billing/invoices.py": '''from decimal import Decimal


def compute_total(lines, tax_rate):
    subtotal = sum(Decimal(str(price)) * quantity for price, quantity in lines)
    return (subtotal * (1 + Decimal(str(tax_rate)))).quantize(Decimal("0.01"))
''',
    "billing/settings.py": '''import os

SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_USER = os.environ.get("SMTP_USER", "billing")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
''',
    "config/development.py": 'DEBUG = True\nALLOWED_HOSTS = ["localhost"]\nLOG_LEVEL = "DEBUG"\n',
    "config/production.py": 'DEBUG = True\nALLOWED_HOSTS = ["billing.example.com"]\nLOG_LEVEL = "INFO"\n',
    "tests/test_invoices.py": '''from decimal import Decimal

from billing.invoices import compute_total


def test_total_includes_tax():
    assert compute_total([(10, 2), (5, 1)], 0.1) == Decimal("27.50")


def test_empty_invoice_is_zero():
    assert compute_total([], 0.2) == Decimal("0.00")
''',
    ".vscode/settings.json": '''{
    "python.defaultInterpreterPath": "/home/alice/.virtualenvs/billing/bin/python",
    "editor.formatOnSave": true
}
''',
    ".github/workflows/ci.yml": '''name: CI

on:
  push:
    branches: [main]

permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: pip install -e ".[dev]"
      - name: Lint
        run: ruff check .
      - name: Test
        run: pytest -q || true
''',
    ".github/workflows/pr-triage.yml": '''name: PR triage

on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Install project
        run: pip install -e .
      - name: Announce
        run: echo "Triaging ${{ github.event.pull_request.title }}"
''',
    ".github/workflows/release.yml": '''name: Release

on:
  push:
    branches: [main]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Build
        run: pip install build && python -m build
      - name: Create GitHub release
        uses: softprops/action-gh-release@master
        with:
          tag_name: nightly
          files: dist/*
      - name: Publish to PyPI
        run: pip install twine && twine upload dist/* -u __token__ -p ${{ secrets.PYPI_TOKEN }}
''',
}
SUBTLE_KEY = [
    {"id": "ci-skips-pull-requests", "categories": ["ci_cd"], "file": ".github/workflows/ci.yml", "find": ["push:", "branches: [main]"],
     "keywords": ["pull request", "pull_request", "pr", "trigger"]},
    {"id": "workflow-write-all", "categories": ["security", "ci_cd"], "file": ".github/workflows/ci.yml", "find": ["permissions: write-all"]},
    {"id": "test-failures-ignored", "categories": ["ci_cd", "testing"], "file": ".github/workflows/ci.yml", "find": ["|| true"]},
    {"id": "pull-request-target-checkout", "categories": ["security", "ci_cd"], "file": ".github/workflows/pr-triage.yml",
     "find": ["pull_request_target", "ref: ${{", "pip install -e ."], "keywords": ["pull_request_target", "checkout", "untrusted", "head"]},
    {"id": "script-injection", "categories": ["security", "ci_cd"], "file": ".github/workflows/pr-triage.yml",
     "find": ["github.event.pull_request.title"], "keywords": ["inject", "title", "interpolat", "untrusted"]},
    {"id": "publish-on-every-push", "categories": ["build_release", "ci_cd"], "file": ".github/workflows/release.yml",
     "keywords": ["every push", "each push", "push to main", "gate", "without test", "no test", "approval", "tag", "nightly", "release"]},
    {"id": "action-on-branch-ref", "categories": ["ci_cd", "security", "build_release"], "file": ".github/workflows/release.yml",
     "find": ["@master"], "keywords": ["master", "branch", "pin", "mutable", "sha"]},
    {"id": "secret-on-command-line", "categories": ["security", "ci_cd", "build_release"], "file": ".github/workflows/release.yml",
     "find": ["twine upload"], "keywords": ["command line", "command-line", "-p", "argument", "log", "process", "password"]},
    {"id": "secret-in-history", "categories": ["security"], "file": "billing/settings.py", "file_optional": True,
     "keywords": ["history", "commit", "removed", "previous", "earlier"]},
    {"id": "debug-in-production", "categories": ["security", "configuration"], "file": "config/production.py", "find": ["DEBUG = True"]},
    {"id": "inconsistent-dependencies", "categories": ["dependency_management"], "file": "requirements.txt", "alt_files": ["pyproject.toml"],
     "keywords": ["inconsist", "conflict", "mismatch", "differ", "disagree", "contradict"]},
    {"id": "committed-editor-settings", "categories": ["configuration", "repository_hygiene"], "file": ".vscode/settings.json"},
    {"id": "pr-triage-no-permissions", "categories": ["security", "ci_cd"], "file": ".github/workflows/pr-triage.yml", "optional": True,
     "keywords": ["permission"]},
    {"id": "release-no-permissions", "categories": ["security", "ci_cd", "build_release"], "file": ".github/workflows/release.yml", "optional": True,
     "keywords": ["permission"]},
    {"id": "gitignore-missing-vscode", "categories": ["repository_hygiene"], "file": ".gitignore", "optional": True, "keywords": ["vscode", "editor"]},
]

# ---------------------------------------------------------------------------------------------------------------
# C: healthy project with false-positive traps
# ---------------------------------------------------------------------------------------------------------------
HEALTHY_FILES = {
    "README.md": '''# textstats

Small text statistics library and command-line tool.

## Install

```bash
pip install textstats
```

## Development

```bash
python -m venv .venv
pip install -e ".[dev]"
pre-commit install
pytest
ruff check . && ruff format --check .
```

Optional configuration: copy `.env.example` to `.env` (git-ignored) and set `TEXTSTATS_REMOTE_TOKEN` to upload reports.

## Releasing

Push a tag `vX.Y.Z`. The release workflow runs the tests, builds the package, and publishes it to PyPI from the protected
`pypi` environment using trusted publishing.
''',
    "LICENSE": "MIT License\n\nCopyright (c) 2026 textstats contributors\n",
    "CONTRIBUTING.md": "# Contributing\n\nOpen a pull request against `main`. CI must pass (ruff and pytest) before review.\n",
    ".gitignore": "__pycache__/\n*.py[cod]\n.venv/\nvenv/\n.env\ndist/\nbuild/\n*.egg-info/\n.pytest_cache/\n.ruff_cache/\n.coverage\n.vscode/\n.idea/\n",
    ".env.example": "# Copy to .env; never commit real values.\nTEXTSTATS_REMOTE_TOKEN=your-token-here\nTEXTSTATS_LOG_LEVEL=INFO\n",
    ".pre-commit-config.yaml": '''repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.9
    hooks:
      - id: ruff
      - id: ruff-format
''',
    "pyproject.toml": '''[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "textstats"
version = "0.3.1"
description = "Small text statistics library"
readme = "README.md"
license = "MIT"
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=8,<9", "ruff>=0.6,<1"]

[project.scripts]
textstats = "textstats.cli:main"

[tool.ruff]
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]

[tool.pytest.ini_options]
testpaths = ["tests"]
''',
    "src/textstats/__init__.py": '''"""Text statistics."""

from textstats.core import top_words, word_count

__all__ = ["top_words", "word_count"]
''',
    "src/textstats/core.py": '''import re
from collections import Counter

WORD = re.compile(r"[a-z']+")


def words(text: str) -> list[str]:
    return WORD.findall(text.lower())


def word_count(text: str) -> int:
    return len(words(text))


def top_words(text: str, n: int = 3) -> list[tuple[str, int]]:
    return Counter(words(text)).most_common(n)
''',
    "src/textstats/config.py": '''import os


def remote_token() -> str | None:
    """Token for the optional report upload, read from the environment only."""
    return os.environ.get("TEXTSTATS_REMOTE_TOKEN")
''',
    "src/textstats/cli.py": '''import argparse
import sys

from textstats.core import top_words, word_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print text statistics.")
    parser.add_argument("path", help="Text file to analyse")
    args = parser.parse_args(argv)
    with open(args.path, encoding="utf-8") as handle:
        text = handle.read()
    print(f"words: {word_count(text)}")
    for word, count in top_words(text):
        print(f"{word}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
''',
    "tests/test_core.py": '''from textstats.core import top_words, word_count


def test_word_count_ignores_punctuation():
    assert word_count("Hello, world! Hello.") == 3


def test_top_words_orders_by_frequency():
    assert top_words("b a b c b a", n=2) == [("b", 3), ("a", 2)]
''',
    "tests/test_config.py": '''from textstats.config import remote_token


def test_remote_token_comes_from_environment(monkeypatch):
    monkeypatch.setenv("TEXTSTATS_REMOTE_TOKEN", "dummy-test-token")
    assert remote_token() == "dummy-test-token"


def test_remote_token_is_optional(monkeypatch):
    monkeypatch.delenv("TEXTSTATS_REMOTE_TOKEN", raising=False)
    assert remote_token() is None
''',
    ".github/dependabot.yml": '''version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
''',
    ".github/workflows/ci.yml": '''name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      matrix:
        python-version: ["3.10", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: pytest
''',
    ".github/workflows/release.yml": '''name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -e ".[dev]"
      - run: pytest

  build:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install build && python -m build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc  # v1.12.4
''',
}
HEALTHY_KEY: list[dict] = []

FIXTURES = {
    "devops-fixture-obvious": {"commits": [("Initial inventory service", OBVIOUS_FILES, OBVIOUS_BINARY)], "key": OBVIOUS_KEY},
    "devops-fixture-subtle": {
        "commits": [
            ("Initial billing service", {**SUBTLE_FILES, "billing/settings.py": SUBTLE_SETTINGS_V1}, {}),
            ("Read SMTP password from the environment", {"billing/settings.py": SUBTLE_FILES["billing/settings.py"]}, {}),
            ("Add release workflow notes to README", {"README.md": SUBTLE_FILES["README.md"] + "\nReleases are published automatically.\n"}, {}),
        ],
        "key": SUBTLE_KEY,
    },
    "devops-fixture-healthy": {"commits": [("Initial textstats release", HEALTHY_FILES, {})], "key": HEALTHY_KEY},
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**os.environ, **GIT_ENV})


def _remove_tree(path: Path) -> None:
    """Delete a directory, clearing the read-only flag Git sets on object files (needed on Windows)."""
    def make_writable(function, target, _info):
        os.chmod(target, stat.S_IWRITE)
        function(target)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable)
    else:
        shutil.rmtree(path, onerror=make_writable)


def build(name: str, spec: dict, out: Path) -> Path:
    repo = out / name
    if repo.exists():
        _remove_tree(repo)
    repo.mkdir(parents=True)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "core.autocrlf", "false")
    for message, text_files, binary_files in spec["commits"]:
        for path, content in text_files.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content.encode("utf-8"))
        for path, content in binary_files.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        git(repo, "add", "-A", "-f")
        git(repo, "commit", "-q", "-m", message)
    return repo


def resolve_key(repo: Path, key: list[dict]) -> list[dict]:
    """Turn each entry's `find` strings into the line numbers where they occur in the generated file."""
    resolved = []
    for entry in key:
        entry = dict(entry)
        finds = entry.pop("find", [])
        if finds:
            lines = (repo / entry["file"]).read_text(encoding="utf-8").splitlines()
            entry["lines"] = sorted({number for number, line in enumerate(lines, 1) for text in finds if text in line})
            if not entry["lines"]:
                raise SystemExit(f"{repo.name}: {finds} not found in {entry['file']}")
        resolved.append(entry)
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, help="Directory to create the fixture repositories in (outside this project)")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    project = Path(__file__).resolve().parent.parent
    if out == project or project in out.parents:
        raise SystemExit("Choose an --out directory outside this project, so the fixtures are not committed with it.")
    KEYS_DIR.mkdir(exist_ok=True)
    for name, spec in FIXTURES.items():
        repo = build(name, spec, out)
        key = {"repository": name, "expected": resolve_key(repo, spec["key"])}
        (KEYS_DIR / f"{name}.json").write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
        required = sum(1 for entry in key["expected"] if not entry.get("optional"))
        print(f"{repo}  ({required} known defects)")
    print(f"Answer keys written to {KEYS_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
