---
name: brew-tap-python
description: Create a complete, production-ready Homebrew tap for a Python CLI tool. Use when the user wants to publish a Python package via Homebrew, create a brew tap, or distribute a Python CLI with brew install.
triggers:
  - homebrew tap
  - brew tap
  - create a tap
  - publish python cli
  - homebrew formula
  - brew install python
---

## Homebrew Tap for Python

Create a production-ready Homebrew tap for an existing Python CLI package on GitHub and/or PyPI.

## Defaults

- Use `Language::Python::Virtualenv` with `virtualenv_install_with_resources`.
- Prefer the PyPI sdist for `url` and `sha256`.
- Use `uv` for local verification when it helps.
- Derive metadata from the GitHub repo and PyPI page whenever possible.

## Ask For

- GitHub username/owner for the tap
- Main project GitHub repository URL (e.g., https://github.com/owner/name)
- PyPI package name (if different from repo name)
- Preferred command name / formula name
- Any special requirements (extra deps, build flags, conflicts, etc.)

## Deliverables

1. Suggest a tap repo name in the form `homebrew-<kebab-case-package-name>`.
2. Generate `Formula/<formula-name>.rb` with `desc`, `homepage`, `url`, `sha256`, `license`, `depends_on "python@X.Y"`, `virtualenv_install_with_resources`, and a solid `test do`.
3. Write a tap `README.md` with install instructions.
4. Provide the exact shell commands to create the repo, publish the tap, test the formula, run `brew style`, `brew audit --new-formula`, and `brew test`.
5. Optional: add `.github/workflows/update.yml` for formula refreshes.

## Workflow

1. Inspect the GitHub repo and PyPI metadata.
2. Extract version, sdist URL, SHA256, description, homepage, license, and CLI entry point.
3. Generate the formula and any supporting files.
4. Give `uv` commands for local verification when useful.
5. Finish with a short execution checklist of the next concrete steps.

## Rules

- Stay idiomatic to current Homebrew best practices.
- Avoid fragile or non-standard approaches.
- If `gh` is missing, say: "The `gh` CLI is not installed on this machine. You can install it with `brew install gh`, or create the repository manually on GitHub.com."
- Choose the newest Homebrew `python` version that still satisfies the package's `Requires-Python` and tested compatibility; if there is no useful constraint, default to Homebrew's current stable `python` formula at generation time.

Ask for any missing GitHub repo URL or package details first, then generate the tap.
