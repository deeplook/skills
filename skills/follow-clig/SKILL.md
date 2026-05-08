---
name: follow-clig
description: Audit an existing CLI against the CLIG guidelines, guide the creation of a new CLIG-compliant CLI, or fix violations inline. Use when the user wants to check, improve, or build a CLI tool that follows clig.dev best practices.
triggers:
  - clig
  - cli guidelines
  - audit cli
  - fix cli
  - cli best practices
  - follow clig
allowed-tools: WebFetch, Read, Grep, Glob, Edit  # Claude Code tool names
---

## Purpose

Help the user build or improve CLI tools that follow the [CLIG guidelines](https://clig.dev).

Act based on the user's expressed intent:

| Intent | Action |
|--------|--------|
| **Audit** — "check my CLI", "does this follow CLIG?" | Analyse the codebase and produce a structured compliance report |
| **Guide** — "help me build a CLI", "what should I do?" | Walk through design decisions interactively using CLIG as the reference |
| **Fix** — "fix the violations", "apply the guidelines" | Apply inline edits to bring the CLI into compliance |

If intent is unclear, ask: "Should I audit for violations, guide you through building something new, or apply fixes directly?"

## Step 1 — Load the guidelines

Before doing anything else, load the CLIG guidelines using the first source that succeeds:

1. **GitHub raw** (preferred — most up to date):
   `https://raw.githubusercontent.com/cli-guidelines/cli-guidelines/refs/heads/main/content/_index.md`
2. **Bundled fallback** — read `clig.md` from the skill's own directory (same folder as this `SKILL.md`). Use this if the network fetch fails.
3. **clig.dev** (last resort):
   `https://clig.dev`

Parse the Markdown to extract the sections and their rules. Use this as your authoritative reference throughout the session. Do not rely solely on training-data knowledge of CLIG.

## Step 2 — Understand the target

Ask (or infer from context) what CLI is being discussed:

- For **audit / fix**: ask for the project path or relevant files. Read the entry point(s), argument parsing code, help text, and output formatting.
- For **guide**: ask what the tool will do and what language/framework they are using.

## Audit mode

1. Read the CLI source (entry points, argument parsers, help strings, output code).
2. Map each CLIG guideline section to observations about the CLI.
3. Produce a report structured as:

```
## CLIG Compliance Report

### Passes
- ...

### Violations
#### <Section name> — <Guideline summary>
- **File**: path/to/file.py:42
- **Issue**: What is wrong
- **Fix**: What to change

### Not applicable
- ...
```

4. Summarise with a count: `N passes · M violations · K not applicable`.
5. Ask: "Would you like me to apply fixes for any of these violations?"

## Fix mode

For each violation the user wants fixed:

1. Read the relevant file if not already read.
2. Apply the minimal edit that satisfies the guideline — do not refactor unrelated code.
3. Confirm the fix with a one-line description of what changed and why.

## Guide mode

Walk the user through CLIG sections that are relevant to what they are building. For each section:

1. Summarise the key rules.
2. Ask targeted questions about their design (e.g., "Will your tool ever be piped? Then stdout should be clean by default").
3. Give concrete recommendations for their chosen language/framework.
4. Offer to write the skeleton code if they want it.

## Rules

- Always fetch the guidelines fresh — do not skip Step 1.
- Be language-agnostic: focus on behaviour, UX, and output patterns, not framework APIs.
- Make the smallest change that satisfies a guideline. Do not over-engineer.
- Cite the specific CLIG section for every violation or recommendation.
- If a guideline is ambiguous for the user's use case, explain the trade-off and let them decide.
