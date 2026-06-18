---
name: release-hygiene
description: Audit and improve release hygiene for GitHub-hosted Python packages, including PEP 740 attestations, PyPI Trusted Publishing, workflow triggers and credentials, action pinning, Dependabot, wheel availability, version consistency, and changelog coverage. Use when checking PyPI release integrity, supply-chain hygiene, attestations, or publish workflows, and when applying approved repository fixes.
---

# Release Hygiene

Audit first, explain uncertainty explicitly, and apply repository changes only with user approval.

## Identify Targets

Use explicit `owner/repo` arguments when provided. Otherwise infer the current repository with:

```bash
git remote get-url origin
```

Parse HTTPS and SSH GitHub remotes. Default the PyPI package name to the repository name. If PyPI returns 404, ask for the package name and rerun with `--package`.

## Run The Audit

Resolve `<skill-dir>` as the directory containing this `SKILL.md`; `release_hygiene.py` is directly inside it. Run:

```bash
uv run <skill-dir>/release_hygiene.py <owner/repo> [<owner/repo> ...]
```

To audit one historical PyPI release, add `--pypi-version <version>`. Historical audits check that release's artifacts and attestation against the current repository workflow, but skip HEAD-version comparison, recent-run attribution, and the older-release sweep.

The script obtains a GitHub token from `GITHUB_TOKEN` or `gh auth token`. If `uv` is unavailable, report that prerequisite. Do not treat an unavailable API, unparseable workflow, or dynamic version as a failed check; report it as unknown.

## Present Findings

Interpret output as:

| Symbol | Meaning |
|---|---|
| `✓` | Verified check |
| `✗` | Release-integrity failure |
| `!` | Advisory issue or unknown result |

Summarize the main risk and the highest-priority action. Keep separate workflows separate in the explanation; do not assume one workflow's run history or permissions apply to another.

## Apply Approved Fixes

Offer automatable repository fixes by category and apply only those the user approves. Never push, publish, yank releases, change PyPI settings, or open a pull request without explicit approval.

For action pins, resolve the requested ref to its commit SHA and preserve the readable version as a comment:

```yaml
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4
```

Add a `github-actions` Dependabot entry when absent. Remove `skip-existing: true` from production publishing when approved. Accept one tag-bound release action (`created`, `published`, `released`, or `prereleased`) or a push filtered to version tags. Treat broad release triggers, multiple release actions, and branch-capable publishing as failures because they can republish unexpectedly. Treat `workflow_dispatch` as advisory only when every production publish path explicitly requires a tag ref; otherwise fail it. Prefer one production PyPI workflow with `id-token: write` on each publish job and no explicit publish credentials.

For external remediation, provide exact project-specific URLs or commands:

- PyPI release yanking: `https://pypi.org/manage/project/<name>/release/<version>/`
- Trusted Publishing: `https://pypi.org/manage/project/<name>/settings/publishing/`
- Re-release: use the version, tag, and commands emitted by the analyzer, but verify repository conventions before proposing files or branch names.

## Verify

After repository fixes, rerun the analyzer. Report which findings cleared and which remain external, historical, or unknown. Do not claim success from the edit alone.
