# Skills

This repository is a collection of reusable agent skills.

## Layout

Skills currently live under `skills/<skill-name>/`.

For now, the repo stays flat at the skill level. Category folders can be added later once there are enough skills to justify grouping.

## Current Skills

- `brew-tap-python` - Create a production-ready Homebrew tap for a Python CLI tool.
- `follow-clig` - Audit, guide, or fix a CLI tool against the CLIG guidelines (clig.dev).

## Install

Use the Skills CLI to install from this repository.

Canonical install:

```bash
npx skills add deeplook/skills --skill brew-tap-python
```

Interactive discovery:

```bash
npx skills find
```

List skills in this repo without installing them:

```bash
npx skills add deeplook/skills --list
```

To target a specific AI host, add `--agent`:

```bash
npx skills add deeplook/skills --skill brew-tap-python --agent claude-code
```

If you prefer the direct URL form:

```bash
npx skills add https://github.com/deeplook/skills/tree/main/skills/brew-tap-python
```

## Adding a New Skill

1. Create `skills/<new-skill-name>/`.
2. Add `SKILL.md` with valid YAML frontmatter.
3. Add `agents/openai.yaml` if you want richer skill metadata in UI surfaces.
4. Keep the skill self-contained. Add `scripts/`, `references/`, or `assets/` only if the skill needs them.
5. Update this README and `skills/README.md`.

## Conventions

- Skill directory names use lowercase hyphenated names.
- `SKILL.md` is the required entrypoint for each skill.
- Avoid extra documentation inside skill folders unless it is bundled resource material the skill actually uses.

## Validation

Run `python3 scripts/validate_skills.py` to check the repo structure and basic skill metadata.
