#!/usr/bin/env python3
"""Validate the skills repo structure."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"


def read_frontmatter(skill_md: Path) -> dict[str, str]:
    content = skill_md.read_text(encoding="utf-8")
    if not content.startswith("---\n"):
        raise ValueError("missing YAML frontmatter")

    lines = content.splitlines()
    try:
        end = lines[1:].index("---") + 1
    except ValueError as exc:
        raise ValueError("missing closing frontmatter delimiter") from exc

    frontmatter: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        frontmatter[key.strip()] = value.strip().strip('"')
    return frontmatter


def validate_skill_dir(skill_dir: Path) -> list[str]:
    errors: list[str] = []
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        errors.append("missing SKILL.md")
        return errors

    try:
        frontmatter = read_frontmatter(skill_md)
    except ValueError as exc:
        errors.append(str(exc))
        return errors

    name = frontmatter.get("name")
    if not name:
        errors.append("missing frontmatter name")
    elif name != skill_dir.name:
        errors.append(f"name '{name}' does not match directory '{skill_dir.name}'")
    elif not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
        errors.append("name must be lowercase hyphen-case")

    description = frontmatter.get("description")
    if not description:
        errors.append("missing frontmatter description")

    agents_yaml = skill_dir / "agents" / "openai.yaml"
    if not agents_yaml.exists():
        errors.append("missing agents/openai.yaml")

    return errors


def discover_skill_dirs() -> list[Path]:
    return sorted(
        {
            path.parent
            for path in SKILLS_DIR.rglob("SKILL.md")
            if path.is_file()
        }
    )


def main() -> int:
    if not SKILLS_DIR.exists():
        print("skills/ directory not found")
        return 1

    skill_dirs = discover_skill_dirs()
    if not skill_dirs:
        print("no skill directories found")
        return 1

    failures: list[str] = []
    for skill_dir in skill_dirs:
        errors = validate_skill_dir(skill_dir)
        if errors:
            failures.append(f"{skill_dir.relative_to(ROOT)}: " + "; ".join(errors))

    if failures:
        print("Skill validation failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Validated {len(skill_dirs)} skill directory(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
