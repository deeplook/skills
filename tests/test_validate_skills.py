from __future__ import annotations

import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / "scripts" / "validate_skills.py"
SPEC = spec_from_file_location("validate_skills", MODULE_PATH)
validate_skills = module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(validate_skills)


class ValidateSkillsTests(unittest.TestCase):
    def test_repo_skill_is_valid(self) -> None:
        errors = validate_skills.validate_skill_dir(ROOT / "skills" / "brew-tap-python")
        self.assertEqual(errors, [])

    def test_readme_mentions_canonical_install(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("npx skills add deeplook/skills --skill brew-tap-python", readme)

    def test_skill_metadata_matches_name(self) -> None:
        skill_md = (ROOT / "skills" / "brew-tap-python" / "SKILL.md").read_text(encoding="utf-8")
        openai_yaml = (
            ROOT / "skills" / "brew-tap-python" / "agents" / "openai.yaml"
        ).read_text(encoding="utf-8")

        self.assertIn("name: brew-tap-python", skill_md)
        self.assertIn("Use $brew-tap-python", openai_yaml)

    def test_missing_skill_md_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "example-skill"
            skill_dir.mkdir()

            errors = validate_skills.validate_skill_dir(skill_dir)

            self.assertIn("missing SKILL.md", errors)

    def test_name_mismatch_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "example-skill"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                "---\nname: wrong-name\ndescription: Example skill\n---\n",
                encoding="utf-8",
            )

            errors = validate_skills.validate_skill_dir(skill_dir)

            self.assertIn("name 'wrong-name' does not match directory 'example-skill'", errors)

    def test_missing_agents_metadata_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            skill_dir = Path(tmp) / "example-skill"
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                "---\nname: example-skill\ndescription: Example skill\n---\n",
                encoding="utf-8",
            )

            errors = validate_skills.validate_skill_dir(skill_dir)

            self.assertIn("missing agents/openai.yaml", errors)


if __name__ == "__main__":
    unittest.main()
