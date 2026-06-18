from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path
from typing import Any

import httpx
from typer.testing import CliRunner


MODULE_PATH = (
    Path(__file__).parents[1]
    / "skills"
    / "release-hygiene"
    / "release_hygiene.py"
)
SPEC = importlib.util.spec_from_file_location("release_hygiene", MODULE_PATH)
assert SPEC and SPEC.loader
release_hygiene = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_hygiene
SPEC.loader.exec_module(release_hygiene)
RUNNER = CliRunner()
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class FakeClient:
    def __init__(self, responses: dict[str, tuple[int, Any]]) -> None:
        self.responses = responses
        self.requests: list[str] = []

    def get(self, url: str, **_: object) -> httpx.Response:
        self.requests.append(url)
        status, payload = self.responses.get(url, (404, {}))
        request = httpx.Request("GET", url)
        if isinstance(payload, str):
            return httpx.Response(status, text=payload, request=request)
        return httpx.Response(status, json=payload, request=request)


class CliHelpTests(unittest.TestCase):
    def test_help_is_self_contained(self) -> None:
        result = RUNNER.invoke(release_hygiene.app, ["--help"])
        output = ANSI_ESCAPE.sub("", result.output)

        self.assertEqual(0, result.exit_code)
        self.assertIn("--pypi-version", output)
        self.assertIn("Historical audits", output)
        self.assertIn("status is 0", output)
        self.assertIn("does not modify", output)
        self.assertNotIn("--version", output)

    def test_no_arguments_prints_concise_help(self) -> None:
        result = RUNNER.invoke(release_hygiene.app, [])

        self.assertEqual(2, result.exit_code)
        self.assertIn("Usage:", result.output)
        self.assertIn("Examples:", result.output)
        self.assertIn("--help", result.output)

    def test_legacy_version_alias_still_validates_as_pypi_version(self) -> None:
        result = RUNNER.invoke(
            release_hygiene.app,
            ["owner/one", "owner/two", "--version", "1.0.0"],
        )

        self.assertEqual(1, result.exit_code)
        self.assertIn("--version is deprecated", result.output)
        self.assertIn("--pypi-version accepts one repository", result.output)


class WorkflowParsingTests(unittest.TestCase):
    def test_parses_release_only_oidc_workflow_structurally(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yml",
            """
name: Publish
on:
  release:
    types: [published]
permissions:
  contents: read
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
      - uses: pypa/gh-action-pypi-publish@2222222222222222222222222222222222222222
  unrelated:
    env:
      PASSWORD: not-a-pypi-credential
    steps:
      - run: "echo password:"
""",
        )

        self.assertIsNotNone(workflow)
        assert workflow
        self.assertTrue(workflow.has_safe_publish_trigger)
        self.assertEqual("release: published", workflow.trigger_description)
        self.assertTrue(workflow.has_id_token_write)
        self.assertFalse(workflow.has_workflow_dispatch)
        self.assertFalse(workflow.uses_token_auth)
        self.assertEqual([], workflow.unpinned_actions)

    def test_accepts_created_release_event(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yml",
            """
on:
  release:
    types: [created]
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@1111111111111111111111111111111111111111
""",
        )

        assert workflow
        self.assertTrue(workflow.has_safe_publish_trigger)
        self.assertEqual("release: created", workflow.trigger_description)

    def test_detects_extra_trigger_and_publish_credentials(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yaml",
            """
on:
  release:
    types: published
  workflow_dispatch:
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_TOKEN }}
          skip-existing: true
""",
        )

        assert workflow
        self.assertFalse(workflow.has_safe_publish_trigger)
        self.assertTrue(workflow.has_workflow_dispatch)
        self.assertFalse(workflow.workflow_dispatch_tag_guarded)
        self.assertTrue(workflow.uses_token_auth)
        self.assertTrue(workflow.has_skip_existing_true)
        self.assertEqual(
            ["actions/checkout@v4", "pypa/gh-action-pypi-publish@release/v1"],
            workflow.unpinned_actions,
        )

    def test_ignores_testpypi_publish_step(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "test.yml",
            """
on: [push]
jobs:
  publish:
    steps:
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/
""",
        )
        self.assertIsNone(workflow)

    def test_malformed_publish_workflow_is_unknown(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "broken.yml", "jobs: [\n  uses: pypa/gh-action-pypi-publish@release/v1"
        )
        assert workflow
        self.assertIsNone(workflow.has_safe_publish_trigger)
        self.assertIsNone(workflow.has_id_token_write)
        self.assertIsNotNone(workflow.parse_error)

    def test_accepts_version_tag_push(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yml",
            """
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@1111111111111111111111111111111111111111
""",
        )

        assert workflow
        self.assertTrue(workflow.has_safe_publish_trigger)
        self.assertEqual("tag push: v*", workflow.trigger_description)

    def test_rejects_branch_capable_push(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yml",
            """
on: push
jobs:
  publish:
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@1111111111111111111111111111111111111111
""",
        )

        assert workflow
        self.assertFalse(workflow.has_safe_publish_trigger)

    def test_accepts_tag_guarded_manual_dispatch_as_advisory(self) -> None:
        workflow = release_hygiene._parse_workflow(
            "publish.yml",
            """
on: workflow_dispatch
jobs:
  publish:
    if: github.ref_type == 'tag'
    permissions:
      id-token: write
    steps:
      - uses: pypa/gh-action-pypi-publish@1111111111111111111111111111111111111111
""",
        )

        assert workflow
        self.assertTrue(workflow.has_safe_publish_trigger)
        self.assertTrue(workflow.workflow_dispatch_tag_guarded)

    def test_fetches_and_returns_every_publish_workflow(self) -> None:
        contents_url = (
            "https://api.github.com/repos/acme/example/contents/.github/workflows"
        )
        good = """
on:
  release:
    types: [published]
permissions:
  id-token: write
jobs:
  publish:
    steps:
      - uses: pypa/gh-action-pypi-publish@1111111111111111111111111111111111111111
"""
        client = FakeClient(
            {
                contents_url: (
                    200,
                    [
                        {"name": "z.yml", "download_url": "https://raw/z.yml"},
                        {"name": "a.yaml", "download_url": "https://raw/a.yaml"},
                        {"name": "notes.txt", "download_url": "https://raw/notes.txt"},
                    ],
                ),
                "https://raw/z.yml": (200, good),
                "https://raw/a.yaml": (200, good),
            }
        )

        workflows = release_hygiene._find_publish_workflows(
            "acme", "example", client, None
        )

        self.assertEqual(["a.yaml", "z.yml"], [item.filename for item in workflows])

    def test_api_failure_does_not_look_like_an_empty_workflow_directory(self) -> None:
        contents_url = (
            "https://api.github.com/repos/acme/example/contents/.github/workflows"
        )
        client = FakeClient({contents_url: (403, {"message": "rate limited"})})

        with self.assertRaises(httpx.HTTPStatusError):
            release_hygiene._find_publish_workflows("acme", "example", client, None)


class ReleaseHistoryTests(unittest.TestCase):
    def test_fetches_an_explicit_release_version(self) -> None:
        url = "https://pypi.org/pypi/example/1.2.0/json"
        client = FakeClient(
            {
                url: (
                    200,
                    {
                        "info": {"version": "1.2.0"},
                        "urls": [{"filename": "example-1.2.0.whl"}],
                    },
                )
            }
        )

        release = release_hygiene._fetch_pypi_release(
            "example", client, "1.2.0"
        )

        assert release
        self.assertEqual("1.2.0", release.version)
        self.assertEqual([url], client.requests)

    def test_checks_newest_versions_before_applying_limit(self) -> None:
        versions = [f"1.2.{index}" for index in range(25)]
        project_url = "https://pypi.org/pypi/example/json"
        responses: dict[str, tuple[int, Any]] = {
            project_url: (
                200,
                {
                    "releases": {
                        version: [{"filename": f"example-{version}.whl", "yanked": False}]
                        for version in reversed(versions)
                    }
                },
            )
        }
        for version in versions:
            responses[
                f"https://pypi.org/integrity/example/{version}/example-{version}.whl/provenance"
            ] = (404, {})
        client = FakeClient(responses)

        bad = release_hygiene._find_unyanked_bad_releases(
            "example", "1.2.25", client
        )

        self.assertEqual([f"1.2.{index}" for index in range(24, 4, -1)], bad)

    def test_empty_provenance_is_bad(self) -> None:
        project_url = "https://pypi.org/pypi/example/json"
        provenance_url = (
            "https://pypi.org/integrity/example/1.2.0/example-1.2.0.whl/provenance"
        )
        client = FakeClient(
            {
                project_url: (
                    200,
                    {
                        "releases": {
                            "1.2.0": [
                                {"filename": "example-1.2.0.whl", "yanked": False}
                            ]
                        }
                    },
                ),
                provenance_url: (200, {"attestation_bundles": []}),
            }
        )

        self.assertEqual(
            ["1.2.0"],
            release_hygiene._find_unyanked_bad_releases(
                "example", "1.2.1", client
            ),
        )


class DiagnosisTests(unittest.TestCase):
    def test_next_patch_handles_short_and_prerelease_versions(self) -> None:
        self.assertEqual("2.0.1", release_hygiene._next_patch("2.0"))
        self.assertEqual("2.0.3", release_hygiene._next_patch("2.0.2rc1"))

    def test_historical_remediation_does_not_reuse_next_patch(self) -> None:
        steps = release_hygiene._repub_steps("example", "2.0.1", historical=True)
        self.assertTrue(any("immutable" in step for step in steps))
        self.assertFalse(any("2.0.2" in step for step in steps))

    def test_historical_audit_does_not_infer_from_recent_runs(self) -> None:
        report = release_hygiene.Report(
            repo="acme/example",
            pypi_name="example",
            requested_version="1.0.0",
            release=release_hygiene.PyPIRelease(
                name="example", version="1.0.0", filenames=["example-1.0.0.whl"]
            ),
            workflows=[],
            workflow_check_error="not relevant",
            recent_runs=[
                release_hygiene.RunSummary(
                    run_id=99,
                    event="release",
                    conclusion="failure",
                    head_branch="v2.0.0",
                    url="https://example.invalid/run/99",
                )
            ],
            attestation=release_hygiene.Attestation(present=False),
        )

        release_hygiene._diagnose(report)

        self.assertFalse(any("run #99" in issue for issue in report.issues))

    def test_hard_workflow_issue_keeps_report_failed(self) -> None:
        report = release_hygiene.Report(
            repo="acme/example",
            pypi_name="example",
            release=release_hygiene.PyPIRelease(
                name="example", version="1.0.0", filenames=["example-1.0.0.whl"]
            ),
            workflows=[
                release_hygiene.WorkflowFile(
                    filename="publish.yml",
                    has_safe_publish_trigger=False,
                    trigger_description="push",
                    has_id_token_write=True,
                    has_workflow_dispatch=False,
                    workflow_dispatch_tag_guarded=False,
                    uses_token_auth=False,
                    has_skip_existing_true=False,
                    unpinned_actions=[],
                )
            ],
            attestation=release_hygiene.Attestation(
                present=True,
                cert=release_hygiene.CertFields(
                    san_uri="", git_ref="refs/tags/v1.0.0", trigger="release"
                ),
            ),
            has_dependabot_actions=True,
            changelog_has_entry=True,
        )

        release_hygiene._diagnose(report)

        self.assertFalse(report.ok)
        self.assertTrue(any("not restricted" in issue for issue in report.issues))

    def test_workflow_api_error_is_not_reported_as_missing_workflow(self) -> None:
        report = release_hygiene.Report(
            repo="acme/example",
            pypi_name="example",
            release=release_hygiene.PyPIRelease(
                name="example", version="1.0.0", filenames=["example-1.0.0.whl"]
            ),
            workflow_check_error="rate limited",
            attestation=release_hygiene.Attestation(
                present=True,
                cert=release_hygiene.CertFields(
                    san_uri="", git_ref="refs/tags/v1.0.0", trigger="release"
                ),
            ),
            has_dependabot_actions=None,
            changelog_has_entry=True,
        )

        release_hygiene._diagnose(report)

        self.assertTrue(report.ok)
        self.assertFalse(any("No PyPI publish workflow" in item for item in report.issues))


if __name__ == "__main__":
    unittest.main()
