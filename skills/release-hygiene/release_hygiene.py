#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx", "typer", "cryptography", "packaging", "pyyaml"]
# ///
"""
release-hygiene: supply-chain hygiene checks for GitHub-hosted Python packages.

For each owner/repo it checks:
  • PEP 740 attestation present on PyPI
  • Attestation cert signed from the correct git ref (refs/tags/vX.Y.Z)
  • Publish workflow exists, uses OIDC (not a token), triggers only on release
  • No skip-existing: true silencing upload errors
  • Actions pinned to commit SHAs
  • Dependabot keeping those pins rotated
  • wheel published alongside the sdist
  • pyproject.toml version on HEAD matches what's on PyPI
  • CHANGELOG has an entry for the current version
  • Old same-series releases with broken attestations are yanked

Concrete fix steps are printed for every issue found.
"""
from __future__ import annotations

import base64
import re
import subprocess
import tomllib
from dataclasses import dataclass, field
from typing import Optional

import httpx
import typer
import yaml
from cryptography import x509
from packaging.version import InvalidVersion, Version

_HELP = {"help_option_names": ["-h", "--help"]}
app = typer.Typer(
    context_settings=_HELP,
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="markdown",
)

GH_API = "https://api.github.com"
PYPI_API = "https://pypi.org"

# Fulcio OID → our field name.  Both old (raw UTF-8) and new (DER SET>SEQ>UTF8) formats.
_FULCIO_OIDS: dict[str, str] = {
    "1.3.6.1.4.1.57264.1.2": "trigger",    # old: GitHub event name
    "1.3.6.1.4.1.57264.1.6": "ref",        # old: GitHub ref
    "1.3.6.1.4.1.57264.1.20": "trigger",   # new: GitHub event name
    "1.3.6.1.4.1.57264.1.21": "ref_type",  # new: refs/tags or refs/heads
}

_CHANGELOG_NAMES = (
    "CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG",
    "CHANGES.md", "CHANGES.rst", "HISTORY.md", "HISTORY.rst",
)
_CHANGELOG_DIRS = ("", "docs", "changes")

_MAX_YANK_CHECK = 20  # max same-series releases to integrity-check


# ── data model ────────────────────────────────────────────────────────────────

@dataclass
class PyPIRelease:
    name: str
    version: str
    filenames: list[str]


@dataclass
class CertFields:
    san_uri: str   # full Fulcio SAN URI
    git_ref: str   # e.g. refs/tags/v2.0.2 or refs/heads/main
    trigger: str   # release, workflow_dispatch, push, …

    @property
    def is_tag_ref(self) -> bool:
        return self.git_ref.startswith("refs/tags/")


@dataclass
class Attestation:
    present: bool
    cert: Optional[CertFields] = None
    publisher_repo: Optional[str] = None
    publisher_workflow: Optional[str] = None


@dataclass
class WorkflowFile:
    filename: str
    has_safe_publish_trigger: Optional[bool]
    trigger_description: str
    has_id_token_write: Optional[bool]
    has_workflow_dispatch: bool    # manual trigger → race-condition risk
    workflow_dispatch_tag_guarded: bool
    uses_token_auth: bool          # password: / secret overrides OIDC
    has_skip_existing_true: bool   # silently swallows upload errors
    unpinned_actions: list[str]    # uses: refs not pinned to a 40-char SHA
    parse_error: Optional[str] = None


@dataclass
class RunSummary:
    run_id: int
    event: str       # release, workflow_dispatch, push, …
    conclusion: str  # success, failure, cancelled, …
    head_branch: str
    url: str
    workflow_filename: str = ""


@dataclass
class Report:
    repo: str
    pypi_name: str
    requested_version: Optional[str] = None
    release: Optional[PyPIRelease] = None
    workflows: list[WorkflowFile] = field(default_factory=list)
    workflow_check_error: Optional[str] = None
    recent_runs: list[RunSummary] = field(default_factory=list)
    runs_check_failed: bool = False
    attestation: Optional[Attestation] = None
    unyanked_old_versions: list[str] = field(default_factory=list)
    head_version: Optional[str] = None
    head_version_dynamic: bool = False
    changelog_has_entry: Optional[bool] = None   # None = no changelog found
    changelog_check_failed: bool = False
    has_dependabot_actions: Optional[bool] = None
    issues: list[str] = field(default_factory=list)   # hard failures → ok=False
    warnings: list[str] = field(default_factory=list) # advisory, ok may still be True
    steps: list[str] = field(default_factory=list)
    ok: bool = False


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _gh_headers(token: Optional[str]) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _resolve_token(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    try:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


# ── PyPI ──────────────────────────────────────────────────────────────────────

def _fetch_pypi_release(
    name: str, client: httpx.Client, version: Optional[str] = None
) -> Optional[PyPIRelease]:
    suffix = f"/{version}" if version else ""
    r = client.get(f"{PYPI_API}/pypi/{name}{suffix}/json")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    d = r.json()
    return PyPIRelease(
        name=name,
        version=d["info"]["version"],
        filenames=[u["filename"] for u in d.get("urls", [])],
    )


def _check_attestation(release: PyPIRelease, client: httpx.Client) -> Attestation:
    filename = (
        next((f for f in release.filenames if f.endswith(".whl")), None)
        or (release.filenames[0] if release.filenames else None)
    )
    if filename is None:
        return Attestation(present=False)

    r = client.get(
        f"{PYPI_API}/integrity/{release.name}/{release.version}/{filename}/provenance"
    )
    if r.status_code == 404:
        return Attestation(present=False)
    r.raise_for_status()

    bundles = r.json().get("attestation_bundles", [])
    if not bundles:
        return Attestation(present=False)

    bundle = bundles[0]
    pub = bundle.get("publisher", {})

    certs: list[CertFields] = []
    for candidate_bundle in bundles:
        for attestation in candidate_bundle.get("attestations", []):
            cert_b64 = (
                attestation.get("verification_material", {}).get("certificate", "")
            )
            cert = _parse_cert(cert_b64) if cert_b64 else None
            if cert:
                certs.append(cert)
    expected_tags = {release.version, f"v{release.version}"}
    cert = next(
        (
            candidate
            for candidate in certs
            if candidate.is_tag_ref
            and candidate.git_ref.removeprefix("refs/tags/") in expected_tags
        ),
        None,
    )
    if cert is None:
        cert = next((candidate for candidate in certs if candidate.is_tag_ref), None)
    if cert is None and certs:
        cert = certs[0]

    return Attestation(
        present=True,
        cert=cert,
        publisher_repo=pub.get("repository"),
        publisher_workflow=pub.get("workflow"),
    )


def _major_minor(version: str) -> str:
    """Return 'major.minor' from a version string, ignoring pre/post-release suffixes."""
    m = re.match(r"(\d+)\.(\d+)", version)
    return f"{m.group(1)}.{m.group(2)}" if m else version


def _find_unyanked_bad_releases(
    name: str, current_version: str, client: httpx.Client
) -> list[str]:
    """Return same-series versions that lack a valid attestation and are not yet yanked."""
    r = client.get(f"{PYPI_API}/pypi/{name}/json")
    if r.status_code == 404:
        return []
    r.raise_for_status()

    current_mm = _major_minor(current_version)
    releases: dict[str, list[dict]] = r.json().get("releases", {})

    candidates = [
        v for v, files in releases.items()
        if v != current_version
        and files
        and _major_minor(v) == current_mm
        and not all(f.get("yanked", False) for f in files)
    ]

    def release_key(version: str) -> tuple[int, object]:
        try:
            return (1, Version(version))
        except InvalidVersion:
            return (0, version)

    bad: list[str] = []
    for version in sorted(candidates, key=release_key, reverse=True)[:_MAX_YANK_CHECK]:
        files = releases[version]
        fname = next(
            (f["filename"] for f in files if f["filename"].endswith(".whl")),
            files[0]["filename"],
        )
        ar = client.get(f"{PYPI_API}/integrity/{name}/{version}/{fname}/provenance")
        if ar.status_code == 404:
            bad.append(version)
            continue
        ar.raise_for_status()
        expected_tags = {version, f"v{version}"}
        has_valid_cert = False
        for bundle in ar.json().get("attestation_bundles", []):
            for attestation in bundle.get("attestations", []):
                cert_b64 = (
                    attestation.get("verification_material", {}).get("certificate", "")
                )
                cert = _parse_cert(cert_b64) if cert_b64 else None
                if cert and cert.git_ref.removeprefix("refs/tags/") in expected_tags:
                    has_valid_cert = cert.is_tag_ref
                    break
            if has_valid_cert:
                break
        if not has_valid_cert:
            bad.append(version)

    return bad


# ── Fulcio cert parsing ───────────────────────────────────────────────────────

def _asn1_length(data: bytes, i: int) -> tuple[int, int]:
    """Return (length, next_index) for a DER length field at position i."""
    b = data[i]
    if b < 0x80:
        return b, i + 1
    n = b & 0x7F
    return int.from_bytes(data[i + 1 : i + 1 + n], "big"), i + 1 + n


def _decode_fulcio_ext(raw: bytes) -> str:
    """Decode a Fulcio OID extension value.

    Old-format certs store the value as a raw UTF-8 string.
    New-format certs wrap it in DER: SET { SEQUENCE { UTF8String { value } } }.
    """
    if not raw:
        return ""
    if raw[0] == 0x31:  # SET tag → new format: SET { SEQUENCE { UTF8String } }
        try:
            _, i = _asn1_length(raw, 1)
            if raw[i] == 0x30:              # SEQUENCE
                _, i = _asn1_length(raw, i + 1)
                if raw[i] == 0x0C:          # UTF8String
                    vlen, i = _asn1_length(raw, i + 1)
                    return raw[i : i + vlen].decode("utf-8")
        except (IndexError, UnicodeDecodeError):
            pass
    if raw[0] == 0x0C:  # bare UTF8String tag → mid format
        try:
            vlen, i = _asn1_length(raw, 1)
            return raw[i : i + vlen].decode("utf-8")
        except (IndexError, UnicodeDecodeError):
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _parse_cert(cert_b64: str) -> Optional[CertFields]:
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
    except Exception:
        return None

    san_uri = ""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            san_uri = uris[0]
    except x509.ExtensionNotFound:
        pass

    fields: dict[str, str] = {}
    for ext in cert.extensions:
        oid = ext.oid.dotted_string
        if oid in _FULCIO_OIDS:
            raw = getattr(ext.value, "value", b"")
            if isinstance(raw, bytes):
                fields[_FULCIO_OIDS[oid]] = _decode_fulcio_ext(raw)

    git_ref = fields.get("ref", "")
    if not git_ref and "@" in san_uri:
        git_ref = san_uri.split("@", 1)[-1]

    return CertFields(
        san_uri=san_uri,
        git_ref=git_ref,
        trigger=fields.get("trigger", ""),
    )


# ── GitHub ────────────────────────────────────────────────────────────────────

def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _sequence(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _is_true(value: object) -> bool:
    return str(value).lower() == "true"


def _publish_steps(job: dict[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for raw_step in _sequence(job.get("steps")):
        step = _mapping(raw_step)
        uses = str(step.get("uses", "")).lower()
        run = str(step.get("run", "")).lower()
        with_values = _mapping(step.get("with"))
        repository_url = str(with_values.get("repository-url", "")).lower()
        is_publish = "pypa/gh-action-pypi-publish" in uses or (
            ("twine upload" in run or "uv publish" in run)
            and "test.pypi.org" not in run
        )
        is_test = "test.pypi.org" in repository_url or "testpypi" in repository_url
        if is_publish and not is_test:
            result.append(step)
    return result


def _detect_token_auth(job: dict[str, object], steps: list[dict[str, object]]) -> bool:
    """Return True when a production publish step explicitly supplies credentials."""
    environments = [_mapping(job.get("env"))]
    for step in steps:
        with_values = _mapping(step.get("with"))
        if "password" in with_values:
            return True
        environments.append(_mapping(step.get("env")))

    credential_names = {"TWINE_PASSWORD", "UV_PUBLISH_PASSWORD"}
    return any(any(str(key).upper() in credential_names for key in env) for env in environments)


def _unpinned_actions(jobs: dict[str, object]) -> list[str]:
    """Return action references not pinned to a full 40-char commit SHA."""
    unpinned: list[str] = []
    for raw_job in jobs.values():
        job = _mapping(raw_job)
        refs = [job.get("uses")]
        refs.extend(_mapping(step).get("uses") for step in _sequence(job.get("steps")))
        for raw_ref in refs:
            if not raw_ref:
                continue
            ref = str(raw_ref)
            if ref.startswith(("./", "docker://")):
                continue
            pin = ref.rsplit("@", 1)[-1] if "@" in ref else ""
            if not re.fullmatch(r"[a-f0-9]{40}", pin):
                unpinned.append(ref)
    return unpinned


_SAFE_RELEASE_ACTIONS = {"created", "published", "released", "prereleased"}


def _safe_release_action(trigger_map: dict[str, object]) -> tuple[bool, str]:
    release = _mapping(trigger_map.get("release"))
    types = release.get("types")
    actions = {str(types)} if isinstance(types, str) else {
        str(item) for item in _sequence(types)
    }
    action = next(iter(actions)) if len(actions) == 1 else ""
    return action in _SAFE_RELEASE_ACTIONS, action


def _tag_push(trigger_map: dict[str, object]) -> tuple[bool, list[str]]:
    push = _mapping(trigger_map.get("push"))
    raw_tags = push.get("tags")
    tags = [str(raw_tags)] if isinstance(raw_tags, str) else [
        str(item) for item in _sequence(raw_tags)
    ]
    branch_filters = {"branches", "branches-ignore"} & set(push)
    return bool(tags) and not branch_filters, tags


def _condition_is_tag_guard(condition: object) -> bool:
    value = str(condition or "")
    return bool(
        re.search(r"github\.ref_type\s*==\s*['\"]tag['\"]", value)
        or re.search(
            r"startsWith\(\s*github\.ref\s*,\s*['\"]refs/tags/['\"]\s*\)",
            value,
            re.IGNORECASE,
        )
    )


def _manual_publish_is_tag_guarded(
    publish_jobs: list[dict[str, object]]
) -> bool:
    for job in publish_jobs:
        if _condition_is_tag_guard(job.get("if")):
            continue
        steps = _publish_steps(job)
        if not steps or not all(_condition_is_tag_guard(step.get("if")) for step in steps):
            return False
    return bool(publish_jobs)


def _publish_trigger_policy(
    config: dict[str, object], publish_jobs: list[dict[str, object]]
) -> tuple[bool, str, bool, bool]:
    trigger_map = _mapping(config.get("on"))
    names = _trigger_names(config)
    has_dispatch = "workflow_dispatch" in names
    automatic = names - {"workflow_dispatch"}
    guarded = has_dispatch and _manual_publish_is_tag_guarded(publish_jobs)

    safe_automatic = False
    description = ", ".join(sorted(names)) or "no recognized trigger"
    if automatic == {"release"}:
        safe_release, action = _safe_release_action(trigger_map)
        safe_automatic = safe_release
        if action:
            description = f"release: {action}"
    elif automatic == {"push"}:
        safe_push, tags = _tag_push(trigger_map)
        safe_automatic = safe_push
        if tags:
            description = f"tag push: {', '.join(tags)}"

    safe = safe_automatic or (not automatic and guarded)
    if has_dispatch and not guarded:
        safe = False
    return safe, description, has_dispatch, guarded


def _trigger_names(config: dict[str, object]) -> set[str]:
    triggers = config.get("on")
    if isinstance(triggers, str):
        return {triggers}
    if isinstance(triggers, list):
        return {str(item) for item in triggers}
    return {str(key) for key in _mapping(triggers)}


def _has_id_token_write(
    config: dict[str, object], publish_jobs: list[dict[str, object]]
) -> bool:
    workflow_permissions = _mapping(config.get("permissions"))
    for job in publish_jobs:
        permissions = _mapping(job.get("permissions")) or workflow_permissions
        if str(permissions.get("id-token", "")).lower() != "write":
            return False
    return bool(publish_jobs)


def _parse_workflow(filename: str, content: str) -> Optional[WorkflowFile]:
    try:
        config = yaml.load(content, Loader=yaml.BaseLoader)
    except yaml.YAMLError as exc:
        if "pypa/gh-action-pypi-publish" not in content and "twine upload" not in content:
            return None
        return WorkflowFile(
            filename=filename,
            has_safe_publish_trigger=None,
            trigger_description="unparseable",
            has_id_token_write=None,
            has_workflow_dispatch="workflow_dispatch" in content,
            workflow_dispatch_tag_guarded=False,
            uses_token_auth=False,
            has_skip_existing_true=False,
            unpinned_actions=[],
            parse_error=str(exc).splitlines()[0],
        )

    if not isinstance(config, dict):
        return None
    jobs = _mapping(config.get("jobs"))
    publish_jobs: list[dict[str, object]] = []
    publish_steps: list[dict[str, object]] = []
    for raw_job in jobs.values():
        job = _mapping(raw_job)
        steps = _publish_steps(job)
        if steps:
            publish_jobs.append(job)
            publish_steps.extend(steps)
    if not publish_jobs:
        return None

    safe_trigger, trigger_description, has_dispatch, dispatch_guarded = (
        _publish_trigger_policy(config, publish_jobs)
    )
    return WorkflowFile(
        filename=filename,
        has_safe_publish_trigger=safe_trigger,
        trigger_description=trigger_description,
        has_id_token_write=_has_id_token_write(config, publish_jobs),
        has_workflow_dispatch=has_dispatch,
        workflow_dispatch_tag_guarded=dispatch_guarded,
        uses_token_auth=any(
            _detect_token_auth(job, _publish_steps(job)) for job in publish_jobs
        ),
        has_skip_existing_true=any(
            _is_true(_mapping(step.get("with")).get("skip-existing"))
            for step in publish_steps
        ),
        unpinned_actions=_unpinned_actions(jobs),
    )


def _find_publish_workflows(
    owner: str, repo: str, client: httpx.Client, token: Optional[str]
) -> list[WorkflowFile]:
    headers = _gh_headers(token)
    r = client.get(
        f"{GH_API}/repos/{owner}/{repo}/contents/.github/workflows", headers=headers
    )
    if r.status_code == 404:
        return []
    r.raise_for_status()

    workflows: list[WorkflowFile] = []

    for entry in r.json():
        if not entry["name"].endswith((".yml", ".yaml")):
            continue
        download_url = entry.get("download_url")
        if not download_url:
            continue
        cr = client.get(download_url)
        if cr.status_code == 404:
            continue
        cr.raise_for_status()
        workflow = _parse_workflow(entry["name"], cr.text)
        if workflow is not None:
            workflows.append(workflow)

    return sorted(workflows, key=lambda workflow: workflow.filename)


def _get_recent_runs(
    owner: str,
    repo: str,
    workflow_filename: str,
    client: httpx.Client,
    token: Optional[str],
    limit: int = 10,
) -> list[RunSummary]:
    headers = _gh_headers(token)
    r = client.get(
        f"{GH_API}/repos/{owner}/{repo}/actions/workflows/{workflow_filename}/runs",
        headers=headers,
        params={"per_page": limit},
    )
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return [
        RunSummary(
            run_id=run["id"],
            event=run["event"],
            conclusion=run.get("conclusion") or "",
            head_branch=run.get("head_branch") or "",
            url=run["html_url"],
            workflow_filename=workflow_filename,
        )
        for run in r.json().get("workflow_runs", [])
    ]


def _check_head_version(
    owner: str, repo: str, client: httpx.Client, token: Optional[str]
) -> tuple[Optional[str], bool]:
    """Return (static version, is_dynamic) from pyproject.toml."""
    headers = _gh_headers(token)
    r = client.get(
        f"{GH_API}/repos/{owner}/{repo}/contents/pyproject.toml", headers=headers
    )
    if r.status_code != 200:
        if r.status_code == 404:
            return None, False
        r.raise_for_status()
    try:
        content = base64.b64decode(r.json()["content"])
        project = _mapping(tomllib.loads(content.decode()).get("project"))
        version = project.get("version")
        dynamic = [str(item) for item in _sequence(project.get("dynamic"))]
        return (str(version) if version is not None else None, "version" in dynamic)
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None, False


def _check_changelog_entry(
    owner: str, repo: str, version: str, client: httpx.Client, token: Optional[str]
) -> Optional[bool]:
    """Return True/False if a changelog exists; None if no changelog file found."""
    headers = _gh_headers(token)
    for directory in _CHANGELOG_DIRS:
        for name in _CHANGELOG_NAMES:
            path = f"{directory}/{name}" if directory else name
            r = client.get(
                f"{GH_API}/repos/{owner}/{repo}/contents/{path}", headers=headers
            )
            if r.status_code == 404:
                continue
            r.raise_for_status()
            try:
                content = base64.b64decode(r.json()["content"]).decode()
            except (KeyError, UnicodeDecodeError, ValueError):
                continue
            return bool(
                re.search(
                    rf"(?:^#+\s.*{re.escape(version)}|^{re.escape(version)}\b)",
                    content,
                    re.MULTILINE,
                )
            )
    return None


def _check_dependabot_actions(
    owner: str, repo: str, client: httpx.Client, token: Optional[str]
) -> bool:
    headers = _gh_headers(token)
    for fname in ("dependabot.yml", "dependabot.yaml"):
        r = client.get(
            f"{GH_API}/repos/{owner}/{repo}/contents/.github/{fname}", headers=headers
        )
        if r.status_code != 404:
            r.raise_for_status()
        if r.status_code == 200:
            try:
                content = base64.b64decode(r.json()["content"]).decode()
                if "github-actions" in content:
                    return True
            except Exception:
                pass
    return False


# ── Diagnosis ─────────────────────────────────────────────────────────────────

def _next_patch(version: str) -> str:
    try:
        parsed = Version(version)
        release = list(parsed.release)
        while len(release) < 3:
            release.append(0)
        release[2] += 1
        return ".".join(str(part) for part in release[:3])
    except InvalidVersion:
        return version + ".1"


def _repub_steps(
    pypi_name: str, current_version: str, historical: bool = False
) -> list[str]:
    if historical:
        return [
            f"Do not reuse historical version {current_version}; PyPI releases are immutable",
            "If remediation is required, publish a new version above the current PyPI latest",
            "Publish the new version only from its tag-bound workflow path",
        ]
    nv = _next_patch(current_version)
    return [
        f"Bump the project version to {nv} using the repository's version source",
        "Update the repository's changelog and lockfile if they are tracked",
        f"Commit the release metadata changes for {nv} and push the current branch",
        f"Create and push the repository's conventional release tag for {nv}",
        f"Create a GitHub release for that tag, titled '{pypi_name} {nv}'",
        "Publish only from the new tag; do not race it with another publish path",
    ]


def _diagnose(report: Report) -> None:  # noqa: C901
    """Populate report.issues, report.warnings, report.steps, and report.ok."""
    version = report.release.version if report.release else "?"

    # ── Package not on PyPI ───────────────────────────────────────────────────
    if report.release is None:
        target = (
            f"release {report.requested_version!r} of package {report.pypi_name!r}"
            if report.requested_version
            else f"package {report.pypi_name!r}"
        )
        report.issues.append(f"PyPI {target} not found")
        report.steps.append(
            "Check the package name (--package flag) or publish to PyPI first"
        )
        return

    # ── Wheel ─────────────────────────────────────────────────────────────────
    if not any(f.endswith(".whl") for f in report.release.filenames):
        report.issues.append(
            f"No wheel (.whl) published for {report.pypi_name} {version} — only sdist"
        )
        report.steps.append(
            "Ensure the publish workflow runs `python -m build` (not just `--sdist`)"
        )

    # ── Unyanked old releases with bad attestations ───────────────────────────
    for v in report.unyanked_old_versions:
        report.warnings.append(
            f"{report.pypi_name} {v} has no valid attestation and is not yanked on PyPI"
        )
        report.steps.append(
            f"Yank {v}: pypi.org/manage/project/{report.pypi_name}/release/{v}/"
        )

    # ── No publish workflow ───────────────────────────────────────────────────
    if not report.workflows and not report.workflow_check_error:
        report.issues.append("No PyPI publish workflow found in .github/workflows/")
        report.steps += [
            "Create .github/workflows/publish-to-pypi.yml using pypa/gh-action-pypi-publish",
            "Add `permissions: id-token: write` to the publish job",
            "Use one tag-bound release action or a version-tag-filtered push trigger",
            "Configure PyPI Trusted Publishing at pypi.org (no API token needed)",
        ]

    # ── Multiple publish workflows ────────────────────────────────────────────
    if len(report.workflows) > 1:
        report.issues.append(
            f"{len(report.workflows)} workflows publish to PyPI — "
            "concurrent runs could race each other"
        )
        report.steps.append(
            "Keep exactly one publish workflow; remove or disable the others"
        )

    for wf in report.workflows:
        if wf.parse_error:
            report.warnings.append(
                f"{wf.filename}: workflow YAML could not be parsed; checks are unknown "
                f"({wf.parse_error})"
            )
            continue

        if wf.has_safe_publish_trigger is False:
            report.issues.append(
                f"{wf.filename}: production publishing is not restricted to a "
                f"release or tag ref (found {wf.trigger_description})"
            )
            report.steps.append(
                f"Restrict {wf.filename} to one tag-bound release action or a "
                "version-tag-filtered push; tag-guard any manual publish path"
            )

        if wf.has_id_token_write is False:
            report.issues.append(
                f"{wf.filename}: each publish job needs `permissions: id-token: write` "
                "(or an equivalent workflow-level permission)"
            )
            report.steps.append(
                f"Add `id-token: write` to the publish job in {wf.filename}"
            )

        if wf.uses_token_auth:
            report.issues.append(
                f"{wf.filename}: explicit publish credentials detected; "
                "these override OIDC and prevent attestation generation"
            )
            report.steps += [
                f"Remove publish password inputs/environment variables from {wf.filename}",
                "Configure PyPI Trusted Publishing so no token is needed",
            ]

        if wf.has_skip_existing_true:
            report.warnings.append(
                f"{wf.filename}: `skip-existing: true` silently swallows upload errors "
                "— a failed publish shows as green"
            )
            report.steps.append(
                f"Remove `skip-existing: true` from {wf.filename} (default is false)"
            )

        for ref in wf.unpinned_actions:
            report.warnings.append(
                f"{wf.filename}: action not pinned to a commit SHA: {ref}"
            )
        if wf.unpinned_actions:
            report.steps.append(
                f"Pin each `uses:` reference in {wf.filename} to a full 40-char "
                "commit SHA (use `pinact run` or Dependabot for rotation)"
            )

    # ── Dependabot for Actions ────────────────────────────────────────────────
    if report.has_dependabot_actions is False:
        report.warnings.append(
            "No Dependabot entry for `github-actions` — "
            "pinned SHA references will never be rotated automatically"
        )
        report.steps.append(
            "Add a `package-ecosystem: github-actions` block to .github/dependabot.yml"
        )

    # ── workflow_dispatch race risk ───────────────────────────────────────────
    for wf in report.workflows:
        if wf.has_workflow_dispatch:
            if wf.workflow_dispatch_tag_guarded:
                report.warnings.append(
                    f"{wf.filename}: manual publishing is enabled but explicitly "
                    "guarded to tag refs"
                )
            else:
                report.warnings.append(
                    f"{wf.filename}: unguarded `workflow_dispatch` can publish from "
                    "a branch ref"
                )
                report.steps.append(
                    f"Remove `workflow_dispatch:` from {wf.filename} or guard every "
                    "publish job with `github.ref_type == 'tag'`"
                )

    # ── Attestation ───────────────────────────────────────────────────────────
    att = report.attestation
    if att is None or not att.present:
        report.issues.append(
            f"No PEP 740 attestation on PyPI for {report.pypi_name} {version}"
        )
        if report.requested_version is None:
            runs = report.recent_runs
            release_run = next((r for r in runs if r.event == "release"), None)
            push_run = next((r for r in runs if r.event == "push"), None)
            dispatch_run = next(
                (r for r in runs if r.event == "workflow_dispatch"), None
            )

            if release_run and release_run.conclusion == "failure":
                report.issues.append(
                    f"Release-event run #{release_run.run_id} failed — the package was "
                    "probably already on PyPI (a manual publish raced the workflow)"
                )
            elif push_run and push_run.conclusion == "failure":
                report.issues.append(
                    f"Tag-push run #{push_run.run_id} failed; inspect the workflow run "
                    "before republishing"
                )
            elif dispatch_run and dispatch_run.run_id > max(
                (run.run_id for run in (release_run, push_run) if run), default=0
            ):
                report.issues.append(
                    "The latest publish run was a workflow_dispatch; verify that it ran "
                    "against the release tag"
                )
            elif (
                not release_run
                and not push_run
                and not dispatch_run
                and not report.runs_check_failed
            ):
                report.issues.append(
                    "No publish workflow runs found — "
                    "package was likely published manually (e.g. `uv publish`)"
                )
        report.steps += _repub_steps(
            report.pypi_name, version, historical=report.requested_version is not None
        )
        return

    cert = att.cert
    if cert is None:
        report.issues.append(
            "Attestation present on PyPI but the Sigstore certificate could not be parsed"
        )
        return

    if not cert.is_tag_ref:
        trigger_hint = f" (trigger: {cert.trigger!r})" if cert.trigger else ""
        report.issues.append(
            f"Attestation cert signed from {cert.git_ref!r}{trigger_hint} — not a "
            "release tag; a branch-capable publish path uploaded the package"
        )
        report.steps += _repub_steps(
            report.pypi_name, version, historical=report.requested_version is not None
        )
        return

    tag_name = cert.git_ref.removeprefix("refs/tags/")
    if tag_name not in (f"v{version}", version):
        report.issues.append(
            f"Attestation tag {tag_name!r} does not match PyPI version {version!r}"
        )
        report.steps += _repub_steps(
            report.pypi_name, version, historical=report.requested_version is not None
        )
        return

    # ── Version consistency ───────────────────────────────────────────────────
    if report.head_version and report.head_version != version:
        report.warnings.append(
            f"pyproject.toml on HEAD has version {report.head_version!r} "
            f"but latest PyPI release is {version!r} — "
            "unreleased changes exist on the default branch"
        )
    elif report.head_version_dynamic:
        report.warnings.append(
            "pyproject.toml declares a dynamic version; HEAD/PyPI version consistency "
            "was not checked"
        )

    # ── CHANGELOG ─────────────────────────────────────────────────────────────
    if report.changelog_has_entry is False:
        report.warnings.append(f"No CHANGELOG entry found for version {version}")
        report.steps.append(f"Add a {version} section to the CHANGELOG")
    elif report.changelog_has_entry is None and not report.changelog_check_failed:
        report.warnings.append("No CHANGELOG file found in known repository locations")

    report.ok = not report.issues


# ── Main analysis pipeline ────────────────────────────────────────────────────

def _analyze(
    repo: str,
    pypi_name: str,
    client: httpx.Client,
    token: Optional[str],
    version: Optional[str] = None,
) -> Report:
    owner, name = repo.split("/", 1)
    report = Report(repo=repo, pypi_name=pypi_name, requested_version=version)

    try:
        report.release = _fetch_pypi_release(pypi_name, client, version)
    except Exception as e:
        report.issues.append(f"PyPI fetch error: {e}")
        return report

    if report.release:
        try:
            report.attestation = _check_attestation(report.release, client)
        except Exception as e:
            report.issues.append(f"Attestation check error: {e}")

        if version is None:
            try:
                report.unyanked_old_versions = _find_unyanked_bad_releases(
                    pypi_name, report.release.version, client
                )
            except Exception as e:
                report.warnings.append(f"Yanked-release check error: {e}")

    try:
        report.workflows = _find_publish_workflows(owner, name, client, token)
    except Exception as e:
        report.workflow_check_error = str(e)
        report.warnings.append(f"GitHub workflow check unavailable: {e}")

    if version is None:
        for workflow in report.workflows:
            try:
                report.recent_runs.extend(
                    _get_recent_runs(owner, name, workflow.filename, client, token)
                )
            except Exception as e:
                report.runs_check_failed = True
                report.warnings.append(
                    f"GitHub runs fetch error for {workflow.filename}: {e}"
                )
    report.recent_runs.sort(key=lambda run: run.run_id, reverse=True)

    if version is None:
        try:
            report.head_version, report.head_version_dynamic = _check_head_version(
                owner, name, client, token
            )
        except Exception as e:
            report.warnings.append(f"Head-version check error: {e}")

    if report.release:
        try:
            report.changelog_has_entry = _check_changelog_entry(
                owner, name, report.release.version, client, token
            )
        except Exception as e:
            report.changelog_check_failed = True
            report.warnings.append(f"Changelog check error: {e}")

    try:
        report.has_dependabot_actions = _check_dependabot_actions(
            owner, name, client, token
        )
    except Exception as e:
        report.warnings.append(f"Dependabot check error: {e}")

    _diagnose(report)
    return report


# ── Output ────────────────────────────────────────────────────────────────────

_G = "\033[32m"  # green
_R = "\033[31m"  # red
_Y = "\033[33m"  # yellow
_B = "\033[1m"   # bold
_X = "\033[0m"   # reset


def _print_report(r: Report) -> None:
    version = r.release.version if r.release else "?"
    mark = f"{_G}✓{_X}" if r.ok else f"{_R}✗{_X}"
    typer.echo(f"\n{_B}{r.repo}{_X}  {version}  {mark}")

    if r.ok:
        att = r.attestation
        cert = att.cert if att else None
        typer.echo(f"  {_G}✓{_X} PEP 740 attestation present")
        if cert:
            typer.echo(f"  {_G}✓{_X} Signed from {cert.git_ref!r}")
            if cert.trigger:
                typer.echo(f"  {_G}✓{_X} Trigger: {cert.trigger!r}")

    for issue in r.issues:
        typer.echo(f"  {_R}✗{_X} {issue}")

    for warning in r.warnings:
        typer.echo(f"  {_Y}!{_X} {warning}")

    if r.steps:
        label = "Advisory steps" if r.ok else "Fix steps"
        typer.echo(f"\n  {_Y}{label}:{_X}")
        for i, step in enumerate(r.steps, 1):
            typer.echo(f"    {i}. {step}")


# ── CLI ───────────────────────────────────────────────────────────────────────

@app.command(context_settings=_HELP)
def main(
    repos: list[str] = typer.Argument(
        None,
        metavar="OWNER/REPO...",
        help="One or more GitHub repositories. The repo name is the default PyPI name.",
    ),
    package: Optional[str] = typer.Option(
        None, "--package", "-p",
        metavar="NAME",
        help="Use NAME instead of the repo name on PyPI (single-repo only).",
    ),
    pypi_version: Optional[str] = typer.Option(
        None, "--pypi-version", "-V",
        metavar="VERSION",
        help="Audit one immutable PyPI release instead of the latest (single-repo only).",
    ),
    legacy_version: Optional[str] = typer.Option(
        None,
        "--version",
        hidden=True,
    ),
    token: Optional[str] = typer.Option(
        None, "--token", "-t",
        envvar="GITHUB_TOKEN",
        metavar="TOKEN",
        help="GitHub API token. Defaults to GITHUB_TOKEN, then `gh auth token`.",
    ),
) -> None:
    """Audit PyPI release integrity and GitHub publishing hygiene.

    Checks attestations, tag identity, Trusted Publishing permissions, safe
    triggers, action pins, Dependabot, wheels, version consistency, and
    changelog coverage. This command reads public PyPI and GitHub APIs; it does
    not modify repositories or releases.

    **Examples**

    ```console
    # Audit the latest release; PyPI package defaults to "svglib"
    release_hygiene.py deeplook/svglib

    # Audit several latest releases
    release_hygiene.py deeplook/svglib deeplook/sparklines

    # Audit one historical PyPI release
    release_hygiene.py deeplook/svglib --pypi-version 2.0.1

    # Override a PyPI name that differs from the repository
    release_hygiene.py owner/repo --package distribution-name
    ```

    **Results:** `✓` verified, `✗` release-integrity failure, `!` advisory or
    unknown. Exit status is 0 when no hard failures are found, 1 when an audit
    or invocation fails, and 2 for command-line syntax errors.

    Historical audits inspect the selected PyPI artifacts against the current
    repository workflow. They do not infer causality from recent workflow runs
    or compare the historical version with today's HEAD.
    """
    if not repos:
        typer.echo(
            "Audit PyPI release integrity and GitHub publishing hygiene.\n\n"
            "Usage: release_hygiene.py OWNER/REPO... [OPTIONS]\n\n"
            "Examples:\n"
            "  release_hygiene.py deeplook/svglib\n"
            "  release_hygiene.py deeplook/svglib --pypi-version 2.0.1\n\n"
            "Run `release_hygiene.py --help` for all checks and options.",
            err=True,
        )
        raise typer.Exit(2)

    if legacy_version:
        typer.echo(
            "Warning: --version is deprecated; use --pypi-version instead.",
            err=True,
        )
        if pypi_version and pypi_version != legacy_version:
            typer.echo(
                "Error: --pypi-version and deprecated --version disagree.", err=True
            )
            raise typer.Exit(1)
        pypi_version = legacy_version

    if package and len(repos) > 1:
        typer.echo(
            "Error: --package accepts one repository; run separate audits for "
            "different package names.",
            err=True,
        )
        raise typer.Exit(1)
    if pypi_version and len(repos) > 1:
        typer.echo(
            "Error: --pypi-version accepts one repository; run one historical "
            "audit at a time.",
            err=True,
        )
        raise typer.Exit(1)

    resolved_token = _resolve_token(token)
    all_ok = True

    with httpx.Client(follow_redirects=True, timeout=30.0) as client:
        for repo in repos:
            if "/" not in repo:
                typer.echo(
                    f"Error: {repo!r} is not a valid GitHub repository; expected "
                    "OWNER/REPO (for example, deeplook/svglib).",
                    err=True,
                )
                all_ok = False
                continue
            pypi_name = package if (package and len(repos) == 1) else repo.split("/")[-1]
            report = _analyze(
                repo, pypi_name, client, resolved_token, pypi_version
            )
            _print_report(report)
            if not report.ok:
                all_ok = False

    typer.echo()
    raise typer.Exit(0 if all_ok else 1)


if __name__ == "__main__":
    app()
