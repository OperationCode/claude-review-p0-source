"""Workflow file checks (spec "Workflow details", "Fixture eval credential", "Testing").

Parses every file in .github/workflows with PyYAML (duplicate keys rejected).
No network. Each check returns violations as "<file>: <where>: <tag>: <detail>".
The real files must have none. Fixtures prove that each tag catches its
violation: `fixtures/workflows/edits.yml` edits a copy of the real files, and
`fixtures/workflows/eval-boundary/<case>/` holds whole workflow directories
for the eval environment rules (V27).
"""

import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
WORKFLOWS = REPO / ".github" / "workflows"
FIXTURES = Path(__file__).parent / "fixtures" / "workflows"
EVAL_BOUNDARY = FIXTURES / "eval-boundary"

CENTRAL = "claude-review.yml"
TEST = "test.yml"
EVAL = "eval.yml"
EVAL_ENVIRONMENT = "eval"

HARDEN = "step-security/harden-runner"
CHECKOUT = "actions/checkout"
UPLOAD = "actions/upload-artifact"
DOWNLOAD = "actions/download-artifact"
DEPENDENCY_REVIEW_ACTION = "actions/dependency-review-action"
SETUP_UV = "astral-sh/setup-uv"

USES_RE = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}")
USES_LINE_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
VERSION_COMMENT_RE = re.compile(r"#\s*v\d+\.\d+\.\d+\b")
NEEDS_ID_RE = re.compile(r"\$\{\{ needs\.([a-z-]+)\.outputs\.([a-z-]+-artifact-id) \}\}")
STEP_ARTIFACT_ID_RE = re.compile(r"\$\{\{ steps\.([A-Za-z0-9_-]+)\.outputs\.artifact-id \}\}")
# The `secrets` context in any form: secrets.X, secrets['X'], secrets [ 'X' ],
# toJSON(secrets), and the `secrets:` key of a job. Expressions ignore case.
SECRETS_RE = re.compile(r"(?<![\w.-])secrets(?![\w-])", re.IGNORECASE)

# timeout-minutes per job, by workflow file (spec "Workflow details", plan 2.1).
TIMEOUT_MINUTES = {"claude-review.yml": 10, "test.yml": 10, "eval.yml": 30}
DEFAULT_TIMEOUT_MINUTES = 10
# Central workflow (spec "Architecture", "Workflow details").
COLLECT, ANALYZE, DEPENDENCY_REVIEW, GATE = "collect", "analyze", "dependency-review", "oc-claude-review"
CENTRAL_PERMISSIONS = {
    COLLECT: {"contents": "read", "pull-requests": "read"},
    ANALYZE: {"contents": "read", "pull-requests": "read", "id-token": "write"},
    DEPENDENCY_REVIEW: {"contents": "read"},
    GATE: {"contents": "read", "pull-requests": "write", "issues": "write", "actions": "read"},
}
CENTRAL_NEEDS = {
    COLLECT: set(),
    ANALYZE: {COLLECT},
    DEPENDENCY_REVIEW: {COLLECT},
    GATE: {COLLECT, ANALYZE, DEPENDENCY_REVIEW},
}
CENTRAL_REPOSITORY = "OperationCode/.github"
JOB_WORKFLOW_SHA = "${{ job.workflow_sha }}"
# Never the target repo's default branch commit, the run's workflow ref, or any PR ref.
FORBIDDEN_TEXT = ("github.sha", "github.workflow_sha", "pull_request.head", "github.head_ref", "refs/pull/")
# Artifact id output -> (producer upload path, gate download path), under runner.temp.
ARTIFACTS = {
    (COLLECT, "bundle-artifact-id"): ("data/bundle/bundle.json", "data/bundle"),
    (ANALYZE, "review-artifact-id"): ("out/pass-review/pass-review.json", "data/pass-review"),
    (ANALYZE, "security-artifact-id"): ("out/pass-security/pass-security.json", "data/pass-security"),
    (ANALYZE, "supply-chain-artifact-id"): ("out/pass-supply-chain/pass-supply-chain.json", "data/pass-supply-chain"),
}
DOWNLOAD_FORBIDDEN_INPUTS = ("name", "pattern", "run-id", "repository", "github-token", "merge-multiple")
ANALYZE_ENV = {
    "GITHUB_TOKEN": "${{ github.token }}",
    "JOB_WORKFLOW_SHA": JOB_WORKFLOW_SHA,
    "BUNDLE_DIGEST": "${{ needs.collect.outputs.bundle-digest }}",
}
PUBLISH_ENV = {
    "GITHUB_TOKEN": "${{ github.token }}",
    "NEEDS_JSON": "${{ toJSON(needs) }}",
    "BUNDLE_DIGEST": "${{ needs.collect.outputs.bundle-digest }}",
    "REVIEW_DIGEST": "${{ needs.analyze.outputs.review-digest }}",
    "SECURITY_DIGEST": "${{ needs.analyze.outputs.security-digest }}",
    "SUPPLY_CHAIN_DIGEST": "${{ needs.analyze.outputs.supply-chain-digest }}",
    "DEPENDENCY_REVIEW_OUTCOME": "${{ needs.dependency-review.outputs.outcome }}",
}
PUBLISH_STEP_ENV = {**PUBLISH_ENV, "PYTHONPATH": "${{ github.workspace }}/central/review/src"}
GATE_JOB_ENV = {"UV_PYTHON_DOWNLOADS": "never", "UV_PYTHON": "python3.12"}
# The exit code of publish is the gate. With no `shell:` the runner uses
# `bash -e {0}`, so this script exits with the exit code of publish.
PUBLISH_RUN = (
    "printf '%s' \"$NEEDS_JSON\" > \"$RUNNER_TEMP/needs.json\"\n"
    "uv run --no-sync --project central/review python -m oc_review.publish"
    " --data-dir \"$RUNNER_TEMP/data\" --needs-json \"$RUNNER_TEMP/needs.json\"\n"
)
DEFAULT_SHELL = ("bash", "-e")

# test.yml triggers (plan 2.1, O11): every PR with no filter, so the required
# check never stays pending, and pushes to main.
TEST_TRIGGER_PUSH = {"branches": ["main"]}

EVAL_JOB_PERMISSIONS = {"contents": "read", "id-token": "write"}

TAGS = frozenset({
    "parse", "top-permissions", "jobs", "timeout", "continue-on-error", "credential-separation",
    "anthropic-env", "harden-runner", "unpinned-uses", "version-comment", "cache", "setup-uv",
    "run-expression", "trigger", "concurrency", "job-permissions", "job-if", "step-if", "environment",
    "checkout", "forbidden-text", "download", "upload", "job-outputs", "needs", "dependency-review",
    "analyze-env", "publish-env", "publish-run", "secrets", "test-workflow", "eval-environment",
    "eval-permissions", "eval-trigger",
})


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects a duplicate mapping key (it could hide a value)."""


def _construct_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    seen = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


@dataclass(frozen=True)
class Workflow:
    name: str
    text: str
    doc: dict


def load_workflow(path: Path) -> Workflow:
    text = path.read_text(encoding="utf-8")
    doc = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    if not isinstance(doc, dict):
        raise ValueError("not a mapping")
    return Workflow(path.name, text, doc)


def workflow_files(directory: Path) -> list[Path]:
    return sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])


# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

def raw_on(doc: dict) -> Any:
    # PyYAML (YAML 1.1) reads the key `on` as True.
    return doc["on"] if "on" in doc else doc.get(True)


def triggers(doc: dict) -> set[str]:
    on = raw_on(doc)
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return {str(t) for t in on}
    return set()


def jobs(doc: dict) -> dict[str, dict]:
    js = doc.get("jobs")
    return {k: v for k, v in js.items() if isinstance(v, dict)} if isinstance(js, dict) else {}


def steps(job: dict) -> list[dict]:
    ss = job.get("steps")
    return [s for s in ss if isinstance(s, dict)] if isinstance(ss, list) else []


def uses(step: dict) -> str:
    u = step.get("uses")
    return u if isinstance(u, str) else ""


def action(step: dict) -> str:
    return uses(step).split("@", 1)[0]


def inputs(step: dict) -> dict:
    w = step.get("with")
    return w if isinstance(w, dict) else {}


def env(mapping: dict) -> dict:
    e = mapping.get("env")
    return e if isinstance(e, dict) else {}


def needs(job: dict) -> set[str]:
    n = job.get("needs")
    if isinstance(n, str):
        return {n}
    return {str(x) for x in n} if isinstance(n, list) else set()


def strings(node: Any) -> Iterator[str]:
    """Every string key and string value in a parsed document (no comments)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(k)
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def is_false(value: Any) -> bool:
    return value is False or value == "false"


def effective_permissions(doc: dict, job: dict) -> Any:
    return job["permissions"] if "permissions" in job else doc.get("permissions")


def step_running(job: dict, module: str) -> tuple[int, dict] | None:
    for i, step in enumerate(steps(job)):
        run = step.get("run")
        if isinstance(run, str) and f"-m {module}" in run:
            return i, step
    return None


def step_by_id(job: dict, step_id: str) -> dict | None:
    return next((s for s in steps(job) if s.get("id") == step_id), None)


def download_guard(step: dict) -> str | None:
    """The only allowed step `if:` for a download step (decision O4)."""
    m = NEEDS_ID_RE.fullmatch(str(inputs(step).get("artifact-ids", "")))
    return f"needs.{m.group(1)}.outputs.{m.group(2)} != ''" if m else None


def tag_of(violation: str) -> str:
    return violation.split(": ")[2]


class Report:
    def __init__(self, name: str):
        self.name = name
        self.items: list[str] = []

    def add(self, where: str, tag: str, detail: str) -> None:
        assert tag in TAGS, tag
        self.items.append(f"{self.name}: {where}: {tag}: {detail}")


# ---------------------------------------------------------------------------
# Checks for every workflow
# ---------------------------------------------------------------------------

def common_violations(wf: Workflow) -> list[str]:
    r = Report(wf.name)
    doc = wf.doc
    if not isinstance(doc.get("permissions"), dict):
        r.add("workflow", "top-permissions", f"must be a mapping of scopes, got {doc.get('permissions')!r}")
    if any(str(k).startswith("ANTHROPIC_") for k in env(doc)):
        r.add("workflow", "anthropic-env", "no ANTHROPIC_* variable")
    if not jobs(doc):
        r.add("workflow", "jobs", "no jobs")
    used = [s for s in strings(doc) if SECRETS_RE.search(s)]
    if used:
        r.add("workflow", "secrets", f"no secrets context in any form, got {used!r}")
    want_timeout = TIMEOUT_MINUTES.get(wf.name, DEFAULT_TIMEOUT_MINUTES)
    parsed_uses = 0
    for name, job in jobs(doc).items():
        timeout = job.get("timeout-minutes")
        if type(timeout) is not int or timeout != want_timeout:
            r.add(name, "timeout", f"timeout-minutes must be {want_timeout}, got {timeout!r}")
        if "continue-on-error" in job:
            r.add(name, "continue-on-error", "not allowed on a job")
        perms = effective_permissions(doc, job)
        if perms == "write-all" or (
            isinstance(perms, dict)
            and perms.get("id-token") == "write"
            and any(v == "write" for k, v in perms.items() if k != "id-token")
        ):
            r.add(name, "credential-separation", f"a job with id-token: write has no GitHub write, got {perms!r}")
        if any(str(k).startswith("ANTHROPIC_") for k in env(job)):
            r.add(name, "anthropic-env", "no ANTHROPIC_* variable")
        if isinstance(job.get("uses"), str):
            parsed_uses += 1
            if not USES_RE.fullmatch(job["uses"]):
                r.add(name, "unpinned-uses", f"{job['uses']!r} is not pinned by full commit SHA")
        ss = steps(job)
        if not ss or action(ss[0]) != HARDEN:
            r.add(name, "harden-runner", "step 1 must be step-security/harden-runner")
        for i, step in enumerate(ss, 1):
            where = f"{name} step {i}"
            if "continue-on-error" in step:
                r.add(where, "continue-on-error", "not allowed on a step")
            if any(str(k).startswith("ANTHROPIC_") for k in env(step)):
                r.add(where, "anthropic-env", "no ANTHROPIC_* variable")
            run = step.get("run")
            if isinstance(run, str) and "${{" in run:
                r.add(where, "run-expression", "no ${{ }} in run:, pass values through env:")
            if "uses" not in step:
                continue
            parsed_uses += 1
            u, a, w = uses(step), action(step), inputs(step)
            if not USES_RE.fullmatch(u):
                r.add(where, "unpinned-uses", f"{u!r} is not pinned by full commit SHA")
            if a == "actions/cache" or a.startswith("actions/cache/"):
                r.add(where, "cache", "actions/cache is not allowed")
            if a == SETUP_UV and not is_false(w.get("enable-cache")):
                r.add(where, "setup-uv", "setup-uv needs enable-cache: false")
            if a == HARDEN:
                policy = w.get("egress-policy")
                if policy not in ("audit", "block"):
                    r.add(where, "harden-runner", f"egress-policy must be audit or block, got {policy!r}")
                if policy == "block" and not str(w.get("allowed-endpoints") or "").split():
                    r.add(where, "harden-runner", "block mode needs allowed-endpoints")
    raw_uses = 0
    for lineno, line in enumerate(wf.text.splitlines(), 1):
        m = USES_LINE_RE.match(line)
        if m:
            raw_uses += 1
            if not VERSION_COMMENT_RE.search(m.group(2)):
                r.add(f"line {lineno}", "version-comment", "uses: needs a version comment like # v1.2.3")
    if raw_uses != parsed_uses:
        r.add("workflow", "version-comment", f"{parsed_uses} uses: values but {raw_uses} plain uses: lines")
    return r.items


# ---------------------------------------------------------------------------
# Central workflow
# ---------------------------------------------------------------------------

def central_violations(wf: Workflow) -> list[str]:
    r = Report(wf.name)
    doc = wf.doc
    js = jobs(doc)
    if raw_on(doc) not in ("pull_request_target", ["pull_request_target"], {"pull_request_target": None}):
        r.add("workflow", "trigger", f"pull_request_target only, with no filters, got {raw_on(doc)!r}")
    if doc.get("permissions") != {}:
        r.add("workflow", "top-permissions", "must be {}")
    if "concurrency" in doc:
        r.add("workflow", "concurrency", "no concurrency group")
    if set(js) != set(CENTRAL_PERMISSIONS):
        r.add("workflow", "jobs", f"jobs must be {sorted(CENTRAL_PERMISSIONS)}, got {sorted(js)}")
    for s in FORBIDDEN_TEXT:
        if s in wf.text:
            r.add("workflow", "forbidden-text", f"{s!r} must not appear")

    for name, job in js.items():
        if "concurrency" in job:
            r.add(name, "concurrency", "no concurrency group")
        if "environment" in job:
            r.add(name, "environment", "no job uses an environment")
        if name in CENTRAL_PERMISSIONS and job.get("permissions") != CENTRAL_PERMISSIONS[name]:
            r.add(name, "job-permissions", f"must be {CENTRAL_PERMISSIONS[name]}, got {job.get('permissions')!r}")
        if name in CENTRAL_NEEDS and needs(job) != CENTRAL_NEEDS[name]:
            r.add(name, "needs", f"must need {sorted(CENTRAL_NEEDS[name])}, got {sorted(needs(job))}")
        if name == GATE:
            if job.get("if") != "always()":
                r.add(name, "job-if", "the gate job has if: always()")
        elif "if" in job:
            r.add(name, "job-if", "only the gate job has an if:")
        checkouts = 0
        gate_downloads = set()
        ss = steps(job)
        for i, step in enumerate(ss):
            where = f"{name} step {i + 1}"
            a, w = action(step), inputs(step)
            if "if" in step and not (name == GATE and a == DOWNLOAD and step["if"] == download_guard(step)):
                r.add(where, "step-if", f"no step if: except the gate download guard, got {step['if']!r}")
            if a == CHECKOUT:
                checkouts += 1
                if (
                    w.get("repository") != CENTRAL_REPOSITORY
                    or w.get("ref") != JOB_WORKFLOW_SHA
                    or w.get("persist-credentials") is not False
                ):
                    r.add(where, "checkout", f"check out {CENTRAL_REPOSITORY} at {JOB_WORKFLOW_SHA} only, "
                                             "with persist-credentials: false")
            elif a == DOWNLOAD:
                m = NEEDS_ID_RE.fullmatch(str(w.get("artifact-ids", "")))
                key = (m.group(1), m.group(2)) if m else None
                if key not in ARTIFACTS:
                    r.add(where, "download", "artifact-ids must be one producer artifact id output")
                if any(k in w for k in DOWNLOAD_FORBIDDEN_INPUTS):
                    r.add(where, "download", f"download by artifact-ids only, never {DOWNLOAD_FORBIDDEN_INPUTS}")
                if w.get("digest-mismatch") != "error":
                    r.add(where, "download", "digest-mismatch: error")
                if name == GATE and key in ARTIFACTS:
                    gate_downloads.add(key)
                    if step.get("if") != download_guard(step):
                        r.add(where, "download", f"gate downloads need the guard if: {download_guard(step)}")
                    if w.get("path") != "${{ runner.temp }}/" + ARTIFACTS[key][1]:
                        r.add(where, "download", f"path must be runner.temp/{ARTIFACTS[key][1]}")
                elif name == ANALYZE and key == (COLLECT, "bundle-artifact-id"):
                    prev = ss[i - 1] if i else {}
                    run = str(prev.get("run", ""))
                    if (
                        env(prev).get("BUNDLE_ARTIFACT_ID") != "${{ needs.collect.outputs.bundle-artifact-id }}"
                        or '-z "$BUNDLE_ARTIFACT_ID"' not in run
                        or "exit 1" not in run
                    ):
                        r.add(where, "download", "the step before the download fails on an empty bundle id")
                    if w.get("path") != "${{ runner.temp }}/data/bundle":
                        r.add(where, "download", "path must be runner.temp/data/bundle")
                else:
                    r.add(where, "download", "only analyze (bundle) and the gate job download artifacts")
            elif a == UPLOAD:
                if name not in (COLLECT, ANALYZE):
                    r.add(where, "upload", "only collect and analyze upload artifacts")
                if w.get("if-no-files-found") != "error":
                    r.add(where, "upload", "if-no-files-found: error")
                if "${{ github.run_attempt }}" not in str(w.get("name", "")):
                    r.add(where, "upload", "the artifact name carries github.run_attempt")
            elif a == DEPENDENCY_REVIEW_ACTION and name != DEPENDENCY_REVIEW:
                r.add(where, "dependency-review", "only the dependency-review job runs the action")
        if name in (COLLECT, ANALYZE, GATE) and checkouts != 1:
            r.add(name, "checkout", f"exactly one checkout of the central code, got {checkouts}")
        if name == DEPENDENCY_REVIEW and checkouts:
            r.add(name, "checkout", "dependency-review has no checkout")
        if name == GATE and gate_downloads != {k for k in ARTIFACTS}:
            r.add(name, "download", f"the gate downloads each artifact once, got {sorted(gate_downloads)}")

    # Artifact ids come from the upload steps; digests from the trusted producer steps.
    for (job_name, output), (upload_path, _) in ARTIFACTS.items():
        job = js.get(job_name, {})
        outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
        m = STEP_ARTIFACT_ID_RE.fullmatch(str(outputs.get(output, "")))
        step = step_by_id(job, m.group(1)) if m else None
        if step is None or action(step) != UPLOAD or inputs(step).get("path") != "${{ runner.temp }}/" + upload_path:
            r.add(job_name, "job-outputs", f"{output} must be the artifact-id of the upload of {upload_path}")
    for job_name, module, digests in (
        (COLLECT, "oc_review.collect", ("bundle-digest",)),
        (ANALYZE, "oc_review.analyze", ("review-digest", "security-digest", "supply-chain-digest")),
    ):
        job = js.get(job_name, {})
        outputs = job.get("outputs") if isinstance(job.get("outputs"), dict) else {}
        found = step_running(job, module)
        sid = found[1].get("id") if found else None
        for d in digests:
            if not sid or outputs.get(d) != f"${{{{ steps.{sid}.outputs.{d} }}}}":
                r.add(job_name, "job-outputs", f"{d} must come from the {module} step")

    dr_job = js.get(DEPENDENCY_REVIEW, {})
    drs = [s for s in steps(dr_job) if action(s) == DEPENDENCY_REVIEW_ACTION]
    if len(drs) != 1 or not drs[0].get("id"):
        r.add(DEPENDENCY_REVIEW, "dependency-review", "exactly one dependency-review-action step, with an id")
    else:
        w = inputs(drs[0])
        outputs = dr_job.get("outputs") if isinstance(dr_job.get("outputs"), dict) else {}
        if outputs.get("outcome") != f"${{{{ steps.{drs[0]['id']}.outcome }}}}":
            r.add(DEPENDENCY_REVIEW, "dependency-review", "job output `outcome` is the step outcome")
        if w.get("fail-on-severity") != "high":
            r.add(DEPENDENCY_REVIEW, "dependency-review", "fail-on-severity: high")
        if w.get("warn-only") is not None and not is_false(w.get("warn-only")):
            r.add(DEPENDENCY_REVIEW, "dependency-review", "warn-only is never true")
        if (w.get("base-ref"), w.get("head-ref")) != (
            "${{ needs.collect.outputs.merge-base-sha }}",
            "${{ needs.collect.outputs.head-sha }}",
        ):
            r.add(DEPENDENCY_REVIEW, "dependency-review", "base-ref and head-ref are the collected pair")

    found = step_running(js.get(ANALYZE, {}), "oc_review.analyze")
    if found is None or any(env(found[1]).get(k) != v for k, v in ANALYZE_ENV.items()):
        r.add(ANALYZE, "analyze-env", f"the analyze step sets {ANALYZE_ENV}")

    gate = js.get(GATE, {})
    found = step_running(gate, "oc_review.publish")
    if found is None or found[0] != len(steps(gate)) - 1:
        r.add(GATE, "publish-env", "publish is the last step of the gate job (its exit code is the gate)")
    else:
        step = found[1]
        if env(step) != PUBLISH_STEP_ENV:
            r.add(GATE, "publish-env", f"the publish step env is exactly {PUBLISH_STEP_ENV}")
        if step.get("run") != PUBLISH_RUN:
            r.add(GATE, "publish-run", "the publish script is exactly PUBLISH_RUN, so its exit code is the gate")
        if "shell" in step:
            r.add(GATE, "publish-run", f"the publish step uses the default shell, got {step['shell']!r}")
    # Nothing may change the shell or the environment that runs publish.
    if "defaults" in doc or "defaults" in gate:
        r.add(GATE, "publish-run", "no defaults: in the workflow or the gate job")
    if "env" in doc:
        r.add("workflow", "publish-run", "no workflow env:")
    if env(gate) != GATE_JOB_ENV:
        r.add(GATE, "publish-run", f"the gate job env is exactly {GATE_JOB_ENV}")
    return r.items


# ---------------------------------------------------------------------------
# test.yml (decision O11)
# ---------------------------------------------------------------------------

def read_only(perms: Any) -> bool:
    return isinstance(perms, dict) and all(
        v in ("read", "none") and (k != "id-token" or v == "none") for k, v in perms.items()
    )


def ci_workflow_violations(wf: Workflow) -> list[str]:
    r = Report(wf.name)
    on = raw_on(wf.doc)
    if (
        not isinstance(on, dict)
        or set(on) != {"pull_request", "push"}
        or on["pull_request"] not in (None, {})
        or on["push"] != TEST_TRIGGER_PUSH
    ):
        r.add("workflow", "test-workflow", f"pull_request with no filter and push to {TEST_TRIGGER_PUSH}, got {on!r}")
    if not read_only(wf.doc.get("permissions")):
        r.add("workflow", "test-workflow", "read-only token")
    for name, job in jobs(wf.doc).items():
        if not read_only(effective_permissions(wf.doc, job)):
            r.add(name, "test-workflow", "read-only token, no id-token")
        if "environment" in job:
            r.add(name, "test-workflow", "no environment")
    return r.items


# ---------------------------------------------------------------------------
# Eval environment boundary (spec "Fixture eval credential", V27)
# ---------------------------------------------------------------------------

def environment_name(value: Any) -> str | None:
    """The literal environment name, or None when it is not a literal string."""
    name = value.get("name") if isinstance(value, dict) else value
    if not isinstance(name, str) or "${{" in name:
        return None
    return name


def eval_boundary_violations(directory: Path) -> list[str]:
    """Only eval.yml may use `eval`, and each job that does states exactly
    contents: read and id-token: write itself. Environment names are not case
    sensitive, so `EVAL` counts; a name that is not a literal counts too."""
    out: list[str] = []
    for path in workflow_files(directory):
        r = Report(path.name)
        try:
            wf = load_workflow(path)
        except (yaml.YAMLError, ValueError) as exc:
            r.add("workflow", "parse", str(exc).splitlines()[0])
            out += r.items
            continue
        if wf.name == EVAL:
            if triggers(wf.doc) != {"workflow_dispatch"}:
                r.add("workflow", "eval-trigger", f"workflow_dispatch only, got {sorted(triggers(wf.doc))}")
            if wf.doc.get("permissions") == "write-all":
                r.add("workflow", "eval-permissions", "write-all at workflow level")
        for name, job in jobs(wf.doc).items():
            if "environment" not in job:
                continue
            env_name = environment_name(job["environment"])
            if env_name is None:
                r.add(name, "eval-environment", f"environment must be a literal string, got {job['environment']!r}")
            uses_eval = env_name is None or env_name.strip().casefold() == EVAL_ENVIRONMENT
            if not uses_eval:
                continue
            if wf.name != EVAL:
                r.add(name, "eval-environment", "only eval.yml may use the eval environment")
            if "permissions" not in job:
                r.add(name, "eval-permissions", "a job that uses eval sets job-level permissions")
            elif job["permissions"] != EVAL_JOB_PERMISSIONS:
                r.add(name, "eval-permissions", f"must be exactly {EVAL_JOB_PERMISSIONS}, got {job['permissions']!r}")
        out += r.items
    return out


# ---------------------------------------------------------------------------
# All checks over one workflow directory
# ---------------------------------------------------------------------------

def all_violations(directory: Path) -> list[str]:
    out: list[str] = []
    for path in workflow_files(directory):
        try:
            wf = load_workflow(path)
        except (yaml.YAMLError, ValueError) as exc:
            out.append(f"{path.name}: workflow: parse: {str(exc).splitlines()[0]}")
            continue
        out += common_violations(wf)
        if wf.name == CENTRAL:
            out += central_violations(wf)
        elif wf.name == TEST:
            out += ci_workflow_violations(wf)
    for required in (CENTRAL, TEST, EVAL):
        if not (directory / required).is_file():
            out.append(f"{required}: workflow: jobs: file missing")
    return out + eval_boundary_violations(directory)


# ---------------------------------------------------------------------------
# Tests: the real files
# ---------------------------------------------------------------------------

def central() -> Workflow:
    return load_workflow(WORKFLOWS / CENTRAL)


def test_real_workflows_have_no_violations():
    assert all_violations(WORKFLOWS) == []


def test_central_job_permissions_are_exact():
    assert {name: job.get("permissions") for name, job in jobs(central().doc).items()} == CENTRAL_PERMISSIONS


def test_only_analyze_holds_id_token():
    holders = [name for name, job in jobs(central().doc).items() if "id-token" in job.get("permissions", {})]
    assert holders == [ANALYZE]


def test_dependency_review_exports_the_step_outcome():
    job = jobs(central().doc)[DEPENDENCY_REVIEW]
    (step,) = [s for s in steps(job) if action(s) == DEPENDENCY_REVIEW_ACTION]
    assert job["outputs"] == {"outcome": f"${{{{ steps.{step['id']}.outcome }}}}"}


def test_no_continue_on_error_anywhere():
    for path in workflow_files(WORKFLOWS):
        for name, job in jobs(load_workflow(path).doc).items():
            assert "continue-on-error" not in job, f"{path.name} {name}"
            assert all("continue-on-error" not in s for s in steps(job)), f"{path.name} {name}"


def test_only_eval_yml_uses_the_eval_environment():
    users = [
        (path.name, name)
        for path in workflow_files(WORKFLOWS)
        for name, job in jobs(load_workflow(path).doc).items()
        if "environment" in job and (environment_name(job["environment"]) or EVAL_ENVIRONMENT).strip().casefold() == EVAL_ENVIRONMENT
    ]
    assert users == [(EVAL, "fixture-evals")]


def run_publish_script(script: str, tmp_path: Path, publish_exit: int) -> tuple[int, str]:
    """Run a publish script as the runner does (`bash -e`), with a stub `uv`
    that records its arguments and exits with `publish_exit`. No network."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "uv"
    stub.write_text('#!/bin/sh\nprintf "%s " "$@" > "$RUNNER_TEMP/uv-args"\nexit "$PUBLISH_EXIT"\n', encoding="utf-8")
    stub.chmod(0o755)
    path = tmp_path / "step.sh"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [*DEFAULT_SHELL, str(path)],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "RUNNER_TEMP": str(tmp_path), "NEEDS_JSON": "{}",
             "PUBLISH_EXIT": str(publish_exit)},
        capture_output=True, text=True, timeout=30, check=False,
    )
    args = tmp_path / "uv-args"
    return proc.returncode, args.read_text(encoding="utf-8") if args.exists() else ""


def test_publish_step_runs_the_real_script():
    found = step_running(jobs(central().doc)[GATE], "oc_review.publish")
    assert found is not None
    assert found[1]["run"] == PUBLISH_RUN
    assert "shell" not in found[1]


@pytest.mark.parametrize("publish_exit", [0, 1, 3])
def test_publish_exit_code_is_the_step_exit_code(publish_exit, tmp_path):
    code, args = run_publish_script(PUBLISH_RUN, tmp_path, publish_exit)
    assert code == publish_exit
    assert "-m oc_review.publish" in args
    assert (tmp_path / "needs.json").read_text(encoding="utf-8") == "{}"


# Scripts that hide the publish exit code. The stub check above fails on each,
# and the exact PUBLISH_RUN check rejects each (edits.yml publish-* cases).
HIDDEN_EXIT_SCRIPTS = {
    "true-or": PUBLISH_RUN.replace("uv run", "true || uv run"),
    "or-true": PUBLISH_RUN.replace('needs.json"\n', 'needs.json" || true\n'),
    "exit-trap": "trap 'exit 0' EXIT\n" + PUBLISH_RUN,
}


@pytest.mark.parametrize("case", sorted(HIDDEN_EXIT_SCRIPTS))
def test_publish_stub_check_fails_on_hidden_exit(case, tmp_path):
    script = HIDDEN_EXIT_SCRIPTS[case]
    assert script != PUBLISH_RUN
    code, _ = run_publish_script(script, tmp_path, 3)
    assert code == 0


@pytest.mark.release
def test_harden_runner_blocks_egress():
    """V10 (live step L8): block mode with the measured list. Fails until then."""
    for path in workflow_files(WORKFLOWS):
        for name, job in jobs(load_workflow(path).doc).items():
            w = inputs(steps(job)[0])
            assert w.get("egress-policy") == "block", f"{path.name} {name}"
            assert str(w.get("allowed-endpoints") or "").split(), f"{path.name} {name}"
            assert w.get("disable-telemetry") is True, f"{path.name} {name}"


# ---------------------------------------------------------------------------
# Tests: fixtures prove that each check fails on its violation
# ---------------------------------------------------------------------------

EDITS = yaml.safe_load((FIXTURES / "edits.yml").read_text(encoding="utf-8"))

# Eval boundary fixture directory -> the tag its violation must carry.
EVAL_CASES = {
    "other-file-uses-eval": "eval-environment",
    "other-file-name-form": "eval-environment",
    "other-file-expression": "eval-environment",
    "other-file-uppercase": "eval-environment",
    "yaml-extension": "eval-environment",
    "duplicate-key": "parse",
    "job-write-all": "eval-permissions",
    "workflow-write-all": "eval-permissions",
    "job-read-all": "eval-permissions",
    "job-block-missing": "eval-permissions",
    "pull-requests-write": "eval-permissions",
    "contents-missing": "eval-permissions",
    "workflow-call-trigger": "eval-trigger",
    "push-trigger": "eval-trigger",
}


def expected_tags(case):
    """`expect` is one tag or an exact list of tags the edit trips."""
    expect = case["expect"]
    return {expect} if isinstance(expect, str) else set(expect)


@pytest.mark.parametrize("case", EDITS, ids=[c["id"] for c in EDITS])
def test_edit_is_caught(case, tmp_path):
    directory = tmp_path / "workflows"
    shutil.copytree(WORKFLOWS, directory)
    path = directory / case["file"]
    text = path.read_text(encoding="utf-8")
    assert case["old"] in text, f"edit {case['id']}: old text not in {case['file']}; update the fixture"
    path.write_text(text.replace(case["old"], case["new"], 1), encoding="utf-8")
    violations = all_violations(directory)
    assert {tag_of(v) for v in violations} == expected_tags(case), violations


def test_eval_boundary_good_fixture_passes():
    assert eval_boundary_violations(EVAL_BOUNDARY / "good") == []


@pytest.mark.parametrize("case", sorted(EVAL_CASES))
def test_eval_boundary_fixture_fails(case):
    violations = eval_boundary_violations(EVAL_BOUNDARY / case)
    assert EVAL_CASES[case] in {tag_of(v) for v in violations}, violations


def test_every_eval_fixture_has_a_case():
    dirs = {p.name for p in EVAL_BOUNDARY.iterdir() if p.is_dir()}
    assert dirs == set(EVAL_CASES) | {"good"}


def test_every_tag_has_a_failing_fixture():
    covered = set().union(*(expected_tags(c) for c in EDITS)) | set(EVAL_CASES.values())
    assert covered == TAGS, f"no fixture for {sorted(TAGS - covered)}"
