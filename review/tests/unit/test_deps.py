"""Unit tests for oc_review.deps. No network: registry tests use a fake fetcher."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oc_review import deps
from oc_review.deps import DepsError, RegistryError, UnsupportedVersionError

FIXTURES = Path(__file__).parent / "fixtures" / "deps"


def load(fixture: str, as_path: str) -> deps.ParsedDeps:
    return deps.parse_file(as_path, (FIXTURES / fixture).read_bytes())


def by_name(parsed: deps.ParsedDeps) -> dict[str, list[deps.Package]]:
    out: dict[str, list[deps.Package]] = {}
    for pkg in parsed.packages:
        out.setdefault(pkg.name, []).append(pkg)
    return out


def one(parsed: deps.ParsedDeps, name: str) -> deps.Package:
    found = by_name(parsed)[name]
    assert len(found) == 1, found
    return found[0]


# --- family detection ---------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "family"),
    [
        ("package.json", "package.json"),
        ("web/package-lock.json", "package-lock.json"),
        ("yarn.lock", "yarn.lock"),
        ("pnpm-lock.yaml", "pnpm-lock.yaml"),
        ("pyproject.toml", "pyproject.toml"),
        ("a/b/poetry.lock", "poetry.lock"),
        ("uv.lock", "uv.lock"),
        ("requirements.txt", "requirements"),
        ("requirements-dev.txt", "requirements"),
        ("sub/requirements_test.txt", "requirements"),
        ("constraints.txt", None),
        ("requirements.in", None),
        ("package.json.bak", None),
        ("Gemfile.lock", None),
    ],
)
def test_family_for_path(path, family):
    assert deps.family_for_path(path) == family


def test_unsupported_dep_files():
    assert deps.is_unsupported_dep_file("Gemfile.lock")
    assert deps.is_unsupported_dep_file("svc/go.sum")
    assert not deps.is_unsupported_dep_file("package-lock.json")


def test_parse_unsupported_path_raises():
    with pytest.raises(DepsError):
        deps.parse_file("go.sum", b"")


# --- byte cap and decode ------------------------------------------------------


def test_byte_cap_applies_before_parsing(monkeypatch):
    monkeypatch.setattr(deps, "MAX_DEP_FILE_BYTES", 10)
    called = []
    monkeypatch.setitem(deps._PARSERS, "package.json", lambda text: called.append(text))
    with pytest.raises(DepsError, match="byte cap"):
        deps.parse_file("package.json", b"{" + b" " * 20 + b"}")
    assert called == []


def test_non_utf8_raises():
    with pytest.raises(DepsError, match="UTF-8"):
        deps.parse_file("package.json", b"\xff\xfe{}")


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("package.json", b"{not json"),
        ("package.json", b"[]"),
        ("package.json", b'{"dependencies": ["a"]}'),
        ("package.json", b'{"dependencies": {"a": 1}}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": []}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": {"node_modules/a": 5}}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": {"node_modules/a": {"resolved": "https://registry.npmjs.org/a.tgz"}}}'),
        ("yarn.lock", b"# yarn lockfile v1\n\nfoo@^1:\n  resolved \"x\"\n"),
        ("yarn.lock", b"nothing here"),
        ("pnpm-lock.yaml", b"lockfileVersion: '9.0'\npackages: [1]\n"),
        ("pnpm-lock.yaml", b"lockfileVersion: '9.0'\n: : :\n  - ["),
        ("pyproject.toml", b"[project\n"),
        ("pyproject.toml", b'[project]\ndependencies = ["???"]\n'),
        ("poetry.lock", b"[metadata]\nlock-version = \"2.0\"\n[[package]]\nname = 1\n"),
        ("uv.lock", b"version = 1\n[[package]]\nname = \"a\"\n"),
        ("uv.lock", b"version = 1\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"x\", git = \"y\" }\n"),
    ],
)
def test_malformed_files_raise(path, data):
    with pytest.raises(DepsError):
        deps.parse_file(path, data)


def test_yaml_is_loaded_safely():
    with pytest.raises(DepsError):
        deps.parse_file("pnpm-lock.yaml", b"lockfileVersion: !!python/object/apply:os.getcwd []\n")


# --- package.json --------------------------------------------------------------


def test_package_json():
    parsed = load("package.json", "package.json")
    assert parsed.format_version is None
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "short").source.kind == "git"
    assert one(parsed, "tarball").source.kind == "url"
    assert one(parsed, "local").source.kind == "file"
    assert one(parsed, "aliased").source.official
    assert one(parsed, "ws").source.kind == "workspace"
    assert one(parsed, "jest").version == "^29.0.0"
    assert "fsevents" in by_name(parsed)


# --- package-lock.json ---------------------------------------------------------


def test_package_lock_v2():
    parsed = load("package-lock.v2.json", "package-lock.json")
    assert parsed.format_version == "2"
    assert one(parsed, "left-pad").version == "1.3.0"
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "esbuild").has_install_script is True
    assert one(parsed, "left-pad").has_install_script is False
    nested = one(parsed, "nested")
    assert nested.direct is False
    assert all(p.source.official for p in parsed.packages)
    assert deps.non_registry_sources(parsed) == []


def test_package_lock_v3_sources():
    parsed = load("package-lock.v3.json", "package-lock.json")
    assert parsed.format_version == "3"
    gitdep = one(parsed, "gitdep")
    assert gitdep.source.kind == "git"
    assert gitdep.source.normalized == "git+ssh://github.com/o/r.git#0123456789abcdef"
    assert "git@" not in gitdep.source.normalized
    evil = one(parsed, "evil")
    assert evil.source.kind == "url" and evil.source.host == "evil.example.com"
    assert one(parsed, "real-name").version == "2.0.0"  # alias uses the real name
    assert one(parsed, "linked").source.kind == "workspace"
    assert one(parsed, "bundled").source.kind == "bundled"
    assert "linked" in by_name(parsed) and len(by_name(parsed)["linked"]) == 1
    foreign = {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign}
    assert foreign == {"gitdep", "evil"}
    assert not one(parsed, "bundled").source.foreign


def test_package_lock_v1_is_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("package-lock.v1.json", "package-lock.json")


def test_package_lock_missing_resolved_is_unknown_source():
    data = json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
    ).encode()
    parsed = deps.parse_file("package-lock.json", data)
    assert parsed.packages[0].source.kind == "unknown"
    assert parsed.packages[0].source.foreign


@pytest.mark.parametrize(
    "resolved",
    [
        "http://registry.npmjs.org/a/-/a-1.0.0.tgz",
        "https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz",
        "https://user:pw@registry.npmjs.org/a/-/a-1.0.0.tgz",
        "https://registry.npmjs.org:8443/a/-/a-1.0.0.tgz",
        "https://evil.example/registry.npmjs.org/a.tgz",
    ],
)
def test_lookalike_registry_hosts_are_foreign(resolved):
    source = deps.classify_source(resolved, deps.NPM_OFFICIAL_HOSTS)
    assert source.foreign


def test_url_credentials_are_redacted():
    source = deps.classify_source("https://tok:secret@example.com/a.tgz", frozenset())
    assert "secret" not in source.normalized and "tok" not in source.normalized


# --- yarn.lock -----------------------------------------------------------------


def test_yarn_v1():
    parsed = load("yarn.v1.lock", "yarn.lock")
    assert parsed.format_version == "1"
    core = one(parsed, "@babel/core")
    assert core.version == "7.1.0" and core.source.official
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "tarball").source.kind == "url"
    alias = one(parsed, "real-name")  # `alias@npm:real-name@...`
    assert alias.version == "2.0.1"


@pytest.mark.parametrize("fixture", [f"yarn.berry{v}.lock" for v in (4, 5, 6, 7, 8)])
def test_yarn_berry_versions_parse(fixture):
    parsed = load(fixture, "yarn.lock")
    assert parsed.format_version in {"4", "5", "6", "7", "8"}
    assert parsed.packages


def test_yarn_berry6_sources():
    parsed = load("yarn.berry6.lock", "yarn.lock")
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "demo").source.kind == "workspace"
    assert one(parsed, "typescript").source.official  # builtin patch
    mirror = one(parsed, "mirror")
    assert mirror.source.kind == "url" and mirror.source.host == "evil.example.com"
    assert {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign} == {"forked", "mirror"}


def test_yarn_berry8_scoped_name():
    parsed = load("yarn.berry8.lock", "yarn.lock")
    assert one(parsed, "@scope/pkg").version == "2.1.0"


def test_yarn_berry_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("yarn.berry99.lock", "yarn.lock")


# --- pnpm-lock.yaml ------------------------------------------------------------


@pytest.mark.parametrize(("fixture", "version"), [("pnpm-lock.v6.yaml", "6.0"), ("pnpm-lock.v6_1.yaml", "6.1")])
def test_pnpm_v6(fixture, version):
    parsed = load(fixture, "pnpm-lock.yaml")
    assert parsed.format_version == version
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "@babel/core").version == "7.1.0"  # peer suffix stripped
    assert one(parsed, "esbuild").has_install_script is True
    forked = one(parsed, "forked")
    assert forked.source.kind == "git"
    assert forked.source.normalized.endswith("#abcdef")
    assert one(parsed, "tar").source.kind == "url"


def test_pnpm_v9():
    parsed = load("pnpm-lock.v9.yaml", "pnpm-lock.yaml")
    assert parsed.format_version == "9.0"
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "@babel/core").version == "7.1.0"
    assert one(parsed, "esbuild").has_install_script is True
    evil = one(parsed, "evil")
    assert evil.source.kind == "url" and evil.source.foreign
    assert one(parsed, "left-pad").source.official


def test_pnpm_v5_is_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("pnpm-lock.v5.yaml", "pnpm-lock.yaml")


# --- pyproject.toml ------------------------------------------------------------


def test_pyproject_pep621():
    parsed = load("pyproject.toml", "pyproject.toml")
    assert one(parsed, "requests").version == ">=2.31"
    assert one(parsed, "flask").version == "3.0.0"
    assert one(parsed, "hatchling").direct is True  # build-system.requires
    assert one(parsed, "pytest").version == ">=8"
    assert one(parsed, "ruff").version == ""
    private = one(parsed, "private-lib")
    assert private.source.kind == "git"
    assert one(parsed, "tarpkg").source.kind == "url"
    internal = one(parsed, "internal-pkg")
    assert internal.source.kind == "registry" and not internal.source.official
    assert internal.source.host == "pypi.corp.example"
    assert one(parsed, "rich").source.kind == "file"
    # The corp index is also a file-wide source.
    assert [s.host for s in parsed.global_sources] == ["pypi.corp.example"]
    assert "include-group" not in str(by_name(parsed).keys())


def test_pyproject_poetry():
    parsed = load("pyproject-poetry.toml", "pyproject.toml")
    assert "python" not in by_name(parsed)
    assert one(parsed, "requests").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "local").source.kind == "file"
    # A list of alternatives is one package per alternative.
    assert sorted(p.version for p in by_name(parsed)["multi"]) == ["^1.0", "^2.0"]
    assert one(parsed, "pytest").version == "^8"


# --- poetry.lock ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "version"),
    [("poetry.v1_1.lock", "1.1"), ("poetry.v2_0.lock", "2.0"), ("poetry.v2_1.lock", "2.1")],
)
def test_poetry_lock_versions(fixture, version):
    parsed = load(fixture, "poetry.lock")
    assert parsed.format_version == version
    assert one(parsed, "requests").source.official


def test_poetry_lock_sources():
    parsed = load("poetry.v2_0.lock", "poetry.lock")
    forked = one(parsed, "forked-pkg")  # name is PEP 503 normalized
    assert forked.source.kind == "git"
    assert forked.source.normalized == "https://github.com/o/forked.git#0123456789abcdef"
    corp = one(parsed, "corp")
    assert corp.source.kind == "registry" and corp.source.foreign
    assert one(parsed, "viapypi").source.official


def test_poetry_lock_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("poetry.v3_0.lock", "poetry.lock")


# --- uv.lock -------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["uv.v1.lock", "uv.v1-rev3.lock"])
def test_uv_lock_version_1(fixture):
    parsed = load(fixture, "uv.lock")
    assert parsed.format_version == "1"
    assert one(parsed, "requests").source.official


def test_uv_lock_sources():
    parsed = load("uv.v1.lock", "uv.lock")
    assert one(parsed, "demo").source.kind == "workspace"
    assert one(parsed, "forked-pkg").source.kind == "git"
    assert one(parsed, "tarpkg").source.kind == "url"
    assert one(parsed, "corp").source.foreign
    assert one(parsed, "localpkg").source.kind == "file"
    foreign = {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign}
    assert foreign == {"forked-pkg", "tarpkg", "corp"}


def test_uv_lock_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("uv.v2.lock", "uv.lock")


# --- requirements*.txt ---------------------------------------------------------


def test_requirements():
    parsed = load("requirements.txt", "requirements.txt")
    assert one(parsed, "requests").version == "2.31.0"  # continuation and hashes
    assert one(parsed, "flask").version == ">=3.0"
    assert one(parsed, "django").version == ">=4.2,<5"
    assert one(parsed, "private-lib").source.kind == "git"
    assert one(parsed, "other-pkg").source.kind == "git"
    edit = one(parsed, "edit")
    assert edit.source.kind == "git" and "secret" not in edit.source.normalized
    assert one(parsed, "(url)").source.kind == "url"
    paths = [p for p in parsed.packages if p.name == "(path)"]
    assert {p.version for p in paths} == {"./local/pkg", "../editable"}
    # index-url on another host counts as a file-wide foreign source; pypi.org does not.
    issues = deps.non_registry_sources(parsed)
    assert issues[0].name is None and issues[0].source.host == "pypi.corp.example"
    assert [i.source.host for i in issues if i.name is None] == ["pypi.corp.example"]


# --- delta and agreement -------------------------------------------------------


def test_compute_delta():
    old = deps.parse_file(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                    "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
                    "node_modules/gone": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz"},
                },
            }
        ).encode(),
    )
    new = deps.parse_file(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                    "node_modules/b": {"version": "1.1.0", "resolved": "https://registry.npmjs.org/b/-/b-1.1.0.tgz", "hasInstallScript": True},
                    "node_modules/c": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/c/-/c-2.0.0.tgz"},
                },
            }
        ).encode(),
    )
    changes = {c.name: c for c in deps.compute_delta(old, new)}
    assert set(changes) == {"b", "c"}
    assert changes["b"].old_versions == ("1.0.0",)
    assert changes["b"].new_version == "1.1.0"
    assert changes["b"].has_install_script is True
    assert changes["c"].old_versions == ()
    assert len(deps.compute_delta(None, new)) == 3


def test_delta_catches_source_change_at_same_version():
    def lock(resolved):
        return deps.parse_file(
            "package-lock.json",
            json.dumps(
                {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "resolved": resolved}}}
            ).encode(),
        )

    old = lock("https://registry.npmjs.org/a/-/a-1.0.0.tgz")
    new = lock("https://evil.example.com/a-1.0.0.tgz")
    assert [c.name for c in deps.compute_delta(old, new)] == ["a"]


def test_manifest_without_lockfile():
    repo = ["package.json", "package-lock.json", "svc/pyproject.toml", "svc/uv.lock", "tools/pyproject.toml"]
    assert deps.manifest_without_lockfile(["package.json"], repo) == ["package.json"]
    assert deps.manifest_without_lockfile(["package.json", "package-lock.json"], repo) == []
    assert deps.manifest_without_lockfile(["svc/pyproject.toml"], repo) == ["svc/pyproject.toml"]
    assert deps.manifest_without_lockfile(["svc/pyproject.toml", "svc/uv.lock"], repo) == []
    # No lockfile for this manifest in the repo: no signal.
    assert deps.manifest_without_lockfile(["tools/pyproject.toml"], repo) == []
    # A root lockfile covers a workspace manifest below it.
    assert deps.manifest_without_lockfile(["web/package.json"], repo) == ["web/package.json"]
    assert deps.manifest_without_lockfile(["web/package.json", "package-lock.json"], repo) == []


# --- registry: URL builders ----------------------------------------------------


def test_npm_url():
    assert deps.npm_url("left-pad") == "https://registry.npmjs.org/left-pad"
    assert deps.npm_url("@babel/core") == "https://registry.npmjs.org/@babel%2Fcore"


def test_pypi_url_uses_normalized_name():
    assert deps.pypi_url("Flask_SQLAlchemy") == "https://pypi.org/pypi/flask-sqlalchemy/json"


@pytest.mark.parametrize(
    "name",
    [
        "",
        "../etc/passwd",
        "a/b",
        "@scope/",
        "@/name",
        "a b",
        "a?x=1",
        "a#frag",
        "a%2Fb",
        "https://evil.example/x",
        "evil.example:8080@x",
        ".hidden",
        "_private",
        "a" * 215,
        "a\nb",
        "a\n",
        "a\\b",
    ],
)
def test_npm_url_rejects_bad_names(name):
    with pytest.raises(RegistryError):
        deps.npm_url(name)


@pytest.mark.parametrize(
    "name", ["", "a/b", "../x", "a b", "-x", "x-", "a?b", "a#b", "a%2Fb", "a" * 215, "a\nb", "a\n", "@scope/x"]
)
def test_pypi_url_rejects_bad_names(name):
    with pytest.raises(RegistryError):
        deps.pypi_url(name)


# --- registry: lookups with a fake fetcher ------------------------------------

NPM_DOC = {
    "name": "esbuild",
    "time": {"created": "2020-01-01T00:00:00.000Z", "0.19.0": "2023-06-01T12:30:00.000Z"},
    "versions": {
        "0.19.0": {
            "scripts": {"postinstall": "node install.js", "test": "jest", "prepare": "husky"},
        }
    },
}
PYPI_DOC = {
    "info": {"name": "Flask"},
    "releases": {
        "3.0.0": [
            {"upload_time_iso_8601": "2023-09-30T10:00:00.500000Z"},
            {"upload_time_iso_8601": "2023-09-30T09:59:00.000000Z"},
        ],
        "3.0.1": [],
    },
}


class FakeFetch:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, int, float]] = []

    def __call__(self, url, max_bytes, timeout):
        self.calls.append((url, max_bytes, timeout))
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        return item


def ok(doc, url, status=200):
    return deps.FetchResult(status=status, body=json.dumps(doc).encode(), url=url)


def test_lookup_npm():
    fetch = FakeFetch(ok(NPM_DOC, "https://registry.npmjs.org/esbuild"))
    info = deps.lookup_npm("esbuild", "0.19.0", fetch)
    assert info.published == datetime(2023, 6, 1, 12, 30, tzinfo=UTC)
    assert info.install_scripts == {"postinstall": "node install.js", "prepare": "husky"}
    url, max_bytes, timeout = fetch.calls[0]
    assert url == "https://registry.npmjs.org/esbuild"
    assert max_bytes == deps.NPM_MAX_RESPONSE_BYTES
    assert timeout == deps.REGISTRY_TIMEOUT_SECONDS


def test_lookup_npm_scoped_url():
    doc = {"name": "@a/b", "time": {"1.0.0": "2024-01-01T00:00:00Z"}, "versions": {"1.0.0": {}}}
    fetch = FakeFetch(ok(doc, "https://registry.npmjs.org/@a%2Fb"))
    info = deps.lookup_npm("@a/b", "1.0.0", fetch)
    assert fetch.calls[0][0] == "https://registry.npmjs.org/@a%2Fb"
    assert info.install_scripts == {}


def test_lookup_pypi_takes_earliest_upload():
    fetch = FakeFetch(ok(PYPI_DOC, "https://pypi.org/pypi/flask/json"))
    info = deps.lookup_pypi("Flask", "3.0.0", fetch)
    assert info.published == datetime(2023, 9, 30, 9, 59, tzinfo=UTC)
    assert fetch.calls[0][0] == "https://pypi.org/pypi/flask/json"
    assert fetch.calls[0][1] == deps.PYPI_MAX_RESPONSE_BYTES


def test_lookup_npm_keeps_every_install_lifecycle_script():
    scripts = {"preprepare": "a", "postprepare": "b", "prepublish": "c", "test": "jest", "build": "tsc"}
    doc = {"name": "a", "time": {"1.0.0": "2024-01-01T00:00:00Z"}, "versions": {"1.0.0": {"scripts": scripts}}}
    info = deps.lookup_npm("a", "1.0.0", FakeFetch(ok(doc, "https://registry.npmjs.org/a")))
    assert info.install_scripts == {"preprepare": "a", "postprepare": "b", "prepublish": "c"}


@pytest.mark.parametrize("stamp", ["2020-01-01T00:00:00", "2020-01-01T00:00:00.000", "2020-01-01"])
def test_lookup_npm_time_without_time_zone_is_incomplete(stamp):
    doc = {"name": "a", "time": {"1.0.0": stamp}, "versions": {"1.0.0": {}}}
    with pytest.raises(RegistryError, match="time zone"):
        deps.lookup_npm("a", "1.0.0", FakeFetch(ok(doc, "https://registry.npmjs.org/a")))


@pytest.mark.parametrize(
    "files",
    [
        [{"upload_time_iso_8601": "2020-01-01T00:00:00"}],
        # One naive time among good ones still fails the version.
        [{"upload_time_iso_8601": "2023-01-01T00:00:00Z"}, {"upload_time_iso_8601": "2020-01-01T00:00:00"}],
        # The naive `upload_time` field is never a fallback.
        [{"upload_time": "2020-01-01T00:00:00"}],
        [{"upload_time": "2020-01-01T00:00:00Z"}],
    ],
)
def test_lookup_pypi_time_without_time_zone_is_incomplete(files):
    doc = {"info": {"name": "a"}, "releases": {"1.0": files}}
    with pytest.raises(RegistryError):
        deps.lookup_pypi("a", "1.0", FakeFetch(ok(doc, "https://pypi.org/pypi/a/json")))


def test_lookup_converts_an_offset_to_utc():
    doc = {"name": "a", "time": {"1.0.0": "2020-01-01T02:00:00+02:00"}, "versions": {"1.0.0": {}}}
    info = deps.lookup_npm("a", "1.0.0", FakeFetch(ok(doc, "https://registry.npmjs.org/a")))
    assert info.published == datetime(2020, 1, 1, 0, 0, tzinfo=UTC)


@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:00:00-01:00"])
def test_lookup_time_out_of_utc_range_is_incomplete(stamp):
    doc = {"name": "a", "time": {"1.0.0": stamp}, "versions": {"1.0.0": {}}}
    with pytest.raises(RegistryError, match="out of range"):
        deps.lookup_npm("a", "1.0.0", FakeFetch(ok(doc, "https://registry.npmjs.org/a")))


def test_lookup_never_fetches_for_a_bad_name():
    fetch = FakeFetch(ok({}, "x"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("../x", "1.0.0", fetch)
    with pytest.raises(RegistryError):
        deps.lookup_pypi("a/b", "1.0.0", fetch)
    assert fetch.calls == []


def test_version_is_never_part_of_the_url():
    fetch = FakeFetch(ok(NPM_DOC, "https://registry.npmjs.org/esbuild"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("esbuild", "../../evil", fetch)
    assert fetch.calls[0][0] == "https://registry.npmjs.org/esbuild"


@pytest.mark.parametrize(
    "final_url",
    [
        "https://evil.example.com/esbuild",
        "http://registry.npmjs.org/esbuild",
        "https://registry.npmjs.org.evil.example/esbuild",
        "https://registry.npmjs.org:8443/esbuild",
        "https://user@registry.npmjs.org@evil.example/esbuild",
    ],
)
def test_redirect_to_another_host_is_rejected(final_url):
    fetch = FakeFetch(ok(NPM_DOC, final_url))
    with pytest.raises(RegistryError, match="another host"):
        deps.lookup_npm("esbuild", "0.19.0", fetch)


def test_redirect_status_is_rejected():
    resp = deps.FetchResult(status=302, body=b"", url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="HTTP 302"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


def test_oversized_response_is_rejected_before_parsing():
    body = b"x" * (deps.NPM_MAX_RESPONSE_BYTES + 1)
    resp = deps.FetchResult(status=200, body=body, url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="byte cap"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"name": "other", "time": {}, "versions": {}},
        {"name": "esbuild"},
        {"name": "esbuild", "time": {"0.19.0": "x"}, "versions": {"0.19.0": {}}},
        {"name": "esbuild", "time": {}, "versions": {"0.19.0": {}}},
        {"name": "esbuild", "time": {"0.19.0": "2023-01-01T00:00:00Z"}, "versions": {"0.19.0": {"scripts": []}}},
        {"name": "esbuild", "time": {"0.19.0": "2023-01-01T00:00:00Z"}, "versions": {"0.19.0": {"scripts": {"install": 1}}}},
    ],
)
def test_invalid_npm_documents_raise(doc):
    fetch = FakeFetch(ok(doc, "https://registry.npmjs.org/esbuild"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("esbuild", "0.19.0", fetch)


def test_not_json_raises():
    resp = deps.FetchResult(status=200, body=b"<html>", url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="not JSON"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


@pytest.mark.parametrize("version", ["9.9.9", "3.0.1"])
def test_pypi_missing_or_empty_version_raises(version):
    fetch = FakeFetch(ok(PYPI_DOC, "https://pypi.org/pypi/flask/json"))
    with pytest.raises(RegistryError, match="not found"):
        deps.lookup_pypi("flask", version, fetch)


def test_pypi_response_for_another_package_raises():
    doc = {**PYPI_DOC, "info": {"name": "other"}}
    with pytest.raises(RegistryError, match="another package"):
        deps.lookup_pypi("flask", "3.0.0", FakeFetch(ok(doc, "https://pypi.org/pypi/flask/json")))


def test_retries_then_succeeds():
    sleeps = []
    fetch = FakeFetch(
        TimeoutError("slow"),
        deps.FetchResult(status=503, body=b"", url="https://registry.npmjs.org/esbuild"),
        ok(NPM_DOC, "https://registry.npmjs.org/esbuild"),
    )
    info = deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=sleeps.append)
    assert info.version == "0.19.0"
    assert len(fetch.calls) == 3
    assert len(sleeps) == 2


def test_retries_exhausted_raises():
    fetch = FakeFetch(OSError("down"))
    with pytest.raises(RegistryError, match="failed after 3 attempts"):
        deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=lambda _s: None)
    assert len(fetch.calls) == 3


def test_client_error_is_not_retried():
    resp = deps.FetchResult(status=404, body=b"", url="https://registry.npmjs.org/esbuild")
    fetch = FakeFetch(resp)
    with pytest.raises(RegistryError, match="HTTP 404"):
        deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=lambda _s: None)
    assert len(fetch.calls) == 1


def test_default_fetch_refuses_other_hosts():
    with pytest.raises(RegistryError):
        deps.default_fetch("https://evil.example.com/x", 10, 1.0)
    with pytest.raises(RegistryError):
        deps.default_fetch("http://registry.npmjs.org/x", 10, 1.0)


# --- fix round 1 ---------------------------------------------------------------


def parse(path: str, text: str) -> deps.ParsedDeps:
    return deps.parse_file(path, text.encode())


def foreign_names(parsed: deps.ParsedDeps) -> set[str | None]:
    return {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign}


UV_HEAD = 'version = 1\n[[package]]\nname = "a"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\n'


@pytest.mark.parametrize(
    "tail",
    [
        'wheels = [{ url = "https://evil.com/a.whl", hash = "sha256:x" }]\n',
        'sdist = { url = "https://evil.com/a.tar.gz", hash = "sha256:x" }\n',
        'wheels = [{ url = "https://files.pythonhosted.org/a.whl" }, { url = "https://evil.com/b.whl" }]\n',
    ],
)
def test_uv_lock_foreign_file_host_is_foreign(tail):
    assert foreign_names(parse("uv.lock", UV_HEAD + tail)) == {"a"}


def test_uv_lock_official_file_hosts_are_official():
    tail = 'sdist = { url = "https://files.pythonhosted.org/a.tar.gz" }\nwheels = [{ url = "https://files.pythonhosted.org/a.whl" }]\n'
    assert foreign_names(parse("uv.lock", UV_HEAD + tail)) == set()


@pytest.mark.parametrize(
    "line",
    [
        "-ihttps://evil.com/simple",
        "-fhttps://evil.com",
        "--index=https://evil.com/s",
        "--extra-index https://evil.com/s",
        "--index-url=https://evil.com/s",
        "-i https://evil.com/s",
        "--find-links https://evil.com/s",
    ],
)
def test_requirements_index_option_forms_are_foreign(line):
    parsed = parse("requirements.txt", f"{line}\nflask==3.0.0\n")
    assert None in foreign_names(parsed)


@pytest.mark.parametrize("line", ["--proxy http://x", "-v", "--use-feature=x", "--no-bin x", "--index-url"])
def test_requirements_unknown_option_fails_closed(line):
    with pytest.raises(DepsError):
        parse("requirements.txt", f"{line}\n")


def test_requirements_allowlisted_options_pass():
    text = "--require-hashes\n--no-index\n--pre\n-r other.txt\n-rother.txt\n-c c.txt\n--trusted-host a.b\nflask==3.0.0 --hash=sha256:ab\n"
    parsed = parse("requirements.txt", text)
    assert parsed.global_sources == ()
    assert [p.name for p in parsed.packages] == ["flask"]


def test_requirements_attached_editable():
    parsed = parse("requirements.txt", "-egit+https://github.com/a/b.git#egg=b\n")
    assert one(parsed, "b").source.kind == "git"


NPM_LOCK = (
    '{"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1"}}, '
    '"node_modules/a": {"version": "1.0.0", "resolved": "%s"}}}'
)


def test_npm_tarball_path_must_match_package():
    good = parse("package-lock.json", NPM_LOCK % "https://registry.npmjs.org/a/-/a-1.0.0.tgz")
    assert one(good, "a").source.official
    swapped = parse("package-lock.json", NPM_LOCK % "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz")
    assert foreign_names(swapped) == {"a"}


def test_npm_scoped_tarball_path():
    text = NPM_LOCK.replace('"node_modules/a"', '"node_modules/@s/n"').replace('"1.0.0"', '"1.0.0"')
    ok_ = parse("package-lock.json", text % "https://registry.npmjs.org/@s/n/-/n-1.0.0.tgz")
    assert one(ok_, "@s/n").source.official


def test_npm_tarball_path_change_shows_in_delta():
    old = parse("package-lock.json", NPM_LOCK % "https://registry.npmjs.org/a/-/a-1.0.0.tgz")
    new = parse("package-lock.json", NPM_LOCK % "https://registry.npmjs.org/b/-/b-1.0.0.tgz")
    assert [c.name for c in deps.compute_delta(old, new)] == ["a"]


def test_npm_lock_entry_without_node_modules_is_classified():
    text = '{"lockfileVersion": 3, "packages": {"": {}, "weird": {"version": "1.0.0", "resolved": "git+ssh://evil/x.git"}}}'
    assert foreign_names(parse("package-lock.json", text)) == {"weird"}


def test_npm_lock_workspace_member_dependencies_are_direct():
    text = (
        '{"lockfileVersion": 3, "packages": {"": {"workspaces": ["w"]}, "w": {"dependencies": {"a": "1"}}, '
        '"node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"}}}'
    )
    assert one(parse("package-lock.json", text), "a").direct is True


def test_package_json_extra_sections_are_classified():
    text = (
        '{"peerDependencies": {"p": "git+https://evil/p.git"}, "overrides": {"o": "github:x/y", "n": {".": "1.0.0", "m": "https://evil/m.tgz"}}, '
        '"resolutions": {"**/r": "file:../r"}, "pnpm": {"overrides": {"q": "https://evil/q.tgz"}}}'
    )
    parsed = parse("package.json", text)
    assert foreign_names(parsed) == {"p", "o", "m", "q"}
    assert one(parsed, "n").source.official


def test_berry_patch_of_foreign_descriptor_is_foreign():
    text = (
        '__metadata:\n  version: 8\n\n'
        '"foo@patch:foo@https://evil.example.com/x.tgz#./p.patch::locator=r":\n'
        '  version: 1.0.0\n'
        '  resolution: "foo@patch:foo@https://evil.example.com/x.tgz#./p.patch::version=1.0.0&hash=a"\n'
    )
    assert foreign_names(parse("yarn.lock", text)) == {"foo"}


def test_duplicate_yaml_keys_are_refused():
    with pytest.raises(DepsError, match="duplicate"):
        parse("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: {}\npackages: {}\n")
    with pytest.raises(DepsError, match="duplicate"):
        parse("yarn.lock", "__metadata:\n  version: 8\n  version: 6\n")


def test_pyproject_global_index_options_and_poetry_sources():
    uv = parse(
        "pyproject.toml",
        '[tool.uv]\nindex-url = "https://evil.com/s"\nextra-index-url = ["https://pypi.org/simple", "https://e2.com/s"]\n'
        '[tool.uv.pip]\nfind-links = ["https://e3.com/f"]\n',
    )
    assert {s.host for s in uv.global_sources if s.foreign} == {"evil.com", "e2.com", "e3.com"}
    poetry = parse("pyproject.toml", '[[tool.poetry.source]]\nname = "x"\nurl = "https://evil.com/s"\n')
    assert [s.host for s in poetry.global_sources] == ["evil.com"]


def test_uv_sources_keys_are_normalized():
    text = '[project]\ndependencies = ["my-pkg"]\n[tool.uv.sources]\nMy_Pkg = { git = "https://evil.com/x.git" }\n'
    assert foreign_names(parse("pyproject.toml", text)) == {"my-pkg"}


# Regression (final review I-1): only the first alternative of a source list
# was read, so a later git source, or a second exact pin, was never checked.
UV_ALT_BASE = (
    '[project]\nname = "example"\nversion = "1.0"\ndependencies = ["demo>=1"]\n'
    "[tool.uv.sources]\ndemo = [\n"
    "  {path = \"./demo\", marker = \"sys_platform == 'darwin'\"},\n"
)
UV_ALT_HEAD = UV_ALT_BASE + "  {git = \"https://evil.example/demo.git\", marker = \"sys_platform == 'linux'\"},\n]\n"


def test_uv_source_list_reads_every_alternative():
    parsed = parse("pyproject.toml", UV_ALT_HEAD)
    assert sorted(p.source.kind for p in by_name(parsed)["demo"]) == ["file", "git"]
    assert foreign_names(parsed) == {"demo"}


def test_uv_later_git_alternative_is_in_the_delta():
    [c] = deps.compute_delta(parse("pyproject.toml", UV_ALT_BASE + "]\n"), parse("pyproject.toml", UV_ALT_HEAD))
    assert (c.name, c.source.kind, c.source.foreign) == ("demo", "git", True)
    assert c.source.host == "evil.example"


def test_uv_source_list_with_unknown_alternative_fails():
    text = '[project]\ndependencies = ["demo"]\n[tool.uv.sources]\ndemo = [{path = "./d"}, {marker = "x"}]\n'
    with pytest.raises(DepsError, match="alternative"):
        parse("pyproject.toml", text)


@pytest.mark.parametrize(
    "value, kinds",
    [
        # Local source followed by a foreign one.
        ('[{path = "../d", python = "<3.9"}, {git = "https://evil.example/d.git", python = ">=3.9"}]', ["file", "git"]),
        ('[{path = "../d", python = "<3.9"}, {version = "1.0", source = "corp", python = ">=3.9"}]', ["file", "registry"]),
        ('[{path = "../d", python = "<3.9"}, {url = "https://evil.example/d.tgz", python = ">=3.9"}]', ["file", "url"]),
    ],
)
def test_poetry_local_alternative_then_foreign(value, kinds):
    text = (
        '[[tool.poetry.source]]\nname = "corp"\nurl = "https://pypi.corp.example/simple"\n'
        f"[tool.poetry.dependencies]\ndemo = {value}\n"
    )
    parsed = parse("pyproject.toml", text)
    assert sorted(p.source.kind for p in by_name(parsed)["demo"]) == kinds
    # The corp index is also a file-wide source, with no name.
    assert foreign_names(parsed) - {None} == {"demo"}


def test_poetry_exact_pins_are_one_package_each():
    text = '[tool.poetry.dependencies]\ndemo = [{version = "1.0.0", python = "<3.9"}, {version = "2.0.0", python = ">=3.9"}]\n'
    changes = deps.compute_delta(None, parse("pyproject.toml", text))
    assert sorted(c.new_version for c in changes) == ["1.0.0", "2.0.0"]
    assert all(c.source.official for c in changes)


def test_poetry_empty_alternative_list_fails():
    with pytest.raises(DepsError, match="empty"):
        parse("pyproject.toml", "[tool.poetry.dependencies]\ndemo = []\n")


def test_shrinkwrap_is_an_unsupported_dep_file():
    assert deps.is_unsupported_dep_file("web/npm-shrinkwrap.json")


def test_pnpm_empty_packages_and_non_mapping():
    assert parse("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n").packages == ()
    with pytest.raises(DepsError):
        parse("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: []\n")


def test_lookup_retries_http_client_errors():
    import http.client

    fetch = FakeFetch(http.client.IncompleteRead(b"x"))
    with pytest.raises(RegistryError, match="failed after 3 attempts"):
        deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=lambda _s: None)
    assert len(fetch.calls) == 3


def test_pypi_has_wheel():
    doc = {
        "info": {"name": "x"},
        "releases": {
            "1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z", "packagetype": "sdist"}],
            "2.0": [
                {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "packagetype": "sdist"},
                {"upload_time_iso_8601": "2024-01-01T00:00:00Z", "packagetype": "bdist_wheel"},
            ],
        },
    }
    url = "https://pypi.org/pypi/x/json"
    assert deps.lookup_pypi("x", "1.0", FakeFetch(ok(doc, url))).has_wheel is False
    assert deps.lookup_pypi("x", "2.0", FakeFetch(ok(doc, url))).has_wheel is True
    assert deps.lookup_npm("esbuild", "0.19.0", FakeFetch(ok(NPM_DOC, "https://registry.npmjs.org/esbuild"))).has_wheel is None


def test_lookup_pypi_matches_normalized_version():
    doc = {"info": {"name": "x"}, "releases": {"1.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00Z"}]}}
    info = deps.lookup_pypi("x", "1.0.0", FakeFetch(ok(doc, "https://pypi.org/pypi/x/json")))
    assert info.version == "1.0.0"


class _Resp:
    def __init__(self, chunks, status=200, url="https://registry.npmjs.org/a"):
        self.chunks, self.status, self.url = list(chunks), status, url

    def read(self, n):
        return self.chunks.pop(0)[:n] if self.chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Opener:
    def __init__(self, outcome):
        self.outcome = outcome

    def open(self, request, timeout):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def test_default_fetch_reads_body_and_caps_bytes():
    got = deps.default_fetch("https://registry.npmjs.org/a", 10, 5.0, opener=_Opener(_Resp([b"abcd", b"efgh"])))
    assert got.body == b"abcdefgh" and got.status == 200
    big = deps.default_fetch("https://registry.npmjs.org/a", 4, 5.0, opener=_Opener(_Resp([b"abcdefgh"])))
    assert len(big.body) > 4  # one byte over the cap: the caller refuses it


def test_default_fetch_http_error_and_redirect_statuses():
    import urllib.error

    for code in (302, 404):
        err = urllib.error.HTTPError("https://registry.npmjs.org/a", code, "x", {}, None)
        got = deps.default_fetch("https://registry.npmjs.org/a", 10, 5.0, opener=_Opener(err))
        assert got.status == code
    redirect = deps.FetchResult(status=302, body=b"", url="https://registry.npmjs.org/a")
    with pytest.raises(RegistryError, match="HTTP 302"):
        deps.lookup_npm("a", "1.0.0", FakeFetch(redirect))


def test_default_fetch_total_deadline_and_httplib_errors():
    import http.client

    ticks = iter([0.0, 1.0, 99.0, 99.0])
    with pytest.raises(TimeoutError):
        deps.default_fetch(
            "https://registry.npmjs.org/a", 100, 5.0, opener=_Opener(_Resp([b"a", b"b"])), clock=lambda: next(ticks)
        )
    with pytest.raises(OSError):
        deps.default_fetch(
            "https://registry.npmjs.org/a", 10, 5.0, opener=_Opener(http.client.IncompleteRead(b"x"))
        )
