"""Manifest and lockfile parsers, and registry lookups for the dependency delta.

One parser per supported file family (spec "Dependency delta"). Every parser
reads bytes that a caller took from a blob by SHA. Nothing here reads a path,
runs PR content or opens a URL taken from PR content.

Rules this module keeps:

- The byte cap applies before any parser runs (`MAX_DEP_FILE_BYTES`).
- A file that does not parse, or a lockfile version that is not on the
  supported list, raises `DepsError`. The caller maps it to the hard block
  "incomplete dependency data". A parser never skips an entry it cannot read.
- A lockfile `resolved` field is only classified (registry, git, URL, local).
  It is never fetched.
- Registry lookups go to two fixed routes built from a validated package name.
  The fetch function is injected, so unit tests use a fake and no network.
"""

from __future__ import annotations

import http.client
import json
import re
import shlex
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import yaml

# Byte cap on one manifest or lockfile, applied before parsing.
MAX_DEP_FILE_BYTES = 16 * 1024 * 1024
# Byte caps on registry responses, applied before parsing.
NPM_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
PYPI_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
REGISTRY_TIMEOUT_SECONDS = 20.0
REGISTRY_RETRIES = 2

NPM_REGISTRY_HOST = "registry.npmjs.org"
PYPI_REGISTRY_HOST = "pypi.org"

# Hosts that count as the official registry when found in a lockfile.
# registry.yarnpkg.com is the official npm mirror that yarn v1 writes.
NPM_OFFICIAL_HOSTS = frozenset({"registry.npmjs.org", "registry.yarnpkg.com"})
PYPI_OFFICIAL_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})

# Install lifecycle scripts, for the registry manifest and package.json
# checks alike: the four install scripts, plus the three npm also runs on
# install.
NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish")

FAMILIES = (
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "requirements",
)
LOCKFILE_FAMILIES = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"}
)
# Which lockfile families belong to which manifest family.
MANIFEST_LOCKFILES = {
    "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "pyproject.toml": ("poetry.lock", "uv.lock"),
}

# Dependency files of ecosystems this module does not parse. A change to one
# of them is a prefilter signal.
UNSUPPORTED_DEP_FILES = frozenset(
    {
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "composer.json",
        "composer.lock",
        "pipfile",
        "pipfile.lock",
        "pdm.lock",
        "npm-shrinkwrap.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "mix.exs",
        "mix.lock",
        "pubspec.yaml",
        "pubspec.lock",
        "packages.lock.json",
        "bun.lock",
        "bun.lockb",
        "setup.py",
        "setup.cfg",
        "environment.yml",
    }
)

# Lockfile versions each parser accepts. Anything else is "unknown version".
SUPPORTED_NPM_LOCK_VERSIONS = frozenset({2, 3})
SUPPORTED_YARN_BERRY_VERSIONS = frozenset({4, 5, 6, 7, 8})
SUPPORTED_PNPM_LOCK_VERSIONS = frozenset({"6.0", "6.1", "9.0"})
SUPPORTED_POETRY_LOCK_VERSIONS = frozenset({"1.1", "2.0", "2.1"})
SUPPORTED_UV_LOCK_VERSIONS = frozenset({1})


class DepsError(Exception):
    """Dependency data is incomplete. The caller raises the hard block."""


class UnsupportedVersionError(DepsError):
    """A lockfile has a version this module does not know."""


class RegistryError(DepsError):
    """A registry lookup failed or its response did not validate."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Source:
    """Where a package resolves from, normalized and without credentials.

    kind: registry, git, url, file, workspace, bundled, patch or unknown.
    `official` is true only for a registry source on an official host.
    """

    kind: str
    normalized: str
    host: str | None = None
    official: bool = False

    @property
    def foreign(self) -> bool:
        """True when the prefilter must hard block this source.

        A registry other than the official one, a git or tarball URL, or a
        source the parser cannot place. Local sources (file, workspace,
        bundled, patch) are not foreign; the caller may still show them.
        """
        if self.kind == "registry":
            return not self.official
        return self.kind in ("git", "url", "unknown")


@dataclass(frozen=True)
class Package:
    ecosystem: str  # "npm" or "pypi"
    name: str
    # Resolved version in a lockfile; the declared specifier in a manifest.
    version: str
    source: Source
    # None when the file cannot say (for example yarn.lock, any manifest).
    direct: bool | None = None
    # npm `hasInstallScript` or pnpm `requiresBuild`; None when unknown.
    has_install_script: bool | None = None


@dataclass(frozen=True)
class ParsedDeps:
    path: str
    family: str
    # lockfileVersion, __metadata.version, lock-version and so on; None for
    # a manifest.
    format_version: str | None
    packages: tuple[Package, ...]
    # Sources that apply to the whole file (pip index URLs, find-links).
    global_sources: tuple[Source, ...] = ()

    @property
    def is_lockfile(self) -> bool:
        return self.family in LOCKFILE_FAMILIES


@dataclass(frozen=True)
class SourceIssue:
    """A package or file-wide source that is not the official registry."""

    path: str
    name: str | None
    version: str | None
    source: Source


@dataclass(frozen=True)
class PackageChange:
    path: str
    ecosystem: str
    name: str
    old_versions: tuple[str, ...]
    new_version: str
    source: Source
    direct: bool | None
    has_install_script: bool | None


# ---------------------------------------------------------------------------
# File family detection and signals
# ---------------------------------------------------------------------------

_REQUIREMENTS_RE = re.compile(r"^requirements.*\.txt$")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def family_for_path(path: str) -> str | None:
    """The supported family of a changed path, or None."""
    base = _basename(path)
    if base in FAMILIES and base != "requirements":
        return base
    if _REQUIREMENTS_RE.match(base):
        return "requirements"
    return None


def is_unsupported_dep_file(path: str) -> bool:
    """True for a dependency file of an ecosystem this module does not parse."""
    return _basename(path).lower() in UNSUPPORTED_DEP_FILES


def manifest_without_lockfile(
    changed_paths: Iterable[str], repo_paths: Iterable[str]
) -> list[str]:
    """Changed manifests with a lockfile in the repo but no lockfile change.

    A lockfile matches when it is in the manifest's directory or in a parent
    directory (workspaces keep one root lockfile) and is from the manifest's
    family. The result is sorted. It feeds the "manifest change with no
    lockfile change" signal.
    """
    changed = set(changed_paths)
    repo = set(repo_paths)
    out = []
    for path in sorted(changed):
        family = family_for_path(path)
        if family not in MANIFEST_LOCKFILES:
            continue
        existing = [
            candidate
            for candidate in repo
            if _basename(candidate) in MANIFEST_LOCKFILES[family]
            and _is_ancestor_dir(candidate, path)
        ]
        if existing and not any(candidate in changed for candidate in existing):
            out.append(path)
    return out


def _is_ancestor_dir(file_path: str, other: str) -> bool:
    directory = file_path.rsplit("/", 1)[0] if "/" in file_path else ""
    return directory == "" or other.startswith(directory + "/")


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------

_GIT_PREFIXES = (
    "git+",
    "git://",
    "git@",
    "ssh://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
)
_FILE_PREFIXES = ("file:", "link:", "portal:", "exec:", "./", "../", "/", "~/")
# npm shorthand "user/repo" or "user/repo#ref" means a GitHub repository.
_NPM_GITHUB_SHORTHAND_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(#.*)?$")


def _registry_source(host: str, official: bool) -> Source:
    return Source(kind="registry", normalized=host, host=host, official=official)


def official_npm_source() -> Source:
    return _registry_source(NPM_REGISTRY_HOST, True)


def official_pypi_source() -> Source:
    return _registry_source(PYPI_REGISTRY_HOST, True)


def _npm_registry_source(url: str, name: str, version: str) -> Source:
    """Classify an npm tarball URL; an official host must serve this package.

    The path of an official tarball must be `/<name>/-/<base>-<version>.tgz`.
    Any other path on an official host is a foreign `url` source. The path
    stays in `normalized`, so a swapped tarball shows in the delta.
    """
    src = classify_source(url, NPM_OFFICIAL_HOSTS)
    if src.kind != "registry" or not src.official:
        return src
    text, _host = _normalize_url(url.strip(), keep_fragment=True)
    path = urllib.parse.urlsplit(url.strip()).path
    base = name.rsplit("/", 1)[-1]
    expected = {f"/{name}/-/{base}-{version}.tgz", f"/{name}/-/{base}-{version.split('+', 1)[0]}.tgz"}
    if path not in expected:
        return Source(kind="url", normalized=text, host=src.host)
    return Source(kind="registry", normalized=text.removeprefix("https://"), host=src.host, official=True)


def _normalize_url(url: str, keep_fragment: bool) -> tuple[str, str | None]:
    """Lowercase scheme and host, drop credentials; return (text, host)."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or "").lower()
    netloc = host
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{host}:{port}"
    text = f"{parts.scheme.lower()}://{netloc}{parts.path}"
    if parts.query:
        text += "?" + parts.query
    if keep_fragment and parts.fragment:
        text += "#" + parts.fragment
    return text, host or None


def classify_source(url: str | None, official_hosts: frozenset[str]) -> Source:
    """Classify a lockfile `resolved` value without fetching it."""
    if url is None or not url.strip():
        return Source(kind="unknown", normalized="")
    url = url.strip()
    low = url.lower()
    if low.startswith("workspace:"):
        return Source(kind="workspace", normalized=url)
    if low.startswith(_FILE_PREFIXES):
        return Source(kind="file", normalized=url)
    if low.startswith(_GIT_PREFIXES):
        if "://" in url:
            text, host = _normalize_url(url, keep_fragment=True)
            return Source(kind="git", normalized=text, host=host)
        return Source(kind="git", normalized=url)
    if "://" not in url:
        return Source(kind="unknown", normalized=url)
    parts = urllib.parse.urlsplit(url)
    text, host = _normalize_url(url, keep_fragment=False)
    try:
        port = parts.port
    except ValueError:
        port = -1
    plain = parts.username is None and parts.password is None and port is None
    if parts.scheme.lower() == "https" and host in official_hosts and plain:
        return _registry_source(host or "", True)
    if parts.path.endswith(".git") or ".git#" in url:
        text, host = _normalize_url(url, keep_fragment=True)
        return Source(kind="git", normalized=text, host=host)
    return Source(kind="url", normalized=text, host=host)


def _classify_npm_spec(spec: str) -> Source:
    """Classify a package.json dependency value."""
    spec = spec.strip()
    low = spec.lower()
    if low.startswith("npm:"):
        return official_npm_source()
    if low.startswith(("http://", "https://")):
        return classify_source(spec, frozenset())
    if low.startswith(("workspace:",) + _FILE_PREFIXES + _GIT_PREFIXES):
        return classify_source(spec, frozenset())
    if _NPM_GITHUB_SHORTHAND_RE.match(spec) and not spec.startswith(("@", ".")):
        return Source(kind="git", normalized=f"github:{spec}")
    return official_npm_source()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _decode(data: bytes, path: str) -> str:
    if len(data) > MAX_DEP_FILE_BYTES:
        raise DepsError(f"{path}: {len(data)} bytes is over the {MAX_DEP_FILE_BYTES} byte cap")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise DepsError(f"{path}: not valid UTF-8") from exc


def parse_file(path: str, data: bytes) -> ParsedDeps:
    """Parse one supported dependency file from its blob bytes.

    Raises `DepsError` for an unsupported path, a file over the byte cap, a
    parse failure or an unknown lockfile version.
    """
    family = family_for_path(path)
    if family is None:
        raise DepsError(f"{path}: not a supported dependency file")
    text = _decode(data, path)
    parser = _PARSERS[family]
    try:
        version, packages, global_sources = parser(text)
    except DepsError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
        RecursionError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
    ) as exc:
        raise DepsError(f"{path}: does not parse ({type(exc).__name__}: {exc})") from exc
    return ParsedDeps(
        path=path,
        family=family,
        format_version=version,
        packages=_dedupe(packages),
        global_sources=tuple(global_sources),
    )


def _dedupe(packages: Iterable[Package]) -> tuple[Package, ...]:
    merged: dict[tuple[str, str, str, str], Package] = {}
    for pkg in packages:
        key = (pkg.ecosystem, pkg.name, pkg.version, pkg.source.normalized)
        old = merged.get(key)
        if old is None:
            merged[key] = pkg
            continue
        merged[key] = Package(
            ecosystem=pkg.ecosystem,
            name=pkg.name,
            version=pkg.version,
            source=pkg.source,
            direct=_or_tri(old.direct, pkg.direct),
            has_install_script=_or_tri(old.has_install_script, pkg.has_install_script),
        )
    return tuple(sorted(merged.values(), key=lambda p: (p.ecosystem, p.name, p.version, p.source.normalized)))


def _or_tri(a: bool | None, b: bool | None) -> bool | None:
    if a is True or b is True:
        return True
    if a is None or b is None:
        return None
    return False


# ---------------------------------------------------------------------------
# Small typed accessors: a wrong type is a parse failure, never a skip
# ---------------------------------------------------------------------------


def _as_dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DepsError(f"{what} is not an object")
    return value


def _as_list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise DepsError(f"{what} is not a list")
    return value


def _as_str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise DepsError(f"{what} is not a string")
    return value


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# npm: package.json
# ---------------------------------------------------------------------------

_NPM_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
# Sections npm or pnpm also install from; their values can be git or URL specs.
_NPM_EXTRA_SECTIONS = ("peerDependencies", "overrides", "resolutions")

_Result = tuple[str | None, list[Package], list[Source]]


def _parse_package_json(text: str) -> _Result:
    doc = _as_dict(json.loads(text), "package.json")
    packages = []
    for section in _NPM_DEP_SECTIONS:
        if section not in doc:
            continue
        for name, spec in _as_dict(doc[section], section).items():
            spec = _as_str(spec, f"{section}.{name}")
            packages.append(
                Package(
                    ecosystem="npm",
                    name=name,
                    version=spec,
                    source=_classify_npm_spec(spec),
                    direct=True,
                )
            )
    extra: list[tuple[str, Any]] = [(s_, doc[s_]) for s_ in _NPM_EXTRA_SECTIONS if s_ in doc]
    if "pnpm" in doc and "overrides" in _as_dict(doc["pnpm"], "pnpm"):
        extra.append(("pnpm.overrides", doc["pnpm"]["overrides"]))
    for section, table in extra:
        for name, spec in _walk_npm_specs(_as_dict(table, section), section):
            packages.append(
                Package(ecosystem="npm", name=name, version=spec, source=_classify_npm_spec(spec), direct=True)
            )
    return None, packages, []


def _walk_npm_specs(table: dict[str, Any], what: str) -> Iterable[tuple[str, str]]:
    """(name, spec) pairs of a dependency table; npm `overrides` may nest."""
    for name, value in table.items():
        if isinstance(value, dict):
            for inner, spec in _walk_npm_specs(value, f"{what}.{name}"):
                yield (name if inner == "." else inner), spec
        else:
            yield name, _as_str(value, f"{what}.{name}")


# ---------------------------------------------------------------------------
# npm: package-lock.json (v2, v3)
# ---------------------------------------------------------------------------


def _parse_package_lock(text: str) -> _Result:
    doc = _as_dict(json.loads(text), "package-lock.json")
    version = doc.get("lockfileVersion")
    if isinstance(version, bool) or version not in SUPPORTED_NPM_LOCK_VERSIONS:
        raise UnsupportedVersionError(f"package-lock.json lockfileVersion {version!r} is not supported")
    entries = _as_dict(doc.get("packages"), "packages")
    root = entries.get("", {})
    root_deps: set[str] = set()
    # The root and every workspace member (a key without `node_modules/`)
    # declare direct dependencies.
    for key, entry in entries.items():
        if key != "" and "node_modules/" in key:
            continue
        member = _as_dict(entry, f"packages[{key!r}]")
        for section in (*_NPM_DEP_SECTIONS, "peerDependencies"):
            if section in member:
                root_deps.update(_as_dict(member[section], section))
    packages = []
    for key, entry in entries.items():
        if key == "":
            continue
        entry = _as_dict(entry, f"packages[{key!r}]")
        if "node_modules/" not in key:
            # A workspace member is code in the repo, not a download. One with
            # a `resolved` value is not a plain member: classify it.
            if entry.get("resolved") is not None:
                url = _as_str(entry["resolved"], f"{key} resolved")
                member_name = _as_str(entry.get("name", key), f"{key} name")
                member_version = _as_str(entry.get("version", ""), f"{key} version")
                packages.append(
                    Package(
                        ecosystem="npm",
                        name=member_name,
                        version=member_version,
                        source=_npm_registry_source(url, member_name, member_version),
                        direct=False,
                    )
                )
            continue
        key_name = key.rsplit("node_modules/", 1)[1]
        name = _as_str(entry.get("name", key_name), f"{key} name")
        top_level = key == f"node_modules/{key_name}"
        resolved = entry.get("resolved")
        if resolved is not None:
            resolved = _as_str(resolved, f"{key} resolved")
        if entry.get("link") is True:
            source = Source(kind="workspace", normalized=resolved or "")
        elif resolved is None:
            if entry.get("inBundle") is True:
                source = Source(kind="bundled", normalized="")
            else:
                source = Source(kind="unknown", normalized="")
        pkg_version = entry.get("version")
        if pkg_version is None and entry.get("link") is True:
            pkg_version = ""
        pkg_version = _as_str(pkg_version, f"{key} version")
        if entry.get("link") is not True and resolved is not None:
            source = _npm_registry_source(resolved, name, pkg_version)
        install = entry.get("hasInstallScript")
        if install is not None and not isinstance(install, bool):
            raise DepsError(f"{key} hasInstallScript is not a boolean")
        packages.append(
            Package(
                ecosystem="npm",
                name=name,
                version=pkg_version,
                source=source,
                direct=(key_name in root_deps) if top_level else False,
                has_install_script=bool(install),
            )
        )
    return str(version), packages, []


# ---------------------------------------------------------------------------
# npm: yarn.lock (v1 and berry)
# ---------------------------------------------------------------------------


def _name_from_pattern(pattern: str) -> str:
    """Package name of a yarn descriptor like `@a/b@^1`, `a@npm:b@^1`."""
    i = pattern.find("@", 1)
    if i < 0:
        raise DepsError(f"yarn descriptor {pattern!r} has no range")
    name, spec = pattern[:i], pattern[i + 1 :]
    if spec.startswith("npm:"):
        rest = spec[4:]
        j = rest.find("@", 1)
        if j > 0:  # `alias@npm:real@range`; `name@npm:range` keeps its name
            name = rest[:j]
    return name


_YARN_HEADER_PATTERN_RE = re.compile(r'"[^"]*"|[^,\s][^,]*')
_YARN_FIELD_RE = re.compile(r'^  ([A-Za-z]\w*) (.*)$')


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _parse_yarn_lock(text: str) -> _Result:
    if re.search(r"^__metadata:", text, re.MULTILINE):
        return _parse_yarn_berry(text)
    if not re.search(r"^# yarn lockfile v1\s*$", text, re.MULTILINE):
        raise UnsupportedVersionError("yarn.lock is neither v1 nor berry")
    return "1", _parse_yarn_v1(text), []


def _parse_yarn_v1(text: str) -> list[Package]:
    packages: list[Package] = []
    patterns: list[str] | None = None
    fields: dict[str, str] = {}

    def flush() -> None:
        if patterns is None:
            return
        if "version" not in fields:
            raise DepsError(f"yarn.lock entry {patterns[0]!r} has no version")
        resolved = fields.get("resolved")
        if resolved is None:
            local = all(p.split("@", 1)[-1].startswith(("file:", "link:", "workspace:")) for p in patterns)
            source = Source(kind="file", normalized="") if local else Source(kind="unknown", normalized="")
        else:
            source = _npm_registry_source(resolved, _name_from_pattern(patterns[0]), fields["version"])
        packages.append(
            Package(
                ecosystem="npm",
                name=_name_from_pattern(patterns[0]),
                version=fields["version"],
                source=source,
            )
        )

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            flush()
            if not raw.rstrip().endswith(":"):
                raise DepsError(f"yarn.lock header without colon: {raw[:60]!r}")
            header = raw.rstrip()[:-1]
            patterns = [_unquote(p) for p in _YARN_HEADER_PATTERN_RE.findall(header)]
            if not patterns:
                raise DepsError("yarn.lock entry without a descriptor")
            fields = {}
            continue
        if patterns is None:
            raise DepsError("yarn.lock field before the first entry")
        match = _YARN_FIELD_RE.match(raw)
        if match and match.group(1) in ("version", "resolved"):
            fields[match.group(1)] = _unquote(match.group(2))
    flush()
    return packages


def _yarn_berry_source(resolution: str, name: str, version: str) -> Source:
    # resolution looks like `name@npm:1.2.3` or `name@workspace:.`.
    i = resolution.find("@", 1)
    if i < 0:
        raise DepsError(f"yarn resolution {resolution!r} has no protocol")
    ref = resolution[i + 1 :]
    if ref.startswith("npm:"):
        if "__archiveUrl=" in ref:
            archive = urllib.parse.unquote(ref.split("__archiveUrl=", 1)[1])
            return _npm_registry_source(archive, name, version)
        return official_npm_source()
    if ref.startswith("workspace:"):
        return Source(kind="workspace", normalized=ref)
    if ref.startswith("patch:"):
        # `patch:<inner descriptor>#<patch>::<params>`: classify the inner one.
        inner = urllib.parse.unquote(ref[len("patch:") :].split("#", 1)[0])
        inner_source = _yarn_berry_source(inner, name, version)
        if inner_source.foreign:
            return inner_source
        if "builtin<" in ref:
            return official_npm_source()
        return Source(kind="patch", normalized=ref)
    if ref.startswith(("file:", "link:", "portal:", "exec:")):
        return Source(kind="file", normalized=ref)
    return classify_source(ref, NPM_OFFICIAL_HOSTS)


def _parse_yarn_berry(text: str) -> _Result:
    doc = _as_dict(yaml.load(text, Loader=_UniqueKeyLoader), "yarn.lock")
    meta = _as_dict(doc.get("__metadata"), "__metadata")
    version = meta.get("version")
    if isinstance(version, bool) or version not in SUPPORTED_YARN_BERRY_VERSIONS:
        raise UnsupportedVersionError(f"yarn.lock berry __metadata.version {version!r} is not supported")
    packages = []
    for key, entry in doc.items():
        if key == "__metadata":
            continue
        entry = _as_dict(entry, f"yarn entry {key!r}")
        descriptors = [_unquote(p) for p in _as_str(key, "yarn key").split(",")]
        name = _name_from_pattern(descriptors[0].strip())
        pkg_version = entry.get("version")
        pkg_version = str(pkg_version) if isinstance(pkg_version, (int, float)) else pkg_version
        resolution = _as_str(entry.get("resolution"), f"{key} resolution")
        pkg_version = _as_str(pkg_version, f"{key} version")
        packages.append(
            Package(
                ecosystem="npm",
                name=name,
                version=pkg_version,
                source=_yarn_berry_source(resolution, name, pkg_version),
            )
        )
    return str(version), packages, []


# ---------------------------------------------------------------------------
# npm: pnpm-lock.yaml (v6 and later)
# ---------------------------------------------------------------------------

_SafeLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _UniqueKeyLoader(_SafeLoader):  # type: ignore[misc, valid-type]
    """Safe loader that refuses a duplicate mapping key (parser differential)."""

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise DepsError(f"duplicate YAML key {str(key)[:60]!r}")
            seen.add(key)
        return super().construct_mapping(node, deep)


def _pnpm_split_key(key: str) -> tuple[str, str]:
    """Name and version of a pnpm package key (`/a@1(peer@2)` or `a@1`)."""
    key = key.lstrip("/").split("(", 1)[0]
    i = key.find("@", 1)
    if i < 0:
        raise DepsError(f"pnpm package key {key!r} has no version")
    return key[:i], key[i + 1 :]


def _pnpm_source(resolution: dict[str, Any], key: str, name: str, version: str) -> Source:
    if "tarball" in resolution:
        return _npm_registry_source(_as_str(resolution["tarball"], f"{key} tarball"), name, version)
    rtype = resolution.get("type")
    if rtype == "git" or "repo" in resolution:
        repo = _as_str(resolution.get("repo", ""), f"{key} repo")
        commit = resolution.get("commit", "")
        base = classify_source(repo if "://" in repo else f"git+{repo}", frozenset())
        return Source(kind="git", normalized=f"{base.normalized}#{commit}" if commit else base.normalized, host=base.host)
    if rtype == "directory" or "directory" in resolution:
        return Source(kind="file", normalized=str(resolution.get("directory", "")))
    if "integrity" in resolution:
        return official_npm_source()
    return Source(kind="unknown", normalized="")


def _parse_pnpm_lock(text: str) -> _Result:
    doc = _as_dict(yaml.load(text, Loader=_UniqueKeyLoader), "pnpm-lock.yaml")
    version = str(doc.get("lockfileVersion"))
    if version not in SUPPORTED_PNPM_LOCK_VERSIONS:
        raise UnsupportedVersionError(f"pnpm-lock.yaml lockfileVersion {version!r} is not supported")
    entries = _as_dict({} if doc.get("packages") is None else doc["packages"], "packages")
    snapshots = _as_dict({} if doc.get("snapshots") is None else doc["snapshots"], "snapshots")
    build_names: set[tuple[str, str]] = set()
    for key, snap in snapshots.items():
        if _as_dict(snap, f"snapshots[{key!r}]").get("requiresBuild") is True:
            build_names.add(_pnpm_split_key(key))
    direct_names = _pnpm_direct_names(doc)
    packages = []
    for key, entry in entries.items():
        entry = _as_dict(entry, f"packages[{key!r}]")
        if "name" in entry and "version" in entry:
            # Old-style git and tarball keys carry no `name@version`.
            name, pkg_version = entry["name"], entry["version"]
        else:
            name, pkg_version = _pnpm_split_key(key)
        name = _as_str(name, f"{key} name")
        pkg_version = _as_str(str(pkg_version), f"{key} version")
        resolution = _as_dict(entry.get("resolution"), f"{key} resolution")
        requires_build = entry.get("requiresBuild") is True or (name, pkg_version) in build_names
        packages.append(
            Package(
                ecosystem="npm",
                name=name,
                version=pkg_version,
                source=_pnpm_source(resolution, key, name, pkg_version),
                direct=name in direct_names,
                has_install_script=requires_build,
            )
        )
    return version, packages, []


def _pnpm_direct_names(doc: dict[str, Any]) -> set[str]:
    """Names in the importers (v9, v6 with workspaces) or the root section."""
    sections = [doc]
    importers = doc.get("importers")
    if importers is not None:
        sections.extend(_as_dict(v, "importer") for v in _as_dict(importers, "importers").values())
    names: set[str] = set()
    for section in sections:
        for dep_key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = section.get(dep_key)
            if deps is not None:
                names.update(_as_dict(deps, dep_key))
    return names


# ---------------------------------------------------------------------------
# PyPI: PEP 508 strings
# ---------------------------------------------------------------------------

_PYPI_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_PEP508_RE = re.compile(r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)", re.DOTALL)


def _pypi_package_from_requirement(req: str, *, direct: bool | None) -> Package:
    """Parse a PEP 508 requirement. A direct URL reference sets the source."""
    req = req.strip()
    match = _PEP508_RE.fullmatch(req)
    if not match:
        raise DepsError(f"requirement {req[:60]!r} does not parse")
    name, rest = match.group(1), match.group(2).strip()
    source = official_pypi_source()
    if rest.startswith("@"):
        url = rest[1:].split(";", 1)[0].strip()
        source = classify_source(url, frozenset())
        version = url
    else:
        version = rest.split(";", 1)[0].strip().strip("()").replace(" ", "")
        if version.startswith("==") and not version.startswith("==="):
            exact = version[2:]
            if re.fullmatch(r"[^,<>=!~*]+", exact):
                version = exact
    return Package(ecosystem="pypi", name=_pep503(name), version=version, source=source, direct=direct)


# ---------------------------------------------------------------------------
# PyPI: pyproject.toml
# ---------------------------------------------------------------------------


def _uv_source_overrides(entry: Any, index_urls: Mapping[str, str], what: str) -> list[Source]:
    """Every source a `tool.uv.sources` value names; [] for no override.

    A list holds alternatives, usually split by markers. uv may install any of
    them, so each one is read, whatever its marker. An alternative with no
    known source key is a parse failure, never a skip.
    """
    if entry is None:
        return []
    if not isinstance(entry, list):
        source = _uv_source_override(entry, index_urls, what)
        return [] if source is None else [source]
    sources = []
    for item in entry:
        source = _uv_source_override(item, index_urls, what)
        if source is None:
            raise DepsError(f"{what}: an alternative names no source")
        sources.append(source)
    return sources


def _uv_source_override(entry: Any, index_urls: Mapping[str, str], what: str) -> Source | None:
    entry = _as_dict(entry, what)
    if "git" in entry:
        ref = entry.get("rev") or entry.get("tag") or entry.get("branch") or ""
        base = classify_source(f"git+{entry['git']}" if "://" in str(entry["git"]) else str(entry["git"]), frozenset())
        return Source(kind="git", normalized=f"{base.normalized}#{ref}" if ref else base.normalized, host=base.host)
    if "url" in entry:
        return classify_source(_as_str(entry["url"], what), frozenset())
    if "path" in entry:
        return Source(kind="file", normalized=str(entry["path"]))
    if entry.get("workspace") is True:
        return Source(kind="workspace", normalized="workspace")
    if "index" in entry:
        url = index_urls.get(str(entry["index"]))
        if url is None:
            return Source(kind="unknown", normalized=f"index:{entry['index']}")
        return classify_source(url, PYPI_OFFICIAL_HOSTS) if _is_official_index(url) else _foreign_registry(url)
    return None


def _is_official_index(url: str) -> bool:
    return classify_source(url, PYPI_OFFICIAL_HOSTS).official


def _foreign_registry(url: str) -> Source:
    text, host = _normalize_url(url, keep_fragment=False)
    return Source(kind="registry", normalized=text, host=host, official=False)


def _poetry_dep_source(item: Any, poetry_sources: Mapping[str, str], what: str) -> Source:
    """The source of one Poetry constraint (one alternative of a list)."""
    if isinstance(item, str):
        return official_pypi_source()
    item = _as_dict(item, what)
    if "git" in item:
        ref = item.get("rev") or item.get("tag") or item.get("branch") or ""
        base = classify_source(f"git+{item['git']}" if "://" in str(item["git"]) else str(item["git"]), frozenset())
        return Source(kind="git", normalized=f"{base.normalized}#{ref}" if ref else base.normalized, host=base.host)
    if "url" in item:
        return classify_source(_as_str(item["url"], what), frozenset())
    if "path" in item:
        return Source(kind="file", normalized=str(item["path"]))
    if "source" in item:
        url = poetry_sources.get(str(item["source"]))
        if url is None:
            return Source(kind="unknown", normalized=f"source:{item['source']}")
        if not _is_official_index(url):
            return _foreign_registry(url)
    return official_pypi_source()


def _poetry_dep_version(value: Any) -> str:
    """The version of one Poetry constraint (one alternative of a list)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("version", "git", "url", "path"):
            if key in value:
                return str(value[key])
        return "*"
    raise DepsError("poetry dependency has an unexpected type")


def _parse_pyproject(text: str) -> _Result:
    doc = _as_dict(tomllib.loads(text), "pyproject.toml")
    packages: list[Package] = []
    global_sources: list[Source] = []

    uv_tool = _as_dict(_as_dict(doc.get("tool", {}), "tool").get("uv", {}), "tool.uv")
    index_urls: dict[str, str] = {}
    for index in _as_list(uv_tool.get("index", []), "tool.uv.index"):
        index = _as_dict(index, "tool.uv.index entry")
        if "url" in index:
            url = _as_str(index["url"], "tool.uv.index url")
            if "name" in index:
                index_urls[str(index["name"])] = url
            if not _is_official_index(url):
                global_sources.append(_foreign_registry(url))
    for table, what in ((uv_tool, "tool.uv"), (_as_dict(uv_tool.get("pip", {}), "tool.uv.pip"), "tool.uv.pip")):
        for key in ("index-url", "extra-index-url", "find-links"):
            if key not in table:
                continue
            values = table[key] if isinstance(table[key], list) else [table[key]]
            for url in values:
                url = _as_str(url, f"{what}.{key}")
                if not _is_official_index(url):
                    global_sources.append(_foreign_registry(url) if "://" in url else Source(kind="file", normalized=url))
    uv_sources = {
        _pep503(str(k)): v for k, v in _as_dict(uv_tool.get("sources", {}), "tool.uv.sources").items()
    }

    def add(reqs: Any, what: str) -> None:
        for req in _as_list(reqs, what):
            pkg = _pypi_package_from_requirement(_as_str(req, what), direct=True)
            overrides = _uv_source_overrides(uv_sources.get(pkg.name), index_urls, f"tool.uv.sources.{pkg.name}")
            # One package per source alternative, so each one is checked.
            packages.extend([replace(pkg, source=o) for o in overrides] or [pkg])

    project = _as_dict(doc.get("project", {}), "project")
    if "dependencies" in project:
        add(project["dependencies"], "project.dependencies")
    for group, reqs in _as_dict(project.get("optional-dependencies", {}), "optional-dependencies").items():
        add(reqs, f"optional-dependencies.{group}")
    for group, reqs in _as_dict(doc.get("dependency-groups", {}), "dependency-groups").items():
        # An `{include-group = ...}` table is a reference, not a package.
        add([r for r in _as_list(reqs, group) if not isinstance(r, dict)], f"dependency-groups.{group}")
    if "dev-dependencies" in uv_tool:
        add(uv_tool["dev-dependencies"], "tool.uv.dev-dependencies")
    build = _as_dict(doc.get("build-system", {}), "build-system")
    if "requires" in build:
        add(build["requires"], "build-system.requires")

    poetry = _as_dict(_as_dict(doc.get("tool", {}), "tool").get("poetry", {}), "tool.poetry")
    poetry_sources: dict[str, str] = {}
    for src in _as_list(poetry.get("source", []), "tool.poetry.source"):
        src = _as_dict(src, "tool.poetry.source entry")
        if "name" in src and "url" in src:
            poetry_sources[str(src["name"])] = _as_str(src["url"], "tool.poetry.source url")
        if "url" in src and not _is_official_index(_as_str(src["url"], "tool.poetry.source url")):
            global_sources.append(_foreign_registry(src["url"]))
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    for group in _as_dict(poetry.get("group", {}), "tool.poetry.group").values():
        tables.append(_as_dict(group, "poetry group").get("dependencies"))
    for table in tables:
        if table is None:
            continue
        for name, value in _as_dict(table, "poetry dependencies").items():
            if name.lower() == "python":
                continue
            # A list holds alternatives (split by markers). Poetry may install
            # any of them, so each one is a package with its own version and
            # source.
            alternatives = value if isinstance(value, list) else [value]
            if not alternatives:
                raise DepsError(f"poetry dependency {name} has an empty list")
            for item in alternatives:
                packages.append(
                    Package(
                        ecosystem="pypi",
                        name=_pep503(name),
                        version=_poetry_dep_version(item),
                        source=_poetry_dep_source(item, poetry_sources, f"poetry dependency {name}"),
                        direct=True,
                    )
                )
    return None, packages, global_sources


# ---------------------------------------------------------------------------
# PyPI: poetry.lock
# ---------------------------------------------------------------------------


def _parse_poetry_lock(text: str) -> _Result:
    doc = _as_dict(tomllib.loads(text), "poetry.lock")
    meta = _as_dict(doc.get("metadata", {}), "metadata")
    version = meta.get("lock-version")
    if version not in SUPPORTED_POETRY_LOCK_VERSIONS:
        raise UnsupportedVersionError(f"poetry.lock lock-version {version!r} is not supported")
    packages = []
    for entry in _as_list(doc.get("package", []), "package"):
        entry = _as_dict(entry, "package entry")
        name = _as_str(entry.get("name"), "package name")
        source = official_pypi_source()
        if "source" in entry:
            src = _as_dict(entry["source"], f"{name} source")
            stype = _as_str(src.get("type"), f"{name} source type")
            url = _as_str(src.get("url", ""), f"{name} source url")
            if stype == "git":
                base = classify_source(url if "://" in url else f"git+{url}", frozenset())
                ref = src.get("resolved_reference") or src.get("reference") or ""
                source = Source(kind="git", normalized=f"{base.normalized}#{ref}" if ref else base.normalized, host=base.host)
            elif stype == "url":
                source = classify_source(url, frozenset())
            elif stype in ("file", "directory"):
                source = Source(kind="file", normalized=url)
            elif stype == "legacy":
                source = classify_source(url, PYPI_OFFICIAL_HOSTS)
                if source.kind != "registry":
                    source = _foreign_registry(url) if "://" in url else Source(kind="unknown", normalized=url)
            else:
                source = Source(kind="unknown", normalized=f"{stype}:{url}")
        packages.append(
            Package(
                ecosystem="pypi",
                name=_pep503(name),
                version=_as_str(entry.get("version"), f"{name} version"),
                source=source,
            )
        )
    return str(version), packages, []


# ---------------------------------------------------------------------------
# PyPI: uv.lock
# ---------------------------------------------------------------------------


def _parse_uv_lock(text: str) -> _Result:
    doc = _as_dict(tomllib.loads(text), "uv.lock")
    version = doc.get("version")
    if isinstance(version, bool) or version not in SUPPORTED_UV_LOCK_VERSIONS:
        raise UnsupportedVersionError(f"uv.lock version {version!r} is not supported")
    packages = []
    for entry in _as_list(doc.get("package", []), "package"):
        entry = _as_dict(entry, "package entry")
        name = _as_str(entry.get("name"), "package name")
        src = _as_dict(entry.get("source"), f"{name} source")
        if len(src) != 1:
            raise DepsError(f"{name} source must have exactly one key")
        ((kind, value),) = src.items()
        value = _as_str(value, f"{name} source {kind}")
        if kind == "registry":
            if "://" in value:
                source = classify_source(value, PYPI_OFFICIAL_HOSTS)
                if source.kind != "registry":
                    source = _foreign_registry(value)
            else:
                source = Source(kind="file", normalized=value)
        elif kind == "git":
            base = classify_source(value if "://" in value else f"git+{value}", frozenset())
            source = Source(kind="git", normalized=base.normalized, host=base.host)
        elif kind == "url":
            source = classify_source(value, frozenset())
        elif kind in ("path", "directory"):
            source = Source(kind="file", normalized=value)
        elif kind in ("editable", "virtual"):
            source = Source(kind="workspace", normalized=value)
        else:
            source = Source(kind="unknown", normalized=f"{kind}:{value}")
        if source.official:
            source = _uv_file_hosts_source(entry, name, source)
        pkg_version = entry.get("version", "")
        packages.append(
            Package(
                ecosystem="pypi",
                name=_pep503(name),
                version=_as_str(pkg_version, f"{name} version"),
                source=source,
            )
        )
    return str(version), packages, []


def _uv_file_hosts_source(entry: dict[str, Any], name: str, source: Source) -> Source:
    """uv installs from the sdist and wheel URLs, not from `source`: check them."""
    urls = []
    sdist = entry.get("sdist")
    if sdist is not None and "url" in _as_dict(sdist, f"{name} sdist"):
        urls.append(_as_str(sdist["url"], f"{name} sdist url"))
    for wheel in _as_list(entry.get("wheels", []), f"{name} wheels"):
        wheel = _as_dict(wheel, f"{name} wheel")
        if "url" in wheel:
            urls.append(_as_str(wheel["url"], f"{name} wheel url"))
    for url in urls:
        found = classify_source(url, PYPI_OFFICIAL_HOSTS)
        if not found.official:
            return found if found.foreign else _foreign_registry(url)
    return source


# ---------------------------------------------------------------------------
# PyPI: requirements*.txt
# ---------------------------------------------------------------------------

_EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)")


def _requirement_lines(text: str) -> Iterable[str]:
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line = buf + line
        buf = ""
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if line:
            yield line
    if buf.strip():
        yield re.sub(r"(^|\s)#.*$", "", buf).strip()


def _parse_requirements(text: str) -> _Result:
    packages: list[Package] = []
    global_sources: list[Source] = []
    for line in _requirement_lines(text):
        if line.startswith("-"):
            _requirements_option(line, packages, global_sources)
            continue
        packages.append(_requirements_entry(line))
    return None, packages, global_sources


# Options on a requirements line. Anything not listed fails closed: pip
# (optparse) takes attached values (`-ihttps://x`) and unique prefixes
# (`--index=...`), so a parser that skips unknown options can miss an index.
_REQ_VALUE_OPTIONS = frozenset(
    {"-r", "--requirement", "-c", "--constraint", "--hash", "--no-binary", "--only-binary", "--trusted-host"}
)
_REQ_FLAG_OPTIONS = frozenset({"--no-index", "--require-hashes", "--prefer-binary", "--pre"})
_REQ_INDEX_LONG = ("--index-url", "--extra-index-url", "--find-links")
_REQ_SHORT = {"-i": "--index-url", "-f": "--find-links", "-e": "--editable", "-r": "-r", "-c": "-c"}


def _requirements_option(line: str, packages: list[Package], global_sources: list[Source]) -> None:
    try:
        tokens = shlex.split(line, comments=False)
    except ValueError as exc:
        raise DepsError(f"requirements option line does not parse: {line[:60]!r}") from exc
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        attached: str | None = None
        if token.startswith("--"):
            opt, eq, value = token.partition("=")
            attached = value if eq else None
            if opt in _REQ_FLAG_OPTIONS:
                if eq:
                    raise DepsError(f"requirements option {opt} takes no value")
                continue
            if opt in _REQ_VALUE_OPTIONS:
                if attached is None:
                    i += 1
                continue
            if opt == "--editable":
                canonical = "--editable"
            else:
                matches = [name for name in _REQ_INDEX_LONG if len(opt) > 2 and name.startswith(opt)]
                if not matches:
                    raise DepsError(f"requirements option {opt!r} is not on the allowlist")
                canonical = matches[0]
        elif token.startswith("-") and len(token) >= 2:
            canonical = _REQ_SHORT.get(token[:2])
            if canonical is None:
                raise DepsError(f"requirements option {token[:2]!r} is not on the allowlist")
            attached = token[2:] or None
        else:
            raise DepsError(f"unexpected token {token[:60]!r} on a requirements option line")
        if canonical in ("-r", "-c"):
            if attached is None:
                i += 1
            continue
        if attached is not None:
            value = attached.lstrip("=")
        elif canonical == "--editable":
            value = " ".join(tokens[i:])
            i = len(tokens)
        elif i < len(tokens):
            value = tokens[i]
            i += 1
        else:
            value = ""
        value = value.strip()
        if not value:
            raise DepsError(f"requirements option {canonical} has no value")
        if canonical == "--editable":
            packages.append(_requirements_entry(value, editable=True))
        elif "://" in value:
            source = classify_source(value, PYPI_OFFICIAL_HOSTS)
            global_sources.append(source if source.kind == "registry" else _foreign_registry(value))
        else:
            global_sources.append(Source(kind="file", normalized=value))


def _requirements_entry(line: str, editable: bool = False) -> Package:
    line = re.sub(r"\s+--hash[= ]\S+", "", line).strip()
    if "://" in line.split(";", 1)[0] and "@" not in line.split("://", 1)[0]:
        # A bare URL or VCS reference without `name @`.
        url = line.split(";", 1)[0].strip()
        egg = _EGG_RE.search(url)
        name = _pep503(egg.group(1)) if egg else "(url)"
        return Package(ecosystem="pypi", name=name, version=url, source=classify_source(url, frozenset()), direct=True)
    if line.startswith((".", "/", "~")) or (editable and not _PEP508_RE.fullmatch(line)):
        return Package(ecosystem="pypi", name="(path)", version=line, source=Source(kind="file", normalized=line), direct=True)
    return _pypi_package_from_requirement(line, direct=True)


_PARSERS: dict[str, Callable[[str], _Result]] = {
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_pnpm_lock,
    "pyproject.toml": _parse_pyproject,
    "poetry.lock": _parse_poetry_lock,
    "uv.lock": _parse_uv_lock,
    "requirements": _parse_requirements,
}


# ---------------------------------------------------------------------------
# What the prefilter and the delta need
# ---------------------------------------------------------------------------


def non_registry_sources(parsed: ParsedDeps) -> list[SourceIssue]:
    """Every source in a parsed file that is not the official registry.

    The list includes local sources (file, workspace, bundled, patch); the
    prefilter picks `source.foreign` for the hard block and may show the rest.
    File-wide sources (pip index URLs) come first, with no name.
    """
    issues = [
        SourceIssue(parsed.path, None, None, src)
        for src in parsed.global_sources
        if not src.official
    ]
    issues.extend(
        SourceIssue(parsed.path, pkg.name, pkg.version, pkg.source)
        for pkg in parsed.packages
        if not pkg.source.official
    )
    return issues


def compute_delta(old: ParsedDeps | None, new: ParsedDeps) -> list[PackageChange]:
    """Packages added or changed in `new` against `old` (None for a new file).

    A package counts when its (name, version, source) is not in `old`. The
    result lists the old versions of that name so the summary can show
    "1.0.0 -> 1.0.1". Removed packages do not appear.
    """
    old_keys: set[tuple[str, str, str]] = set()
    old_versions: dict[tuple[str, str], list[str]] = {}
    if old is not None:
        for pkg in old.packages:
            old_keys.add((pkg.name, pkg.version, pkg.source.normalized))
            old_versions.setdefault((pkg.ecosystem, pkg.name), []).append(pkg.version)
    changes = []
    for pkg in new.packages:
        if (pkg.name, pkg.version, pkg.source.normalized) in old_keys:
            continue
        changes.append(
            PackageChange(
                path=new.path,
                ecosystem=pkg.ecosystem,
                name=pkg.name,
                old_versions=tuple(sorted(set(old_versions.get((pkg.ecosystem, pkg.name), [])))),
                new_version=pkg.version,
                source=pkg.source,
                direct=pkg.direct,
                has_install_script=pkg.has_install_script,
            )
        )
    return changes


# ---------------------------------------------------------------------------
# Registry lookups: fixed routes, injected fetch
# ---------------------------------------------------------------------------

_NPM_NAME_RE = re.compile(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*")


def validate_npm_name(name: str) -> str:
    if not isinstance(name, str) or len(name) > 214 or not _NPM_NAME_RE.fullmatch(name):
        raise RegistryError(f"not a valid npm package name: {str(name)[:60]!r}")
    return name


def validate_pypi_name(name: str) -> str:
    if not isinstance(name, str) or len(name) > 214 or not _PYPI_NAME_RE.fullmatch(name):
        raise RegistryError(f"not a valid PyPI package name: {str(name)[:60]!r}")
    return _pep503(name)


def npm_url(name: str) -> str:
    """`https://registry.npmjs.org/<encoded-name>`; a scope slash becomes %2F."""
    validate_npm_name(name)
    return f"https://{NPM_REGISTRY_HOST}/{urllib.parse.quote(name, safe='@')}"


def pypi_url(name: str) -> str:
    """`https://pypi.org/pypi/<name>/json` with the PEP 503 normalized name."""
    normalized = validate_pypi_name(name)
    return f"https://{PYPI_REGISTRY_HOST}/pypi/{urllib.parse.quote(normalized, safe='')}/json"


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes
    # The URL that served the body, after any redirect the fetcher followed.
    url: str


# fetch(url, max_bytes, timeout_seconds) -> FetchResult. It raises OSError,
# TimeoutError or http.client.HTTPException on a network failure.
Fetcher = Callable[[str, int, float], FetchResult]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D401
        return None


def default_fetch(
    url: str,
    max_bytes: int,
    timeout: float,
    *,
    opener: Any = None,
    clock: Callable[[], float] = time.monotonic,
) -> FetchResult:
    """urllib fetch for the two fixed routes. It never follows a redirect.

    `timeout` bounds each socket operation and also the whole fetch.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in (NPM_REGISTRY_HOST, PYPI_REGISTRY_HOST):
        raise RegistryError("default_fetch refuses a URL outside the fixed registry hosts")
    opener = opener or urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "oc-claude-review"})
    deadline = clock() + timeout
    try:
        with opener.open(request, timeout=timeout) as resp:
            chunks: list[bytes] = []
            size = 0
            while size <= max_bytes:
                if clock() > deadline:
                    raise TimeoutError(f"{url}: over the {timeout}s total deadline")
                chunk = resp.read(min(65536, max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            return FetchResult(status=resp.status, body=b"".join(chunks), url=resp.url)
    except urllib.error.HTTPError as exc:
        return FetchResult(status=exc.code, body=b"", url=url)
    except http.client.HTTPException as exc:
        raise OSError(f"{url}: {type(exc).__name__}: {exc}") from exc


@dataclass(frozen=True)
class RegistryInfo:
    ecosystem: str
    name: str
    version: str
    published: datetime  # timezone-aware, UTC
    # npm only: the NPM_LIFECYCLE_SCRIPTS of this version, from the registry
    # manifest.
    install_scripts: Mapping[str, str] = field(default_factory=dict)
    # PyPI only: some file of this version is a wheel (`bdist_wheel`). None
    # for npm. False means sdist only, which runs build code at install.
    has_wheel: bool | None = None


def _parse_time(value: Any, what: str) -> datetime:
    if not isinstance(value, str):
        raise RegistryError(f"{what} is not a timestamp")
    try:
        stamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise RegistryError(f"{what} is not an ISO timestamp") from exc
    # A publish time with no time zone is incomplete dependency data; never
    # guess UTC.
    if stamp.tzinfo is None:
        raise RegistryError(f"{what} has no time zone")
    try:
        return stamp.astimezone(UTC)
    except OverflowError as exc:  # e.g. year 1 with a positive offset
        raise RegistryError(f"{what} is out of range in UTC") from exc


def _fetch_json(
    url: str,
    expected_host: str,
    max_bytes: int,
    fetch: Fetcher,
    timeout: float,
    retries: int,
    sleep: Callable[[float], None],
) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(retries + 1):
        if attempt:
            sleep(0.5 * 2 ** (attempt - 1))
        try:
            result = fetch(url, max_bytes, timeout)
        except (OSError, http.client.HTTPException) as exc:  # TimeoutError is an OSError
            last = exc
            continue
        if result.status == 429 or result.status >= 500:
            last = RegistryError(f"{url}: HTTP {result.status}")
            continue
        parts = urllib.parse.urlsplit(result.url)
        if parts.scheme != "https" or parts.hostname != expected_host or parts.port is not None:
            raise RegistryError(f"{url}: response came from another host")
        if result.status != 200:
            raise RegistryError(f"{url}: HTTP {result.status}")
        if len(result.body) > max_bytes:
            raise RegistryError(f"{url}: response is over the {max_bytes} byte cap")
        try:
            doc = json.loads(result.body)
        except (ValueError, RecursionError) as exc:
            raise RegistryError(f"{url}: response is not JSON") from exc
        if not isinstance(doc, dict):
            raise RegistryError(f"{url}: response is not an object")
        return doc
    raise RegistryError(f"{url}: failed after {retries + 1} attempts ({last})")


def lookup_npm(
    name: str,
    version: str,
    fetch: Fetcher = default_fetch,
    *,
    timeout: float = REGISTRY_TIMEOUT_SECONDS,
    retries: int = REGISTRY_RETRIES,
    sleep: Callable[[float], None] = time.sleep,
) -> RegistryInfo:
    """Publish time and lifecycle scripts of one npm version."""
    url = npm_url(name)
    doc = _fetch_json(url, NPM_REGISTRY_HOST, NPM_MAX_RESPONSE_BYTES, fetch, timeout, retries, sleep)
    if doc.get("name", name) != name:
        raise RegistryError(f"{url}: response is for another package")
    times = doc.get("time")
    versions = doc.get("versions")
    if not isinstance(times, dict) or not isinstance(versions, dict):
        raise RegistryError(f"{url}: no time or versions map")
    manifest = versions.get(version)
    if not isinstance(manifest, dict) or version not in times:
        raise RegistryError(f"{url}: version {version!r} not found")
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        raise RegistryError(f"{url}: scripts is not an object")
    found = {}
    for key in NPM_LIFECYCLE_SCRIPTS:
        if key in scripts:
            if not isinstance(scripts[key], str):
                raise RegistryError(f"{url}: script {key} is not a string")
            found[key] = scripts[key]
    return RegistryInfo(
        ecosystem="npm",
        name=name,
        version=version,
        published=_parse_time(times[version], f"time[{version}]"),
        install_scripts=found,
    )


def _norm_version(value: str) -> str:
    """Rough PEP 440 normal form: no `v`, no trailing `.0`, no separators."""
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)(.*)", value.strip().lower())
    if not match:
        return value.strip().lower()
    release = match.group(1).split(".")
    while len(release) > 1 and release[-1] == "0":
        release.pop()
    return ".".join(release) + re.sub(r"[-_.]", "", match.group(2))


def lookup_pypi(
    name: str,
    version: str,
    fetch: Fetcher = default_fetch,
    *,
    timeout: float = REGISTRY_TIMEOUT_SECONDS,
    retries: int = REGISTRY_RETRIES,
    sleep: Callable[[float], None] = time.sleep,
) -> RegistryInfo:
    """Publish time of one PyPI version: the earliest upload of its files."""
    url = pypi_url(name)
    normalized = validate_pypi_name(name)
    doc = _fetch_json(url, PYPI_REGISTRY_HOST, PYPI_MAX_RESPONSE_BYTES, fetch, timeout, retries, sleep)
    info = doc.get("info")
    if isinstance(info, dict) and isinstance(info.get("name"), str) and _pep503(info["name"]) != normalized:
        raise RegistryError(f"{url}: response is for another package")
    releases = doc.get("releases")
    if not isinstance(releases, dict):
        raise RegistryError(f"{url}: no releases map")
    files = releases.get(version)
    if files is None:
        # The lockfile may spell the version differently from the PyPI key.
        wanted = _norm_version(version)
        matches = [key for key in releases if isinstance(key, str) and _norm_version(key) == wanted]
        files = releases[matches[0]] if len(matches) == 1 else None
    if not isinstance(files, list) or not files:
        raise RegistryError(f"{url}: version {version!r} not found")
    stamps = []
    has_wheel = False
    for item in files:
        if not isinstance(item, dict):
            raise RegistryError(f"{url}: release file is not an object")
        has_wheel = has_wheel or item.get("packagetype") == "bdist_wheel"
        # Only the ISO field carries a time zone; the naive `upload_time` is
        # never a fallback.
        stamps.append(_parse_time(item.get("upload_time_iso_8601"), "upload time"))
    return RegistryInfo(
        ecosystem="pypi",
        name=normalized,
        version=version,
        published=min(stamps),
        has_wheel=has_wheel,
    )
