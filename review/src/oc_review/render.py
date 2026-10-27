"""Bundle envelope -> prompt text with nonce delimiters and redaction.

Spec "Request shape": the bundle goes to Claude as one user message,

    <untrusted_pr_{nonce}>
    ...bundle rendered as text...
    </untrusted_pr_{nonce}>

`{nonce}` is 16 random hex characters per run. Every untrusted string goes
through the same steps before it is placed in the text:

1. `redact_text`: credential-like strings become `[REDACTED:<kind>]`.
2. `neutralize_delimiters`: any text that reads as the delimiter name
   (`untrusted_pr`, also in other case, with Unicode lookalikes or with
   invisible characters inside) becomes `[NEUTRALIZED:delimiter]`.
3. Control, format and line-break characters become visible `<U+XXXX>` text,
   so content cannot start a new line of the rendered text by itself.

Every line of a multi-line value starts with a `| ` prefix (with line numbers
for content and patches), so PR text cannot forge a section header. As a last
step, `check_no_delimiter` makes sure that the rendered bundle does not
contain `untrusted_pr_{nonce}`.

Steps 1-3 keep the line count (ruling R-LINES). `model_text` gives the text
exactly as Claude sees it, for the citation check in verdict.py.

Bundle payload shape (written by collect.py). Keys are optional; render shows
any other key with the same generic rules, so it drops nothing:

    pr:                {repository, repository_id, number, title, body,
                        author_login, author_association, labels}
    files:             [{path, old_path, status, additions, deletions,
                         head_blob_sha, base_blob_sha, binary, size, coverage,
                         patch, patch_redaction, content, head_content,
                         base_content}]
    dependency_delta, prefilter: {signals, hard_blocks}, coverage, size

- `pr.title` and `pr.body` are shown like files, with line numbers, at the
  reserved paths `/.pr/title` and `/.pr/body` (ruling R-META).
- `patch` is a unified diff of the two blobs (`@@` hunks; an optional
  `diff`/`---`/`+++` preamble), passed through `redact_patch` with both full
  blobs, and `patch_redaction` is `PATCH_REDACTION`. Render refuses a patch
  without it, adds the base and head line numbers and fails closed when the
  hunk counts do not match the lines.
- `content` is the full head text that goes to Claude, set by collect only
  for text files under 2,000 lines (spec "Bundle"); render omits a longer one.
  Patches are not cut; the size gate bounds them.
- `head_content` and `base_content` are raw blob text for the citation check
  in verdict.py only. Render never shows them (`VERIFY_ONLY_FILE_KEYS`).

Prompts: `load_prompt` reads `review/prompts/<name>.md` and fills `{nonce}`.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import secrets
import unicodedata
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

# Spec "Bundle": full head content only for text files under 2,000 lines.
MAX_HEAD_CONTENT_LINES = 2000
# Generic renderer depth cap. Collect writes a shallow structure.
MAX_DEPTH = 32

DELIMITER_NAME = "untrusted_pr"
# PR title and body are shown and cited as pseudo-files (ruling R-META). Same
# values as verdict.META_TITLE_PATH and verdict.META_BODY_PATH.
PR_TITLE_PATH = "/.pr/title"
PR_BODY_PATH = "/.pr/body"
NEUTRALIZED = "[NEUTRALIZED:delimiter]"

_NONCE_RE = re.compile(r"^[0-9a-f]{16}$")

# Sections in this order first, then any other payload key in its own order.
_SECTION_ORDER = ("pr", "files", "dependency_delta", "prefilter", "coverage", "size")
_SNAPSHOT_FIELDS = (
    "repository_id",
    "pr_number",
    "head_sha",
    "base_repository_id",
    "base_ref",
    "base_tip_sha",
    "merge_base_sha",
)


class RenderError(Exception):
    """The bundle cannot be rendered safely. The pass fails, so the gate fails."""


@dataclass(frozen=True)
class RenderedBundle:
    nonce: str
    text: str  # the full user message: open tag, bundle, close tag

    @property
    def open_tag(self) -> str:
        return f"<{DELIMITER_NAME}_{self.nonce}>"

    @property
    def close_tag(self) -> str:
        return f"</{DELIMITER_NAME}_{self.nonce}>"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

REDACTED = "[REDACTED:{kind}]"
# Text that is already exactly one marker. Redaction leaves it as it is, so
# redact_text(redact_text(x)) == redact_text(x).
_MARKER_ONLY = re.compile(r"\[REDACTED:[^\[\]\s]+\]")

# Credential-like strings: token prefixes with their fixed formats. Order
# matters where one prefix contains another (sk-ant- before sk-).
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("slack-app-token", re.compile(r"\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{32,}\b")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("digitalocean-token", re.compile(r"\bdo[opr]_v1_[a-f0-9]{64}\b")),
    ("vault-token", re.compile(r"\bhv[sbr]\.[A-Za-z0-9_\-]{24,}")),
    ("grafana-token", re.compile(r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b")),
    ("grafana-token", re.compile(r"\bglc_[A-Za-z0-9+/]{32,}={0,2}")),
    ("shopify-token", re.compile(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b")),
    ("databricks-token", re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b")),
    ("doppler-token", re.compile(r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}\b")),
    ("linear-api-key", re.compile(r"\blin_api_[A-Za-z0-9]{40}\b")),
    ("postman-api-key", re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b")),
    ("twilio-api-key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("google-oauth-secret", re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28}")),
    ("google-oauth-token", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b")),
    ("discord-webhook", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+")),
    ("azure-storage-key", re.compile(r"\bAccountKey=[A-Za-z0-9+/]{86}==")),
    ("age-secret-key", re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b")),
)
# user:password@ in a URL. Only the userinfo is replaced. The password part
# runs to the last @ before the path, so a raw @ in a password does not leak.
_URL_CREDENTIALS = re.compile(r"\b([A-Za-z][A-Za-z0-9+.\-]{0,31}://)[^\s/?#@:]{1,256}:[^\s/?#]{1,256}@")

# JWT (JWS compact form): three base64url segments. The header is JSON with an
# "alg" member, so it starts with "ey" ('{' in base64). The candidate is
# checked by decoding (`_is_jwt`), not by segment length, so a token with short
# claims (`e30` is `{}`) is caught. Possessive quantifiers: linear time.
_JWT_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9_\-])(ey[A-Za-z0-9_\-]++)\.([A-Za-z0-9_\-]*+)\.([A-Za-z0-9_\-]*+)(?![A-Za-z0-9_\-])"
)
# Fallback shape for a token whose header does not decode: both JSON parts
# start with '{"'. This was the only JWT rule before.
_JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}")
_JWT_MAX_HEADER = 8192


def _b64url_json(segment: str) -> Any:
    if len(segment) > _JWT_MAX_HEADER or len(segment) % 4 == 1:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, binascii.Error):
        return None


def _is_jwt(m: re.Match[str]) -> bool:
    header, claims, signature = m.groups()
    if len(claims) % 4 == 1 or len(signature) % 4 == 1:
        return False
    if _JWT_SHAPE.fullmatch(header) and _JWT_SHAPE.fullmatch(claims):
        return True
    h = _b64url_json(header)
    return isinstance(h, dict) and isinstance(h.get("alg"), str)


# A value after a credential name: `password = "..."`, `aws_secret_access_key:
# ...`, `"api_key": "..."`, `TOKEN=...`. Only the value is replaced; the name
# stays, so Claude sees what kind of value was there. The name holds one of
# these words, not followed by a lower-case letter (so `tokenizer` and
# `secretary` do not count). The value must pass `_secret_like`.
_CRED_WORD = (
    r"(?:passw(?:or)?d|pwd|passphrase|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key"
    r"|signing[_\-]?key|encryption[_\-]?key|session[_\-]?key|master[_\-]?key|auth[_\-]?key|credentials?)"
)
_NAME_CHARS = r"[A-Za-z0-9_.\-]"
_ASSIGNMENT = re.compile(
    rf"(?<!{_NAME_CHARS})(?P<name>{_NAME_CHARS}{{0,64}}?{_CRED_WORD}s?(?-i:(?![a-z])){_NAME_CHARS}{{0,64}})"
    r"(?P<sep>[\"'`]?\]?[ \t]*(?::=|=>|=(?!=)|:(?![:/\\]))[ \t]*)"
    r"(?:(?P<q>[\"'`])(?P<qv>[^\"'`\s]{8,4096}+)(?P=q)|(?P<uv>[^\s\"'`,;()\[\]{}<>]{8,4096}+)(?![(\[]))",
    re.IGNORECASE,
)
# `Authorization: Bearer <token>` and `Basic <base64>`.
_AUTH_SCHEME = re.compile(r"\b(?P<name>bearer|basic)(?P<sep>[ \t]+)(?P<uv>[A-Za-z0-9\-._~+/]{8,4096}+=*)", re.IGNORECASE)
# Unquoted values that are code, not data: `self.password`, `os.environ`,
# `DEFAULT_TOKEN_NAME`.
_DOTTED_NAME = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Minimum Shannon entropy, in bits per character.
_MIN_ENTROPY_QUOTED = 2.5
_MIN_ENTROPY_UNQUOTED = 3.0


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _secret_like(value: str, quoted: bool) -> bool:
    """Value test for a credential assignment. All of these must hold:

    - not a reference or a template: does not start with `$ % < { [ * & @ #`,
      and holds no `${`, `{{` or `://` (URL credentials have their own rule);
    - a letter and at least two character classes (lower, upper, digit, other);
    - Shannon entropy of at least 2.5 bits per character (3.0 unquoted);
    - unquoted only: holds a digit, holds no `(`, is not a dotted name, and is
      not an identifier with `_` shorter than 20 characters.
    """
    if value[0] in "$%<{[*&@#" or "${" in value or "{{" in value or "://" in value:
        return False
    if not quoted and (
        not any(c.isdigit() for c in value)
        or "(" in value
        or _DOTTED_NAME.fullmatch(value)
        or (_IDENTIFIER.fullmatch(value) and "_" in value and len(value) < 20)
    ):
        return False
    classes = (
        any(c.islower() for c in value)
        + any(c.isupper() for c in value)
        + any(c.isdigit() for c in value)
        + any(not c.isalnum() for c in value)
    )
    if classes < 2 or not any(c.isalpha() for c in value):
        return False
    return _entropy(value) >= (_MIN_ENTROPY_QUOTED if quoted else _MIN_ENTROPY_UNQUOTED)


def _assignment_kind(name: str) -> str:
    flat = re.sub(r"[^a-z]", "", name.lower())
    if "secretaccesskey" in flat or ("aws" in flat and "secret" in flat):
        return "aws-secret-access-key"
    return "credential-assignment"


def _value_spans(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) of values after credential names and auth schemes."""
    found = []
    pos = 0
    while (m := _ASSIGNMENT.search(text, pos)) is not None:
        group = "qv" if m.group("qv") is not None else "uv"
        if _secret_like(m.group(group), quoted=group == "qv"):
            found.append((_assignment_kind(m.group("name")), m.start(group), m.end(group)))
            pos = m.end()
        else:
            # Not a secret: search again from the value, so a value that is not
            # a secret cannot hide an assignment inside it (`pw=$X&token=...`).
            pos = m.start(group)
    for m in _AUTH_SCHEME.finditer(text):
        if _secret_like(m.group("uv"), quoted=True):
            found.append((f"{m.group('name').lower()}-credentials", m.start("uv"), m.end("uv")))
    return found


def _replace_spans(text: str, spans: list[tuple[str, int, int]]) -> str:
    out, pos = [], 0
    for kind, start, end in sorted(spans, key=lambda s: s[1]):
        if start < pos:  # overlaps a span already replaced
            continue
        out.append(text[pos:start])
        out.append(REDACTED.format(kind=kind))
        pos = end
    out.append(text[pos:])
    return "".join(out)


# Private keys. After a BEGIN header, all text up to the END header with the
# same label is key payload, whatever it looks like: no entropy or length
# test decides. Each payload line becomes one marker (indent kept), so the
# line count does not change (ruling R-LINES). A payload line that cannot be
# key data (it holds characters outside base64, armor headers and the quotes
# and escapes of a key in code) gets its own kind, so Claude can see that a
# key block hides text. The kind says only that; it shows no part of the line.
#
# Ruling R-KEYBLOCK: a header with no END anywhere after it redacts at most
# `PK_UNTERMINATED_MAX_LINES` lines after the header line, so a fake header
# cannot hide the rest of the file. The prefilter makes the coverage of such a
# file `unavailable` (`unterminated_private_keys`). Key data that has lost its
# header is still redacted: the lines before an END with no open block, and
# runs of full-width base64 lines (`KEY_BODY_WIDTHS`). A PuTTY `Private-Lines`
# count is held to the same cap, and a block over the cap or cut short is
# unterminated too.
#
# A key block (PEM, OpenSSH, SSH2, PuTTY, the text of a base64-encoded PEM key,
# and the key data before an END with no BEGIN) must hold key material only,
# or the file's coverage is `unavailable` too (`_KeyBody`): a block with an
# END line must not hide code either.
#
# Headers: PEM, OpenSSH and PGP (five dashes), and SSH2 (RFC 4716 form, four
# dashes and spaces).
_PK_BEGIN = re.compile(
    r"-----BEGIN(?P<pem>[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----"
    r"|---- BEGIN(?P<ssh2>[A-Z0-9 ]{0,40}PRIVATE KEY) ----"
)
_PK_END = re.compile(r"-----END[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|---- END[A-Z0-9 ]{0,40}PRIVATE KEY ----")
# Any other PEM header (certificate, public key): the base64 under it is public.
_PEM_PUBLIC_BEGIN = re.compile(r"-----BEGIN (?![A-Z0-9 ]*PRIVATE)[A-Z0-9 ]{1,40}-----")
PK_UNTERMINATED_MAX_LINES = 100
# Armor header lines a key block may hold before its base64: RFC 1421 and
# OpenPGP under five dashes, RFC 4716 under four. Free text has no brackets,
# operators, backticks or `$`, so a header line cannot call code either.
_HEADER_TEXT = r"[^()\[\]{}<>;=`$|&\\]*"
_PEM_HEADER = re.compile(
    r"Proc-Type: \d+,[A-Z-]+|DEK-Info: [A-Za-z0-9-]+(?:,[0-9A-Fa-f]+)?"
    rf"|(?:Version|Comment|Hash|Charset|MessageID): {_HEADER_TEXT}"
)
_SSH2_HEADER = re.compile(rf"(?i:Subject|Comment|x-[a-z0-9-]+): {_HEADER_TEXT}")
# Key data: base64 (with `\n` escapes of a one-line key) inside optional quotes
# and concatenation of a key in code, or an armor header line.
_PK_DATA = re.compile(
    r"[\s\"'`+(,]*+(?:[A-Za-z0-9+/=]|\\[nr])*+[\s\"'`+),;]*+"
    rf"|{_PEM_HEADER.pattern}|{_SSH2_HEADER.pattern}"
)
# One line of a key block: base64 with `\n` escapes, in optional quotes, with
# the concatenation of a key in code around it. A `+` before the data is
# concatenation only before a quote; elsewhere it is base64.
_KEY_LINE = re.compile(
    r"\s*+(?:[+,(]\s*+(?=[\"'`]))?[\"'`]?((?:[A-Za-z0-9+/=]|\\[nr])*+)[\"'`]?\s*+(?:[+,);]\s*+)*+"
)
_ESCAPED_EOL = re.compile(r"\\r\\n|\\n|\\r")
_B64_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_PGP_CHECKSUM = re.compile(r"=[A-Za-z0-9+/]{4}")
# Key material: every base64 line but the last has one of these widths (PEM
# and PGP 64, OpenSSH 70, RFC 4716 at most 72, MIME 76; PuTTY always 64), the
# last may be shorter, and all of it is padded base64 of at least
# `KEY_BLOCK_MIN_CHARS` characters (the smallest private key part, a PuTTY
# Ed25519 or ECDSA blob, has 44 or more).
KEY_BLOCK_WIDTHS = frozenset({64, 70, 72, 76})
PUTTY_KEY_WIDTHS = frozenset({64})
KEY_BLOCK_MIN_CHARS = 44
# A key body that lost its header: at least `KEY_BODY_MIN_LINES` lines of
# base64 of one of these widths (PEM and PGP 64, OpenSSH 70, MIME 76), and an
# optional shorter last line.
KEY_BODY_WIDTHS = frozenset({64, 70, 76})
KEY_BODY_MIN_LINES = 3
_KEY_BODY_LINE = re.compile(r"[\s\"'`]*+([A-Za-z0-9+/]++={0,2})(?:\\n)?[\"'`]?[\s,;+]*+")
# PuTTY key files: `Private-Lines: N`, then N lines of key data. N over
# `PK_UNTERMINATED_MAX_LINES` redacts only that many lines and is unterminated.
_PUTTY_HEADER = re.compile(r"PuTTY-User-Key-File-\d+:")
_PUTTY_PRIVATE_LINES = re.compile(r"\s*Private-Lines:\s*(\d{1,6})\s*")
# A whole PEM file encoded as base64 (a Kubernetes secret, for example). These
# are the parts of base64("-----BEGIN") that do not depend on the byte offset.
_B64_BEGIN_SIGNATURES = ("LS0tLS1CRUdJT", "0tLS0tQkVHSU", "tLS0tLUJFR0lO")
_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{20,}+={0,2}")


def _pk_payload(segment: str) -> str:
    body = segment.strip()
    if not body or _MARKER_ONLY.fullmatch(body):
        return segment
    kind = "private-key" if _PK_DATA.fullmatch(body) else "text-in-private-key-block"
    return segment[: len(segment) - len(segment.lstrip())] + REDACTED.format(kind=kind)


def _is_key_data(line: str) -> bool:
    body = line.strip()
    return bool(body) and any(c.isalnum() for c in body) and _PK_DATA.fullmatch(body) is not None


class _KeyBody:
    """Whether the text of one key block is key material only.

    Key material: the header lines the format allows, then base64 lines of one
    full width (the last may be shorter), padded and at least
    `KEY_BLOCK_MIN_CHARS` long, then for OpenPGP one `=XXXX` checksum line.
    Blank lines are allowed. A real key has nothing else, so any other line
    means the block can hide code (ruling R-KEYBLOCK).
    """

    def __init__(self, headers: re.Pattern[str] | None, widths: frozenset[int], pgp: bool = False) -> None:
        self.headers, self.widths, self.pgp = headers, widths, pgp
        self.width = self.chars = 0
        self.last = self.checksum = False
        self.ok = True

    @classmethod
    def for_header(cls, header: str) -> _KeyBody:
        """For the block of a BEGIN or END line: five dashes or SSH2."""
        if header.startswith("-----"):
            return cls(_PEM_HEADER, KEY_BLOCK_WIDTHS, pgp="PGP" in header)
        return cls(_SSH2_HEADER, KEY_BLOCK_WIDTHS)

    def feed(self, segment: str) -> None:
        s = segment.strip()
        if not s or not self.ok:
            return
        if self.headers is not None and not self.chars and self.headers.fullmatch(s):
            return
        m = _KEY_LINE.fullmatch(s)
        if m is None:
            self.ok = False
            return
        for piece in _ESCAPED_EOL.split(m.group(1)):
            if piece:
                self._line(piece)

    def _line(self, piece: str) -> None:
        if self.pgp and self.chars and not self.checksum and _PGP_CHECKSUM.fullmatch(piece):
            self.checksum = True
            return
        n = len(piece)
        if (
            self.checksum
            or self.last
            or not _B64_LINE.fullmatch(piece)
            or n > (self.width or max(self.widths))
        ):
            self.ok = False
            return
        if not self.width and n in self.widths:
            self.width = n
        if n != self.width or piece.endswith("="):
            self.last = True
        self.chars += n

    def complete(self) -> bool:
        return self.ok and (not self.chars or (self.chars >= KEY_BLOCK_MIN_CHARS and self.chars % 4 == 0))


@dataclass
class _KeyScan:
    lines: list[str]  # redacted lines, trailing CR kept
    found: list[tuple[str, int, int]]  # (kind, start, end) in the input text
    unterminated: list[int]  # 1-based lines of BEGIN headers with no END
    not_key_material: list[int]  # 1-based header lines of blocks that hold other text


def _scan_private_keys(text: str, cap: int | None = PK_UNTERMINATED_MAX_LINES) -> _KeyScan:
    """Redact private key blocks. `cap`: the most lines a block with no END
    redacts; None runs it to the end of the text (for decoded base64)."""
    raw = text.split("\n")
    lines = list(raw)
    found: list[tuple[str, int, int]] = []
    unterminated: list[int] = []
    not_key_material: list[int] = []
    has_pem = "PRIVATE KEY" in text
    has_putty = _PUTTY_HEADER.search(text) is not None
    starts = [0]
    for line in raw[:-1]:
        starts.append(starts[-1] + len(line) + 1)

    end_tag: str | None = None
    left: int | None = None  # lines left in an unterminated block; None: until END
    key = _KeyBody(None, KEY_BLOCK_WIDTHS)  # the text of the open block
    key_line = 0  # 1-based line of its BEGIN header
    putty_left = 0
    if has_pem or has_putty:
        for i, line in enumerate(raw):
            cr = "\r" if line.endswith("\r") else ""
            body = line[: len(line) - len(cr)]
            if putty_left > 0:
                lines[i], putty_left = _pk_payload(body) + cr, putty_left - 1
                continue
            if end_tag is not None and left is not None:
                if left == 0:
                    if not key.ok:
                        not_key_material.append(key_line)
                    end_tag = left = None
                else:
                    left -= 1
            if has_pem:
                out: list[str] = []
                pos = 0
                while True:
                    if end_tag is not None:
                        stop = body.find(end_tag, pos)
                        segment = body[pos : len(body) if stop < 0 else stop]
                        key.feed(segment)
                        out.append(_pk_payload(segment))
                        if stop < 0:
                            break
                        if not key.complete():
                            not_key_material.append(key_line)
                        out.append(end_tag)
                        pos, end_tag, left = stop + len(end_tag), None, None
                        continue
                    begin = _PK_BEGIN.search(body, pos)
                    orphan = _PK_END.search(body, pos)
                    if orphan is not None and (begin is None or orphan.start() < begin.start()):
                        # An END with no open block: its BEGIN line was removed.
                        # Redact the key data before it.
                        prefix = body[pos : orphan.start()]
                        orphan_key = _KeyBody.for_header(orphan.group())
                        if pos == 0:
                            for j in range(_redact_orphan_body(raw, lines, i), i):
                                orphan_key.feed(raw[j].rstrip("\r"))
                        if _is_key_data(prefix):
                            orphan_key.feed(prefix)
                            prefix = _pk_payload(prefix)
                        if not orphan_key.complete():
                            not_key_material.append(i + 1)
                        out.append(prefix)
                        out.append(orphan.group())
                        found.append(("private-key", starts[i] + orphan.start(), starts[i] + orphan.end()))
                        pos = orphan.end()
                        continue
                    if begin is None:
                        out.append(body[pos:])
                        break
                    out.append(body[pos : begin.end()])
                    if begin.group("pem") is not None:
                        tag = f"-----END{begin.group('pem')}-----"
                    else:
                        tag = f"---- END{begin.group('ssh2')} ----"
                    found.append(("private-key", starts[i] + begin.start(), starts[i] + begin.end()))
                    if text.find(tag, starts[i] + begin.end()) < 0:
                        unterminated.append(i + 1)
                        left = cap
                    else:
                        left = None
                    pos, end_tag = begin.end(), tag
                    key, key_line = _KeyBody.for_header(begin.group()), i + 1
                body = "".join(out)
                lines[i] = body + cr
            if has_putty and end_tag is None:
                m = _PUTTY_PRIVATE_LINES.fullmatch(body)
                if m:
                    # PuTTY has no END header; the count is the only bound, so
                    # the same 100-line cap applies. A block over the cap or
                    # cut short is unterminated; one with a line that is not
                    # key material does not hold a key.
                    count = int(m.group(1))
                    putty_left = count if cap is None else min(count, cap)
                    block = raw[i + 1 : i + 1 + putty_left]
                    if (cap is not None and count > cap) or len(block) < count:
                        unterminated.append(i + 1)
                    putty_key = _KeyBody(None, PUTTY_KEY_WIDTHS)
                    for b in block:
                        putty_key.feed(b.rstrip("\r"))
                    if not (putty_key.complete() if len(block) == count else putty_key.ok):
                        not_key_material.append(i + 1)
            if has_putty:
                m = _PUTTY_HEADER.search(body)
                if m:
                    found.append(("private-key", starts[i] + m.start(), starts[i] + m.end()))
    if end_tag is not None and not key.ok:
        not_key_material.append(key_line)
    found.extend(_redact_key_body_runs(raw, lines, starts))
    return _KeyScan(lines, found, unterminated, not_key_material)


def _redact_orphan_body(raw: list[str], lines: list[str], end_line: int) -> int:
    """Redact the key data lines just before an END line with no BEGIN.
    Returns the index of the first redacted line (`end_line` if none)."""
    for j in range(end_line - 1, max(-1, end_line - 1 - PK_UNTERMINATED_MAX_LINES), -1):
        if lines[j] != raw[j] or not _is_key_data(raw[j].rstrip("\r")):
            return j + 1
        cr = "\r" if raw[j].endswith("\r") else ""
        lines[j] = _pk_payload(raw[j][: len(raw[j]) - len(cr)]) + cr
    return max(0, end_line - PK_UNTERMINATED_MAX_LINES)


def _key_body_width(line: str) -> int:
    m = _KEY_BODY_LINE.fullmatch(line)
    return len(m.group(1)) if m else 0


def _redact_key_body_runs(raw: list[str], lines: list[str], starts: list[int]) -> list[tuple[str, int, int]]:
    """Redact runs of full-width base64 lines that no header explains."""
    found = []
    i, n = 0, len(raw)
    while i < n:
        width = _key_body_width(raw[i]) if lines[i] == raw[i] else 0
        if width not in KEY_BODY_WIDTHS:
            i += 1
            continue
        j = i
        while j < n and lines[j] == raw[j] and _key_body_width(raw[j]) == width:
            j += 1
        full = j - i
        if j < n and lines[j] == raw[j] and 0 < _key_body_width(raw[j]) < width:
            j += 1  # the shorter last line
        public = i > 0 and _PEM_PUBLIC_BEGIN.search(raw[i - 1]) is not None
        if full >= KEY_BODY_MIN_LINES and not public:
            for k in range(i, j):
                cr = "\r" if raw[k].endswith("\r") else ""
                body = raw[k][: len(raw[k]) - len(cr)]
                lines[k] = body[: len(body) - len(body.lstrip())] + REDACTED.format(kind="key-body") + cr
            found.append(("key-body", starts[i], starts[i] + len(raw[i])))
        i = j
    return found


def _redact_private_keys(text: str) -> str:
    return "\n".join(_scan_private_keys(text).lines)


def unterminated_private_keys(text: str) -> list[int]:
    """1-based lines of key blocks whose redaction does not show all code:
    private key headers with no END header after them, PuTTY `Private-Lines`
    lines whose block is cut off, and blocks (headers, PuTTY counts, END lines
    with no BEGIN, base64-encoded PEM keys) that hold text that is not key
    material.

    Ruling R-KEYBLOCK: such a block can hide code from Claude, so the
    prefilter marks the file's coverage `unavailable`.
    """
    b64 = _b64_pem_keys(text)
    if "PRIVATE KEY" not in text and _PUTTY_HEADER.search(text) is None and not b64:
        return []
    scan = _scan_private_keys(text)
    lines = {*scan.unterminated, *scan.not_key_material}
    for start, _, decoded in b64:
        # The token is redacted whole. A block cut off at the end of the
        # token is one line of a wrapped encoding, so only other text counts.
        if _scan_private_keys(decoded.decode("latin-1"), cap=None).not_key_material:
            lines.add(text.count("\n", 0, start) + 1)
    return sorted(lines)


def _b64_pem_keys(text: str) -> list[tuple[int, int, bytes]]:
    """Base64 tokens that decode to a PEM private key: (start, end, decoded)."""
    if not any(sig in text for sig in _B64_BEGIN_SIGNATURES):
        return []
    found = []
    for m in _B64_TOKEN.finditer(text):
        token = m.group()
        if not any(sig in token for sig in _B64_BEGIN_SIGNATURES):
            continue
        for off in range(4):
            # Decode up to the last byte, so the text of the key is whole.
            chunk = token[off:].rstrip("=")
            chunk = chunk[: len(chunk) - 1] if len(chunk) % 4 == 1 else chunk
            chunk += "=" * (-len(chunk) % 4)
            try:
                decoded = base64.b64decode(chunk)
            except (ValueError, binascii.Error):
                continue
            if b"PRIVATE KEY" in decoded:
                found.append((m.start(), m.end(), decoded))
                break
    return found


def _b64_pem_spans(text: str) -> list[tuple[str, int, int]]:
    return [("private-key-base64", start, end) for start, end, _ in _b64_pem_keys(text)]


def find_credentials(text: str) -> list[tuple[str, int, int]]:
    """Locations of credential-like strings: (kind, start, end), by start.

    Private keys are reported by their header (or END line, or the first line
    of a key body with no header) only. Used by the prefilter signal, which
    shows the location and never the value, so the signal and the redaction
    agree.
    """
    found: list[tuple[str, int, int]] = list(_scan_private_keys(text).found)
    found.extend(_b64_pem_spans(text))
    for kind, pattern in _TOKEN_PATTERNS:
        found.extend((kind, m.start(), m.end()) for m in pattern.finditer(text))
    found.extend(("jwt", m.start(), m.end()) for m in _JWT_CANDIDATE.finditer(text) if _is_jwt(m))
    found.extend(("url-credentials", m.start(), m.end()) for m in _URL_CREDENTIALS.finditer(text))
    found.extend(_value_spans(text))
    return sorted(found, key=lambda f: (f[1], f[2]))


def redact_text(text: str) -> str:
    """Replace credential-like strings with `[REDACTED:<kind>]`.

    Keeps the line structure, so line numbers do not move. Used by render
    (before Claude sees the bundle) and by publish (before anything is posted).
    Idempotent: a marker is never redacted again.

    Order: private keys (they need the lines around them), base64-encoded PEM
    keys, token prefixes, JWTs, URL credentials, then values after credential names (last, so a
    value with a known prefix keeps its own kind).
    """
    if not isinstance(text, str):
        raise TypeError("redact_text takes a str")
    text = _redact_private_keys(text)
    text = _replace_spans(text, _b64_pem_spans(text))
    for kind, pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED.format(kind=kind), text)
    text = _JWT_CANDIDATE.sub(lambda m: REDACTED.format(kind="jwt") if _is_jwt(m) else m.group(), text)
    text = _URL_CREDENTIALS.sub(lambda m: m.group(1) + REDACTED.format(kind="url-credentials") + "@", text)
    return _replace_spans(text, _value_spans(text))


# ---------------------------------------------------------------------------
# Delimiter neutralization
# ---------------------------------------------------------------------------

# Lookalikes for the letters of the delimiter name that NFKD and casefold do
# not map to ASCII (Cyrillic, Greek, Armenian, Latin small capitals).
_CONFUSABLES = {
    "\u03c5": "u", "\u057d": "u", "\u1d1c": "u", "\u028b": "u",
    "\u0578": "n", "\u043f": "n", "\u03b7": "n", "\u0274": "n",
    "\u0442": "t", "\u03c4": "t", "\u1d1b": "t",
    "\u0433": "r", "\u0280": "r", "\u027e": "r",
    "\u0455": "s", "\ua731": "s",
    "\u0435": "e", "\u04bd": "e", "\u03b5": "e", "\u1d07": "e",
    "\u0501": "d", "\u1d05": "d",
    "\u0440": "p", "\u03c1": "p", "\u1d18": "p",
}
_DELIM_SKELETON = re.compile(r"untrusted[^a-z0-9\n]{0,3}pr")
_DELIM_ASCII = re.compile(r"untrusted[^A-Za-z0-9\n]{0,3}pr", re.IGNORECASE)
# ASCII control characters (other than tab and newline) are skipped like any
# invisible character, so such text takes the slow path.
_ASCII_IGNORABLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _ignorable(ch: str) -> bool:
    cp = ord(ch)
    return (
        unicodedata.category(ch) in ("Cf", "Mn", "Me", "Cc")
        and ch != "\n"
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or cp in (0x115F, 0x1160, 0x3164, 0xFFA0)
    )


def _skeleton(ch: str) -> str:
    if ch.isascii():
        return "" if ch != "\n" and _ignorable(ch) else ch.lower()
    if _ignorable(ch):
        return ""
    s = unicodedata.normalize("NFKD", ch)
    s = "".join(c for c in s if not _ignorable(c)).casefold()
    s = unicodedata.normalize("NFKC", s)
    return "".join(_CONFUSABLES.get(c, c) for c in s)


def neutralize_delimiters(text: str) -> str:
    """Replace text that reads as the delimiter name with a fixed marker.

    Matches `untrusted` + up to 3 separators + `pr` after case folding, NFKD,
    a lookalike table, and removal of invisible characters. A match never
    spans a newline, so line numbers do not move.
    """
    if text.isascii() and not _ASCII_IGNORABLE.search(text):
        return _DELIM_ASCII.sub(NEUTRALIZED, text)
    skel: list[str] = []
    owner: list[int] = []
    for i, ch in enumerate(text):
        for c in _skeleton(ch):
            skel.append(c)
            owner.append(i)
    out: list[str] = []
    pos = 0
    for m in _DELIM_SKELETON.finditer("".join(skel)):
        start, end = owner[m.start()], owner[m.end() - 1] + 1
        out.append(text[pos:start])
        out.append(NEUTRALIZED)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def check_no_delimiter(rendered_bundle: str, nonce: str) -> None:
    """Spec: the rendered bundle must not contain `untrusted_pr_{nonce}`."""
    if f"{DELIMITER_NAME}_{nonce}".casefold() in rendered_bundle.casefold():
        raise RenderError("rendered bundle contains the delimiter for this run")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_ASCII_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _u(ch: str) -> str:
    return f"<U+{ord(ch):04X}>"


def _visible(s: str) -> str:
    """Show control, format, line-break and invisible characters as `<U+XXXX>`.

    Tab is kept. Newline is shown too: callers split blocks on newline first.
    """
    if s.isascii():
        return _ASCII_CONTROL.sub(lambda m: _u(m.group()), s)
    out = []
    for ch in s:
        cp = ord(ch)
        if ch == "\t":
            out.append(ch)
        elif (
            unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp")
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
            or cp in (0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0)
        ):
            out.append(_u(ch))
        else:
            out.append(ch)
    return "".join(out)


def _clean(s: str) -> str:
    return neutralize_delimiters(redact_text(s))


def _scalar(s: str) -> str:
    return _visible(_clean(s))


def model_lines(text: str) -> list[str]:
    """The lines of `text` exactly as Claude sees them in the bundle.

    Redacted, delimiter names neutralized, invisible characters made visible,
    one trailing CR per line dropped. Split on newline only, so line numbers
    match git; redaction keeps the line count (ruling R-LINES).
    """
    lines = _clean(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [_visible(line[:-1] if line.endswith("\r") else line) for line in lines]


def model_text(text: str) -> str:
    """`model_lines` joined, each line ending in a newline.

    The citation check (verdict.py `FileSides`) takes this text, so a quote is
    compared with what Claude saw, on the same line numbers.
    """
    return "".join(line + "\n" for line in model_lines(text))


def _key(k: Any) -> str:
    return _scalar(k if isinstance(k, str) else str(k))


def _emit(out: list[str], indent: int, key: str, value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise RenderError("bundle nesting too deep")
    pad = "  " * indent
    if isinstance(value, Mapping):
        out.append(f"{pad}{key}:" + ("" if value else " {}"))
        for k, v in value.items():
            _emit(out, indent + 1, _key(k), v, depth + 1)
    elif isinstance(value, list):
        out.append(f"{pad}{key}: ({len(value)} items)")
        for i, v in enumerate(value, 1):
            _emit(out, indent + 1, f"[{i}]", v, depth + 1)
    elif isinstance(value, str):
        if "\n" in value or "\r" in value:
            lines = model_lines(value.replace("\r\n", "\n").replace("\r", "\n"))
            out.append(f"{pad}{key}: ({len(lines)} lines)")
            out.extend(f"{pad}  | {line}" for line in lines)
        else:
            out.append(f"{pad}{key}: {_scalar(value)}")
    elif value is None or isinstance(value, (bool, int, float)):
        out.append(f"{pad}{key}: {json.dumps(value)}")
    else:
        raise RenderError(f"unsupported value type {type(value).__name__}")


def _emit_numbered(out: list[str], label: str, text: str) -> None:
    lines = model_lines(text)
    out.append(f"{label}: ({len(lines)} lines)")
    out.extend(f"  | {n:>5} | {line}" for n, line in enumerate(lines, 1))


def _emit_content(out: list[str], content: Any) -> None:
    if not isinstance(content, str):
        _emit(out, 0, "content", content, 1)
        return
    n = content.count("\n") + (0 if content.endswith("\n") or not content else 1)
    if n >= MAX_HEAD_CONTENT_LINES:
        out.append(f"content: omitted, {n} lines (limit: under {MAX_HEAD_CONTENT_LINES} lines)")
        return
    _emit_numbered(out, "content", content)


_HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", re.DOTALL)
_PATCH_PREAMBLE = ("diff ", "index ", "--- ", "+++ ", "new file mode ", "deleted file mode ",
                   "old mode ", "new mode ", "similarity index ", "rename from ", "rename to ")


_Row = tuple[int | None, int | None, str]


def _parse_patch(patch: str) -> tuple[list[_Row], list[str]]:
    """Unified diff -> rows (base number, head number, marker) and their texts.

    Marker "@" is a hunk header (its text is the section text after `@@`).
    Strict: hunk counts must match the lines, else RenderError (fail closed).
    """
    raw = patch.split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    # (base number, head number, marker) per row; marker "@" is a hunk header.
    rows: list[tuple[int | None, int | None, str]] = []
    texts: list[str] = []
    base = head = rem_base = rem_head = 0
    seen_hunk = False
    for line in raw:
        if rem_base == 0 and rem_head == 0:
            m = _HUNK_RE.fullmatch(line)
            if m:
                base, rem_base = int(m.group(1)), int(m.group(2) or 1)
                head, rem_head = int(m.group(3)), int(m.group(4) or 1)
                seen_hunk = True
                rows.append((None, None, "@" + m.group(0)[: m.start(5)]))
                texts.append(m.group(5))
                continue
            if line.startswith("\\") and seen_hunk:
                rows.append((None, None, "\\"))
                texts.append(line[1:])
                continue
            if not seen_hunk and line.startswith(_PATCH_PREAMBLE):
                continue
            raise RenderError("malformed patch: line outside a hunk")
        marker, body = (line[:1], line[1:]) if line else (" ", "")
        if marker == " " and rem_base > 0 and rem_head > 0:
            rows.append((base, head, " "))
            base, head, rem_base, rem_head = base + 1, head + 1, rem_base - 1, rem_head - 1
        elif marker == "-" and rem_base > 0:
            rows.append((base, None, "-"))
            base, rem_base = base + 1, rem_base - 1
        elif marker == "+" and rem_head > 0:
            rows.append((None, head, "+"))
            head, rem_head = head + 1, rem_head - 1
        elif marker == "\\":
            rows.append((None, None, "\\"))
        else:
            raise RenderError("malformed patch: hunk counts do not match")
        texts.append(body)
    if rem_base or rem_head:
        raise RenderError("malformed patch: hunk ends early")
    return rows, texts


# File keys kept in the bundle for the citation check only, never sent to
# Claude, at any length. Claude sees head text in `content` and the patch, and
# base lines only inside the numbered patch hunks.
VERIFY_ONLY_FILE_KEYS = frozenset({"head_content", "base_content"})

# Value of `files[].patch_redaction` when the patch came from `redact_patch`.
PATCH_REDACTION = "blob-context"
_NO_NEWLINE = "\\ No newline at end of file"


def _blob_lines(text: str | None, side: str) -> tuple[list[str], list[str]] | None:
    if text is None:
        return None
    if not isinstance(text, str):
        raise RenderError(f"{side} blob is not text")
    raw, shown = text.split("\n"), redact_text(text).split("\n")
    if len(raw) != len(shown):
        raise RenderError("redaction changed the line count")
    return raw, shown


def _side_line(lines: tuple[list[str], list[str]] | None, n: int | None, text: str, side: str) -> str:
    if lines is None or n is None or not 1 <= n <= len(lines[0]) or lines[0][n - 1] != text:
        raise RenderError(f"patch line does not match the {side} blob")
    return lines[1][n - 1]


_ANY_MARKER = re.compile(r"\[REDACTED:[^\[\]\s]+\]")


def _more_redacted(from_base: str, from_head: str) -> str:
    """The redacted form of a context line that hides more of it: fewer
    characters left outside markers, then more markers. A full tie takes the
    head, which is then the same text."""

    def rank(line: str) -> tuple[int, int]:
        return (len(_ANY_MARKER.sub("", line)), -len(_ANY_MARKER.findall(line)))

    return from_base if rank(from_base) < rank(from_head) else from_head


def redact_patch(patch: str, base_text: str | None, head_text: str | None) -> str:
    """Redact a unified diff with the context of its two full blobs.

    collect.py must call this for every patch it puts in the bundle and set
    `patch_redaction` to `PATCH_REDACTION`; render_bundle refuses a patch
    without it. A hunk alone cannot show that its lines are inside a private
    key whose header is outside the hunk, so each patch line is replaced with
    the same line of `redact_text(<whole blob>)`, which is also the text that
    verdict.py cites (`model_text`). Removed lines come from the base blob,
    added lines from the head blob. A context line takes the side that hides
    more of it (`_more_redacted`).

    `base_text` is None for an added file, `head_text` for a removed one. Every
    patch line must equal its blob line, else RenderError (fail closed).
    Hunk section text (after the second `@@`) is dropped: it is a line of the
    file with no line number, so it cannot be redacted with its context.
    """
    rows, texts = _parse_patch(patch)
    base, head = _blob_lines(base_text, "base"), _blob_lines(head_text, "head")
    out = []
    for (b, h, marker), text in zip(rows, texts):
        if marker.startswith("@"):
            out.append(marker[1:].rstrip())
        elif marker == "\\":
            out.append(_NO_NEWLINE)
        elif marker == "-":
            out.append("-" + _side_line(base, b, text, "base"))
        elif marker == "+":
            out.append("+" + _side_line(head, h, text, "head"))
        else:
            out.append(" " + _more_redacted(_side_line(base, b, text, "base"), _side_line(head, h, text, "head")))
    return "".join(line + "\n" for line in out)


def _annotate_patch(patch: str) -> list[str]:
    """Unified diff -> lines with base and head line numbers (spec "Bundle").

    Content lines always start with a diff marker, so PR text cannot forge a
    hunk header. Each line is cleaned on its own: the patch was already
    redacted with whole-blob context (`redact_patch`), and markers are not
    redacted again, so a line shows the same text as `model_text` of its blob.
    """
    rows, texts = _parse_patch(patch)
    out = []
    for (b, h, marker), text in zip(rows, texts):
        shown = model_lines(text)
        text = shown[0] if shown else ""
        nums = f"{'' if b is None else b:>5} {'' if h is None else h:>5}"
        if marker.startswith("@"):
            out.append(f"{nums} | {marker[1:]}{text}")
        else:
            out.append(f"{nums} | {marker}{text}")
    return out


def _emit_patch(out: list[str], patch: Any, redaction: Any) -> None:
    if not isinstance(patch, str):
        _emit(out, 0, "patch", patch, 1)
        return
    if redaction != PATCH_REDACTION:
        raise RenderError("patch was not redacted with its blob context (redact_patch)")
    lines = _annotate_patch(patch)
    out.append(f"patch: ({len(lines)} lines; columns: base line, head line)")
    out.extend(f"  | {line}" for line in lines)


def _emit_file(out: list[str], index: int, total: int, f: Any) -> None:
    out.append(f"--- file {index} of {total} ---")
    if not isinstance(f, Mapping):
        _emit(out, 0, "file", f, 1)
        return
    binary = f.get("binary") is True
    for k, v in f.items():
        if k not in ("patch", "content") and k not in VERIFY_ONLY_FILE_KEYS:
            _emit(out, 0, _key(k), v, 1)
    if binary:
        return
    if "patch" in f:
        _emit_patch(out, f["patch"], f.get("patch_redaction"))
    if "content" in f:
        _emit_content(out, f["content"])


def _emit_pr(out: list[str], pr: Mapping[str, Any]) -> None:
    for k, v in pr.items():
        if k not in ("title", "body"):
            _emit(out, 0, _key(k), v, 1)
    # Title and body are shown like files, at reserved paths (ruling R-META).
    for path, key in ((PR_TITLE_PATH, "title"), (PR_BODY_PATH, "body")):
        value = pr.get(key)
        out.append(f"--- {path} ---")
        out.append(f"path: {path}")
        if value is None or isinstance(value, str):
            _emit_numbered(out, "content", value or "")
        else:
            _emit(out, 0, "content", value, 1)


def _render_inner(envelope: Mapping[str, Any]) -> str:
    payload = envelope["payload"]
    out: list[str] = ["=== snapshot ==="]
    for field in _SNAPSHOT_FIELDS:
        _emit(out, 0, field, envelope.get(field), 1)

    keys = [k for k in _SECTION_ORDER if k in payload]
    keys += [k for k in payload if k not in _SECTION_ORDER]
    for key in keys:
        value = payload[key]
        if key == "files" and isinstance(value, list):
            out.append(f"=== files ({len(value)}) ===")
            for i, f in enumerate(value, 1):
                _emit_file(out, i, len(value), f)
            continue
        out.append(f"=== {_key(key)} ===")
        if key == "pr" and isinstance(value, Mapping):
            _emit_pr(out, value)
        elif isinstance(value, Mapping):
            for k, v in value.items():
                _emit(out, 0, _key(k), v, 1)
        else:
            _emit(out, 0, _key(key), value, 1)
    return "\n".join(out)


def new_nonce() -> str:
    """16 random hex characters, new for each run."""
    return secrets.token_hex(8)


def _check_nonce(nonce: Any) -> str:
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        raise RenderError("nonce must be 16 lowercase hex characters")
    return nonce


def render_bundle(envelope: Mapping[str, Any], *, nonce: str | None = None) -> RenderedBundle:
    """Render a checked bundle envelope (status `ok`) as the untrusted user message.

    All three passes use the same nonce and text, so they share one cache entry.
    """
    nonce = _check_nonce(new_nonce() if nonce is None else nonce)
    if not isinstance(envelope, Mapping) or envelope.get("kind") != "bundle":
        raise RenderError("not a bundle envelope")
    if envelope.get("status") != "ok" or not isinstance(envelope.get("payload"), Mapping):
        raise RenderError("bundle status is not ok")
    try:
        inner = _render_inner(envelope)
    except RecursionError as e:
        raise RenderError("bundle nesting too deep") from e
    # Second pass over the whole text: a name can also form across the
    # scaffold, for example a key that ends in `untrusted` and a value that
    # starts with `pr`. The scaffold itself never holds the name.
    inner = neutralize_delimiters(inner)
    check_no_delimiter(inner, nonce)
    text = f"<{DELIMITER_NAME}_{nonce}>\n{inner}\n</{DELIMITER_NAME}_{nonce}>"
    return RenderedBundle(nonce=nonce, text=text)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
PROMPT_NAMES = ("system", "review", "security", "supply-chain")
_PLACEHOLDER = "{nonce}"


def fill_prompt(template: str, nonce: str) -> str:
    """Put the run nonce into a prompt. Plain replace, never str.format."""
    nonce = _check_nonce(nonce)
    if _PLACEHOLDER not in template:
        raise RenderError("prompt has no {nonce} placeholder")
    return template.replace(_PLACEHOLDER, nonce)


def load_prompt(name: str, nonce: str) -> str:
    """Read `review/prompts/<name>.md` (system or a pass) and fill the nonce."""
    if name not in PROMPT_NAMES:
        raise RenderError(f"unknown prompt {name!r}")
    return fill_prompt((PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8"), nonce)
