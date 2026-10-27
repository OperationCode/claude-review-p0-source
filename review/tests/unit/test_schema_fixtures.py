import re

import pytest

from oc_review.envelope import EnvelopeError, validate_envelope, validate_findings

from .conftest import fixture_names, load_fixture


# Every bad fixture names the error path and keyword it must raise. A fixture that
# fails for another reason fails its test.
FINDINGS_BAD = {
    "bad-bad-category": "'findings'/0/'category': [enum]",
    "bad-bad-confidence": "'findings'/0/'confidence': [enum]",
    "bad-bad-severity": "'findings'/0/'severity': [enum]",
    "bad-bad-side": "'findings'/0/'side': [enum]",
    "bad-empty-file": "'findings'/0/'file': [minLength]",
    "bad-empty-quote": "'findings'/0/'quote': [minLength]",
    "bad-extra-finding-property": "'findings'/0: [additionalProperties]",
    "bad-extra-top-property": "<root>: [additionalProperties]",
    "bad-findings-not-array": "'findings': [type]",
    "bad-line-float": "'findings'/0/'line': [type]",
    "bad-line-string": "'findings'/0/'line': [type]",
    "bad-line-zero": "'findings'/0/'line': [minimum]",
    "bad-long-explanation": "'findings'/0/'explanation': [maxLength]",
    "bad-long-file": "'findings'/0/'file': [maxLength]",
    "bad-long-quote": "'findings'/0/'quote': [maxLength]",
    "bad-long-summary": "'summary': [maxLength]",
    "bad-long-title": "'findings'/0/'title': [maxLength]",
    "bad-missing-category": "'findings'/0: [required] 'category'",
    "bad-missing-confidence": "'findings'/0: [required] 'confidence'",
    "bad-missing-explanation": "'findings'/0: [required] 'explanation'",
    "bad-missing-file": "'findings'/0: [required] 'file'",
    "bad-missing-findings": "<root>: [required] 'findings'",
    "bad-missing-line": "'findings'/0: [required] 'line'",
    "bad-missing-quote": "'findings'/0: [required] 'quote'",
    "bad-missing-severity": "'findings'/0: [required] 'severity'",
    "bad-missing-side": "'findings'/0: [required] 'side'",
    "bad-missing-summary": "<root>: [required] 'summary'",
    "bad-missing-title": "'findings'/0: [required] 'title'",
    "bad-too-many-findings": "'findings': [maxItems]",
}

ENVELOPE_BAD = {
    "bad-bad-kind": "envelope schema: 'kind': [enum]",
    "bad-bad-pass-name": "envelope schema: 'pass': [enum]",
    "bad-bad-status": "envelope schema: 'status': [enum]",
    "bad-bundle-failed-with-payload": "'payload': [type]",
    "bad-bundle-hard-block-string": "'payload'/'prefilter'/'hard_blocks'/0: [type]",
    "bad-bundle-hard-block-without-id": "'payload'/'prefilter'/'hard_blocks'/0: [required] 'id'",
    "bad-bundle-missing-coverage": "'payload': [required] 'coverage'",
    "bad-bundle-missing-dependency-delta": "'payload': [required] 'dependency_delta'",
    "bad-bundle-missing-hard-blocks": "'payload'/'prefilter': [required] 'hard_blocks'",
    "bad-bundle-missing-prefilter": "'payload': [required] 'prefilter'",
    "bad-bundle-skipped-size-null-payload": "'payload': [type]",
    "bad-bundle-skipped-size-with-files": "'payload': [enum] 'files' is not one of",
    "bad-bundle-with-meta": "envelope schema: <root>: [not]",
    "bad-bundle-with-pass": "envelope schema: <root>: [not]",
    "bad-empty-base-ref": "'base_ref': [minLength]",
    "bad-extra-property": "<root>: [additionalProperties]",
    "bad-failed-with-payload": "'payload': [type]",
    "bad-meta-bad-schema-sha": "'meta'/'request_schema_sha256': [pattern]",
    "bad-meta-extra-property": "'meta': [additionalProperties]",
    "bad-meta-long-reason": "'meta'/'reason': [maxLength]",
    "bad-meta-not-object": "'meta': [type]",
    "bad-meta-usage-extra-property": "'meta'/'usage': [additionalProperties]",
    "bad-meta-usage-negative": "'meta'/'usage'/'output_tokens': [minimum]",
    "bad-missing-base-ref": "<root>: [required] 'base_ref'",
    "bad-missing-base-repository-id": "<root>: [required] 'base_repository_id'",
    "bad-missing-base-tip-sha": "<root>: [required] 'base_tip_sha'",
    "bad-missing-head-sha": "<root>: [required] 'head_sha'",
    "bad-missing-kind": "<root>: [required] 'kind'",
    "bad-missing-merge-base-sha": "<root>: [required] 'merge_base_sha'",
    "bad-missing-payload": "<root>: [required] 'payload'",
    "bad-missing-pr-number": "<root>: [required] 'pr_number'",
    "bad-missing-repository-id": "<root>: [required] 'repository_id'",
    "bad-missing-run-attempt": "<root>: [required] 'run_attempt'",
    "bad-missing-run-id": "<root>: [required] 'run_id'",
    "bad-missing-schema-version": "<root>: [required] 'schema_version'",
    "bad-missing-status": "<root>: [required] 'status'",
    "bad-ok-null-payload": "'payload': [type]",
    "bad-pass-ok-bad-findings": "findings schema: <root>: [required] 'findings'",
    "bad-pass-without-pass-field": "<root>: [required] 'pass'",
    "bad-payload-array": "'payload': [type]",
    "bad-pr-number-zero": "'pr_number': [minimum]",
    "bad-run-attempt-zero": "'run_attempt': [minimum]",
    "bad-run-id-string": "'run_id': [type]",
    "bad-short-sha": "'head_sha': [pattern]",
    "bad-skipped-size-with-payload": "'payload': [type]",
    "bad-stale-with-payload": "'payload': [type]",
    "bad-uppercase-sha": "'base_tip_sha': [pattern]",
    "bad-wrong-schema-version": "'schema_version': [const]",
}


@pytest.mark.parametrize("name", fixture_names("findings", "good"))
def test_findings_good(name):
    validate_findings(load_fixture("findings", name))


@pytest.mark.parametrize("name", fixture_names("findings", "bad"))
def test_findings_bad(name):
    with pytest.raises(EnvelopeError, match=re.escape(FINDINGS_BAD[name])):
        validate_findings(load_fixture("findings", name))


@pytest.mark.parametrize("name", fixture_names("envelope", "good"))
def test_envelope_good(name):
    validate_envelope(load_fixture("envelope", name))


@pytest.mark.parametrize("name", fixture_names("envelope", "bad"))
def test_envelope_bad(name):
    with pytest.raises(EnvelopeError, match=re.escape(ENVELOPE_BAD[name])):
        validate_envelope(load_fixture("envelope", name))


def test_fixture_sets_not_empty():
    for kind in ("findings", "envelope"):
        assert fixture_names(kind, "good") and fixture_names(kind, "bad")


def test_expected_tables_match_fixture_files():
    assert sorted(FINDINGS_BAD) == fixture_names("findings", "bad")
    assert sorted(ENVELOPE_BAD) == fixture_names("envelope", "bad")
