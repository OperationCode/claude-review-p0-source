"""Unit tests for snapshot.py. No network; API data comes from fixtures."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from oc_review import snapshot as s

FIX = Path(__file__).parent / "fixtures" / "snapshot"
HEAD, TIP, MB = "a" * 40, "b" * 40, "c" * 40


def load(name):
    return json.loads((FIX / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def pr():
    return load("pr")


@pytest.fixture
def compare():
    return load("compare")


@pytest.fixture
def snap(pr, compare):
    return s.capture_snapshot(pr, TIP, compare, HEAD)


def entry(path, sha, mode="100644", kind="blob"):
    return {"path": path, "mode": mode, "type": kind, "sha": sha}


def tree(*entries, truncated=False):
    return {"sha": "d" * 40, "truncated": truncated, "tree": list(entries)}


def diff_by_path(d):
    return {f.path: f for f in d.files}


# ---- capture ----


def test_capture(snap):
    assert snap == s.Snapshot(HEAD, 1234, "main", TIP, MB)


def test_capture_head_differs_from_event(pr, compare):
    with pytest.raises(s.StaleSnapshot) as exc:
        s.capture_snapshot(pr, TIP, compare, "e" * 40)
    assert exc.value.reasons == (s.STALE_HEAD_SHA,)


def test_capture_compare_for_other_base_tip(pr, compare):
    with pytest.raises(s.SnapshotError):
        s.capture_snapshot(pr, "e" * 40, compare, HEAD)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda pr, c: pr["head"].update(sha="XYZ"),
        lambda pr, c: pr["base"]["repo"].pop("id"),
        lambda pr, c: pr["base"]["repo"].update(id="1234"),
        lambda pr, c: pr["base"]["repo"].update(id=True),
        lambda pr, c: pr["base"].update(ref=""),
        lambda pr, c: pr["base"]["repo"].pop("default_branch"),
        lambda pr, c: c.pop("merge_base_commit"),
        lambda pr, c: c["merge_base_commit"].update(sha="short"),
        lambda pr, c: c.pop("base_commit"),
    ],
)
def test_capture_malformed_fails_closed(pr, compare, mutate):
    mutate(pr, compare)
    with pytest.raises(s.SnapshotError):
        s.capture_snapshot(pr, TIP, compare, HEAD)


# ---- re-validation ----


def test_revalidate_current(snap, pr, compare):
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.ok and not r.stale and r.stale_reasons == ()


def test_revalidate_head_sha_changed(snap, pr, compare):
    pr["head"]["sha"] = "e" * 40
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.stale_reasons == (s.STALE_HEAD_SHA,)


def test_revalidate_base_repository_changed(snap, pr, compare):
    pr["base"]["repo"]["id"] = 99
    assert s.revalidate(snap, pr, TIP, compare).stale_reasons == (s.STALE_BASE_REPOSITORY,)


def test_revalidate_base_ref_changed_to_default_is_stale(snap, pr, compare):
    pr["base"]["ref"] = "other"
    pr["base"]["repo"]["default_branch"] = "other"
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.stale_reasons == (s.STALE_BASE_REF,)
    assert not r.base_not_default_branch


def test_revalidate_retarget_to_non_default_branch(snap, pr, compare):
    pr["base"]["ref"] = "release"
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.stale_reasons == (s.STALE_BASE_REF,)
    assert r.base_not_default_branch and not r.ok


def test_revalidate_merge_base_changed_after_base_moves(snap, pr, compare):
    compare["merge_base_commit"]["sha"] = "f" * 40
    compare["base_commit"]["sha"] = "1" * 40  # new base tip
    r = s.revalidate(snap, pr, "1" * 40, compare)
    assert r.stale_reasons == (s.STALE_MERGE_BASE,)


def test_revalidate_new_base_tip_same_merge_base_is_current(snap, pr, compare):
    compare["base_commit"]["sha"] = "1" * 40
    assert s.revalidate(snap, pr, "1" * 40, compare).ok


def test_revalidate_all_conditions_together(snap, pr, compare):
    pr["head"]["sha"] = "e" * 40
    pr["base"]["repo"]["id"] = 99
    pr["base"]["ref"] = "release"
    compare["merge_base_commit"]["sha"] = "f" * 40
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.stale_reasons == (
        s.STALE_HEAD_SHA,
        s.STALE_BASE_REPOSITORY,
        s.STALE_BASE_REF,
        s.STALE_MERGE_BASE,
    )
    assert r.base_not_default_branch


def test_revalidate_compare_for_wrong_tip_fails_closed(snap, pr, compare):
    with pytest.raises(s.SnapshotError):
        s.revalidate(snap, pr, "1" * 40, compare)


def test_base_not_default_branch_with_unchanged_snapshot(pr, compare):
    pr["base"]["ref"] = "release"
    snap = s.capture_snapshot(pr, TIP, compare, HEAD)
    r = s.revalidate(snap, pr, TIP, compare)
    assert r.stale_reasons == () and r.base_not_default_branch and not r.ok
    assert not s.base_is_default_branch(pr)


def test_check_head_and_base_ref(snap, pr):
    assert s.check_head_and_base_ref(snap, pr).ok
    pr["head"]["sha"] = "e" * 40
    assert s.check_head_and_base_ref(snap, pr).stale_reasons == (s.STALE_HEAD_SHA,)
    pr["head"]["sha"] = HEAD
    pr["base"]["ref"] = "release"
    r = s.check_head_and_base_ref(snap, pr)
    assert r.stale_reasons == (s.STALE_BASE_REF,) and r.base_not_default_branch


def test_check_head_and_base_ref_ignores_repo_and_merge_base(snap, pr):
    pr["base"]["repo"]["id"] = 99
    assert s.check_head_and_base_ref(snap, pr).ok


# ---- tree diff: fixture ----


def test_fixture_diff():
    d = s.diff_trees(load("tree_base"), load("tree_head"))
    assert d.complete
    by = diff_by_path(d)
    assert set(by) == {
        "src/edit.py", "src/gone.py", "src/new.py", "run.sh",
        "new/name.py", "link", "vendor/lib",
    }  # fmt: skip
    assert by["src/edit.py"].status == s.STATUS_MODIFIED
    assert by["src/gone.py"].status == s.STATUS_REMOVED
    assert by["src/new.py"].status == s.STATUS_ADDED
    assert by["run.sh"].mode_only and by["run.sh"].became_executable
    assert by["new/name.py"].status == s.STATUS_RENAMED
    assert by["new/name.py"].old_path == "old/name.py"
    assert by["link"].is_symlink and by["vendor/lib"].is_submodule
    assert [f.path for f in d.files] == sorted(by)


# ---- tree diff: cases ----


def test_identical_trees_no_changes():
    t = tree(entry("a", "1" * 40))
    assert s.diff_trees(t, copy.deepcopy(t)).files == ()


def test_added():
    f = s.diff_trees(tree(), tree(entry("a", "1" * 40))).files[0]
    assert (f.status, f.base_sha, f.head_sha, f.base_mode, f.head_mode) == (
        s.STATUS_ADDED, None, "1" * 40, None, "100644",
    )  # fmt: skip


def test_removed_has_base_blob_only():
    f = s.diff_trees(tree(entry("a", "1" * 40)), tree()).files[0]
    assert (f.status, f.base_sha, f.head_sha) == (s.STATUS_REMOVED, "1" * 40, None)


def test_modified_content():
    f = s.diff_trees(tree(entry("a", "1" * 40)), tree(entry("a", "2" * 40))).files[0]
    assert f.status == s.STATUS_MODIFIED and not f.mode_changed and not f.mode_only


def test_mode_only_change_to_executable():
    f = s.diff_trees(
        tree(entry("a", "1" * 40)), tree(entry("a", "1" * 40, "100755"))
    ).files[0]
    assert f.status == s.STATUS_MODIFIED
    assert f.mode_only and f.mode_changed and f.became_executable
    assert (f.base_mode, f.head_mode) == ("100644", "100755")


def test_mode_only_change_from_executable_is_not_a_signal():
    f = s.diff_trees(
        tree(entry("a", "1" * 40, "100755")), tree(entry("a", "1" * 40))
    ).files[0]
    assert f.mode_only and not f.became_executable


def test_content_and_mode_change_together():
    f = s.diff_trees(
        tree(entry("a", "1" * 40)), tree(entry("a", "2" * 40, "100755"))
    ).files[0]
    assert f.status == s.STATUS_MODIFIED and f.mode_changed and not f.mode_only
    assert f.became_executable


def test_added_executable_file_is_executable_signal():
    f = s.diff_trees(tree(), tree(entry("a", "1" * 40, "100755"))).files[0]
    assert f.became_executable


def test_file_replaced_by_symlink_same_blob():
    f = s.diff_trees(
        tree(entry("a", "1" * 40)), tree(entry("a", "1" * 40, "120000"))
    ).files[0]
    assert f.mode_only and f.is_symlink and not f.became_executable


def test_symlink_target_change():
    f = s.diff_trees(
        tree(entry("l", "1" * 40, "120000")), tree(entry("l", "2" * 40, "120000"))
    ).files[0]
    assert f.status == s.STATUS_MODIFIED and f.is_symlink and not f.mode_changed


def test_submodule_commit_change_records_old_and_new_sha():
    f = s.diff_trees(
        tree(entry("m", "1" * 40, "160000", "commit")),
        tree(entry("m", "2" * 40, "160000", "commit")),
    ).files[0]
    assert f.is_submodule and (f.base_sha, f.head_sha) == ("1" * 40, "2" * 40)


def test_submodule_added_and_removed():
    d = s.diff_trees(
        tree(entry("old", "1" * 40, "160000", "commit")),
        tree(entry("new", "1" * 40, "160000", "commit")),
    )
    assert {(f.path, f.status) for f in d.files} == {
        ("old", s.STATUS_REMOVED), ("new", s.STATUS_ADDED),
    }  # fmt: skip


def test_file_replaced_by_submodule():
    f = s.diff_trees(
        tree(entry("m", "1" * 40)), tree(entry("m", "2" * 40, "160000", "commit"))
    ).files[0]
    assert f.status == s.STATUS_MODIFIED and f.is_submodule and f.mode_changed


def test_rename_is_identical_blob_at_new_path():
    d = s.diff_trees(tree(entry("a", "1" * 40)), tree(entry("b", "1" * 40)))
    (f,) = d.files
    assert (f.status, f.path, f.old_path) == (s.STATUS_RENAMED, "b", "a")


def test_rename_with_edit_is_delete_plus_add():
    d = s.diff_trees(tree(entry("a", "1" * 40)), tree(entry("b", "2" * 40)))
    assert {(f.path, f.status) for f in d.files} == {
        ("a", s.STATUS_REMOVED), ("b", s.STATUS_ADDED),
    }  # fmt: skip


def test_rename_with_mode_change_keeps_both_modes():
    (f,) = s.diff_trees(
        tree(entry("a", "1" * 40)), tree(entry("b", "1" * 40, "100755"))
    ).files
    assert f.status == s.STATUS_RENAMED and f.mode_changed and f.became_executable


def test_copy_is_not_a_rename():
    d = s.diff_trees(
        tree(entry("a", "1" * 40)), tree(entry("a", "1" * 40), entry("b", "1" * 40))
    )
    assert [(f.path, f.status) for f in d.files] == [("b", s.STATUS_ADDED)]


def test_duplicate_blobs_pair_one_to_one_in_path_order():
    d = s.diff_trees(
        tree(entry("a1", "1" * 40), entry("a2", "1" * 40)),
        tree(entry("b1", "1" * 40), entry("b2", "1" * 40), entry("b3", "1" * 40)),
    )
    by = diff_by_path(d)
    assert (by["b1"].status, by["b1"].old_path) == (s.STATUS_RENAMED, "a1")
    assert (by["b2"].status, by["b2"].old_path) == (s.STATUS_RENAMED, "a2")
    assert by["b3"].status == s.STATUS_ADDED


def test_tree_entries_are_ignored():
    d = s.diff_trees(
        tree(entry("dir", "1" * 40, "040000", "tree")),
        tree(entry("dir", "2" * 40, "040000", "tree")),
    )
    assert d.files == ()


def test_truncated_either_side_is_incomplete():
    ok = tree(entry("a", "1" * 40))
    cut = tree(entry("a", "1" * 40), truncated=True)
    assert s.diff_trees(ok, ok).complete
    assert not s.diff_trees(cut, ok).complete
    assert not s.diff_trees(ok, cut).complete


@pytest.mark.parametrize(
    "bad",
    [
        entry("a", "short"),
        entry("a", "1" * 40, "755"),
        entry("a", "1" * 40, kind="weird"),
        entry("a", "1" * 40, "160000", "blob"),
        entry("a", "1" * 40, "100644", "commit"),
        entry("", "1" * 40),
        "not-an-object",
        # Octal but not a git mode, or a mode of the wrong type.
        entry("a", "1" * 40, "100664"),
        entry("a", "1" * 40, "000000"),
        entry("a", "1" * 40, "040000", "blob"),
        entry("a", "1" * 40, "100644", "tree"),
        entry("a", "1" * 40, "160000", "tree"),
        entry("a", "1" * 40, mode=None),
    ],
)
def test_malformed_tree_entry_fails_closed(bad):
    with pytest.raises(s.SnapshotError):
        s.diff_trees(tree(bad), tree())


@pytest.mark.parametrize("side", ["base", "head"])
def test_blob_mode_on_tree_entry_does_not_drop_the_file(side):
    # A `tree` type must not hide a file entry as a skipped directory.
    bad = tree(entry("dropped.py", "1" * 40, "100644", "tree"))
    args = (bad, tree()) if side == "base" else (tree(), bad)
    with pytest.raises(s.SnapshotError, match="disagree"):
        s.diff_trees(*args)


@pytest.mark.parametrize(
    "mode, kind",
    [("040000", "tree"), ("100644", "blob"), ("100755", "blob"), ("120000", "blob"), ("160000", "commit")],
)
def test_every_git_mode_is_accepted_with_its_type(mode, kind):
    s.diff_trees(tree(entry("a", "1" * 40, mode, kind)), tree())


def test_duplicate_path_fails_closed():
    with pytest.raises(s.SnapshotError):
        s.diff_trees(tree(entry("a", "1" * 40), entry("a", "2" * 40)), tree())


@pytest.mark.parametrize("side", ["base", "head"])
def test_missing_truncated_key_fails_closed(side):
    # A response with no `truncated` key must not count as a complete tree.
    no_flag = {"sha": "d" * 40, "tree": [entry("a", "1" * 40)]}
    args = (no_flag, tree()) if side == "base" else (tree(), no_flag)
    with pytest.raises(s.SnapshotError, match="truncated"):
        s.diff_trees(*args)


def test_missing_tree_key_fails_closed():
    with pytest.raises(s.SnapshotError):
        s.diff_trees({"truncated": False}, tree())
