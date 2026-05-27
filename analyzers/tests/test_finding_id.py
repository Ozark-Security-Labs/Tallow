from tallow_analyzer_sdk.finding_id import build_finding_id, normalize_evidence_for_id


def _subject(**overrides):
    base = {
        "ecosystem": "npm",
        "package_name": "example",
        "version": "1.0.0",
        "artifact_id": "art_1",
    }
    base.update(overrides)
    return base


def _evidence(path: str = "package.json", **overrides):
    base = {
        "kind": "file",
        "artifact_id": "art_1",
        "path": path,
        "start_line": 1,
        "end_line": 1,
    }
    base.update(overrides)
    return [base]


def test_finding_id_is_stable():
    first = build_finding_id("v1", "npm.lifecycle.install_script", _subject(), _evidence())
    second = build_finding_id("v1", "npm.lifecycle.install_script", _subject(), _evidence())
    assert first == second
    assert first.startswith("fin_v1_")


def test_evidence_order_does_not_change_id():
    evidence = [
        {"kind": "file", "artifact_id": "art_1", "path": "b"},
        {"kind": "file", "artifact_id": "art_1", "path": "a"},
    ]
    normalized = normalize_evidence_for_id(evidence)
    first = build_finding_id("v1", "rule", _subject(), evidence)
    second = build_finding_id("v1", "rule", _subject(), list(reversed(evidence)))
    assert first == second
    assert normalized[0]["path"] <= normalized[-1]["path"]


def test_evidence_order_with_same_start_but_different_end_does_not_change_id():
    evidence = [
        {
            "kind": "file",
            "artifact_id": "art_1",
            "path": "package.json",
            "start_line": 1,
            "end_line": 3,
        },
        {
            "kind": "file",
            "artifact_id": "art_1",
            "path": "package.json",
            "start_line": 1,
            "end_line": 2,
        },
    ]
    first = build_finding_id("v1", "rule", _subject(), evidence)
    second = build_finding_id("v1", "rule", _subject(), list(reversed(evidence)))
    assert first == second
    assert normalize_evidence_for_id(evidence)[0]["end_line"] == 2


def test_evidence_order_with_different_artifacts_does_not_change_id():
    evidence = [
        {
            "kind": "file",
            "artifact_id": "art_to",
            "snapshot_id": "snap_to",
            "path": "package.json",
            "start_line": 1,
        },
        {
            "kind": "file",
            "artifact_id": "art_from",
            "snapshot_id": "snap_from",
            "path": "package.json",
            "start_line": 1,
        },
    ]
    first = build_finding_id("v1", "rule", _subject(), evidence)
    second = build_finding_id("v1", "rule", _subject(), list(reversed(evidence)))
    assert first == second
    assert normalize_evidence_for_id(evidence)[0]["artifact_id"] == "art_from"


def test_timestamp_fields_do_not_affect_id():
    subject = _subject(created_at="2026-01-01T00:00:00Z")
    assert build_finding_id("v1", "rule", subject, _evidence()) == build_finding_id(
        "v1", "rule", _subject(), _evidence()
    )


def test_rule_or_path_change_changes_id():
    base = build_finding_id("v1", "rule.a", _subject(), _evidence("a"))
    assert base != build_finding_id("v1", "rule.b", _subject(), _evidence("a"))
    assert base != build_finding_id("v1", "rule.a", _subject(), _evidence("b"))


def test_evidence_hash_change_changes_id():
    base = build_finding_id("v1", "rule.a", _subject(), _evidence("a", hash="abc"))
    assert base != build_finding_id("v1", "rule.a", _subject(), _evidence("a", hash="def"))
