from tallow_analyzer_sdk.canonical_json import (
    canonical_dumps,
    canonical_sha256,
    sort_findings,
    strip_runtime_fields,
)


def test_canonical_dumps_sorts_keys():
    first = {"b": 1, "a": 2}
    second = {"a": 2, "b": 1}
    assert canonical_dumps(first) == canonical_dumps(second)
    assert canonical_sha256(first) == canonical_sha256(second)


def test_list_order_affects_hash():
    assert canonical_sha256([1, 2]) != canonical_sha256([2, 1])


def test_sort_findings_is_stable():
    findings = [
        {"id": "b", "rule_id": "rule.b", "severity_hint": "low", "evidence": [{"path": "b"}]},
        {"id": "a", "rule_id": "rule.a", "severity_hint": "high", "evidence": [{"path": "a"}]},
    ]
    shuffled = list(reversed(findings))
    assert sort_findings(findings) == sort_findings(shuffled)


def test_strip_runtime_fields():
    payload = {
        "findings": [{"id": "x", "created_at": "2026-01-01T00:00:00Z"}],
        "metrics": {},
    }
    cleaned = strip_runtime_fields(payload)
    assert cleaned == payload
