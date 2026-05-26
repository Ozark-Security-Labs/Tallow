from pathlib import Path

from rules.high_entropy_blob import HighEntropyBlobRule
from rules.registry import build_registry
from tallow_analyzer_sdk.context import AnalysisContext

HIGH_ENTROPY = bytes([*range(33, 127), *range(128, 256)]) * 3


def _run(to_root: Path, from_root: Path | None = None):
    refs = {
        "to": {
            "snapshot_id": "snap_to",
            "root": str(to_root),
            "manifest_path": str(to_root / "manifest.json"),
        }
    }
    if from_root is not None:
        refs["from"] = {
            "snapshot_id": "snap_from",
            "root": str(from_root),
            "manifest_path": str(from_root / "manifest.json"),
        }
    payload = {
        "contract_version": "v1",
        "job_id": "job_entropy",
        "analysis_type": "snapshot_diff" if from_root else "snapshot",
        "subject": {"ecosystem": "npm", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": refs,
    }
    return list(HighEntropyBlobRule().evaluate(AnalysisContext.from_input(payload)))


def _write(root: Path, relative: str, data: bytes | str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")
    (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")


def test_detects_new_high_entropy_blob_without_full_value(tmp_path: Path):
    _write(tmp_path, "src/payload.txt", HIGH_ENTROPY)
    finding = _run(tmp_path)[0]
    evidence = finding.evidence[0]
    assert evidence["path"] == "src/payload.txt"
    assert evidence["start_byte"] == 0
    assert evidence["end_byte"] == len(HIGH_ENTROPY)
    assert len(evidence["sha256"]) == 64
    assert "Entropy" in evidence["description"]
    assert str(HIGH_ENTROPY) not in str(evidence)


def test_unchanged_entropy_blob_is_ignored(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    _write(old, "src/payload.txt", HIGH_ENTROPY)
    _write(new, "src/payload.txt", HIGH_ENTROPY)
    assert _run(new, old) == []


def test_detects_new_entropy_blob_in_diff_mode(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    _write(old, "src/benign.txt", "hello")
    _write(new, "src/benign.txt", "hello")
    _write(new, "src/payload.txt", HIGH_ENTROPY)
    findings = _run(new, old)
    assert [finding.evidence[0]["path"] for finding in findings] == ["src/payload.txt"]


def test_registry_enables_entropy_rule_for_diff_jobs():
    rule_ids = {
        rule.metadata.rule_id for rule in build_registry().enabled_for("npm", "snapshot_diff")
    }
    assert "artifact.entropy.high_blob" in rule_ids


def test_lockfile_and_minified_benign_are_ignored(tmp_path: Path):
    _write(tmp_path, "package-lock.json", HIGH_ENTROPY)
    _write(tmp_path, "dist/app.min.js", HIGH_ENTROPY)
    assert _run(tmp_path) == []
