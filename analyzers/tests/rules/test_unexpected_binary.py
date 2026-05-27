from pathlib import Path

from rules.unexpected_binary import UnexpectedBinaryRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(
    root: Path,
    options: dict | None = None,
    from_root: Path | None = None,
    analysis_type: str | None = None,
):
    refs = {
        "to": {
            "snapshot_id": "snap_pkg",
            "root": str(root),
            "manifest_path": str(root / "manifest.json"),
        }
    }
    if from_root is not None:
        refs["from"] = {
            "snapshot_id": "snap_old",
            "root": str(from_root),
            "manifest_path": str(from_root / "manifest.json"),
        }
    payload = {
        "contract_version": "v1",
        "job_id": "job_binary",
        "analysis_type": analysis_type or ("snapshot_diff" if from_root else "snapshot"),
        "subject": {"ecosystem": "npm", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": refs,
        "options": options or {},
    }
    return list(UnexpectedBinaryRule().evaluate(AnalysisContext.from_input(payload)))


def test_detects_elf_with_hash_size_and_magic(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    binary = tmp_path / "bin" / "native"
    binary.parent.mkdir()
    binary.write_bytes(b"\x7fELF" + b"synthetic-not-executable")
    evidence = _run(tmp_path)[0].evidence[0]
    assert evidence["magic"] == "elf"
    assert evidence["size_bytes"] == binary.stat().st_size
    assert len(evidence["sha256"]) == 64
    assert "synthetic-not-executable" not in str(evidence)


def test_allowed_binary_path_is_ignored(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    binary = tmp_path / "bin" / "native"
    binary.parent.mkdir()
    binary.write_bytes(b"MZ" + b"synthetic")
    assert _run(tmp_path, {"allowed_binary_paths": ["bin/native"]}) == []


def test_allowed_binary_package_is_ignored_for_snapshot(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    binary = tmp_path / "bin" / "native"
    binary.parent.mkdir()
    binary.write_bytes(b"MZ" + b"synthetic")
    assert _run(tmp_path, {"allow_binary_packages": ["npm/pkg"]}) == []


def test_diff_mode_only_emits_new_binaries(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
        (root / "bin").mkdir()
        (root / "bin" / "existing").write_bytes(b"MZ" + b"synthetic")
    (new / "bin" / "added").write_bytes(b"\x7fELF" + b"synthetic")
    findings = _run(new, from_root=old)
    assert [finding.evidence[0]["path"] for finding in findings] == ["bin/added"]


def test_diff_mode_emits_text_to_binary_replacements(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
        (root / "bin").mkdir()
    (old / "bin" / "tool").write_text("console.log('synthetic')", encoding="utf-8")
    (new / "bin" / "tool").write_bytes(b"\x7fELF" + b"synthetic")
    findings = _run(new, from_root=old)
    assert [finding.evidence[0]["path"] for finding in findings] == ["bin/tool"]


def test_snapshot_mode_does_not_use_extra_from_ref_for_diff_suppression(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
        (root / "bin").mkdir()
        (root / "bin" / "tool").write_bytes(b"MZ" + b"synthetic")
    findings = _run(new, from_root=old, analysis_type="snapshot")
    assert [finding.evidence[0]["path"] for finding in findings] == ["bin/tool"]


def test_diff_mode_emits_changed_binary_replacements(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
        (root / "bin").mkdir()
    (old / "bin" / "tool").write_bytes(b"MZ" + b"old-synthetic")
    (new / "bin" / "tool").write_bytes(b"\x7fELF" + b"new-synthetic")
    findings = _run(new, from_root=old)
    assert [finding.evidence[0]["path"] for finding in findings] == ["bin/tool"]
    assert findings[0].evidence[0]["magic"] == "elf"


def test_allowed_binary_package_is_ignored_for_diff(tmp_path: Path):
    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
        (root / "bin").mkdir()
    (new / "bin" / "added").write_bytes(b"\x7fELF" + b"synthetic")
    assert _run(new, {"allow_binary_packages": ["pkg"]}, from_root=old) == []
