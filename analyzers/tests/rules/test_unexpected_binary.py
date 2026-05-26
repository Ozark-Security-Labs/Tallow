from pathlib import Path

from rules.unexpected_binary import UnexpectedBinaryRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path, options: dict | None = None):
    payload = {
        "contract_version": "v1",
        "job_id": "job_binary",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "npm", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_pkg",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
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
