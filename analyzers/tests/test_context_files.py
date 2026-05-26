from datetime import UTC, datetime
from pathlib import Path

import pytest

from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.files import SnapshotWalker

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "snapshots" / "simple_npm"


def _context(root: Path) -> AnalysisContext:
    payload = {
        "contract_version": "v1",
        "job_id": "job_test",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "npm", "package_name": "simple", "version": "1.0.0"},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_test",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
        "options": {"max_file_bytes": 4096},
    }
    return AnalysisContext.from_input(payload)


def test_traversal_sorted_order(tmp_path: Path):
    root = FIXTURE_ROOT
    walker = _context(root).walker("to")
    paths = [item.relative_path for item in walker.iter_files()]
    assert paths == sorted(paths)


def test_oversized_file_skipped(tmp_path: Path):
    root = tmp_path / "snap"
    (root / "package").mkdir(parents=True)
    big = root / "package" / "big.txt"
    big.write_text("x" * 100)
    _context(root)
    walker = SnapshotWalker(root=root, max_file_bytes=16)
    assert walker.iter_files() == []


def test_read_helpers_reject_root_escape(tmp_path: Path):
    root = tmp_path / "snap"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("not fixture data", encoding="utf-8")
    walker = SnapshotWalker(root=root, max_file_bytes=4096)
    with pytest.raises(ValueError, match="escapes root"):
        walker.read_text("../secret.txt")
    with pytest.raises(ValueError, match="escapes root"):
        walker.read_bytes("../secret.txt")


def test_finding_builder_emits_valid_schema():
    from tallow_analyzer_sdk.contracts import validate_finding
    from tallow_analyzer_sdk.evidence import file_evidence
    from tallow_analyzer_sdk.finding import FindingDraft, build_finding
    from tallow_analyzer_sdk.rules import RuleMetadata

    rule = RuleMetadata(
        rule_id="npm.lifecycle.install_script",
        version="1.0.0",
        name="test",
        description="test",
        category="script",
        ecosystems=("npm",),
        default_severity_hint="medium",
        default_confidence="high",
    )
    finding = build_finding(
        FindingDraft(
            rule=rule,
            subject={"ecosystem": "npm", "package_name": "x", "version": "1.0.0"},
            title="title",
            summary="summary",
            evidence=[
                file_evidence(
                    "package/package.json",
                    artifact_id="art_1",
                    snapshot_id="snap_1",
                    start_line=1,
                    end_line=1,
                    snippet='{"name":"x"}',
                )
            ],
            tags=["npm"],
        ),
        created_at=datetime(2026, 5, 26, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
    )
    validate_finding(finding)
