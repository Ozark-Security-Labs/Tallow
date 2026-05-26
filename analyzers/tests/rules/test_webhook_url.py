from pathlib import Path

from rules.webhook_url import WebhookUrlRule
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_webhook",
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
    }
    return list(WebhookUrlRule().evaluate(AnalysisContext.from_input(payload)))


def test_detects_and_redacts_webhook_query(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "index.js").write_text(
        "fetch('https://discord.com/api/webhooks/1/fake?token=fake-secret')\n",
        encoding="utf-8",
    )
    evidence = _run(tmp_path)[0].evidence[0]
    assert "?token=" not in evidence["excerpt"]
    assert "?<redacted>" in evidence["excerpt"]


def test_readme_context_is_ignored(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "README.md").write_text("https://discord.com/api/webhooks/1/fake")
    assert _run(tmp_path) == []
