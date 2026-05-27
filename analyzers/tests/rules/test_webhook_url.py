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


def test_redacts_path_embedded_webhook_tokens(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "index.ts").write_text(
        "fetch('https://hooks.slack.com/services/T00000000/B00000000/FAKESECRET')\n"
        "fetch('https://api.telegram.org/bot123456:FAKESECRET/sendMessage')\n",
        encoding="utf-8",
    )
    excerpts = [finding.evidence[0]["excerpt"] for finding in _run(tmp_path)]
    assert excerpts
    assert "FAKESECRET" not in str(excerpts)
    assert "bot<redacted>" in str(excerpts)
    assert "<redacted>" in str(excerpts)


def test_redacts_generic_exfil_host_path_tokens(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "index.js").write_text(
        "fetch('https://pastebin.com/raw/abcdef1234567890')\n"
        "fetch('https://gist.githubusercontent.com/user/token/raw/file.js')\n",
        encoding="utf-8",
    )
    excerpts = [finding.evidence[0]["excerpt"] for finding in _run(tmp_path)]
    assert excerpts
    assert "abcdef1234567890" not in str(excerpts)
    assert "user/token/raw/file.js" not in str(excerpts)
    assert "https://pastebin.com/raw/<redacted>" in str(excerpts)
    assert "https://gist.githubusercontent.com/<redacted>/<redacted>/<redacted>/<redacted>" in str(
        excerpts
    )


def test_detects_explicit_port_webhook_urls(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "index.js").write_text(
        "fetch('https://hooks.slack.com:443/services/T000000/B000000/SECRET')\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    excerpt = findings[0].evidence[0]["excerpt"]
    assert "SECRET" not in excerpt
    assert "https://hooks.slack.com:443/services/<redacted>/<redacted>/<redacted>" in excerpt


def test_readme_context_is_ignored(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "README.md").write_text("https://discord.com/api/webhooks/1/fake")
    assert _run(tmp_path) == []
