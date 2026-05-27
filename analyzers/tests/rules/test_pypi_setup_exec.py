from pathlib import Path

from rules.pypi_setup_exec import PypiSetupExecRule
from rules.registry import build_registry
from tallow_analyzer_sdk.context import AnalysisContext


def _run(root: Path):
    payload = {
        "contract_version": "v1",
        "job_id": "job_setup",
        "analysis_type": "snapshot",
        "subject": {"ecosystem": "pypi", "package_name": "pkg", "version": "1.0.0"},
        "artifacts": {"to": {"artifact_id": "art_pkg"}},
        "snapshot_refs": {
            "to": {
                "snapshot_id": "snap_pkg",
                "root": str(root),
                "manifest_path": str(root / "manifest.json"),
            }
        },
    }
    return list(PypiSetupExecRule().evaluate(AnalysisContext.from_input(payload)))


def test_detects_setup_py_exec_sink(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "setup.py").write_text("import os\nos.system('echo synthetic')\n")
    findings = _run(tmp_path)
    assert findings[0].rule.rule_id == "pypi.setup.exec_call"
    assert findings[0].evidence[0]["start_line"] == 2


def test_detects_setup_cfg_exec_marker(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "setup.cfg").write_text("[install]\ncmd = subprocess.run(['echo'])\n")
    findings = _run(tmp_path)
    assert findings[0].confidence == "medium"


def test_detects_pyproject_cmdclass_hook(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.setuptools.cmdclass]\ninstall = "pkg.build.InstallCommand"\n',
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert findings[0].confidence == "medium"
    assert findings[0].evidence[0]["path"] == "pyproject.toml"


def test_detects_suspicious_pyproject_build_backend(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "pkg.dynamic_backend"\n',
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert findings[0].evidence[0]["start_line"] == 2


def test_safe_setup_py_does_not_emit(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup(name='safe')\n")
    assert _run(tmp_path) == []


def test_safe_pyproject_backend_does_not_emit(tmp_path: Path):
    (tmp_path / "manifest.json").write_text('{"files":[]}', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "setuptools.build_meta"\n',
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_registry_enables_setup_rule_for_pypi_diff_jobs():
    rule_ids = {
        rule.metadata.rule_id for rule in build_registry().enabled_for("pypi", "snapshot_diff")
    }
    assert "pypi.setup.exec_call" in rule_ids
