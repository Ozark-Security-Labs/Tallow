import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "lint_fixtures",
    REPO_ROOT / "scripts" / "lint_fixtures.py",
)
assert spec is not None and spec.loader is not None
lint_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lint_fixtures)
lint_root = lint_fixtures.lint_root


def test_fixture_linter_accepts_analyzer_fixtures():
    root = Path(__file__).resolve().parents[2] / "testdata" / "analyzer-fixtures"
    assert lint_root(root) == []


def test_fixture_linter_rejects_large_secret_and_executable(tmp_path: Path):
    secret = tmp_path / "secret.txt"
    secret.write_text("token='ghp_abcdefghijklmnopqrstuvwxyz123456'", encoding="utf-8")
    executable = tmp_path / "run.sh"
    executable.write_text("#!/bin/sh\necho synthetic\n", encoding="utf-8")
    executable.chmod(0o755)
    large = tmp_path / "large.bin"
    large.write_bytes(b"0" * (256 * 1024 + 1))

    errors = lint_root(tmp_path)
    assert any("real-looking secret" in error for error in errors)
    assert any("executable bit" in error for error in errors)
    assert any("fixture exceeds" in error for error in errors)


def test_fixture_linter_allows_documented_fake_secret(tmp_path: Path):
    (tmp_path / "fixture-safety.json").write_text(
        '{"allowed_secret_paths":["secret.txt"],"allowed_executable_paths":[]}',
        encoding="utf-8",
    )
    (tmp_path / "secret.txt").write_text(
        "token='tallow_test_000000000000000000'",
        encoding="utf-8",
    )
    assert lint_root(tmp_path) == []
