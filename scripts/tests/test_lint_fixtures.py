from __future__ import annotations

import importlib.util
import stat
from pathlib import Path


def _module():
    path = Path(__file__).resolve().parents[1] / "lint_fixtures.py"
    spec = importlib.util.spec_from_file_location("lint_fixtures", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lint_fixtures = _module()


def test_rejects_realistic_secret_without_fake_marker(tmp_path: Path):
    fixture = tmp_path / "token.txt"
    fixture.write_text("token=ghp_abcdefghijklmnopqrstuvwxyz", encoding="utf-8")
    errors = lint_fixtures.lint_root(tmp_path)
    assert errors == [f"{fixture}: real-looking secret requires fake marker or allowlist"]


def test_allows_fake_secret_marker(tmp_path: Path):
    (tmp_path / "token.txt").write_text(
        "token=tallow_test_000000000000000000", encoding="utf-8"
    )
    assert lint_fixtures.lint_root(tmp_path) == []


def test_rejects_executable_bit_without_allowlist(tmp_path: Path):
    fixture = tmp_path / "script.sh"
    fixture.write_text("#!/bin/sh\necho synthetic fixture\n", encoding="utf-8")
    fixture.chmod(fixture.stat().st_mode | stat.S_IXUSR)
    errors = lint_fixtures.lint_root(tmp_path)
    assert errors == [
        f"{fixture}: executable bit requires {lint_fixtures.ALLOWLIST_NAME} documentation"
    ]


def test_allows_documented_executable_bit(tmp_path: Path):
    (tmp_path / lint_fixtures.ALLOWLIST_NAME).write_text(
        '{"allowed_executable_paths":["script.sh"]}', encoding="utf-8"
    )
    fixture = tmp_path / "script.sh"
    fixture.write_text("#!/bin/sh\necho synthetic fixture\n", encoding="utf-8")
    fixture.chmod(fixture.stat().st_mode | stat.S_IXUSR)
    assert lint_fixtures.lint_root(tmp_path) == []
