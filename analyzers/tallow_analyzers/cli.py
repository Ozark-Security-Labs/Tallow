"""Tallow built-in analyzer CLI."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from rules.registry import build_registry
from tallow_analyzer_sdk.canonical_json import sort_findings
from tallow_analyzer_sdk.constants import (
    ANALYZER_ID,
    ANALYZER_VERSION,
    CONTRACT_VERSION,
    DETERMINISTIC_FINDING_CREATED_AT,
    RULESET_VERSION,
)
from tallow_analyzer_sdk.context import AnalysisContext
from tallow_analyzer_sdk.contracts import (
    ValidationError,
    validate_analyzer_input,
    validate_analyzer_output,
)
from tallow_analyzer_sdk.finding import build_finding


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Tallow deterministic analyzers")
    parser.add_argument("--input", type=Path, help="Analyzer input JSON path")
    parser.add_argument("--output", type=Path, help="Analyzer output JSON path")
    parser.add_argument("--list-rules", action="store_true", help="Print registered rules")
    return parser.parse_args(argv)


def _load_input(path: Path | None) -> dict:
    if path is None:
        payload = json.load(sys.stdin)
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError("analyzer input must be a JSON object")
    validate_analyzer_input(payload)
    return payload


def _write_output(payload: dict, path: Path | None) -> None:
    validate_analyzer_output(payload)
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(encoded)
    else:
        path.write_text(encoded, encoding="utf-8")


def _list_rules() -> None:
    registry = build_registry()
    payload = [
        {
            **asdict(rule.metadata),
            "ecosystems": list(rule.metadata.ecosystems),
            "inputs": list(rule.metadata.inputs),
            "tags": list(rule.metadata.tags),
        }
        for rule in registry.all()
    ]
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def run_analyzer(payload: dict) -> dict:
    context = AnalysisContext.from_input(payload)
    registry = build_registry()
    options = payload.get("options") or {}
    enabled = registry.enabled_for(
        context.ecosystem,
        payload["analysis_type"],
        enabled_rules=options.get("enabled_rules"),
        disabled_rules=options.get("disabled_rules"),
    )
    findings: list[dict] = []
    errors: list[dict] = []
    rules_failed = 0
    files_scanned = 0
    for rule in enabled:
        try:
            drafts = list(rule.evaluate(context))
            for draft in drafts:
                findings.append(build_finding(draft, created_at=DETERMINISTIC_FINDING_CREATED_AT))
            if drafts:
                files_scanned += 1
        except Exception as exc:  # noqa: BLE001 - convert to deterministic error record
            rules_failed += 1
            errors.append(
                {
                    "code": "rule_failed",
                    "message": str(exc),
                    "rule_id": rule.metadata.rule_id,
                }
            )
            if context.fail_fast:
                break
    findings = sort_findings(findings)
    return {
        "contract_version": CONTRACT_VERSION,
        "job_id": payload["job_id"],
        "analyzer": {
            "id": ANALYZER_ID,
            "version": ANALYZER_VERSION,
            "ruleset_version": RULESET_VERSION,
        },
        "status": "failed" if errors else "ok",
        "findings": findings,
        "errors": errors,
        "metrics": {
            "rules_evaluated": len(enabled),
            "files_scanned": files_scanned,
            "findings_emitted": len(findings),
            "rules_failed": rules_failed,
            "files_skipped_size": 0,
            "files_skipped_binary": 0,
        },
    }


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.list_rules:
        _list_rules()
        return 0
    try:
        payload = _load_input(args.input)
        output = run_analyzer(payload)
        _write_output(output, args.output)
        return 0
    except ValidationError:
        return 2
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
