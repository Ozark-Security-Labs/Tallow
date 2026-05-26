"""Analyzer rule metadata and registry protocol."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from tallow_analyzer_sdk.context import AnalysisContext
    from tallow_analyzer_sdk.finding import FindingDraft


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    version: str
    name: str
    description: str
    category: str
    ecosystems: tuple[str, ...]
    default_severity_hint: str
    default_confidence: str
    inputs: tuple[str, ...] = ("snapshot",)
    tags: tuple[str, ...] = field(default_factory=tuple)


class Rule(Protocol):
    metadata: RuleMetadata

    def evaluate(self, context: AnalysisContext) -> Iterable[FindingDraft]: ...


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        rule_id = rule.metadata.rule_id
        if rule_id in self._rules:
            raise ValueError(f"duplicate rule_id: {rule_id}")
        self._rules[rule_id] = rule

    def all(self) -> list[Rule]:
        return [self._rules[key] for key in sorted(self._rules)]

    def enabled_for(
        self,
        ecosystem: str,
        enabled_rules: list[str] | None = None,
        disabled_rules: list[str] | None = None,
    ) -> list[Rule]:
        disabled = set(disabled_rules or [])
        enabled = set(enabled_rules or [])
        selected: list[Rule] = []
        for rule in self.all():
            if ecosystem not in rule.metadata.ecosystems and "*" not in rule.metadata.ecosystems:
                continue
            if enabled and rule.metadata.rule_id not in enabled:
                continue
            if rule.metadata.rule_id in disabled:
                continue
            selected.append(rule)
        return selected
