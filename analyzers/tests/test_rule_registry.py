import pytest

from tallow_analyzer_sdk.rules import RuleMetadata, RuleRegistry


class DummyRule:
    def __init__(self, rule_id: str, ecosystems=("npm",)) -> None:
        self.metadata = RuleMetadata(
            rule_id=rule_id,
            version="1.0.0",
            name=rule_id,
            description="dummy",
            category="script",
            ecosystems=ecosystems,
            default_severity_hint="medium",
            default_confidence="high",
        )

    def evaluate(self, context):  # noqa: ANN001
        return []


def test_duplicate_rule_ids_fail():
    registry = RuleRegistry()
    registry.register(DummyRule("rule.one"))
    with pytest.raises(ValueError):
        registry.register(DummyRule("rule.one"))


def test_registry_lists_rules_in_order():
    registry = RuleRegistry()
    registry.register(DummyRule("b.rule"))
    registry.register(DummyRule("a.rule"))
    assert [rule.metadata.rule_id for rule in registry.all()] == ["a.rule", "b.rule"]


def test_ecosystem_filtering():
    registry = RuleRegistry()
    registry.register(DummyRule("npm.rule", ecosystems=("npm",)))
    registry.register(DummyRule("pypi.rule", ecosystems=("pypi",)))
    enabled = registry.enabled_for("npm")
    assert [rule.metadata.rule_id for rule in enabled] == ["npm.rule"]


def test_enabled_disabled_options():
    registry = RuleRegistry()
    registry.register(DummyRule("a.rule"))
    registry.register(DummyRule("b.rule"))
    enabled = registry.enabled_for("npm", enabled_rules=["a.rule"])
    assert [rule.metadata.rule_id for rule in enabled] == ["a.rule"]
    disabled = registry.enabled_for("npm", disabled_rules=["a.rule"])
    assert [rule.metadata.rule_id for rule in disabled] == ["b.rule"]
