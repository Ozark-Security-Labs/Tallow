import pytest

from tallow_analyzer_sdk.rules import RuleMetadata, RuleRegistry, validate_rule_metadata


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
    registry.register(DummyRule("npm.rule.one"))
    with pytest.raises(ValueError):
        registry.register(DummyRule("npm.rule.one"))


@pytest.mark.parametrize(
    "rule_id",
    ["npm.lifecycle.install_script", "js.secrets.env_token_access", "artifact.binary.unexpected"],
)
def test_namespaced_rule_ids_are_valid(rule_id: str):
    validate_rule_metadata(DummyRule(rule_id).metadata)


@pytest.mark.parametrize("rule_id", ["rule", "Rule.Bad.Name", "npm..bad"])
def test_invalid_rule_ids_fail(rule_id: str):
    with pytest.raises(ValueError):
        validate_rule_metadata(DummyRule(rule_id).metadata)


def test_metadata_requires_description_ecosystem_severity_and_confidence():
    with pytest.raises(ValueError):
        validate_rule_metadata(
            RuleMetadata(
                rule_id="npm.lifecycle.missing_description",
                version="1.0.0",
                name="bad",
                description="",
                category="script",
                ecosystems=("npm",),
                default_severity_hint="medium",
                default_confidence="high",
            )
        )
    with pytest.raises(ValueError):
        validate_rule_metadata(
            RuleMetadata(
                rule_id="npm.lifecycle.missing_ecosystem",
                version="1.0.0",
                name="bad",
                description="bad",
                category="script",
                ecosystems=(),
                default_severity_hint="medium",
                default_confidence="high",
            )
        )
    with pytest.raises(ValueError):
        validate_rule_metadata(
            RuleMetadata(
                rule_id="npm.lifecycle.invalid_severity",
                version="1.0.0",
                name="bad",
                description="bad",
                category="script",
                ecosystems=("npm",),
                default_severity_hint="severe",
                default_confidence="high",
            )
        )
    with pytest.raises(ValueError):
        validate_rule_metadata(
            RuleMetadata(
                rule_id="npm.lifecycle.invalid_confidence",
                version="1.0.0",
                name="bad",
                description="bad",
                category="script",
                ecosystems=("npm",),
                default_severity_hint="medium",
                default_confidence="certain",
            )
        )


def test_registry_lists_rules_in_order():
    registry = RuleRegistry()
    registry.register(DummyRule("npm.rule.b"))
    registry.register(DummyRule("npm.rule.a"))
    assert [rule.metadata.rule_id for rule in registry.all()] == [
        "npm.rule.a",
        "npm.rule.b",
    ]


def test_ecosystem_filtering():
    registry = RuleRegistry()
    registry.register(DummyRule("npm.rule.test", ecosystems=("npm",)))
    registry.register(DummyRule("pypi.rule.test", ecosystems=("pypi",)))
    enabled = registry.enabled_for("npm", "snapshot")
    assert [rule.metadata.rule_id for rule in enabled] == ["npm.rule.test"]


def test_input_type_filtering():
    registry = RuleRegistry()
    registry.register(DummyRule("npm.rule.snapshot"))
    hash_rule = DummyRule("npm.rule.hash")
    hash_rule.metadata = RuleMetadata(
        rule_id="npm.rule.hash",
        version="1.0.0",
        name="hash",
        description="dummy",
        category="hash",
        ecosystems=("npm",),
        default_severity_hint="medium",
        default_confidence="high",
        inputs=("hash_verification",),
    )
    registry.register(hash_rule)
    enabled = registry.enabled_for("npm", "hash_verification")
    assert [rule.metadata.rule_id for rule in enabled] == ["npm.rule.hash"]


def test_enabled_disabled_options():
    registry = RuleRegistry()
    registry.register(DummyRule("npm.rule.a"))
    registry.register(DummyRule("npm.rule.b"))
    enabled = registry.enabled_for("npm", "snapshot", enabled_rules=["npm.rule.a"])
    assert [rule.metadata.rule_id for rule in enabled] == ["npm.rule.a"]
    disabled = registry.enabled_for("npm", "snapshot", disabled_rules=["npm.rule.a"])
    assert [rule.metadata.rule_id for rule in disabled] == ["npm.rule.b"]
