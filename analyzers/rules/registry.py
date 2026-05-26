"""Built-in rule registry."""

from __future__ import annotations

from rules.high_entropy_blob import HighEntropyBlobRule
from rules.js_env_token import JsEnvTokenRule
from rules.js_eval_decode import JsEvalDecodeRule
from rules.npm_lifecycle import NpmLifecycleRule
from rules.npm_network_script import NpmNetworkScriptRule
from rules.py_decode_exec import PyDecodeExecRule
from rules.pypi_setup_exec import PypiSetupExecRule
from rules.unexpected_binary import UnexpectedBinaryRule
from rules.webhook_url import WebhookUrlRule
from tallow_analyzer_sdk.rules import RuleRegistry


def build_registry() -> RuleRegistry:
    registry = RuleRegistry()
    for rule in (
        NpmLifecycleRule(),
        NpmNetworkScriptRule(),
        JsEnvTokenRule(),
        JsEvalDecodeRule(),
        PypiSetupExecRule(),
        PyDecodeExecRule(),
        WebhookUrlRule(),
        UnexpectedBinaryRule(),
        HighEntropyBlobRule(),
    ):
        registry.register(rule)
    return registry
