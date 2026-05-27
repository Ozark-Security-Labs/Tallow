"""Analysis context for rule evaluation."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tallow_analyzer_sdk.files import SnapshotWalker


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class AnalysisContext:
    analyzer_input: dict
    subject: dict
    ecosystem: str
    snapshot_roots: dict[str, Path]
    options: dict
    clock: Callable[[], datetime] = field(default=_utc_now)

    @classmethod
    def from_input(cls, payload: dict, repo_root: Path | None = None) -> AnalysisContext:
        subject = _finding_subject(payload)
        snapshot_refs = payload.get("snapshot_refs") or {}
        roots: dict[str, Path] = {}
        for side in ("from", "to"):
            ref = snapshot_refs.get(side)
            if ref and ref.get("root"):
                roots[side] = Path(ref["root"])
        return cls(
            analyzer_input=payload,
            subject=subject,
            ecosystem=subject["ecosystem"],
            snapshot_roots=roots,
            options=payload.get("options") or {},
        )

    @property
    def max_file_bytes(self) -> int:
        return int(self.options.get("max_file_bytes", 1_048_576))

    @property
    def max_findings_per_rule(self) -> int:
        return int(self.options.get("max_findings_per_rule", 100))

    @property
    def allow_binary_packages(self) -> set[str]:
        values = self.options.get("allow_binary_packages") or []
        if isinstance(values, bool):
            return {"*"} if values else set()
        return {str(value).strip() for value in values if str(value).strip()}

    @property
    def package_binary_allowed(self) -> bool:
        allowed = self.allow_binary_packages
        package_name = str(self.subject.get("package_name") or "")
        ecosystem_name = f"{self.ecosystem}/{package_name}"
        return "*" in allowed or package_name in allowed or ecosystem_name in allowed

    @property
    def allowed_binary_paths(self) -> set[str]:
        values = self.options.get("allowed_binary_paths") or []
        return {str(value).replace("\\", "/") for value in values if str(value).strip()}

    @property
    def fail_fast(self) -> bool:
        return bool(self.options.get("fail_fast", False))

    def artifact_id(self, side: str = "to") -> str | None:
        artifacts = self.analyzer_input.get("artifacts") or {}
        entry = artifacts.get(side) or {}
        artifact_id = entry.get("artifact_id")
        if artifact_id:
            return artifact_id
        return self.subject.get("artifact_id")

    def snapshot_id(self, side: str = "to") -> str | None:
        snapshot_refs = self.analyzer_input.get("snapshot_refs") or {}
        ref = snapshot_refs.get(side) or {}
        snapshot_id = ref.get("snapshot_id")
        if snapshot_id:
            return snapshot_id
        return self.subject.get("snapshot_id")

    def walker(self, side: str = "to") -> SnapshotWalker:
        root = self.snapshot_roots.get(side)
        if root is None:
            raise ValueError(f"snapshot root missing for side {side}")
        return SnapshotWalker(
            root=root,
            max_file_bytes=self.max_file_bytes,
            include_binary=False,
        )


def _finding_subject(payload: dict) -> dict:
    subject = dict(payload["subject"])
    artifacts = payload.get("artifacts") or {}
    snapshot_refs = payload.get("snapshot_refs") or {}
    from_artifact = artifacts.get("from") or {}
    to_artifact = artifacts.get("to") or {}
    to_snapshot = snapshot_refs.get("to") or {}
    if from_artifact.get("artifact_id"):
        subject.setdefault("from_artifact_id", from_artifact["artifact_id"])
    if to_artifact.get("artifact_id"):
        subject.setdefault("to_artifact_id", to_artifact["artifact_id"])
        if subject.get("artifact_id") is None:
            subject["artifact_id"] = to_artifact["artifact_id"]
    if to_snapshot.get("snapshot_id") and subject.get("snapshot_id") is None:
        subject["snapshot_id"] = to_snapshot["snapshot_id"]
    if subject.get("version") is None and subject.get("to_version"):
        subject["version"] = subject["to_version"]
    return subject
