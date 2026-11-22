from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from gateway.canonical import call_hash as compute_call_hash
from gateway.canonical import canonical_json


class DataLabel(Enum):
    """
    Enum representing different data labels.
    """

    PUBLIC = "PUBLIC"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"  # noqa: S105
    UNTRUSTED = "UNTRUSTED"


class Decision(Enum):
    """
    Enum representing different decision types.
    """

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ASK = "ASK"


_RISKS = frozenset({"low", "medium", "high", "critical"})


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class ToolCall:
    agent_id: str
    task_id: str
    tool: str
    arguments: dict[str, Any]
    approval_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.agent_id, "agent_id")
        _require_text(self.task_id, "task_id")
        _require_text(self.tool, "tool")

        if not isinstance(self.arguments, dict):
            raise TypeError("arguments must be a dictionary")

        if self.approval_id is not None:
            _require_text(self.approval_id, "approval_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "tool": self.tool,
            "arguments": self.arguments,
        }

    def canonical_bytes(self) -> bytes:
        """
        Returns the canonical JSON representation of the tool call as bytes.
        """
        return canonical_json(self.to_dict())

    @property
    def call_hash(self) -> str:
        """
        Computes and returns the hash of the tool call.
        """
        return compute_call_hash(self.to_dict())


@dataclass(frozen=True, slots=True)
class ToolManifest:
    tool: str
    version: int
    argument_schema: dict[str, Any]
    risk: str = "critical"
    external_sink: bool = False
    sensitive_fields: list[str] = field(default_factory=list)
    derived_facts: list[str] = field(default_factory=list)
    default_output_labels: set[DataLabel] = field(default_factory=set)

    def __post_init__(self) -> None:
        _require_text(self.tool, "tool")
        # _require_text(self.version, "version")

        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("version must be an integer")

        if self.version < 1:
            raise ValueError("version must be positive")

        if not isinstance(self.argument_schema, dict):
            raise TypeError("argument_schema must be a dictionary")

        if self.risk not in _RISKS:
            raise ValueError(f"risk must be one of {sorted(_RISKS)}")

        if not isinstance(self.external_sink, bool):
            raise TypeError("external_sink must be a boolean")

        for field_name in ("sensitive_fields", "derived_facts"):
            values = getattr(self, field_name)

            if not isinstance(values, list):
                raise TypeError(f"{field_name} must be a list")

            if not all(isinstance(value, str) and value.strip() for value in values):
                raise ValueError(f"{field_name} must contain non-empty strings")

        if not isinstance(self.default_output_labels, set):
            raise TypeError("default_output_labels must be a set")

        if not all(isinstance(label, DataLabel) for label in self.default_output_labels):
            raise TypeError("default_output_labels must contain only DataLabel values")


@dataclass(frozen=True, slots=True)
class DecisionResult:
    decision: Decision | str
    rule_id: str
    reason: str
    policy_version: str
    rule_ids: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            try:
                object.__setattr__(self, "decision", Decision(self.decision))
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid decision") from exc

        _require_text(self.rule_id, "rule_id")
        _require_text(self.reason, "reason")
        _require_text(self.policy_version, "policy_version")

        if not isinstance(self.rule_ids, tuple):
            raise TypeError("rule_ids must be a tuple")
        if not all(isinstance(rule_id, str) and rule_id.strip() for rule_id in self.rule_ids):
            raise ValueError("rule_ids must contain non-empty strings")

        if not isinstance(self.errors, tuple):
            raise TypeError("errors must be a tuple")
        if not all(isinstance(error, str) for error in self.errors):
            raise TypeError("errors must contain strings")
