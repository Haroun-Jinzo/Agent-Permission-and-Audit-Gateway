from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from gateway.decision.models import (
    Decision,
    DecisionResult,
    ToolCall,
    ToolManifest,
)

_PRECEDENCE = {"allow": 1, "ask": 2, "block": 3}
_RISK_ORDER = ("low", "medium", "high", "critical")
_LABELS = {"PUBLIC", "CONFIDENTIAL", "SECRET", "UNTRUSTED"}
_OPS = {
    "equals",
    "not_equals",
    "in",
    "not_in",
    "path_within",
    "path_not_within",
    "domain_in",
    "domain_not_in",
    "lt",
    "lte",
    "gt",
    "gte",
}


class EvaluationError(Exception):
    """Raised when a condition cannot be evaluated due to invalid types or values."""


_ABSENT = object()


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    effect: str
    applies_to: dict[str, Any]
    when: dict[str, Any] = field(default_factory=lambda: {"all": []})
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")

        if self.effect not in {"allow", "ask", "block"}:
            raise ValueError(f"invalid rule effect: {self.effect}")

        if not isinstance(self.applies_to, dict):
            raise TypeError("applies_to must be a dictionary")

        roles = self.applies_to.get("roles")
        tools = self.applies_to.get("tools")
        if not isinstance(roles, list) or not roles:
            raise ValueError("applies_to.roles must be a non-empty list")
        if not isinstance(tools, list) or not tools:
            raise ValueError("applies_to.tools must be a non-empty list")

        if not isinstance(self.when, dict):
            raise TypeError("when must be a dictionary")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            rule_id=data["rule_id"],
            effect=data["effect"],
            applies_to=data.get("applies_to", {}),
            when=data.get("when", {"all": []}),
            description=data.get("description", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "effect": self.effect,
            "applies_to": self.applies_to,
            "when": self.when,
            "description": self.description,
        }


class PolicyEngine:
    def __init__(
        self,
        policy: dict[str, Any],
        policy_version: str,
        rules: list[Rule] | None = None,
        lists: dict[str, list[Any]] | None = None,
    ) -> None:
        if not isinstance(policy, dict):
            raise TypeError("policy must be a dictionary")

        self.policy = policy
        self.policy_version = policy_version
        self.lists = lists if lists is not None else policy.get("lists", {})

        if rules is not None:
            self.rules = rules
        else:
            self.rules = [Rule.from_dict(document) for document in policy.get("rules", [])]

    def evaluate(
        self,
        call: ToolCall,
        manifest: ToolManifest,
        role: str,
        task_labels: set[str] | tuple[str, ...] = (),
        derived: dict[str, Any] | None = None,
    ) -> DecisionResult:
        try:
            if call.tool != manifest.tool:
                raise EvaluationError(
                    f"tool call mismatch: call is for {call.tool}, manifest is for {manifest.tool}"
                )

            labels = {
                label.value if hasattr(label, "value") else str(label) for label in task_labels
            }
            unknown_labels = labels - _LABELS
            if unknown_labels:
                raise EvaluationError(f"unknown task labels: {sorted(unknown_labels)}")

            manifest_document = self._manifest_document(manifest)
            context = {
                "arguments": call.arguments,
                "derived": derived or {},
                "labels": labels,
                "manifest": manifest_document,
                "lists": self.lists,
            }

            matched: list[Rule] = []
            errors: list[str] = []

            for rule in self.rules:
                applies_to = rule.applies_to
                roles = applies_to.get("roles", [])
                tools = applies_to.get("tools", [])

                if "*" not in roles and role not in roles:
                    continue
                if "*" not in tools and call.tool not in tools:
                    continue

                try:
                    hit = self._when(rule.when, context)
                except EvaluationError as exc:
                    errors.append(f"{rule.rule_id}: {exc}")

                    hit = rule.effect in {"block", "ask"}

                if hit:
                    matched.append(rule)

            if not matched:
                return DecisionResult(
                    decision=Decision.BLOCK,
                    rule_id="DEFAULT-DENY",
                    reason="No matching policy rule",
                    policy_version=self.policy_version,
                    rule_ids=("DEFAULT-DENY",),
                    errors=tuple(errors),
                )

            most_restrictive = max(_PRECEDENCE[rule.effect] for rule in matched)
            ordered = sorted(
                matched,
                key=lambda rule: -_PRECEDENCE[rule.effect],
            )

            rule_ids = tuple(rule.rule_id for rule in ordered)

            decision = {
                3: Decision.BLOCK,
                2: Decision.ASK,
                1: Decision.ALLOW,
            }[most_restrictive]

            return DecisionResult(
                decision=decision,
                rule_id=rule_ids[0],
                reason=ordered[0].description or "policy decision",
                policy_version=self.policy_version,
                rule_ids=rule_ids,
                errors=tuple(errors),
            )
        except Exception as exc:
            return DecisionResult(
                decision=Decision.BLOCK,
                rule_id="ENGINE-ERROR",
                reason=f"Policy evaluation error: {exc}",
                policy_version=self.policy_version,
                rule_ids=("ENGINE-ERROR",),
                errors=(repr(exc),),
            )

    def _manifest_document(
        self,
        manifest: ToolManifest,
    ) -> dict[str, Any]:
        """
        Convert a ToolManifest into a dictionary representation for evaluation.

        Args:
            manifest (ToolManifest): The manifest to convert.

        Returns:
            dict[str, Any]: The dictionary representation of the manifest.
        """
        return {
            "tool": manifest.tool,
            "version": manifest.version,
            "risk": manifest.risk,
            "external_sink": manifest.external_sink,
            "argument_schema": manifest.argument_schema,
            "sensitive_fields": manifest.sensitive_fields,
            "derived_facts": manifest.derived_facts,
        }

    def _when(self, node: dict[str, Any], context: dict[str, Any]) -> bool:
        if "all" in node:
            return all(self._when(child, context) for child in node["all"])
        if "any" in node:
            return any(self._when(child, context) for child in node["any"])
        if "not" in node:
            return not self._when(node["not"], context)
        return self._leaf(node, context)

    def _leaf(
        self,
        leaf: dict[str, Any],
        context: dict[str, Any],
    ) -> bool:
        if "task_labels" in leaf:
            labels = context["labels"]
            result = True

            for key, values in leaf["task_labels"].items():
                if key == "any_of":
                    result = result and bool(labels & set(values))
                elif key == "all_of":
                    result = result and set(values) <= labels
                elif key == "none_of":
                    result = result and not (labels & set(values))
                else:
                    raise EvaluationError(f"Unknown task_labels operator: {key}")

            return result

        if "manifest" in leaf:
            if leaf["manifest"] != "external_sink":
                raise EvaluationError("unknown manifest field")

            return bool(context["manifest"].get("external_sink", False) == leaf["equals"])

        if "tool_risk" in leaf:
            at_least = leaf["tool_risk"]["at_least"]

            if at_least not in _RISK_ORDER:
                raise EvaluationError("unknown minimum risk")

            manifest_risk = context["manifest"]["risk"]

            if manifest_risk not in _RISK_ORDER:
                raise EvaluationError("unknown manifest risk")

            return _RISK_ORDER.index(manifest_risk) >= _RISK_ORDER.index(at_least)

        if "arg" in leaf:
            value = self._resolve(context["arguments"], leaf["arg"])
        elif "derived" in leaf:
            value = context["derived"].get(leaf["derived"], _ABSENT)
        else:
            raise EvaluationError("unknown condition")

        if value is _ABSENT:
            return bool(leaf.get("if_absent", False))

        if "list" in leaf:
            operand = context["lists"].get(leaf["list"], _ABSENT)
            if operand is _ABSENT:
                raise EvaluationError(f"unknown list: {leaf['list']}")
        elif "value" in leaf:
            operand = leaf["value"]
        else:
            raise EvaluationError("condition needs value or list")

        if leaf.get("op") not in _OPS:
            raise EvaluationError(f"unknown operator: {leaf.get('op')}")

        if isinstance(value, list):
            quantifier = leaf.get("quantifier")

            if quantifier not in {"any", "all"}:
                raise EvaluationError("list value needs a quantifier")

            results = [self._apply(leaf["op"], item, operand) for item in value]
            return any(results) if quantifier == "any" else all(results)

        return self._apply(leaf["op"], value, operand)

    def _resolve(
        self,
        arguments: dict[str, Any],
        path: str,
    ) -> Any:
        """
        Resolve a nested argument value from the arguments dictionary using a dot-separated path.

        Args:
            arguments (dict[str, Any]): The arguments dictionary.
            path (str): The dot-separated path to the desired value.

        Returns:
            Any: The resolved value, or _ABSENT if the path does not exist.
        """
        current: Any = arguments

        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return _ABSENT
            current = current[part]

        return current

    def _apply(self, op: str, value: Any, operand: Any) -> bool:
        """
        Apply an operator to a value and an operand.

        Args:
            op (str): The operator to apply.
            value (Any): The value to compare.
            operand (Any): The operand to compare against.
        """
        if op == "equals":
            return bool(value == operand)
        if op == "not_equals":
            return bool(value != operand)
        if op in {"in", "not_in"}:
            if not isinstance(operand, list):
                operand = [operand]

            return bool(value in operand if op == "in" else value not in operand)

        if op in {"path_within", "path_not_within"}:
            path = self._normalize_path(value)

            bases = operand if isinstance(operand, list) else [operand]

            inside = any(self._path_within(path, base) for base in bases)
            return inside if op == "path_within" else not inside

        if op in {"domain_in", "domain_not_in"}:
            host = self._domain(value)
            entries = operand if isinstance(operand, list) else [operand]

            inside = any(host == entry or host.endswith("." + entry) for entry in entries)

            return inside if op == "domain_in" else not inside

        if op in {"lt", "lte", "gt", "gte"}:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or isinstance(operand, bool)
                or not isinstance(operand, int)
            ):
                raise EvaluationError("numeric comparison needs integers")

            return {
                "lt": value < operand,
                "lte": value <= operand,
                "gt": value > operand,
                "gte": value >= operand,
            }[op]

        raise EvaluationError(f"unknown op: {op}")

    def _normalize_path(self, value: Any) -> str:
        if not isinstance(value, str) or not value.startswith("/"):
            raise EvaluationError("path must be an absolute string")
        return posixpath.normpath(value)

    def _path_within(self, path: str, base: str) -> bool:
        base = posixpath.normpath(base)
        return path == base or path.startswith(base.rstrip("/") + "/")

    def _domain(self, value: Any) -> str:
        if not isinstance(value, str):
            raise EvaluationError("domain operand must be a string")

        host = value.rsplit("@", 1)[1] if "@" in value else urlparse(value).hostname or value

        return host.strip().lower()
