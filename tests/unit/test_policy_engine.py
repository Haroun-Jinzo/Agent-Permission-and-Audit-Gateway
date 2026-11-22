from __future__ import annotations

from pathlib import Path

import yaml

from gateway.decision.models import DataLabel, ToolCall, ToolManifest
from gateway.decision.policy_engine import PolicyEngine, Rule

SPEC_DIR = Path(__file__).resolve().parents[2] / "spec"


def load_policy_documents() -> tuple[dict, dict[str, dict]]:
    with (SPEC_DIR / "example-policy.yaml").open(encoding="utf-8") as policy_file:
        policy = yaml.safe_load(policy_file)

    with (SPEC_DIR / "example-manifests.yaml").open(encoding="utf-8") as manifest_file:
        documents = {document["tool"]: document for document in yaml.safe_load_all(manifest_file)}

    return policy, documents


def make_manifest(document: dict) -> ToolManifest:
    labels = {
        DataLabel[label] if isinstance(label, str) else label
        for label in document.get("default_output_labels", [])
    }
    return ToolManifest(
        tool=document["tool"],
        version=document["version"],
        argument_schema=document["argument_schema"],
        risk=document.get("risk", "critical"),
        external_sink=document.get("external_sink", False),
        sensitive_fields=document.get("sensitive_fields", []),
        derived_facts=document.get("derived_facts", []),
        default_output_labels=labels,
    )


def make_engine() -> tuple[PolicyEngine, dict[str, dict]]:
    policy, manifest_documents = load_policy_documents()
    engine = PolicyEngine(policy, "default-policy@1:test")
    return engine, manifest_documents


def evaluate(
    tool: str,
    arguments: dict,
    role: str = "support",
    labels: tuple[str, ...] = (),
    derived: dict | None = None,
) -> object:
    engine, manifest_documents = make_engine()
    call = ToolCall(
        agent_id="demo-agent",
        task_id="task-1",
        tool=tool,
        arguments=arguments,
    )
    return engine.evaluate(
        call,
        make_manifest(manifest_documents[tool]),
        role,
        labels,
        derived,
    )


def test_all_golden_decisions() -> None:
    cases = [
        (
            "send_email",
            {"to": ["a@company.example"]},
            "support",
            (),
            None,
            "ALLOW",
            "R-EMAIL-INTERNAL",
        ),
        (
            "send_email",
            {"to": ["a@company.example"]},
            "support",
            ("CONFIDENTIAL",),
            None,
            "ALLOW",
            "R-EMAIL-INTERNAL",
        ),
        (
            "send_email",
            {"to": ["a@mail.company.example"]},
            "support",
            (),
            None,
            "ALLOW",
            "R-EMAIL-INTERNAL",
        ),
        (
            "send_email",
            {"to": ["a@evilcompany.example"]},
            "support",
            (),
            None,
            "ASK",
            "R-EMAIL-EXTERNAL-ASK",
        ),
        (
            "send_email",
            {"to": ["p@vendor.example"]},
            "support",
            ("UNTRUSTED",),
            None,
            "ASK",
            "R-EMAIL-EXTERNAL-ASK",
        ),
        (
            "send_email",
            {"to": ["a@company.example", "x@evil.example"]},
            "support",
            (),
            None,
            "ASK",
            "R-EMAIL-EXTERNAL-ASK",
        ),
        (
            "send_email",
            {"to": ["x@evil.example"]},
            "support",
            ("CONFIDENTIAL",),
            None,
            "BLOCK",
            "R-EXFIL-1",
        ),
        (
            "send_email",
            {"to": ["a@company.example"]},
            "support",
            ("SECRET",),
            None,
            "BLOCK",
            "R-SECRET-SINK-BLOCK",
        ),
        (
            "send_email",
            {"to": ["a@company.example"]},
            "intern",
            (),
            None,
            "BLOCK",
            "DEFAULT-DENY",
        ),
        (
            "read_file",
            {"path": "/data/shared/a.txt"},
            "support",
            (),
            None,
            "ALLOW",
            "R-FILE-READ",
        ),
        (
            "read_file",
            {"path": "/data/shared/../secrets/k.txt"},
            "support",
            (),
            None,
            "BLOCK",
            "DEFAULT-DENY",
        ),
        (
            "read_file",
            {"path": "/data/shared-old/a.txt"},
            "support",
            (),
            None,
            "BLOCK",
            "DEFAULT-DENY",
        ),
        (
            "delete_file",
            {"path": "/data/shared/a.txt"},
            "support",
            (),
            None,
            "ASK",
            "R-DELETE-ASK",
        ),
        (
            "read_inbox",
            {"limit": 10},
            "research",
            (),
            None,
            "ALLOW",
            "R-INBOX-READ",
        ),
        (
            "db_query",
            {"sql": "select 1", "max_rows": 10},
            "analyst",
            (),
            {
                "statement_type": "SELECT",
                "tables": ["sales_summary"],
            },
            "ALLOW",
            "R-DB-SELECT",
        ),
        (
            "db_query",
            {"sql": "x", "max_rows": 10},
            "analyst",
            (),
            {
                "statement_type": "SELECT",
                "tables": ["sales_summary", "hr_salaries"],
            },
            "BLOCK",
            "DEFAULT-DENY",
        ),
        (
            "db_query",
            {"sql": "x", "max_rows": 10},
            "analyst",
            (),
            {"statement_type": "UPDATE", "tables": ["sales_summary"]},
            "BLOCK",
            "R-DB-WRITE-BLOCK",
        ),
    ]

    for tool, arguments, role, labels, derived, decision, rule_id in cases:
        result = evaluate(tool, arguments, role, labels, derived)
        assert result.decision.value == decision
        assert result.rule_ids[0] == rule_id


def test_confidential_external_email_blocks() -> None:
    result = evaluate(
        "send_email",
        {"to": ["x@evil.example"]},
        "support",
        ("UNTRUSTED", "CONFIDENTIAL"),
    )

    assert result.decision.value == "BLOCK"
    assert result.rule_ids[0] == "R-EXFIL-1"


def test_internal_external_recipient_cases() -> None:
    clean = evaluate(
        "send_email",
        {"to": ["a@company.example"]},
        "support",
    )
    external = evaluate(
        "send_email",
        {"to": ["p@vendor.example"]},
        "support",
        ("UNTRUSTED",),
    )

    assert clean.decision.value == "ALLOW"
    assert clean.rule_ids[0] == "R-EMAIL-INTERNAL"
    assert external.decision.value == "ASK"
    assert external.rule_ids[0] == "R-EMAIL-EXTERNAL-ASK"


def test_wrong_argument_type_fails_closed() -> None:
    result = evaluate(
        "send_email",
        {"to": 5},
        "support",
        ("CONFIDENTIAL",),
    )

    assert result.decision.value == "BLOCK"
    assert result.errors


def test_unknown_tool_fails_closed() -> None:
    engine, manifest_documents = make_engine()
    call = ToolCall(
        agent_id="demo-agent",
        task_id="task-1",
        tool="unknown_tool",
        arguments={},
    )
    manifest = make_manifest(manifest_documents["read_inbox"])

    result = engine.evaluate(call, manifest, "support")

    assert result.decision.value == "BLOCK"
    assert result.rule_ids == ("ENGINE-ERROR",)


def test_block_always_beats_allow_and_ask() -> None:
    policy = {
        "lists": {},
        "rules": [
            {
                "rule_id": "ALLOW-RULE",
                "effect": "allow",
                "applies_to": {"roles": ["*"], "tools": ["test"]},
            },
            {
                "rule_id": "BLOCK-RULE",
                "effect": "block",
                "applies_to": {"roles": ["*"], "tools": ["test"]},
            },
        ],
    }
    engine = PolicyEngine(policy, "test-policy@1:test")
    call = ToolCall("demo-agent", "task-1", "test", {})
    manifest = ToolManifest(
        tool="test",
        version=1,
        argument_schema={},
        risk="low",
    )

    result = engine.evaluate(call, manifest, "support")

    assert result.decision.value == "BLOCK"
    assert result.rule_ids == ("BLOCK-RULE", "ALLOW-RULE")


def test_erroring_allow_does_not_fire() -> None:
    policy = {
        "lists": {},
        "rules": [
            {
                "rule_id": "BAD-ALLOW",
                "effect": "allow",
                "applies_to": {"roles": ["support"], "tools": ["read_file"]},
                "when": {
                    "all": [
                        {
                            "arg": "path",
                            "op": "path_within",
                            "value": "/data/shared",
                        }
                    ]
                },
            }
        ],
    }
    engine = PolicyEngine(policy, "test-policy@1:test")
    call = ToolCall("demo-agent", "task-1", "read_file", {"path": 5})
    manifest = ToolManifest(
        tool="read_file",
        version=1,
        argument_schema={"type": "object"},
        risk="medium",
    )

    result = engine.evaluate(call, manifest, "support")

    assert result.decision.value == "BLOCK"
    assert result.rule_ids == ("DEFAULT-DENY",)
    assert result.errors


def test_rule_from_dict_and_to_dict() -> None:
    document = {
        "rule_id": "R1",
        "effect": "allow",
        "description": "Allows a known action",
        "applies_to": {"roles": ["support"], "tools": ["send_email"]},
        "when": {"all": []},
    }

    rule = Rule.from_dict(document)

    assert rule.to_dict() == document
