import pytest

from gateway.decision.models import (
    DataLabel,
    Decision,
    DecisionResult,
    ToolCall,
    ToolManifest,
)


def test_tool_call_hash_matches_published_vector() -> None:
    call = ToolCall(
        agent_id="demo-agent",
        task_id="task-1",
        tool="send_email",
        arguments={
            "to": "attacker@evil.example",
            "body": "hello",
        },
    )

    assert call.call_hash == (
        "7f9b4913798426a3cca83230761db396c9e639704ed34ef677b541f7440b1764"
    )


def test_approval_id_is_excluded_from_call_hash() -> None:
    without_approval = ToolCall(
        "demo-agent",
        "task-1",
        "send_email",
        {"body": "hello"},
    )
    with_approval = ToolCall(
        "demo-agent",
        "task-1",
        "send_email",
        {"body": "hello"},
        approval_id="approval-1",
    )

    assert with_approval.call_hash == without_approval.call_hash


def test_tool_call_rejects_invalid_fields() -> None:
    with pytest.raises(ValueError):
        ToolCall("", "task-1", "send_email", {})

    with pytest.raises(TypeError):
        ToolCall("agent-1", "task-1", "send_email", [])


def test_tool_manifest_defaults_to_critical_risk() -> None:
    manifest = ToolManifest(
        tool="send_email",
        version="1",
        argument_schema={},
    )

    assert manifest.risk == "critical"


def test_tool_manifest_validates_risk_and_labels() -> None:
    manifest = ToolManifest(
        tool="send_email",
        version="1",
        argument_schema={},
        risk="high",
        default_output_labels={DataLabel.CONFIDENTIAL},
    )

    assert manifest.risk == "high"

    with pytest.raises(ValueError):
        ToolManifest("send_email", "1", {}, risk="unknown")

    with pytest.raises(TypeError):
        ToolManifest(
            "send_email",
            "1",
            {},
            default_output_labels={"SECRET"},
        )


def test_decision_result_validates_and_normalizes_decision() -> None:
    result = DecisionResult(
        decision="BLOCK",
        rule_id="DEFAULT-DENY",
        reason="No matching allow rule",
        policy_version="default-policy@1",
    )

    assert result.decision is Decision.BLOCK

    with pytest.raises(ValueError):
        DecisionResult(
            decision="INVALID",
            rule_id="R1",
            reason="reason",
            policy_version="policy@1",
        )