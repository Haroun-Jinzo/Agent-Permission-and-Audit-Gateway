from __future__ import annotations

import pytest

from gateway.decision.models import (
    DataLabel,
    ToolCall,
    ToolManifest,
)
from gateway.execution.adapters.base import (
    ArgumentValidationError,
    ToolAdapter,
)
from gateway.execution.adapters.registry import (
    AdapterRegistry,
    UnknownToolError,
)


class DummyAdapter(ToolAdapter):
    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool="dummy",
            version=1,
            argument_schema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 100,
                    },
                    "count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                    },
                },
                "required": ["message"],
                "additionalProperties": False,
            },
            risk="low",
            external_sink=False,
            sensitive_fields=[],
            derived_facts=[],
            default_output_labels={DataLabel.PUBLIC},
        )

    def execute(
        self,
        call: ToolCall,
        credential: str,
    ) -> dict[str, object]:
        return {
            "tool": call.tool,
            "message": call.arguments["message"],
            "count": call.arguments.get("count", 1),
            "credential": credential,
        }

    def classify_output(
        self,
        result: dict[str, object],
    ) -> set[DataLabel]:
        return {DataLabel.PUBLIC}


def test_dummy_adapter_registers_and_runs() -> None:
    registry = AdapterRegistry()
    adapter = DummyAdapter()
    registry.register(adapter)

    registered = registry.get("dummy")

    call = ToolCall(
        agent_id="demo-agent",
        task_id="task-1",
        tool="dummy",
        arguments={
            "message": "hello",
            "count": 2,
        },
    )

    assert registered.validate(call.arguments)

    result = registered.execute(call, "test-credential")

    assert result["tool"] == "dummy"
    assert result["message"] == "hello"
    assert registered.classify_output(result) == {DataLabel.PUBLIC}


def test_missing_required_argument_is_rejected() -> None:
    adapter = DummyAdapter()

    with pytest.raises(ArgumentValidationError, match="missing required"):
        adapter.validate({"count": 1})


def test_unknown_argument_is_rejected() -> None:
    adapter = DummyAdapter()

    with pytest.raises(ArgumentValidationError, match="unknown arguments"):
        adapter.validate({
            "message": "hello",
            "unexpected": True,
        })


def test_wrong_integer_type_is_rejected() -> None:
    adapter = DummyAdapter()

    with pytest.raises(ArgumentValidationError, match="must be an integer"):
        adapter.validate({
            "message": "hello",
            "count": True,
        })


def test_unknown_tool_fails_closed() -> None:
    registry = AdapterRegistry()

    with pytest.raises(UnknownToolError):
        registry.get("missing-tool")