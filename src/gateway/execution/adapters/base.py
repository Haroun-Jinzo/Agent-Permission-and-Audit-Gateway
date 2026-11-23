from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

from gateway.decision.models import (
    DataLabel,
    ToolCall,
    ToolManifest,
)

ToolResult = Any  # Placeholder for the actual ToolResult type

class ArgumentValidationError(ValueError):
    """Raised when tool arguments do not match the manifest schema."""

class ToolAdapter(ABC):
    """Base class for tool adapters."""

    @abstractmethod
    def manifest(self) -> ToolManifest:
        """Return the manifest for this tool."""
        ...

    def validate(self, arguments: dict[str, Any]) -> bool:
        """Validate the arguments against the manifest schema."""
        
        manifest = self.manifest()

        if not isinstance(arguments, dict):
            raise ArgumentValidationError("arguments must be a dictionary")

        schema = manifest.argument_schema

        if not isinstance(schema, dict):
            raise ArgumentValidationError("manifest argument_schema must be a dictionary")

        if schema.get("type") != "object":
            raise ArgumentValidationError("manifest argument_schema must be of type 'object'")
        
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        if not isinstance(properties, dict):
            raise ArgumentValidationError("manifest argument_schema properties must be a dictionary")
        
        missing = [name for name in required if name not in arguments]
        if missing:
            raise ArgumentValidationError(f"missing required arguments: {', '.join(missing)}")
        
        additional_properties = schema.get("additionalProperties", True)

        if additional_properties is False:
            unknown = set(arguments) - set(properties)
            if unknown:
                raise ArgumentValidationError(f"unknown arguments: {', '.join(unknown)}")

        for name, value in arguments.items():
            if name not in properties:
                continue

            self._validate_value(
                value,
                properties[name],
                path=name,
            )
        
        return True
    
    def _validate_value(self, value: Any, schema: dict[str, Any], *, path: str,) -> None:
        value_type = schema.get("type")

        if value_type == "string":
            if not isinstance(value, str):
                raise ArgumentValidationError(f"{path} must be a string")
            
            if "minLength" in schema and len(value) < schema["minLength"]:
                raise ArgumentValidationError(f"{path} is shorter than minLength")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                raise ArgumentValidationError(f"{path} is longer than maxLength")
        
        elif value_type == "number":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ArgumentValidationError(f"{path} must be an integer")
            
            if "minimum" in schema and value < schema["minimum"]:
                raise ArgumentValidationError(f"{path} is less than minimum")

            if "maximum" in schema and value > schema["maximum"]:
                raise ArgumentValidationError(f"{path} is greater than maximum")

        elif value_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ArgumentValidationError(f"{path} must be an integer")

            if "minimum" in schema and value < schema["minimum"]:
                raise ArgumentValidationError(f"{path} is less than minimum")

            if "maximum" in schema and value > schema["maximum"]:
                raise ArgumentValidationError(f"{path} is greater than maximum")
            
        elif value_type == "array":
            if not isinstance(value, list):
                raise ArgumentValidationError(
                    f"{path} must be an array"
                )

            if "minItems" in schema and len(value) < schema["minItems"]:
                raise ArgumentValidationError(
                    f"{path} has too few items"
                )

            if "maxItems" in schema and len(value) > schema["maxItems"]:
                raise ArgumentValidationError(
                    f"{path} has too many items"
                )
        
            item_schema = schema.get("items")
            if isinstance(item_schema, dict):
                for index, item in enumerate(value):
                    self._validate_value(item, item_schema, path=f"{path}[{index}]",)
        
        elif value_type == "object":
            if not isinstance(value, dict):
                raise ArgumentValidationError(f"{path} must be an object")
            
            nested_schema = dict(schema)
            nested_schema.pop("properties", {})
            nested_schema.pop("required", [])

        elif value_type is not None:
            raise ArgumentValidationError(f"{path} has unsupported type: {value_type}")        
    
    @abstractmethod
    def execute(self, call: ToolCall, credential: str) -> ToolResult:
        """Execute the tool call."""
        ...

    @abstractmethod
    def classify_output(self, result: ToolResult) -> set[DataLabel]:
        """Classify the output of the tool call."""
        ...