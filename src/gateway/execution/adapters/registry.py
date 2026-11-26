from __future__ import annotations

from gateway.execution.adapters.base import ToolAdapter


class AdapterRegistryError(RuntimeError):
    """Raised when there is an error in the adapter registry."""
    pass

class UnknownToolError(AdapterRegistryError, LookupError):
    """Raised when a tool is not found in the registry."""
    pass

class AdapterRegistry:
    "Registry for tool adapters."

    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        manifest = adapter.manifest()

        if manifest.tool in self._adapters:
            raise AdapterRegistryError( f"Adapter for tool {manifest.tool} already registered")

        self._adapters[manifest.tool] = adapter

    def get(self, tool: str) -> ToolAdapter:
        try:
            return self._adapters[tool]
        except KeyError as exc:
            raise UnknownToolError(f"Tool {tool} not found in registry") from exc
