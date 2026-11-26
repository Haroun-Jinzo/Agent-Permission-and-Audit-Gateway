from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from gateway.decision.models import DataLabel, ToolCall, ToolManifest
from gateway.execution.adapters.base import (
    AdapterExecutionError,
    ArgumentValidationError,
    ToolAdapter,
)

_VIRTUAL_ROOT = PurePosixPath("/data/shared")
_MAX_RESPONSE_BYTES = 1_000_000

@dataclass(frozen=True, slots=True)
class FileReadResult:
    path: str
    content: str
    labels: frozenset[DataLabel]

class FilesAdapter(ToolAdapter):
    """Read files beneath a configured root without following symlinks"""

    def __init__(self, root: str | Path, *, max_response_bytes: int = _MAX_RESPONSE_BYTES,) -> None:
        root = Path(root).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("root_dir must be an existing directory")

        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be a positive")

        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_RDONLY"):
            raise NotImplementedError("os.O_NOFOLLOW is not available on this platform")

        self._root_dir = root
        self._max_response_bytes = max_response_bytes

    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool="read_file",
            version=1,
            argument_schema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 512,
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
            risk="medium",
            external_sink=False,
            sensitive_fields=[],
            derived_facts=[],
            default_output_labels=set()
        )

    def execute(self, call: ToolCall, credential: str) -> FileReadResult:
        del credential

        if call.tool != "read_file":
            raise AdapterExecutionError("FilesAdapter only supports read_file")

        self.validate(call.arguments)
        virtual_path = call.arguments["path"]
        relative_parts = self._relative_parts(virtual_path)

        try:
            content = self._read_beneath_root(relative_parts)
        except OSError as exc:
            raise AdapterExecutionError(
                "could not safely read the requested file"
            ) from exc

        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AdapterExecutionError(
                "requested file is not valid UTF-8"
            ) from exc

        normalized_path = str(PurePosixPath(virtual_path))
        return FileReadResult(
            path=normalized_path,
            content=text,
            labels=frozenset(self._labels_for_path(normalized_path)),
        )

    def classify_output(self, result: FileReadResult) -> set[DataLabel]:
        if not isinstance(result, FileReadResult):
            raise TypeError("result must be a FileReadResult")
        return set(result.labels)

    def _relative_parts(self, requested_path: str) -> tuple[str, ...]:
        path = PurePosixPath(requested_path)

        if not path.is_absolute():
            raise ArgumentValidationError("path must be absolute")

        if path.parts[: len(_VIRTUAL_ROOT.parts)] != _VIRTUAL_ROOT.parts:
            raise ArgumentValidationError("path must be inside /data/shared")

        relative_parts = path.parts[len(_VIRTUAL_ROOT.parts) :]
        if not relative_parts or any(part in ("", ".", "..") for part in relative_parts):
            raise ArgumentValidationError("path must not contain empty or relative parts")

        return relative_parts

    def _read_beneath_root(self, parts: tuple[str, ...]) -> bytes:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        root_fd = os.open(self._root_dir, directory_flags)
        parent_fd = root_fd
        file_fd: int | None = None

        try:
            for part in parts[:-1]:
                next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
                if parent_fd != root_fd:
                    os.close(parent_fd)
                parent_fd = next_fd

            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)

            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise AdapterExecutionError("requested path is not a regular file")

            chunks: list[bytes] = []
            remaining = self._max_response_bytes + 1

            while remaining:
                chunk = os.read(file_fd, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)

            content = b"".join(chunks)
            if len(content) > self._max_response_bytes:
                raise AdapterExecutionError("requested file exceeds the response size limit")

            return content
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)
            os.close(root_fd)


    def _labels_for_path(self, path: str) -> set[DataLabel]:
        confidential_root = PurePosixPath("/data/shared/confidential")
        secret_root = PurePosixPath("/data/shared/secrets")
        requested = PurePosixPath(path)

        if requested.is_relative_to(secret_root):
            return {DataLabel.SECRET}
        if requested.is_relative_to(confidential_root):
            return {DataLabel.CONFIDENTIAL}

        return set()

# Preserve the earlier singular class name for callers that already use it.
FileAdapter = FilesAdapter
