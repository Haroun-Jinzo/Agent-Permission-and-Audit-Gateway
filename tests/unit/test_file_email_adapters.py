from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from demo.fake_mail.server import FakeMailServer

from gateway.decision.models import DataLabel, ToolCall
from gateway.execution.adapters.base import (
    AdapterExecutionError,
    ArgumentValidationError,
    ToolAdapter,
)
from gateway.execution.adapters.email_adapter import EmailAdapter
from gateway.execution.adapters.file_adapter import (
    FileReadResult,
    FilesAdapter,
)


def make_call(tool: str, arguments: dict[str, Any]) -> ToolCall:
    return ToolCall(
        agent_id="test-agent",
        task_id="test-task",
        tool=tool,
        arguments=arguments,
    )


def test_files_adapter_reads_file_and_classifies_output(tmp_path: Path) -> None:
    (tmp_path / "report.txt").write_text("hello", encoding="utf-8")
    (tmp_path / "confidential").mkdir()
    (tmp_path / "confidential" / "report.txt").write_text(
        "private",
        encoding="utf-8",
    )

    adapter = FilesAdapter(tmp_path)

    assert isinstance(adapter, ToolAdapter)
    assert adapter.manifest().tool == "read_file"

    result = adapter.execute(
        make_call("read_file", {"path": "/data/shared/report.txt"}),
        credential="unused",
    )
    private_result = adapter.execute(
        make_call(
            "read_file",
            {"path": "/data/shared/confidential/report.txt"},
        ),
        credential="unused",
    )

    assert isinstance(result, FileReadResult)
    assert result.content == "hello"
    assert adapter.classify_output(result) == set()
    assert adapter.classify_output(private_result) == {DataLabel.CONFIDENTIAL}


def test_files_adapter_rejects_path_traversal(tmp_path: Path) -> None:
    adapter = FilesAdapter(tmp_path)

    with pytest.raises(ArgumentValidationError):
        adapter.execute(
            make_call("read_file", {"path": "/data/shared/../outside.txt"}),
            credential="unused",
        )


def test_files_adapter_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")

    try:
        (root / "escape").symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    adapter = FilesAdapter(root)

    with pytest.raises(AdapterExecutionError):
        adapter.execute(
            make_call(
                "read_file",
                {"path": "/data/shared/escape/secret.txt"},
            ),
            credential="unused",
        )


def test_files_adapter_rejects_oversize_file(tmp_path: Path) -> None:
    (tmp_path / "large.txt").write_text("four", encoding="utf-8")
    adapter = FilesAdapter(tmp_path, max_response_bytes=3)

    with pytest.raises(AdapterExecutionError, match="size limit"):
        adapter.execute(
            make_call("read_file", {"path": "/data/shared/large.txt"}),
            credential="unused",
        )


def test_files_adapter_rejects_invalid_utf8(tmp_path: Path) -> None:
    (tmp_path / "invalid.txt").write_bytes(b"\xff")
    adapter = FilesAdapter(tmp_path)

    with pytest.raises(AdapterExecutionError, match="UTF-8"):
        adapter.execute(
            make_call("read_file", {"path": "/data/shared/invalid.txt"}),
            credential="unused",
        )


def test_email_adapter_posts_to_configured_fake_and_keeps_secret_in_header() -> None:
    secret = "local-test-secret"

    with FakeMailServer() as server:
        adapter = EmailAdapter(server.endpoint_url)
        call = make_call(
            "send_email",
            {
                "to": ["person@example.test"],
                "subject": "Hello",
                "body": "Test message",
            },
        )

        result = adapter.execute(call, credential=secret)

        assert result.accepted
        assert result.message_id == "fake-1"
        assert adapter.classify_output(result) == set()
        assert server.messages == [
            {
                "authorization": f"Bearer {secret}",
                "payload": {
                    "to": ["person@example.test"],
                    "subject": "Hello",
                    "body": "Test message",
                },
            }
        ]
        assert secret not in str(server.messages[0]["payload"])


def test_email_adapter_rejects_invalid_arguments_before_http_request() -> None:
    with FakeMailServer() as server:
        adapter = EmailAdapter(server.endpoint_url)
        call = make_call(
            "send_email",
            {
                "to": [],
                "subject": "Hello",
                "body": "Test message",
            },
        )

        with pytest.raises(ArgumentValidationError):
            adapter.execute(call, credential="local-test-secret")

        assert server.messages == []


def test_email_adapter_surfaces_http_failure() -> None:
    with FakeMailServer(response_status=503) as server:
        adapter = EmailAdapter(server.endpoint_url)

        with pytest.raises(AdapterExecutionError, match="HTTP 503"):
            adapter.execute(
                make_call(
                    "send_email",
                    {
                        "to": ["person@example.test"],
                        "subject": "Hello",
                        "body": "Test message",
                    },
                ),
                credential="local-test-secret",
            )


def test_email_adapter_surfaces_timeout() -> None:
    with FakeMailServer(delay_seconds=0.2) as server:
        adapter = EmailAdapter(server.endpoint_url, timeout_seconds=0.02)

        with pytest.raises(AdapterExecutionError, match="could not reach"):
            adapter.execute(
                make_call(
                    "send_email",
                    {
                        "to": ["person@example.test"],
                        "subject": "Hello",
                        "body": "Test message",
                    },
                ),
                credential="local-test-secret",
            )
