from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from gateway.decision.models import DataLabel, ToolCall, ToolManifest
from gateway.execution.adapters.base import (
    AdapterExecutionError,
    ArgumentValidationError,
    ToolAdapter,
)


@dataclass(frozen=True, slots=True)
class EmailSendResult:
    accepted: bool
    message_id: str | None

class EmailAdapter(ToolAdapter):
    """Send email to a preconfigured HTTP service"""

    def __init__(self, endpoint_url: str, *, timeout_seconds: float = 5.0, max_response_bytes: int = 10_000,) -> None:
        parsed = urlsplit(endpoint_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("endpoint_url must be a valid HTTP or HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("endpoint_url must not contain credentials")
        if parsed.fragment:
            raise ValueError("endpoint_url must not contain a fragment")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_response_bytes <= 1:
            raise ValueError("max_response_bytes must be positive")

        self._endpoint_url = endpoint_url
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def manifest(self) -> ToolManifest:
        return ToolManifest(
            tool="send_email",
            version=1,
            argument_schema={
                "type": "object",
                "properties": {
                    "to": {
                        "type": "array",
                        "items": {"type": "string", "maxLength": 254},
                        "minItems": 1,
                        "maxItems": 20,
                    },
                    "subject": {"type": "string", "maxLength": 200},
                    "body": {"type": "string", "maxLength": 20_000},
                },
                "required": ["to", "subject", "body"],
                "additionalProperties": False,
            },
            risk="high",
            external_sink=True,
            sensitive_fields=["body"],
            derived_facts=[],
            default_output_labels=set(),
        )

    def execute(self, call: ToolCall, credential: str) -> EmailSendResult:
        if call.tool != "send_email":
            raise ArgumentValidationError("emailAdapter only supports send_email")
        if not credential:
            raise AdapterExecutionError("emailAdapter service credential is required")

        self.validate(call.arguments)
        payload = json.dumps(
            {
                "to": call.arguments["to"],
                "subject": call.arguments["subject"],
                "body": call.arguments["body"],
            },
            separators=(",", ":"),
        ).encode("utf-8")

        request = Request(
            self._endpoint_url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {credential}",
            },
        )

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                response_body = response.read(self._max_response_bytes + 1)
                status = response.status
        except HTTPError as exc:
            raise AdapterExecutionError(
                f"emailAdapter service returned HTTP {exc.code}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise AdapterExecutionError(
                "could not reach the email service"
            ) from exc

        if len(response_body) > self._max_response_bytes:
            raise AdapterExecutionError("email service response exceeds the size limit")
        if not 200 <= status < 300:
            raise AdapterExecutionError(f"email service returned HTTP {status}")

        try:
            result = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AdapterExecutionError(
                "email service returned an invalid response"
            ) from exc

        if not isinstance(result, dict) or result.get("accepted") is not True:
            raise AdapterExecutionError("email service did not accept the message")

        message_id = result.get("message_id")
        if message_id is not None and not isinstance(message_id, str):
            raise AdapterExecutionError(
                "email service returned an invalid message_id"
            )

        return EmailSendResult(accepted=True, message_id=message_id)

    def classify_output(self, result: EmailSendResult) -> set[DataLabel]:
        if not isinstance(result, EmailSendResult):
            raise TypeError("result must be an EmailSendResult")
        return set(self.manifest().default_output_labels)

