"""Core data structures for normalized SOC events and alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    event_type: str
    host: str
    user: str | None
    source_ip: str | None
    details: dict[str, Any]

    @classmethod
    def from_record(cls, record: dict[str, Any], line_number: int) -> "Event":
        timestamp_value = record.get("timestamp")
        if not isinstance(timestamp_value, str):
            raise ValueError("field 'timestamp' must be an ISO-8601 string")
        try:
            timestamp = datetime.fromisoformat(timestamp_value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid timestamp {timestamp_value!r}") from exc
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone, for example Z or +00:00")

        event_type = record.get("event_type")
        host = record.get("host")
        if not isinstance(event_type, str) or not event_type.strip():
            raise ValueError("field 'event_type' must be a non-empty string")
        if not isinstance(host, str) or not host.strip():
            raise ValueError("field 'host' must be a non-empty string")

        user = record.get("user")
        source_ip = record.get("source_ip")
        details = record.get("details", {})
        if user is not None and not isinstance(user, str):
            raise ValueError("field 'user' must be a string when present")
        if source_ip is not None and not isinstance(source_ip, str):
            raise ValueError("field 'source_ip' must be a string when present")
        if not isinstance(details, dict):
            raise ValueError("field 'details' must be an object when present")

        event_id = record.get("event_id", f"EVT-{line_number:06d}")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError("field 'event_id' must be a non-empty string")

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            host=host,
            user=user,
            source_ip=source_ip,
            details=details,
        )

    def field(self, name: str) -> Any:
        """Read a top-level event field or a dotted details field for rule matching."""
        if name.startswith("details."):
            return self.details.get(name.partition(".")[2])
        return getattr(self, name, None)

    def entities(self) -> dict[str, str]:
        values = {"host": self.host}
        if self.user:
            values["user"] = self.user
        if self.source_ip:
            values["source_ip"] = self.source_ip
        return values
