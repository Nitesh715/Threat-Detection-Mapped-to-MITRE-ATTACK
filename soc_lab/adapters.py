"""Input adapters for the Mini-SOC normalized event model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Event

SUPPORTED_FORMATS = {"normalized", "wazuh"}


def _get_path(data: Any, *path: str, default: Any = None) -> Any:
    current = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return default if current is None else current


def _first_value(data: dict[str, Any], candidates: tuple[tuple[str, ...], ...]) -> Any:
    for path in candidates:
        value = _get_path(data, *path)
        if value not in (None, ""):
            return value
    return None


def _wazuh_event_type(alert: dict[str, Any]) -> str:
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        groups = [groups] if isinstance(groups, str) else []
    description = str(rule.get("description", ""))
    data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
    explicit = _first_value(data, (("soc", "event_type"), ("event_type",)))
    if isinstance(explicit, str) and explicit in {
        "auth_failure", "auth_success", "privileged_group_change", "suspicious_process_execution"
    }:
        return explicit

    group_text = " ".join(str(group) for group in groups).lower().replace("-", "_")
    text = f"{group_text} {description.lower()}"
    if any(term in text for term in (
        "authentication_failed", "authentication_failure", "authentication failed", "authentication failure",
        "failed_login", "login failed", "login failure", "invalid user", "failed password", "logon failure",
    )):
        return "auth_failure"
    if any(term in text for term in (
        "authentication_success", "successful_login", "authentication successful", "successful authentication",
        "accepted password", "login successful", "logon success",
    )):
        return "auth_success"

    group_name = _first_value(
        data,
        (("win", "eventdata", "groupName"), ("win", "eventdata", "targetGroupName"), ("group", "name")),
    )
    group_change_words = ("group membership", "member added", "added to group", "privileged group", "sudoers")
    if group_name and any(term in text for term in group_change_words):
        return "privileged_group_change"

    risky_process_words = ("suspicious", "obfuscated", "encoded command", "malware", "credential theft")
    if "process" in text and any(term in text for term in risky_process_words):
        return "suspicious_process_execution"
    return "wazuh_alert"


def wazuh_to_record(alert: dict[str, Any], line_number: int) -> dict[str, Any]:
    """Convert one Wazuh alert JSON object to the normalized event schema.

    Only explicit alert metadata is copied into `details`; the full raw alert is
    not retained. This keeps case evidence compact and avoids duplicating fields.
    """
    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    host = _first_value(
        alert,
        (("agent", "name"), ("data", "win", "system", "computer"), ("manager", "name")),
    ) or "wazuh-manager"
    user = _first_value(
        alert,
        (
            ("data", "srcuser"),
            ("data", "user"),
            ("data", "dstuser"),
            ("data", "win", "eventdata", "targetUserName"),
            ("data", "win", "eventdata", "subjectUserName"),
        ),
    )
    source_ip = _first_value(
        alert,
        (
            ("data", "srcip"),
            ("data", "src_ip"),
            ("data", "win", "eventdata", "ipAddress"),
            ("data", "win", "eventdata", "sourceAddress"),
        ),
    )
    timestamp = alert.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError("Wazuh alert requires a string 'timestamp'")

    mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
    details = {
        "source": "wazuh",
        "wazuh_rule_id": str(rule.get("id", "")),
        "wazuh_rule_level": rule.get("level"),
        "wazuh_rule_description": str(rule.get("description", "")),
        "wazuh_rule_groups": rule.get("groups", []) if isinstance(rule.get("groups", []), (list, str)) else [],
        "wazuh_agent_id": str(agent.get("id", "")),
        "wazuh_location": str(alert.get("location", "")),
        "wazuh_mitre_ids": mitre.get("id", []) if isinstance(mitre.get("id", []), (list, str)) else [],
    }
    full_log = alert.get("full_log")
    if isinstance(full_log, str) and full_log:
        details["wazuh_full_log"] = full_log[:1500]

    event_id = alert.get("id")
    if not isinstance(event_id, (str, int)) or str(event_id).strip() == "":
        event_id = f"WZ-EVT-{line_number:06d}"
    return {
        "event_id": str(event_id),
        "timestamp": timestamp,
        "event_type": _wazuh_event_type(alert),
        "host": str(host),
        "user": str(user) if user is not None else None,
        "source_ip": str(source_ip) if source_ip is not None else None,
        "details": details,
    }


def load_events(path: Path, source_format: str = "normalized") -> list[Event]:
    if source_format not in SUPPORTED_FORMATS:
        supported = ", ".join(sorted(SUPPORTED_FORMATS))
        raise ValueError(f"unsupported event format {source_format!r}; choose {supported}")

    events: list[Event] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            if not raw_line.strip():
                continue
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number}: each event must be a JSON object")
            if source_format == "wazuh":
                try:
                    record = wazuh_to_record(record, line_number)
                except ValueError as exc:
                    raise ValueError(f"{path}:{line_number}: {exc}") from exc
            try:
                events.append(Event.from_record(record, line_number))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
    return sorted(events, key=lambda event: event.timestamp)
