from __future__ import annotations

import argparse
import copy
import json
import mimetypes
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .engine import build_attack_coverage, correlate_alerts, load_events, load_rules, run_detections

ASSET_ROOT = Path(__file__).resolve().parent / "assets"
STATIC_ROOT = Path(__file__).resolve().parent / "static"
STATIC_FILES = {
    "/": "index.html",
    "/index.html": "index.html",
    "/styles.css": "styles.css",
    "/app.js": "app.js",
}
VALID_STATUSES = {"open", "investigating", "resolved"}


class DashboardContext:
    def __init__(
        self,
        events: list[dict[str, Any]],
        alerts: list[dict[str, Any]],
        cases: list[dict[str, Any]],
        rules: list[dict[str, Any]],
        state_path: Path,
        source_format: str,
    ) -> None:
        self.events = events
        self.alerts = alerts
        self.cases = cases
        self.rules = rules
        self.state_path = state_path
        self.source_format = source_format
        self.lock = threading.RLock()
        self.state = self._load_state()

    def _load_state(self) -> dict[str, dict[str, Any]]:
        if not self.state_path.exists():
            return {}
        with self.state_path.open("r", encoding="utf-8") as source:
            data = json.load(source)
        if not isinstance(data, dict):
            raise ValueError("case state file must contain a JSON object")
        clean_state: dict[str, dict[str, Any]] = {}
        for case_id, value in data.items():
            if not isinstance(case_id, str) or not isinstance(value, dict):
                continue
            status = value.get("status", "open")
            assignee = value.get("assignee", "Unassigned")
            notes = value.get("notes", [])
            clean_state[case_id] = {
                "status": status if isinstance(status, str) and status in VALID_STATUSES else "open",
                "assignee": assignee if isinstance(assignee, str) else "Unassigned",
                "notes": [
                    note for note in notes
                    if isinstance(note, dict) and isinstance(note.get("text"), str)
                ] if isinstance(notes, list) else [],
            }
        return clean_state

    def case(self, case_id: str) -> dict[str, Any] | None:
        base = next((item for item in self.cases if item["case_id"] == case_id), None)
        if base is None:
            return None
        state = self.state.get(case_id, {})
        result = copy.deepcopy(base)
        result["status"] = state.get("status", "open")
        result["assignee"] = state.get("assignee", "Unassigned")
        result["notes"] = copy.deepcopy(state.get("notes", []))
        return result

    def all_cases(self) -> list[dict[str, Any]]:
        return [self.case(item["case_id"]) for item in self.cases]

    def update_case(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        with self.lock:
            if not any(item["case_id"] == case_id for item in self.cases):
                return None
            next_state = copy.deepcopy(self.state)
            entry = next_state.setdefault(case_id, {"status": "open", "assignee": "Unassigned", "notes": []})

            status = payload.get("status")
            if status is not None:
                if not isinstance(status, str) or status not in VALID_STATUSES:
                    raise ValueError("status must be open, investigating, or resolved")
                entry["status"] = status

            assignee = payload.get("assignee")
            if assignee is not None:
                if not isinstance(assignee, str) or len(assignee.strip()) > 100:
                    raise ValueError("assignee must be a string of at most 100 characters")
                entry["assignee"] = assignee.strip() or "Unassigned"

            note = payload.get("note")
            if note is not None:
                if not isinstance(note, str) or len(note.strip()) > 2000:
                    raise ValueError("note must be a string of at most 2,000 characters")
                if note.strip():
                    entry.setdefault("notes", []).append(
                        {
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            "author": entry.get("assignee", "SOC analyst"),
                            "text": note.strip(),
                        }
                    )

            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            temporary_path.write_text(json.dumps(next_state, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary_path, self.state_path)
            self.state = next_state
            return self.case(case_id)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "MiniSOC/0.1"

    @property
    def context(self) -> DashboardContext:
        return self.server.context  # type: ignore[attr-defined]

    def _send_json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_error_json(self, message: str, status: int) -> None:
        self._send_json({"error": message}, status)

    def do_GET(self) -> None:  # noqa: N802 - required handler name
        path = urlparse(self.path).path
        if path == "/api/overview":
            statuses = {status: 0 for status in VALID_STATUSES}
            for case in self.context.all_cases():
                statuses[case["status"]] = statuses.get(case["status"], 0) + 1
            severities = {severity: 0 for severity in ("critical", "high", "medium", "low")}
            for alert in self.context.alerts:
                severities[alert["severity"]] = severities.get(alert["severity"], 0) + 1
            self._send_json(
                {
                    "event_count": len(self.context.events),
                    "alert_count": len(self.context.alerts),
                    "case_count": len(self.context.cases),
                    "open_case_count": statuses.get("open", 0) + statuses.get("investigating", 0),
                    "case_statuses": statuses,
                    "alert_severities": severities,
                    "source_format": self.context.source_format,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            return
        if path == "/api/cases":
            self._send_json(self.context.all_cases())
            return
        if path == "/api/alerts":
            self._send_json(self.context.alerts)
            return
        if path == "/api/coverage":
            self._send_json(build_attack_coverage(self.context.rules, self.context.alerts))
            return
        if path == "/api/events":
            self._send_json(self.context.events)
            return
        if path.startswith("/api/cases/"):
            case_id = path.rsplit("/", 1)[-1]
            case = self.context.case(case_id)
            if case is None:
                self._send_error_json("case not found", 404)
            else:
                self._send_json(case)
            return

        filename = STATIC_FILES.get(path)
        if filename is None:
            self._send_error_json("not found", 404)
            return
        content = (STATIC_ROOT / filename).read_bytes()
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:  # noqa: N802 - required handler name
        path = urlparse(self.path).path
        if not path.startswith("/api/cases/") or not path.endswith("/triage"):
            self._send_error_json("not found", 404)
            return
        case_id = path.removeprefix("/api/cases/").removesuffix("/triage")
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length < 1 or content_length > 65536:
                self._send_error_json("request body must be between 1 byte and 64 KB", 413)
                return
            payload = json.loads(self.rfile.read(content_length))
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            allowed = {"status", "assignee", "note"}
            if payload.keys() - allowed:
                raise ValueError("only status, assignee, and note fields are accepted")
            case = self.context.update_case(case_id, payload)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_error_json(str(exc), 400)
            return
        except OSError as exc:
            self._send_error_json(f"could not persist case state: {exc}", 500)
            return
        if case is None:
            self._send_error_json("case not found", 404)
        else:
            self._send_json(case)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


class LocalDashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Start the local Mini-SOC dashboard.")
    parser.add_argument("--events", type=Path, default=ASSET_ROOT / "sample_events.jsonl")
    parser.add_argument("--rules", type=Path, default=ASSET_ROOT / "detections.json")
    parser.add_argument(
        "--format", choices=("normalized", "wazuh"), default="normalized",
        help="input event format (default: normalized)",
    )
    parser.add_argument("--state", type=Path, default=Path.cwd() / "data" / "case_state.json")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--correlation-minutes", type=float, default=30.0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not 1 <= args.port <= 65535:
        print("dashboard: port must be between 1 and 65535", file=sys.stderr)
        return 2
    try:
        event_objects = load_events(args.events, args.format)
        rules = load_rules(args.rules)
        alerts = run_detections(event_objects, rules)
        cases = correlate_alerts(alerts, args.correlation_minutes)
        events = [
            {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "host": event.host,
                "user": event.user,
                "source_ip": event.source_ip,
                "details": event.details,
            }
            for event in event_objects
        ]
        context = DashboardContext(events, alerts, cases, rules, args.state, args.format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"dashboard: {exc}", file=sys.stderr)
        return 2

    server = LocalDashboardServer(("127.0.0.1", args.port), DashboardHandler)
    server.context = context  # type: ignore[attr-defined]
    print(f"Mini-SOC dashboard ready at http://127.0.0.1:{args.port}")
    print("Press Ctrl+C to stop. The server listens on this computer only.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Mini-SOC dashboard.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
