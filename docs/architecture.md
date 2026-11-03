# Architecture

## Data flow

```text
Authorized telemetry or synthetic JSONL
                │
                ▼
       Normalized Event model
                │
       ┌────────┴─────────┐
       ▼                  ▼
   JSON rules       Event timeline
       │                  │
       └────────┬─────────┘
                ▼
       Detection engine
                │
                ▼
       Alert correlation ───────> Incident cases
                │                       │
                ▼                       ▼
      JSON/Markdown reports       Local analyst dashboard
                                        │
                                        ▼
                          local case state JSON (triage only)
```

## Components

- `adapters.py` converts normalized JSONL directly and maps exported Wazuh alert JSONL into the normalized event model.
- `models.py` validates required fields and timezone-aware timestamps.
- `engine.py` loads JSONL and rule JSON, emits single-event, threshold (including distinct-value thresholds), and sequence alerts, then connects alerts sharing a host or source IP within the selected time window. It carries technique, tactic, and telemetry metadata into alerts and coverage records.
- `cli.py` produces machine-readable alerts/cases, an ATT&CK coverage JSON export, and a Markdown case and mapping summary.
- `dashboard.py` analyzes the input once at startup, serves the static interface and JSON API (including `/api/coverage`) on `127.0.0.1`, and persists only case status, assignee, and analyst notes.
- `static/` is an offline interface with no third-party JavaScript, fonts, or API calls. The Event Explorer also displays events that did not trigger a detection.

## ATT&CK coverage

Detection rules store `attack.technique_id`, `attack.technique_name`, and one or more `attack.tactics` alongside a plain-language summary and `data_sources`. The coverage view displays all configured rules, their current alert counts, telemetry requirements, and official MITRE links. It counts techniques and tactics represented by the rule set; it does not estimate complete enterprise coverage. Mappings are behavior-level context and must be checked against the evidence and current ATT&CK Enterprise content.

## Case scoring

The starter score is intentionally simple and explainable. It maps the highest alert severity to a base score (low 25, medium 45, high 70, critical 90), adds 10 for each additional distinct detection rule, and caps the result at 100. This is a demonstration heuristic, not a calibrated risk model. Tune and validate a scoring model against labeled data before operational use.

## Correlation behavior

Alerts are joined when they share a host or source IP and their timestamps are within the configured window. Connected groups become one case. This can over-correlate on busy shared systems or NAT addresses; production deployments should include tenant, asset, identity, network zone, and causality context, and should measure false merges.

## State and trust boundaries

The server binds to the loopback interface. It has no authentication and is intended for one analyst on a local workstation. It accepts only three case update fields and limits request size and note length. Event data is rendered as text in the browser. Case state is separate from the bundled event data and detection rules. Do not expose this server to a network or treat its state file as an audited record.

## Production extensions

See [the roadmap](roadmap.md). Priorities include authenticated access, durable storage, immutable audit events, vendor-specific event adapters, schema validation, alert deduplication, and explicit approval/rollback controls for any response automation.
