# Wazuh alert JSONL adapter

The adapter imports **exported Wazuh alert JSONL**. It does not connect to a Wazuh manager or query the Wazuh API. The input must contain one alert JSON object per line.

## Use it

```powershell
python -m soc_lab.cli soc_lab/assets/wazuh_sample_alerts.jsonl --format wazuh --out reports/wazuh-demo
python -m soc_lab.dashboard --events path/to/alerts.jsonl --format wazuh
```

PowerShell wrappers are also available:

```powershell
.\run_dashboard.ps1 -Events .\alerts.jsonl -Format wazuh
.\run_analysis.ps1 -Events .\alerts.jsonl -Format wazuh -Output reports\wazuh-demo
```

The bundled sample has five synthetic SSH authentication failures followed by one success. When imported, the starter authentication rules should produce a threshold alert and a sequence alert, which correlate into a case.

## Field mapping

| Wazuh alert value | Normalized field |
|---|---|
| `timestamp` | `timestamp` (must include a timezone) |
| `id`, or generated line ID | `event_id` |
| `agent.name`, then Windows computer, then manager name | `host` |
| `data.srcuser`, `data.user`, `data.dstuser`, or Windows target/subject user | `user` |
| `data.srcip`, `data.src_ip`, or selected Windows IP fields | `source_ip` |
| `rule.groups` and `rule.description` | Used to infer one of the supported event types |
| `rule.id`, `rule.level`, `rule.description`, groups, agent ID, location, MITRE IDs | Preserved under `details` |
| `full_log` | Preserved as `details.wazuh_full_log`, truncated to 1,500 characters |

The Wazuh agent IP is not treated as the remote `source_ip`; it identifies the monitored endpoint. Unrecognized alert types become `wazuh_alert` and remain searchable in the Event Explorer.

## Classification and limits

For event classification, an explicit recognized `data.soc.event_type` or `data.event_type` takes precedence. Otherwise, the adapter checks Wazuh rule groups and descriptions for common authentication failure/success phrases, privileged group-change phrases, and suspicious process indicators. Other alerts remain generic. This heuristic is for a lab demonstration; it is not a substitute for reviewing the actual Wazuh rule and event semantics.

Wazuh rule level and MITRE metadata are preserved in event details. Mini-SOC alert severity is assigned by the Mini-SOC detection rule that matched the normalized event; it does not directly copy Wazuh's numeric rule level. Create and validate explicit rules for any additional event types you need to detect.

The adapter expects valid JSON Lines, timezone-aware timestamps, and field shapes similar to Wazuh alert JSON. It does not handle a JSON array export, alternate schema versions, or native agent logs. Review data handling requirements before importing organization telemetry; the dashboard keeps the loaded events in process memory and sends them only to the local browser interface.
