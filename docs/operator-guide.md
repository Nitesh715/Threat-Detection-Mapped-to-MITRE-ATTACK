# Operator guide

## Start the dashboard

From the extracted project folder in PowerShell:

```powershell
.\run_dashboard.ps1
```

Then open `http://127.0.0.1:8765`. To select a different port:

```powershell
.\run_dashboard.ps1 -Port 9000
```

To use alternate normalized JSONL and rules:

```powershell
.\run_dashboard.ps1 -Events .\lab-events.jsonl -Rules .\lab-rules.json
```

To load an exported Wazuh alerts JSONL file, select the Wazuh format:

```powershell
.\run_dashboard.ps1 -Events .\alerts.json -Format wazuh
```

The dashboard analyzes the data at startup. Restart the process to load changed input files. Case state persists in `data/case_state.json` by default; set `-State` to choose another local file.

Select **ATT&CK coverage** in the dashboard to search rules by tactic or technique, review their required telemetry, and see the alert count for each rule. Technique links open official MITRE ATT&CK Enterprise pages. A mapping is analytic context, not proof that an alert is malicious.

## Batch reports

```powershell
.\run_analysis.ps1
```

The default output is `reports/demo/`; it contains `alerts.json`, `cases.json`, `attack_coverage.json`, and `summary.md`. The summary includes the rule-to-technique map. Provide an alternate dataset and output directory as parameters:

```powershell
.\run_analysis.ps1 -Events .\lab-events.jsonl -Output reports\lab-run
```

The Python module form is also available:

```powershell
python -m soc_lab.cli soc_lab/assets/sample_events.jsonl --out reports/demo
python -m soc_lab.dashboard --port 8765
python -m soc_lab.cli .\alerts.json --format wazuh --out reports/wazuh-run
```

## Triage a case

Open a case from either queue. Review the linked detection evidence and event timeline, select a status, enter an assignee, and add an optional note. Select **Save triage update** to write the changes locally. Status choices are open, investigating, and resolved. Notes are append-only in the UI.

## Prepare a normalized dataset

- Store one JSON object on each line (`.jsonl`).
- Include timezone-aware timestamps, preferably UTC.
- Map source-specific names to `event_type`, `host`, `user`, `source_ip`, and `details`.
- Keep `event_id` unique in the dataset to make evidence references unambiguous.
- Avoid including secrets or unnecessary personal data in a training dataset.

Wazuh alert JSONL can be imported with `--format wazuh`. The starter does not connect to Wazuh live or parse native Sysmon, Windows Event Log, Zeek, or Suricata formats. Build and document a vendor-specific adapter before using those sources.
