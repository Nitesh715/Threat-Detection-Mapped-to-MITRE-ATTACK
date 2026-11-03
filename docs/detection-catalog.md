# Detection catalog and ATT&CK mapping

The bundled detections use synthetic normalized event labels. They demonstrate detection logic and ATT&CK mapping; they do not create malicious activity or prove that an adversary is present. Every mapped rule includes its tactic(s), technique or sub-technique ID and name, a summary, telemetry prerequisites, and analyst guidance. The dashboard **ATT&CK coverage** view and CLI report use the same rule metadata.

## Rule coverage

| Rule | ATT&CK tactic(s) | Detection | Pattern | Technique |
|---|---|---|---|---|
| `AUTH-001` | Credential Access | Repeated authentication failures | Five failures for one host, account, and source in 10 minutes | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) |
| `AUTH-002` | Credential Access | Failures followed by success | Same host, account, and source within 15 minutes | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) |
| `AUTH-003` | Credential Access | Password-spray pattern | Failures for five distinct accounts from one source and host in 10 minutes | [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| `EXEC-001` | Execution | PowerShell process signal | Endpoint telemetry labels PowerShell execution for review | [T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) |
| `IDENTITY-001` | Persistence, Privilege Escalation | Privileged group membership change | Single identity audit event | [T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) |
| `PERSIST-001` | Execution, Persistence, Privilege Escalation | Scheduled task created | Single task creation event | [T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| `PERSIST-002` | Persistence, Privilege Escalation | Registry Run key modified | Single Run/RunOnce change event | [T1547.001 Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/) |
| `CRED-001` | Credential Access | Suspicious LSASS memory access | Single endpoint process-access signal | [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/) |
| `DEFENSE-001` | Defense Impairment | Windows Event Log configuration changed | Single service or audit-policy signal | [T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/) |
| `DISC-001` | Discovery | Network service probing | Three distinct destination IPs in five minutes | [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |
| `LATERAL-001` | Lateral Movement | SSH session observed | Single normalized SSH session event | [T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004/) |
| `C2-001` | Command and Control | DNS tunneling or beaconing signal | Three analytics signals in ten minutes | [T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004/) |
| `EXFIL-001` | Exfiltration | Sensitive file access followed by an outbound-transfer anomaly | Same host and user within 15 minutes | [T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) |
| `INITIAL-001` | Initial Access | Attachment interaction followed by suspicious child process | Same host and user within 15 minutes | [T1566.001 Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) |

ATT&CK techniques describe adversary behavior. A mapping is a hypothesis for organizing detections, not a claim of attribution or intent. Some techniques have multiple tactics; the dashboard displays all tactics in the rule metadata. `DEFENSE-001` follows the current MITRE ATT&CK Enterprise mapping for Windows Event Log impairment (`T1685.001`). Validate technique IDs and names against the official live pages when revising the catalog because ATT&CK changes over time.

## Sample scenario

The bundled 30-event dataset is fully synthetic. It contains two analyst training threads: Windows endpoint and identity signals, plus Linux authentication, network discovery, SSH, and DNS analytics signals. The rules should produce 14 alerts across 14 mapped rules and correlate them into two host-centered cases. A separate benign authentication success remains unalerted. Documentation-only IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`) and `.invalid` DNS names are used in the sample.

## Rule authoring guidance

- Keep `id` stable and unique so analysts can track rule changes.
- Set `attack.technique_id`, `attack.technique_name`, and `attack.tactics` from the official ATT&CK Enterprise pages. Use a sub-technique only when the event semantics support that specificity.
- Keep `summary` precise about what the available event pattern actually observes.
- Describe the required source fields in `data_sources`; event-type labels alone do not imply that a sensor collects the required evidence.
- Group by enough context to reduce accidental aggregation (usually host, identity, and source).
- A threshold rule may use `distinct_by` to count unique field values inside its rolling window. For example, password-spray and network-probe rules count distinct users or destination IPs rather than repeated copies of one value.
- Use exact criteria on top-level event fields (`event_type`, `host`, `user`, `source_ip`) or dotted `details` fields such as `details.interpreter`.
- Add benign and simulated examples and measure precision/recall against labeled data before deploying a rule.

Supported detection patterns:

```json
{"id":"EXAMPLE-001","name":"One event","type":"single","severity":"medium","match":{"event_type":"example_event"},"attack":{"technique_id":"T1046","technique_name":"Network Service Discovery","tactics":["Discovery"]}}
```

```json
{"id":"EXAMPLE-002","name":"Distinct values in a window","type":"threshold","severity":"high","match":{"event_type":"example_event"},"group_by":["host","source_ip"],"distinct_by":["details.destination_ip"],"threshold":3,"window_minutes":5}
```

```json
{"id":"EXAMPLE-003","name":"Event sequence","type":"sequence","severity":"high","start_match":{"event_type":"first_event"},"end_match":{"event_type":"second_event"},"group_by":["host","user"],"window_minutes":15}
```
