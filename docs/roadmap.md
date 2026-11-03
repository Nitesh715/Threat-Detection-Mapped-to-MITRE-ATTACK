# Roadmap

Suggested capstone extension order:

1. **Data quality:** add a JSON schema for events and rules; report invalid or missing fields with line-level errors.
2. **Detection evaluation:** add labeled benign/simulated replay data and measure precision, recall, false-positive rate, and detection latency.
3. **Source adapters:** the Wazuh alert JSONL importer is included. Implement one additional adapter at a time for Sysmon/Windows, Linux audit/auth, and network sensor logs.
4. **Case workflow:** add case history and audit records, analyst ownership, duplicate handling, and exportable incident reports.
5. **Threat context:** enrich with an offline asset inventory and local indicator list, preserving source and confidence for every enrichment.
6. **Safe response:** begin with dry-run playbooks. Only later add reversible actions inside disposable lab hosts, with explicit human approval, allowlists, logging, and rollback.
7. **Operations:** add authenticated access, durable database storage, backup/restore, access control, and deployment hardening before using real organizational data.

Do not enable live response automation until alert quality, authorization, containment scope, and rollback have been reviewed by the system owner.
