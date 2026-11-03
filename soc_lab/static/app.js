const state = { overview: null, cases: [], alerts: [], events: [], coverage: [], activeView: "dashboardView", toastTimer: null };
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

async function requestJson(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function dateLabel(value, withTime = true) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown time";
  return new Intl.DateTimeFormat(undefined, withTime
    ? { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }
    : { month: "short", day: "numeric", year: "numeric" }).format(date);
}

function severityBadge(severity) {
  const safe = escapeHtml(String(severity || "low").toLowerCase());
  return `<span class="severity-badge ${safe}">${safe}</span>`;
}

function attackLink(attack, fallbackId = "") {
  const id = String(attack?.technique_id || fallbackId || "");
  if (!id) return "";
  const name = attack?.technique_name ? ` · ${escapeHtml(attack.technique_name)}` : "";
  if (!/^T\d{4}(?:\.\d{3})?$/.test(id)) return `${escapeHtml(id)}${name}`;
  const href = `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
  const tactics = Array.isArray(attack?.tactics) ? attack.tactics.filter(Boolean).join(", ") : "";
  return `<a class="attack-link" href="${href}" target="_blank" rel="noopener noreferrer">${escapeHtml(id)}${name}</a>${tactics ? `<span class="attack-tactics">${escapeHtml(tactics)}</span>` : ""}`;
}

function statusBadge(status) {
  const safe = escapeHtml(String(status || "open").toLowerCase());
  return `<span class="status-badge ${safe}">${safe}</span>`;
}

function hostLabel(item) {
  const hosts = item.entities?.host || [];
  const users = item.entities?.user || [];
  const host = hosts[0] || "Unknown host";
  const user = users[0] || item.assignee || "";
  return `<span class="host-cell">${escapeHtml(host)}${user ? `<small>${escapeHtml(user)}</small>` : ""}</span>`;
}

function riskMarkup(score, severity) {
  const number = Math.max(0, Math.min(100, Number(score) || 0));
  const riskClass = severity === "critical" ? "risk-critical" : severity === "high" ? "risk-high" : "";
  return `<span class="risk-value">${number}<span class="risk-mini"><i class="${riskClass}" style="width:${number}%"></i></span></span>`;
}

function showError(error) {
  const box = $("#pageError");
  box.textContent = `Could not load SOC data: ${error.message}`;
  box.hidden = false;
}

function hideError() { $("#pageError").hidden = true; }

async function refresh() {
  try {
    hideError();
    const [overview, cases, alerts, events, coverage] = await Promise.all([
      requestJson("/api/overview"), requestJson("/api/cases"), requestJson("/api/alerts"), requestJson("/api/events"), requestJson("/api/coverage")
    ]);
    state.overview = overview;
    state.cases = cases;
    state.alerts = alerts;
    state.events = events;
    state.coverage = coverage;
    renderAll();
  } catch (error) {
    showError(error);
  }
}

function renderAll() {
  renderOverview();
  renderSeverity();
  renderPosture();
  renderOverviewCases();
  renderAlerts();
  renderCases();
  renderEvents();
  renderCoverage();
}

function renderOverview() {
  const overview = state.overview;
  if (!overview) return;
  $("#openCaseMetric").textContent = overview.open_case_count;
  $("#caseMetric").textContent = overview.case_count;
  $("#alertMetric").textContent = overview.alert_count;
  $("#eventMetric").textContent = overview.event_count;
  $("#navCaseCount").textContent = overview.open_case_count;
  $("#queueTotal").textContent = overview.case_count;
  const sourceName = overview.source_format === "wazuh" ? "Wazuh import" : "Normalized events";
  $("#updatedAt").textContent = `${sourceName} · Updated ${dateLabel(overview.updated_at)}`;
  $("#navEventCount").textContent = overview.event_count;
  $("#eventTotal").textContent = overview.event_count;
}

function renderSeverity() {
  const counts = state.overview?.alert_severities || {};
  const order = ["critical", "high", "medium", "low"];
  const total = order.reduce((sum, key) => sum + (counts[key] || 0), 0);
  $("#severityTotal").textContent = `${total} alert${total === 1 ? "" : "s"}`;
  $("#severityChart").innerHTML = order.map((severity) => {
    const count = counts[severity] || 0;
    const width = total ? (count / total) * 100 : 0;
    return `<div class="severity-row"><span class="severity-name">${severity[0].toUpperCase()}${severity.slice(1)}</span><div class="severity-track"><div class="severity-fill ${severity}" style="width:${width}%"></div></div><span class="severity-count">${count}</span></div>`;
  }).join("");
}

function renderPosture() {
  const statuses = state.overview?.case_statuses || {};
  const order = ["open", "investigating", "resolved"];
  const total = order.reduce((sum, key) => sum + (statuses[key] || 0), 0);
  $("#postureOpen").textContent = (statuses.open || 0) + (statuses.investigating || 0);
  $("#postureStack").innerHTML = order.map((status) => {
    const count = statuses[status] || 0;
    const width = total ? (count / total) * 100 : 0;
    return `<span class="posture-segment ${status}" style="width:${width}%" title="${status}: ${count}"></span>`;
  }).join("");
  $("#postureLegend").innerHTML = order.map((status) => `<div class="posture-item"><strong>${statuses[status] || 0}</strong><i class="posture-segment ${status}"></i>${status}</div>`).join("");
}

function renderOverviewCases() {
  const cases = [...state.cases].sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen)).slice(0, 5);
  const body = $("#overviewCasesBody");
  $("#overviewCasesEmpty").hidden = cases.length > 0;
  body.innerHTML = cases.map((item) => `<tr class="case-row" data-case="${escapeHtml(item.case_id)}">
    <td><div class="case-title">${escapeHtml(item.title)}</div><div class="case-id">${escapeHtml(item.case_id)}</div></td>
    <td>${severityBadge(item.severity)}</td><td>${riskMarkup(item.risk_score, item.severity)}</td><td>${statusBadge(item.status)}</td>
    <td>${hostLabel(item)}</td><td>${escapeHtml(dateLabel(item.last_seen))}</td><td><span class="row-arrow">›</span></td>
  </tr>`).join("");
  attachCaseRows(body);
}

function renderAlerts() {
  const alerts = [...state.alerts].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 8);
  const body = $("#alertsBody");
  $("#alertsEmpty").hidden = alerts.length > 0;
  body.innerHTML = alerts.map((alert) => `<tr>
    <td><div class="case-title">${escapeHtml(alert.rule_name)}</div><div class="case-id">${escapeHtml(alert.rule_id)}${alert.attack_technique ? ` · ${attackLink(alert.attack, alert.attack_technique)}` : ""}</div></td>
    <td>${severityBadge(alert.severity)}</td><td>${escapeHtml(alert.entities?.host || "—")}</td>
    <td>${(alert.event_ids || []).length} event${(alert.event_ids || []).length === 1 ? "" : "s"}</td><td>${escapeHtml(dateLabel(alert.timestamp))}</td>
  </tr>`).join("");
}

function renderCases() {
  const query = $("#caseSearch").value.trim().toLowerCase();
  const status = $("#statusFilter").value;
  const severity = $("#severityFilter").value;
  const filtered = [...state.cases].filter((item) => {
    if (status !== "all" && item.status !== status) return false;
    if (severity !== "all" && item.severity !== severity) return false;
    const searchable = [item.case_id, item.title, item.assignee, ...(item.entities?.host || []), ...(item.entities?.user || []), ...(item.entities?.source_ip || [])].join(" ").toLowerCase();
    return !query || searchable.includes(query);
  }).sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
  const body = $("#casesBody");
  $("#casesEmpty").hidden = filtered.length > 0;
  body.innerHTML = filtered.map((item) => `<tr class="case-row" data-case="${escapeHtml(item.case_id)}">
    <td><div class="case-title">${escapeHtml(item.title)}</div><div class="case-id">${escapeHtml(item.case_id)} · ${(item.alert_ids || []).length} alert${(item.alert_ids || []).length === 1 ? "" : "s"}</div></td>
    <td>${severityBadge(item.severity)}</td><td>${riskMarkup(item.risk_score, item.severity)}</td><td>${statusBadge(item.status)}</td>
    <td>${hostLabel(item)}</td><td>${escapeHtml(item.assignee || "Unassigned")}</td><td>${escapeHtml(dateLabel(item.last_seen))}</td><td><span class="row-arrow">›</span></td>
  </tr>`).join("");
  attachCaseRows(body);
}

function renderEvents() {
  const query = $("#eventSearch").value.trim().toLowerCase();
  const selectedType = $("#eventTypeFilter").value;
  const types = [...new Set(state.events.map((event) => event.event_type))].sort();
  const typeFilter = $("#eventTypeFilter");
  const previousType = typeFilter.value;
  typeFilter.innerHTML = `<option value="all">All event types</option>${types.map((type) => `<option value="${escapeHtml(type)}">${escapeHtml(type.replaceAll("_", " "))}</option>`).join("")}`;
  typeFilter.value = types.includes(previousType) ? previousType : "all";
  const activeType = selectedType !== "all" && types.includes(selectedType) ? selectedType : typeFilter.value;
  const filtered = [...state.events].filter((event) => {
    if (activeType !== "all" && event.event_type !== activeType) return false;
    const searchable = [event.event_id, event.event_type, event.host, event.user, event.source_ip, JSON.stringify(event.details || {})].join(" ").toLowerCase();
    return !query || searchable.includes(query);
  }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const visible = filtered.slice(0, 250);
  $("#eventsEmpty").hidden = filtered.length > 0;
  $("#eventsBody").innerHTML = visible.map((event) => {
    const details = event.details || {};
    const detailLabel = details.wazuh_rule_description || details.process_label || details.group || details.source || "—";
    const shortDetail = String(detailLabel).length > 92 ? `${String(detailLabel).slice(0, 89)}…` : String(detailLabel);
    return `<tr><td>${escapeHtml(dateLabel(event.timestamp))}</td><td><span class="event-type">${escapeHtml(event.event_type.replaceAll("_", " "))}</span></td><td>${escapeHtml(event.host)}</td><td>${escapeHtml(event.user || "—")}</td><td>${escapeHtml(event.source_ip || "—")}</td><td class="event-detail" title="${escapeHtml(detailLabel)}">${escapeHtml(shortDetail)}</td><td class="event-id-cell">${escapeHtml(event.event_id)}</td></tr>`;
  }).join("");
  $("#eventResultsNote").textContent = filtered.length > visible.length
    ? `Showing ${visible.length} of ${filtered.length} matching events.`
    : `${filtered.length} matching event${filtered.length === 1 ? "" : "s"}.`;
}

function renderCoverage() {
  const coverage = state.coverage || [];
  const mapped = coverage.filter((row) => row.attack?.technique_id);
  const techniques = new Set(mapped.map((row) => row.attack.technique_id));
  const tactics = new Set(mapped.flatMap((row) => row.attack.tactics || []));
  $("#attackRuleMetric").textContent = mapped.length;
  $("#attackTechniqueMetric").textContent = techniques.size;
  $("#attackTacticMetric").textContent = tactics.size;
  $("#attackAlertMetric").textContent = mapped.reduce((sum, row) => sum + (Number(row.alert_count) || 0), 0);
  $("#navCoverageCount").textContent = mapped.length;

  const tacticFilter = $("#attackTacticFilter");
  const previousTactic = tacticFilter.value;
  const tacticList = [...tactics].sort((a, b) => a.localeCompare(b));
  tacticFilter.innerHTML = `<option value="all">All tactics</option>${tacticList.map((tactic) => `<option value="${escapeHtml(tactic)}">${escapeHtml(tactic)}</option>`).join("")}`;
  tacticFilter.value = tacticList.includes(previousTactic) ? previousTactic : "all";

  const query = $("#attackSearch").value.trim().toLowerCase();
  const selectedTactic = tacticFilter.value;
  const filtered = coverage.filter((row) => {
    const rowTactics = row.attack?.tactics || [];
    if (selectedTactic !== "all" && !rowTactics.includes(selectedTactic)) return false;
    const searchable = [
      row.rule_id, row.rule_name, row.summary, row.attack?.technique_id,
      row.attack?.technique_name, ...rowTactics, ...(row.event_types || []), ...(row.data_sources || [])
    ].join(" ").toLowerCase();
    return !query || searchable.includes(query);
  }).sort((a, b) => {
    const tacticCompare = (a.attack?.tactics?.[0] || "Unmapped").localeCompare(b.attack?.tactics?.[0] || "Unmapped");
    return tacticCompare || String(a.attack?.technique_id || "").localeCompare(String(b.attack?.technique_id || "")) || a.rule_id.localeCompare(b.rule_id);
  });

  const body = $("#attackCoverageBody");
  $("#attackCoverageEmpty").hidden = filtered.length > 0;
  body.innerHTML = filtered.map((row) => {
    const rowTactics = row.attack?.tactics || [];
    const tacticMarkup = rowTactics.length
      ? rowTactics.map((tactic) => `<span class="tactic-pill">${escapeHtml(tactic)}</span>`).join("")
      : `<span class="unmapped-label">Unmapped</span>`;
    const eventMarkup = (row.event_types || []).map((type) => `<span class="event-type">${escapeHtml(type.replaceAll("_", " "))}</span>`).join(" ");
    const sourceMarkup = (row.data_sources || []).map(escapeHtml).join(" ");
    return `<tr>
      <td><div class="tactic-list">${tacticMarkup}</div></td>
      <td>${row.attack ? attackLink(row.attack) : `<span class="unmapped-label">No ATT&amp;CK mapping</span>`}</td>
      <td><div class="case-title">${escapeHtml(row.rule_name)}</div><div class="case-id">${escapeHtml(row.rule_id)} · ${escapeHtml(row.detection_type)} · ${escapeHtml(row.severity)}</div><div class="coverage-summary">${escapeHtml(row.summary)}</div></td>
      <td><div class="coverage-events">${eventMarkup || "—"}</div><div class="coverage-data">${sourceMarkup}</div></td>
      <td><strong class="coverage-alert-count">${Number(row.alert_count) || 0}</strong></td>
    </tr>`;
  }).join("");
}

function attachCaseRows(parent) {
  $$("tr[data-case]", parent).forEach((row) => row.addEventListener("click", () => openCase(row.dataset.case)));
}

function openDrawer() {
  $("#caseDrawer").classList.add("open");
  $("#caseDrawer").setAttribute("aria-hidden", "false");
  $("#drawerBackdrop").classList.add("open");
  document.body.style.overflow = "hidden";
}

function closeDrawer() {
  $("#caseDrawer").classList.remove("open");
  $("#caseDrawer").setAttribute("aria-hidden", "true");
  $("#drawerBackdrop").classList.remove("open");
  document.body.style.overflow = "";
}

function openCase(caseId) {
  const item = state.cases.find((entry) => entry.case_id === caseId);
  if (!item) return;
  const alerts = state.alerts.filter((alert) => (item.alert_ids || []).includes(alert.alert_id));
  const eventIds = new Set(item.event_ids || []);
  const events = state.events.filter((event) => eventIds.has(event.event_id)).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  $("#drawerTitle").textContent = item.title;
  $("#drawerCaseId").textContent = item.case_id;
  const alertCards = alerts.map((alert) => `<article class="alert-evidence"><div class="evidence-head"><strong>${escapeHtml(alert.rule_name)}</strong>${severityBadge(alert.severity)}</div><div class="evidence-meta">${escapeHtml(alert.rule_id)}${alert.attack_technique ? ` · ${attackLink(alert.attack, alert.attack_technique)}` : ""} · ${escapeHtml(dateLabel(alert.timestamp))}</div><div class="evidence-summary">${escapeHtml(alert.summary)}</div><div class="evidence-meta">Evidence: ${(alert.event_ids || []).map(escapeHtml).join(", ")}</div></article>`).join("");
  const timeline = events.map((event) => {
    const details = Object.entries(event.details || {}).filter(([key]) => key !== "source").map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`).join(" · ");
    return `<div class="timeline-item"><div class="timeline-time">${escapeHtml(dateLabel(event.timestamp))}</div><div class="timeline-title">${escapeHtml(event.event_type.replaceAll("_", " "))} · ${escapeHtml(event.host)}</div><div class="timeline-detail">${escapeHtml([event.user && `user ${event.user}`, event.source_ip && `source ${event.source_ip}`, details].filter(Boolean).join(" · ") || event.event_id)}</div></div>`;
  }).join("");
  const notes = (item.notes || []).map((note) => `<div class="note-card"><div class="note-card-top"><span>${escapeHtml(note.author || "SOC analyst")}</span><span>${escapeHtml(dateLabel(note.created_at))}</span></div><p>${escapeHtml(note.text)}</p></div>`).join("");
  $("#drawerContent").innerHTML = `
    <div class="drawer-topline">${severityBadge(item.severity)}<span class="drawer-risk">Risk score <strong>${Number(item.risk_score) || 0}</strong></span></div>
    <div class="drawer-summary">${escapeHtml(alerts[0]?.summary || item.title)}</div>
    <div class="detail-grid">
      <div class="detail-item"><label>First seen</label><strong>${escapeHtml(dateLabel(item.first_seen))}</strong></div>
      <div class="detail-item"><label>Last seen</label><strong>${escapeHtml(dateLabel(item.last_seen))}</strong></div>
      <div class="detail-item"><label>Host</label><strong>${escapeHtml((item.entities?.host || []).join(", ") || "—")}</strong></div>
      <div class="detail-item"><label>Source IP</label><strong>${escapeHtml((item.entities?.source_ip || []).join(", ") || "—")}</strong></div>
      <div class="detail-item"><label>Rules</label><strong>${escapeHtml((item.rule_ids || []).join(", ") || "—")}</strong></div>
      <div class="detail-item"><label>Evidence events</label><strong>${(item.event_ids || []).length}</strong></div>
    </div>
    <section class="drawer-section"><h3 class="drawer-section-title">Triage</h3>
      <div class="triage-fields">
        <label><span class="field-label">Status</span><select id="triageStatus"><option value="open" ${item.status === "open" ? "selected" : ""}>Open</option><option value="investigating" ${item.status === "investigating" ? "selected" : ""}>Investigating</option><option value="resolved" ${item.status === "resolved" ? "selected" : ""}>Resolved</option></select></label>
        <label><span class="field-label">Assignee</span><input id="triageAssignee" maxlength="100" value="${escapeHtml(item.assignee || "Unassigned")}" /></label>
      </div>
    </section>
    <section class="drawer-section"><h3 class="drawer-section-title">Detection evidence (${alerts.length})</h3>${alertCards || `<div class="timeline-detail">No alert details available.</div>`}</section>
    <section class="drawer-section"><h3 class="drawer-section-title">Event timeline (${events.length})</h3><div class="event-timeline">${timeline || `<div class="timeline-detail">No linked events.</div>`}</div></section>
    <section class="drawer-section"><h3 class="drawer-section-title">Analyst notes</h3>
      <div class="note-composer"><textarea class="note-input" id="triageNote" maxlength="2000" placeholder="Record investigation findings or next steps…"></textarea><button class="primary-button" id="saveTriage" type="button">Save triage update</button></div>
      <div class="note-list">${notes || `<div class="timeline-detail">No notes yet.</div>`}</div>
    </section>
    <section class="drawer-section"><h3 class="drawer-section-title">Suggested analyst steps</h3><div class="drawer-summary">${(alerts.flatMap((alert) => alert.recommended_actions || []).filter((action, index, all) => all.indexOf(action) === index).map((action) => `• ${escapeHtml(action)}`).join("<br>") || "Review the linked evidence and document the outcome.")}</div></section>`;
  $("#saveTriage").addEventListener("click", () => saveTriage(item.case_id));
  openDrawer();
}

async function saveTriage(caseId) {
  const payload = {
    status: $("#triageStatus").value,
    assignee: $("#triageAssignee").value,
    note: $("#triageNote").value
  };
  try {
    const updated = await requestJson(`/api/cases/${encodeURIComponent(caseId)}/triage`, {
      method: "POST", body: JSON.stringify(payload)
    });
    state.cases = state.cases.map((item) => item.case_id === caseId ? updated : item);
    await refresh();
    openCase(caseId);
    showToast("Triage update saved locally");
  } catch (error) {
    showToast(`Could not save: ${error.message}`);
  }
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => toast.classList.remove("visible"), 2600);
}

function setView(viewId) {
  state.activeView = viewId;
  $$(".page-view").forEach((view) => { view.hidden = view.id !== viewId; });
  $$(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === viewId));
  $("#pageCrumb").textContent = ({ casesView: "Incident queue", eventsView: "Event explorer", attackView: "ATT&CK coverage" })[viewId] || "Overview";
}

$$('.nav-item').forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
$("[data-open-cases]").addEventListener("click", () => setView("casesView"));
$("#refreshButton").addEventListener("click", refresh);
$("#caseSearch").addEventListener("input", renderCases);
$("#statusFilter").addEventListener("change", renderCases);
$("#severityFilter").addEventListener("change", renderCases);
$("#eventSearch").addEventListener("input", renderEvents);
$("#eventTypeFilter").addEventListener("change", renderEvents);
$("#attackSearch").addEventListener("input", renderCoverage);
$("#attackTacticFilter").addEventListener("change", renderCoverage);
$("#closeDrawer").addEventListener("click", closeDrawer);
$("#drawerBackdrop").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (event) => { if (event.key === "Escape") closeDrawer(); });

refresh();
