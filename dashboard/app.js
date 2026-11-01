(() => {
  "use strict";

  const state = {
    page: "overview",
    datasetId: localStorage.getItem("sop-selected-dataset") || "",
    datasets: [],
    activeInvestigationId: "",
    expandedProposalId: "",
    eventOffset: 0,
  };
  const $ = (id) => document.getElementById(id);
  const svgNs = "http://www.w3.org/2000/svg";

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined && text !== null) element.textContent = String(text);
    return element;
  }

  function icon(name) {
    const svg = document.createElementNS(svgNs, "svg");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS(svgNs, "use");
    use.setAttribute("href", `icons.svg#${name}`);
    svg.append(use);
    return svg;
  }

  async function api(path, options = {}) {
    const response = await fetch(path, { cache: "no-store", ...options });
    const text = await response.text();
    let body = null;
    if (text) {
      try { body = JSON.parse(text); } catch { body = text; }
    }
    if (!response.ok) {
      const detail = typeof body === "object" && body ? body.detail : body;
      const message = typeof detail === "object" && detail ? detail.reason || detail.message || JSON.stringify(detail) : detail;
      throw new Error(message || `Request failed (${response.status})`);
    }
    return body;
  }

  function scoped(path, key = "dataset_id") {
    if (!state.datasetId) return path;
    const separator = path.includes("?") ? "&" : "?";
    return `${path}${separator}${key}=${encodeURIComponent(state.datasetId)}`;
  }

  function formatNumber(value) {
    return new Intl.NumberFormat().format(Number(value || 0));
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  function showNotice(message, kind = "") {
    const notice = $("notice");
    notice.textContent = message;
    notice.className = `notice ${kind}`.trim();
    notice.hidden = false;
    if (kind === "success") window.setTimeout(() => { notice.hidden = true; }, 5000);
  }

  function clearNotice() {
    $("notice").hidden = true;
    $("notice").textContent = "";
  }

  function emptyState(title, message, actionText, actionHref) {
    const box = node("div", "empty-state");
    box.append(node("strong", "", title), node("span", "", message));
    if (actionText && actionHref) {
      const link = node("a", "text-link", actionText);
      link.href = actionHref;
      box.append(document.createElement("br"), link);
    }
    return box;
  }

  function status(value) {
    const safe = String(value || "unknown");
    const badge = node("span", `status status-${safe.toLowerCase().replace(/[^a-z0-9_-]/g, "_")}`, safe.replaceAll("_", " "));
    return badge;
  }

  function severity(value) {
    const safe = String(value || "unknown").toLowerCase();
    return node("span", `severity severity-${safe}`, safe);
  }

  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("sop-theme", theme);
    const toggle = $("theme-toggle");
    const next = theme === "dark" ? "plum" : theme === "plum" ? "light" : "dark";
    toggle.setAttribute("aria-label", `Switch to ${next} mode`);
    toggle.title = `Switch to ${next} mode`;
    toggle.replaceChildren(icon(next === "light" ? "sun" : "moon"));
  }

  function setDataset(datasetId) {
    state.datasetId = datasetId;
    state.eventOffset = 0;
    if (datasetId) localStorage.setItem("sop-selected-dataset", datasetId);
    else localStorage.removeItem("sop-selected-dataset");
    $("global-dataset").value = datasetId;
    updateInvestigationControl();
    if (state.page) loadPage(state.page);
  }

  function setPage(page) {
    state.page = page;
    document.querySelectorAll(".page-section").forEach((section) => {
      section.hidden = section.id !== `page-${page}`;
    });
    document.querySelectorAll(".nav-link").forEach((link) => {
      const active = link.dataset.page === page;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const title = document.querySelector(`#page-${page}`)?.dataset.title || "Overview";
    $("current-section").textContent = title;
    history.replaceState(null, "", `#${page}`);
    document.body.classList.remove("mobile-nav-open");
    $("mobile-menu").setAttribute("aria-expanded", "false");
    clearNotice();
    loadPage(page);
  }

  async function initializeDatasets() {
    try {
      const result = await api("/api/datasets");
      state.datasets = result.datasets || [];
      if (!state.datasets.some((item) => item.dataset_id === state.datasetId)) state.datasetId = "";
      const select = $("global-dataset");
      select.replaceChildren(new Option("All datasets", ""));
      state.datasets.forEach((dataset) => select.add(new Option(`${dataset.name} · ${dataset.dataset_id}`, dataset.dataset_id)));
      select.value = state.datasetId;
      updateInvestigationControl();
    } catch (error) {
      showNotice(`Could not load the local dataset library: ${error.message}`, "error");
    }
  }

  function updateInvestigationControl() {
    const dataset = state.datasets.find((item) => item.dataset_id === state.datasetId);
    const scope = $("investigation-scope");
    if (scope) scope.textContent = dataset ? `Selected dataset: ${dataset.name} (${dataset.dataset_id})` : "Select exactly one dataset in the Dataset Library or top bar.";
    const start = $("start-investigation");
    if (start) start.disabled = !state.datasetId;
  }

  async function loadPage(page) {
    try {
      const loaders = {
        overview: loadOverview,
        datasets: loadDatasets,
        investigations: loadInvestigations,
        findings: loadFindings,
        approvals: loadApprovals,
        processed: loadProcessed,
        audit: loadAudit,
        reports: loadReports,
        settings: loadSettings,
      };
      await (loaders[page] || loadOverview)();
    } catch (error) {
      showNotice(`Unable to load ${page}: ${error.message}`, "error");
    }
  }

  function metric(label, value, note) {
    const wrap = node("div", "metric");
    wrap.append(node("span", "metric-label", label), node("span", "metric-value", formatNumber(value)), node("span", "metric-note", note));
    return wrap;
  }

  function buildTableRow(values) {
    const tr = document.createElement("tr");
    values.forEach((value) => {
      const td = document.createElement("td");
      if (value instanceof Node) td.append(value);
      else td.textContent = value === undefined || value === null ? "—" : String(value);
      tr.append(td);
    });
    return tr;
  }

  function renderLineChart(host, items, label) {
    host.replaceChildren();
    if (!items.length) {
      host.append(emptyState("No event activity", "There are no imported event timestamps in this scope yet."));
      return;
    }
    const width = 640, height = 180, pad = { l: 42, r: 12, t: 12, b: 34 };
    const max = Math.max(1, ...items.map((item) => item.count));
    const svg = document.createElementNS(svgNs, "svg");
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
    const points = items.map((item, index) => ({
      x: pad.l + index * (width - pad.l - pad.r) / Math.max(1, items.length - 1),
      y: pad.t + (height - pad.t - pad.b) * (1 - item.count / max),
      item,
    }));
    for (let i = 0; i < 3; i += 1) {
      const y = pad.t + i * (height - pad.t - pad.b) / 2;
      const line = document.createElementNS(svgNs, "line");
      line.setAttribute("x1", pad.l); line.setAttribute("x2", width - pad.r);
      line.setAttribute("y1", y); line.setAttribute("y2", y); line.setAttribute("class", "chart-grid");
      svg.append(line);
      const tick = document.createElementNS(svgNs, "text");
      tick.setAttribute("x", pad.l - 8); tick.setAttribute("y", y + 4); tick.setAttribute("text-anchor", "end");
      tick.setAttribute("class", "chart-label"); tick.textContent = String(Math.round(max * (1 - i / 2)));
      svg.append(tick);
    }
    const path = document.createElementNS(svgNs, "path");
    path.setAttribute("d", points.map((point, index) => `${index ? "L" : "M"}${point.x},${point.y}`).join(" "));
    path.setAttribute("class", "chart-line"); svg.append(path);
    points.forEach((point, index) => {
      const circle = document.createElementNS(svgNs, "circle");
      circle.setAttribute("cx", point.x); circle.setAttribute("cy", point.y); circle.setAttribute("r", "3.5");
      circle.setAttribute("class", "chart-point");
      const title = document.createElementNS(svgNs, "title");
      title.textContent = `${point.item.period}: ${point.item.count} events`;
      circle.append(title); svg.append(circle);
      if (index === 0 || index === points.length - 1 || index % Math.ceil(points.length / 5) === 0) {
        const text = document.createElementNS(svgNs, "text");
        text.setAttribute("x", point.x); text.setAttribute("y", height - 8); text.setAttribute("text-anchor", "middle");
        text.setAttribute("class", "chart-label"); text.textContent = String(point.item.period).slice(5, 13);
        svg.append(text);
      }
    });
    host.append(svg);
  }

  function renderBars(host, items, options = {}) {
    host.replaceChildren();
    if (!items.length) {
      host.append(node("p", "muted-text", "No events recorded."));
      return;
    }
    const rows = options.limit ? items.slice(0, options.limit) : items;
    const max = Math.max(1, ...rows.map((item) => Number(item.count)));
    rows.forEach((item) => {
      const row = node("div", "bar-row");
      row.setAttribute("aria-label", `${item.label}: ${formatNumber(item.count)}`);
      const label = node("span", "bar-label", item.label);
      label.title = item.label;
      const track = node("span", "bar-track");
      const fill = node("span", `bar-fill ${options.severity ? `severity-${item.label}` : ""}`);
      fill.style.width = `${Math.max(1, Number(item.count) / max * 100)}%`;
      track.append(fill);
      row.append(label, track, node("span", "bar-value", formatNumber(item.count)));
      host.append(row);
    });
  }

  async function loadOverview() {
    const data = await api(scoped("/api/overview"));
    const host = $("overview-content");
    host.replaceChildren();
    const origins = data.provenance_distribution || [];
    $("overview-synthetic-note").textContent = origins.length === 1 && origins[0].label === "synthetic"
      ? "All displayed events are synthetic"
      : origins.length ? origins.map((item) => `${item.label}: ${formatNumber(item.count)}`).join(" · ") : "No event provenance recorded";
    if (!data.total_events) {
      host.append(emptyState("No imported events", "Import a JSONL, JSON, or CSV file into a selected dataset to populate operational metrics.", "Open Dataset Library", "#datasets"));
      return;
    }
    const metrics = node("div", "metric-strip");
    metrics.append(
      metric("Imported events", data.total_events, state.datasetId ? state.datasetId : "All available datasets"),
      metric("Critical + high", data.critical_high_events, "Stored event severity"),
      metric("Investigations", data.investigations.total, `${data.investigations.completed} completed · ${data.investigations.in_progress} in progress`),
      metric("Pending approvals", data.pending_approvals, "Awaiting a final analyst decision"),
    );
    host.append(metrics);
    const grid = node("div", "analysis-grid");
    const activityPanel = node("section", "panel");
    const activityHead = node("div", "panel-heading");
    const titleGroup = node("div");
    titleGroup.append(node("h2", "", "Event activity"), node("span", "panel-subtitle", "Stored events grouped by UTC hour"));
    activityHead.replaceChildren(titleGroup);
    const activityChart = node("div", "chart-wrap");
    renderLineChart(activityChart, data.event_activity, "Stored security events per hour in UTC");
    activityPanel.append(activityHead, activityChart);
    const severityPanel = node("section", "panel");
    const severityHead = node("div", "panel-heading");
    const severityTitle = node("div");
    severityTitle.append(node("h2", "", "Severity distribution"), node("span", "panel-subtitle", "Counts from original events"));
    severityHead.append(severityTitle);
    const severityBars = node("div", "bar-list"); renderBars(severityBars, data.severity_distribution, { severity: true });
    severityPanel.append(severityHead, severityBars);
    grid.append(activityPanel, severityPanel); host.append(grid);

    const categoryPanel = node("section", "panel section-block");
    const categoryHead = node("div", "panel-heading");
    const categoryTitle = node("div"); categoryTitle.append(node("h2", "", "Events by source category"), node("span", "panel-subtitle", "Grouped from normalized event categories"));
    categoryHead.append(categoryTitle);
    const categoryBars = node("div", "bar-list"); renderBars(categoryBars, data.category_distribution, { limit: 10 });
    categoryPanel.append(categoryHead, categoryBars); host.append(categoryPanel);

    const recentSection = node("section", "section-block");
    const recentHead = node("div", "section-block-heading"); recentHead.append(node("h2", "", "Recent investigations"));
    const invLink = node("a", "text-link", "View investigations"); invLink.href = "#investigations"; recentHead.append(invLink);
    recentSection.append(recentHead);
    recentSection.append(renderSimpleTable(
      ["Investigation ID", "Dataset", "Started", "Status", "Findings", "Proposals"],
      data.recent_investigations.map((item) => [
        node("span", "mono", item.investigation_id), item.dataset_id, formatDate(item.started_at), status(item.status),
        item.summary?.finding_count ?? "—", item.summary?.proposal_count ?? "—",
      ]),
      "No investigations have been started.",
    )); host.append(recentSection);

    const findingSection = node("section", "section-block");
    const findingHead = node("div", "section-block-heading"); findingHead.append(node("h2", "", "Recent findings"));
    const findingLink = node("a", "text-link", "View all findings"); findingLink.href = "#findings"; findingHead.append(findingLink);
    findingSection.append(findingHead);
    findingSection.append(renderSimpleTable(
      ["Severity", "Finding", "Dataset", "Event ID", "Confidence"],
      data.recent_findings.map((item) => [severity(item.severity), item.title, item.dataset_id, node("span", "mono", item.event_id), `${Math.round(item.confidence * 100)}%`]),
      "No findings are recorded.",
    )); host.append(findingSection);
  }

  function renderSimpleTable(headers, rows, emptyMessage) {
    if (!rows.length) return emptyState("No records", emptyMessage);
    const wrap = node("div", "table-scroll");
    const table = document.createElement("table");
    const caption = node("caption", "sr-only", "Security operations records");
    const thead = document.createElement("thead"), tr = document.createElement("tr");
    headers.forEach((label) => { const th = node("th", "", label); th.scope = "col"; tr.append(th); });
    thead.append(tr); table.append(caption, thead);
    const tbody = document.createElement("tbody");
    rows.forEach((row) => tbody.append(buildTableRow(row)));
    table.append(tbody); wrap.append(table); return wrap;
  }

  async function loadDatasets() {
    const result = await api("/api/datasets");
    state.datasets = result.datasets || [];
    const rows = $("dataset-rows"); rows.replaceChildren();
    if (!state.datasets.length) {
      rows.append(buildTableRow(["No datasets", "—", "—", "0", "—", "unavailable", "—", "—"]));
      return;
    }
    state.datasets.forEach((dataset) => {
      const datasetCell = node("div"); datasetCell.append(node("strong", "", dataset.name), node("span", "subtext mono", dataset.dataset_id));
      const sourceCell = node("div", "source-list", (dataset.source_categories || []).join(", "));
      const severityCell = node("span", "subtext", (dataset.severity_distribution || []).map((item) => `${item.label}: ${item.count}`).join(" · ") || "No stored events");
      const checksum = node("span", "mono", dataset.checksum_sha256 ? `${dataset.checksum_sha256.slice(0, 14)}…` : "—");
      if (dataset.checksum_sha256) checksum.title = dataset.checksum_sha256;
      const action = node("button", "button button-secondary", state.datasetId === dataset.dataset_id ? "Selected" : "Select");
      action.type = "button"; action.setAttribute("aria-pressed", String(state.datasetId === dataset.dataset_id));
      action.addEventListener("click", () => setDataset(dataset.dataset_id));
      rows.append(buildTableRow([
        datasetCell, dataset.provenance?.origin || "—", sourceCell, formatNumber(dataset.event_count), severityCell,
        status(dataset.validation_status), checksum, action,
      ]));
    });
    $("dataset-library-status").textContent = `${state.datasets.length} datasets available · select one before importing or investigating`;
    const selected = state.datasets.find((dataset) => dataset.dataset_id === state.datasetId);
    if (selected) showSelectedDataset(selected);
    else { $("selected-dataset-panel").hidden = true; $("dataset-events-panel").hidden = true; }
  }

  function showSelectedDataset(dataset) {
    const panel = $("selected-dataset-panel"); panel.hidden = false; panel.replaceChildren();
    const title = node("h2", "", dataset.name);
    panel.append(title, node("p", "muted-text", dataset.description || ""));
    const fields = node("dl", "data-grid");
    addDataField(fields, "Dataset ID", node("span", "mono", dataset.dataset_id));
    addDataField(fields, "Provenance", dataset.provenance?.origin || "unknown");
    addDataField(fields, "Source categories", (dataset.source_categories || []).join(", "));
    addDataField(fields, "Stored event count", formatNumber(dataset.event_count));
    addDataField(fields, "Severity counts", (dataset.severity_distribution || []).map((item) => `${item.label} ${item.count}`).join(" · ") || "No events");
    addDataField(fields, "Created", formatDate(dataset.created_at));
    addDataField(fields, "Last import", `${dataset.import_status} · ${formatDate(dataset.last_import_at)}`);
    addDataField(fields, "Validation", dataset.validation_message || dataset.validation_status);
    addDataField(fields, "SHA-256", node("span", "mono", dataset.checksum_sha256 || "Not available"));
    panel.append(fields);
    const controls = node("div", "action-bar");
    const actorLabel = node("label", "filter-row", "Analyst");
    const actor = node("input"); actor.type = "text"; actor.maxLength = 128; actor.placeholder = "Name required to start"; actor.setAttribute("aria-label", "Analyst name");
    actorLabel.append(actor);
    const start = node("button", "button button-primary", "Start Investigation"); start.type = "button";
    start.append(icon("player-play"));
    start.addEventListener("click", () => startInvestigation(actor.value, actor));
    controls.append(actorLabel, start); panel.append(controls);
    loadDatasetEvents(dataset.dataset_id);
  }

  function addDataField(parent, label, value) {
    const wrapper = node("div", "data-field"); wrapper.append(node("dt", "", label));
    const dd = node("dd"); if (value instanceof Node) dd.append(value); else dd.textContent = String(value ?? "—");
    wrapper.append(dd); parent.append(wrapper);
  }

  async function loadDatasetEvents(datasetId) {
    const panel = $("dataset-events-panel"); panel.hidden = false; panel.replaceChildren();
    const heading = node("div", "section-block-heading"); heading.append(node("h2", "", "Original event sample"));
    const search = node("input"); search.type = "search"; search.placeholder = "Search event text"; search.setAttribute("aria-label", "Search dataset event text");
    const severityFilter = node("select"); severityFilter.setAttribute("aria-label", "Filter events by severity");
    ["All severities", "critical", "high", "medium", "low", "informational"].forEach((value, index) => severityFilter.add(new Option(value, index ? value : "")));
    const searchButton = node("button", "button button-secondary", "Search"); searchButton.type = "button";
    const controls = node("div", "filter-row"); controls.append(search, severityFilter, searchButton);
    const tableHost = node("div");
    const render = async () => {
      tableHost.replaceChildren(node("p", "loading-text", "Searching selected dataset…"));
      const params = new URLSearchParams({ limit: "25", offset: String(state.eventOffset) });
      if (search.value.trim()) params.set("q", search.value.trim());
      if (severityFilter.value) params.set("severity", severityFilter.value);
      try {
        const data = await api(`/api/datasets/${encodeURIComponent(datasetId)}/events?${params}`);
        const rows = data.events.map((event) => [severity(event.event?.severity), node("span", "mono", event.event_id), formatDate(event.event_time), event.source?.type, event.host?.hostname || "—", event.message || "—"]);
        tableHost.replaceChildren(renderSimpleTable(["Severity", "Event ID", "Event time", "Source", "Host", "Message"], rows, "No matching events."));
        const page = node("div", "filter-row");
        page.append(node("span", "muted-text", `${data.total} matching events`));
        const prev = node("button", "button button-secondary", "Previous"); prev.type = "button"; prev.disabled = state.eventOffset === 0;
        prev.addEventListener("click", () => { state.eventOffset = Math.max(0, state.eventOffset - 25); render(); });
        const next = node("button", "button button-secondary", "Next"); next.type = "button"; next.disabled = state.eventOffset + 25 >= data.total;
        next.addEventListener("click", () => { state.eventOffset += 25; render(); });
        page.append(prev, next); tableHost.append(page);
      } catch (error) { tableHost.replaceChildren(emptyState("Event search failed", error.message)); }
    };
    searchButton.addEventListener("click", () => { state.eventOffset = 0; render(); });
    search.addEventListener("keydown", (event) => { if (event.key === "Enter") { state.eventOffset = 0; render(); } });
    severityFilter.addEventListener("change", () => { state.eventOffset = 0; render(); });
    heading.append(node("span", "muted-text", "Search is scoped to the selected dataset")); panel.append(heading, controls, tableHost); render();
  }

  async function importDatasetFile(file) {
    if (!state.datasetId) { showNotice("Select one dataset before importing a file.", "error"); return; }
    $("dataset-library-status").textContent = `Importing ${file.name} into ${state.datasetId}…`;
    try {
      const data = await api(`/api/datasets/${encodeURIComponent(state.datasetId)}/ingestions?filename=${encodeURIComponent(file.name)}`, {
        method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file,
      });
      showNotice(`Import complete: ${formatNumber(data.accepted_count)} accepted, ${formatNumber(data.duplicate_count)} duplicates, ${formatNumber(data.rejected_count)} quarantined.`, data.rejected_count ? "" : "success");
      await loadDatasets();
    } catch (error) { showNotice(`Import failed: ${error.message}`, "error"); }
    finally { $("dataset-file").value = ""; }
  }

  async function startInvestigation(analystName, input) {
    if (!state.datasetId) { showNotice("Select one dataset first.", "error"); return; }
    const datasetIdAtStart = state.datasetId;
    const actor = String(analystName || "").trim();
    if (!actor) { input?.focus(); showNotice("Enter the analyst name before starting an investigation.", "error"); return; }
    const statusPanel = $("investigation-run-status"); statusPanel.hidden = false;
    statusPanel.replaceChildren(node("strong", "", "Creating investigation…"));
    try {
      const created = await api(`/api/datasets/${encodeURIComponent(datasetIdAtStart)}/investigations`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ requested_by: actor }),
      });
      state.activeInvestigationId = created.investigation_id;
      setPage("investigations");
      renderProgress(statusPanel, { status: "in_progress", agents: { threat_investigator: "running", threat_hunter: "waiting", response_planner: "waiting" } }, created.investigation_id);
      const runPromise = api(`/api/investigations/${encodeURIComponent(created.investigation_id)}/run`, { method: "POST" });
      await pollInvestigation(created.investigation_id, statusPanel, datasetIdAtStart);
      await runPromise;
      showNotice(`Investigation ${created.investigation_id} completed.`, "success");
      await loadInvestigations();
    } catch (error) {
      statusPanel.append(node("p", "error-text", `Investigation did not complete: ${error.message}`));
      showNotice(`Investigation failed: ${error.message}`, "error");
      await loadInvestigations().catch(() => {});
    }
  }

  async function pollInvestigation(investigationId, panel, datasetId) {
    for (let attempt = 0; attempt < 300; attempt += 1) {
      const response = await api(`/api/investigations?dataset_id=${encodeURIComponent(datasetId)}&limit=100`);
      const item = response.investigations.find((entry) => entry.investigation_id === investigationId);
      if (item) renderProgress(panel, item, investigationId);
      if (item?.status === "completed") return;
      if (item?.status === "failed") throw new Error(item.summary?.error || `Failed during ${item.summary?.failed_stage || "an agent stage"}`);
      await new Promise((resolve) => window.setTimeout(resolve, 600));
    }
    throw new Error("Timed out waiting for the investigation status.");
  }

  function renderProgress(panel, investigation, investigationId) {
    panel.replaceChildren(node("strong", "", `Investigation ${investigationId}`), node("span", "status", investigation.status.replaceAll("_", " ")));
    const steps = node("div", "agent-progress");
    [["Threat Investigator", "threat_investigator"], ["Threat Hunter", "threat_hunter"], ["Response Planner", "response_planner"]].forEach(([label, key]) => {
      const step = node("div", "agent-step"); step.append(node("strong", "", label), node("span", "", investigation.agents?.[key] || "waiting")); steps.append(step);
    });
    panel.append(steps);
    if (investigation.summary) panel.append(node("p", "muted-text", `${formatNumber(investigation.summary.scanned_event_count)} events scanned · ${formatNumber(investigation.summary.finding_count)} findings · ${formatNumber(investigation.summary.proposal_count)} proposals`));
  }

  async function loadInvestigations() {
    updateInvestigationControl();
    const data = await api(scoped("/api/investigations"));
    const tbody = $("investigation-rows"); tbody.replaceChildren();
    if (!data.investigations.length) {
      tbody.append(buildTableRow(["No investigations have been started", "—", "—", "—", "—", "0", "0"]));
      return;
    }
    data.investigations.forEach((item) => {
      const id = node("button", "text-button mono", item.investigation_id); id.type = "button";
      id.addEventListener("click", () => showInvestigationDetail(item));
      tbody.append(buildTableRow([
        id, item.dataset_id, item.requested_by, formatDate(item.started_at), status(item.status),
        item.summary?.finding_count ?? "—", item.summary?.proposal_count ?? "—",
      ]));
    });
    const active = data.investigations.find((item) => item.investigation_id === state.activeInvestigationId);
    if (active) showInvestigationDetail(active);
  }

  async function showInvestigationDetail(item) {
    const panel = $("investigation-detail"); panel.hidden = false; panel.replaceChildren();
    panel.append(node("h2", "", "Investigation workspace"));
    const meta = node("dl", "data-grid");
    addDataField(meta, "Investigation ID", node("span", "mono", item.investigation_id));
    addDataField(meta, "Selected dataset", item.dataset_id);
    addDataField(meta, "Status", status(item.status));
    addDataField(meta, "Started", formatDate(item.started_at));
    addDataField(meta, "Summary", item.summary ? `${item.summary.scanned_event_count} events · ${item.summary.finding_count} findings · ${item.summary.proposal_count} proposals` : "Summary not available yet");
    panel.append(meta);
    const progress = node("div", "agent-progress");
    [["Threat Investigator", "threat_investigator"], ["Threat Hunter", "threat_hunter"], ["Response Planner", "response_planner"]].forEach(([label, key]) => {
      const row = node("div", "agent-step"); row.append(node("strong", "", label), status(item.agents?.[key] || "waiting")); progress.append(row);
    });
    panel.append(progress);
    if (item.summary?.error) panel.append(node("p", "error-text", `${item.summary.failed_stage || "Agent stage"}: ${item.summary.error}`));
    const findings = await api(`/api/findings?investigation_id=${encodeURIComponent(item.investigation_id)}&limit=50`);
    panel.append(renderFindingsDetail(findings.findings));
  }

  function renderFindingsDetail(findings) {
    const section = node("section", "section-block"); section.append(node("h3", "", "Findings and cited events"));
    if (!findings.length) { section.append(node("p", "muted-text", "No findings recorded for this investigation.")); return section; }
    findings.forEach((finding) => {
      const details = document.createElement("details"); details.className = "finding-detail";
      const summary = document.createElement("summary"); summary.append(severity(finding.severity), document.createTextNode(` ${finding.title} · ${Math.round(finding.confidence * 100)}% confidence`));
      details.append(summary);
      const body = node("div", "finding-evidence");
      body.append(node("p", "", finding.explanation));
      body.append(node("p", "muted-text", `Agent assessment is a hypothesis. Original evidence is event ${finding.event_id}.`));
      const threat = finding.evidence_event?.threat || {};
      body.append(node("p", "", `MITRE ATT&CK: ${threat.tactic || "Not mapped"}${threat.technique_id ? ` · ${threat.technique_id}` : ""}`));
      body.append(node("p", "muted-text", "Potential root cause: Not asserted by the current mock provider."));
      const pre = node("pre", "json-view", JSON.stringify(finding.evidence_event, null, 2));
      body.append(node("h4", "", "Original event evidence"), pre);
      details.append(body); section.append(details);
    });
    return section;
  }

  async function loadFindings() {
    const params = new URLSearchParams({ limit: "500" });
    if (state.datasetId) params.set("dataset_id", state.datasetId);
    const severityFilter = $("finding-severity").value;
    const search = $("finding-search").value.toLowerCase().trim();
    const data = await api(`/api/findings?${params}`);
    const findings = data.findings.filter((item) => (!severityFilter || item.severity === severityFilter) && (!search || [item.title, item.event_id, item.evidence_event?.host?.hostname, item.explanation].join(" ").toLowerCase().includes(search)));
    const tbody = $("finding-rows"); tbody.replaceChildren();
    if (!findings.length) { tbody.append(buildTableRow(["No matching findings", "—", "—", "—", "—", "—"])); return; }
    findings.forEach((finding) => {
      const title = node("details", "finding-table-detail");
      const sum = document.createElement("summary"); sum.textContent = finding.title;
      title.append(sum, node("p", "muted-text", finding.explanation));
      const details = node("pre", "json-view", JSON.stringify(finding.evidence_event, null, 2)); title.append(details);
      tbody.append(buildTableRow([severity(finding.severity), title, finding.dataset_id, node("span", "mono", finding.event_id), `${Math.round(finding.confidence * 100)}%`, formatDate(finding.created_at)]));
    });
  }

  async function loadApprovals() {
    const data = await api(scoped("/api/proposals?limit=500"));
    const filter = $("approval-filter").value;
    let proposals = data.proposals;
    if (filter === "pending") proposals = proposals.filter((item) => !["approved", "denied"].includes(item.policy_status));
    if (filter === "approved" || filter === "denied") proposals = proposals.filter((item) => item.policy_status === filter);
    const host = $("approval-list"); host.replaceChildren();
    if (!proposals.length) { host.append(emptyState("No proposals in this view", filter === "pending" ? "No response proposals are awaiting a decision." : "No proposals match this status.")); return; }
    proposals.forEach((proposal) => host.append(renderProposal(proposal)));
  }

  function renderProposal(proposal) {
    const details = document.createElement("details"); details.className = "approval-item"; details.open = proposal.proposal_id === state.expandedProposalId;
    details.addEventListener("toggle", () => { if (details.open) { state.expandedProposalId = proposal.proposal_id; } });
    const summary = document.createElement("summary"); summary.className = "approval-summary";
    const left = node("div"); left.append(node("h2", "", proposal.action_type.replaceAll("_", " ")), node("span", "subtext", `${proposal.parameters.target_type}: ${proposal.parameters.target_value}`));
    const right = node("div"); right.append(status(proposal.policy_status));
    summary.append(left, right); details.append(summary);
    const body = node("div", "approval-body");
    const evidence = proposal.evidence_event || {};
    const metadata = node("dl", "data-grid");
    addDataField(metadata, "Dataset / investigation", `${proposal.dataset_id} · ${proposal.investigation_id}`);
    addDataField(metadata, "Finding", `${proposal.finding_id} · ${proposal.title || ""}`);
    addDataField(metadata, "Severity / confidence", `${proposal.severity || "unknown"} · ${Math.round((proposal.confidence || 0) * 100)}%`);
    addDataField(metadata, "Affected simulated asset", `${proposal.parameters.target_type}: ${proposal.parameters.target_value}`);
    addDataField(metadata, "Supporting event", node("span", "mono", proposal.event_id || "Not linked"));
    addDataField(metadata, "Risk assessment", `${proposal.severity || "Unknown"} finding; policy requires evidence, confidence, and severity checks.`);
    addDataField(metadata, "Expected impact", "Simulation only: a separate processed-event snapshot may be marked resolved; no endpoint is contacted.");
    addDataField(metadata, "Remediation steps", `${proposal.action_type.replaceAll("_", " ")} for the evidenced ${proposal.parameters.target_type}.`);
    addDataField(metadata, "Verification procedure", "After simulation, inspect the execution result and compare processed and original event snapshots.");
    addDataField(metadata, "Rollback procedure", "No real system changes occur in simulation, so no endpoint rollback is required.");
    body.append(metadata, node("p", "", `Planner rationale: ${proposal.rationale}`));
    const evidenceDetails = document.createElement("details");
    const evidenceSummary = document.createElement("summary"); evidenceSummary.textContent = "Inspect supporting original event";
    evidenceDetails.append(evidenceSummary, node("pre", "json-view", JSON.stringify(evidence, null, 2))); body.append(evidenceDetails);

    const historyButton = node("button", "button button-secondary", "View approval history"); historyButton.type = "button";
    const historyHost = node("div", "approval-history"); historyHost.hidden = true;
    historyButton.addEventListener("click", async () => {
      historyButton.disabled = true;
      try {
        const history = await api(`/api/proposals/${encodeURIComponent(proposal.proposal_id)}/approvals`);
        historyHost.replaceChildren();
        if (!history.approvals.length) historyHost.append(node("p", "muted-text", "No human decision has been recorded."));
        history.approvals.forEach((record) => {
          const entry = node("p", "approval-history-entry");
          entry.append(node("span", "", `${record.decision} by ${record.reviewer} · ${formatDate(record.decided_at)}`));
          if (record.comment) entry.append(node("span", "subtext", record.comment));
          if (record.modified_parameters) entry.append(node("pre", "json-view", JSON.stringify(record.modified_parameters, null, 2)));
          historyHost.append(entry);
        });
        historyHost.hidden = false;
      } catch (error) { showNotice(`Could not load approval history: ${error.message}`, "error"); }
      finally { historyButton.disabled = false; }
    });
    body.append(historyButton, historyHost);

    if (proposal.policy_status === "approved") {
      const approvalId = proposal.latest_decision === "approved" ? proposal.approval_id : "";
      const executePanel = node("div", "execution-confirm");
      executePanel.append(node("p", "muted-text", "This action will write a simulation record only. Confirm before sending the approved proposal to the local simulation worker."));
      const checkLabel = node("label", "confirm-label"); const checkbox = node("input"); checkbox.type = "checkbox";
      checkLabel.append(checkbox, document.createTextNode(" I confirm this simulation"));
      const execute = node("button", "button button-primary", "Run simulation"); execute.type = "button"; execute.disabled = !approvalId;
      checkbox.addEventListener("change", () => { execute.disabled = !checkbox.checked || !approvalId; });
      execute.addEventListener("click", () => executeProposal(proposal.proposal_id, approvalId, execute));
      executePanel.append(checkLabel, execute);
      if (proposal.execution_id) {
        const link = node("a", "text-link", `Execution result: ${proposal.execution_status}`); link.href = `#processed`; executePanel.append(link);
      }
      body.append(executePanel);
      details.append(body); return details;
    }
    if (proposal.policy_status === "denied") {
      body.append(node("p", "muted-text", "This proposal was denied. It cannot be executed.")); details.append(body); return details;
    }

    const policyArea = node("div", "policy-area");
    const checkButton = node("button", "button button-secondary", "Validate proposal against policy"); checkButton.type = "button";
    const resultBox = node("div", "policy-result"); resultBox.hidden = true;
    checkButton.addEventListener("click", async () => {
      checkButton.disabled = true;
      try {
        const result = await api(`/api/proposals/${encodeURIComponent(proposal.proposal_id)}`);
        resultBox.hidden = false; resultBox.className = `policy-result ${result.policy.allowed ? "allowed" : "rejected"}`;
        resultBox.textContent = `Policy ${result.policy.allowed ? "allowed" : "rejected"}: ${result.policy.reason} (v${result.policy.policy_version})`;
      } catch (error) { resultBox.hidden = false; resultBox.className = "policy-result rejected"; resultBox.textContent = error.message; }
      finally { checkButton.disabled = false; }
    });
    policyArea.append(checkButton, resultBox); body.append(policyArea);

    const form = node("form", "approval-review-form");
    const reviewerLabel = node("label", "", "Reviewer name"); const reviewer = node("input"); reviewer.required = true; reviewer.maxLength = 128; reviewer.placeholder = "Enter your name"; reviewerLabel.append(reviewer);
    const commentLabel = node("label", "", "Review comment"); const comment = node("input"); comment.maxLength = 2000; comment.placeholder = "Optional context"; commentLabel.append(comment);
    form.append(reviewerLabel, commentLabel);
    const modifyBox = node("div", "modify-box wide");
    const actionLabel = node("label", "", "Proposed action"); const action = node("select");
    [["isolate_host","Isolate host"],["disable_account","Disable account"],["block_ip","Block IP"],["monitor","Monitor"]].forEach(([value,label]) => action.add(new Option(label,value)));
    action.value = proposal.action_type; actionLabel.append(action);
    const typeLabel = node("label", "", "Target type"); const type = node("select");
    [["host","Host"],["account","Account"],["ip","IP address"]].forEach(([value,label]) => type.add(new Option(label,value)));
    type.value = proposal.parameters.target_type; typeLabel.append(type);
    const valueLabel = node("label", "", "Target value"); const value = node("input"); value.value = proposal.parameters.target_value; value.maxLength = 256; valueLabel.append(value);
    modifyBox.append(actionLabel, typeLabel, valueLabel);
    const decisionActions = node("div", "decision-actions");
    const approve = node("button", "button button-primary", "Approve"); approve.type = "button";
    const deny = node("button", "button button-danger", "Deny"); deny.type = "button";
    const modify = node("button", "button button-secondary", "Save modification"); modify.type = "button";
    approve.addEventListener("click", () => submitDecision(proposal.proposal_id, "approved", reviewer.value, comment.value, {}, approve));
    deny.addEventListener("click", () => submitDecision(proposal.proposal_id, "denied", reviewer.value, comment.value, {}, deny));
    modify.addEventListener("click", () => submitDecision(proposal.proposal_id, "modified", reviewer.value, comment.value, { action_type: action.value, target_type: type.value, target_value: value.value }, modify));
    decisionActions.append(approve, deny, modify);
    form.append(modifyBox, decisionActions);
    body.append(form); details.append(body); return details;
  }

  async function submitDecision(proposalId, decision, reviewer, comment, changes, button) {
    if (!reviewer.trim()) { showNotice("Enter the reviewer name before recording a decision.", "error"); return; }
    button.disabled = true;
    try {
      const body = { decision, reviewer: reviewer.trim(), comment: comment.trim(), ...changes };
      await api(`/api/proposals/${encodeURIComponent(proposalId)}/decisions`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      showNotice(`Proposal decision recorded: ${decision}.`, "success"); await loadApprovals();
    } catch (error) { showNotice(`Decision was not recorded: ${error.message}`, "error"); }
    finally { button.disabled = false; }
  }

  async function executeProposal(proposalId, approvalId, button) {
    if (!approvalId) { showNotice("A final approved record is required before simulation.", "error"); return; }
    button.disabled = true; button.textContent = "Submitting simulation…";
    try {
      const idempotencyKey = crypto.randomUUID();
      const execution = await api(`/api/proposals/${encodeURIComponent(proposalId)}/executions`, {
        method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
        body: JSON.stringify({ approval_id: approvalId }),
      });
      showNotice(`Backend confirmed simulation ${execution.status}.`, "success"); await loadApprovals();
    } catch (error) { button.textContent = "Run simulation"; button.disabled = false; showNotice(`Simulation failed: ${error.message}`, "error"); }
  }

  async function loadProcessed() {
    const data = await api(scoped("/api/processed-events?limit=500"));
    const tbody = $("processed-rows"); tbody.replaceChildren();
    if (!data.processed_events.length) { tbody.append(buildTableRow(["No processed event records", "—", "—", "—", "—", "—", "—"])); return; }
    data.processed_events.forEach((item) => {
      const compare = node("button", "button button-secondary", "Compare"); compare.type = "button";
      compare.addEventListener("click", () => showComparison(item));
      tbody.append(buildTableRow([
        node("span", "mono", item.processed_event_id), node("span", "mono", item.original_event_id),
        node("span", "mono", item.investigation_id), item.approval_id || "—",
        `${item.execution_id || "—"}${item.mode ? ` · ${item.mode}` : ""}`, `${item.approval_status || "—"}${item.approval_id ? ` · ${item.approval_id}` : ""}`, status(item.status), compare,
      ]));
    });
  }

  function showComparison(item) {
    const panel = $("comparison-panel"); panel.hidden = false; panel.replaceChildren();
    panel.append(node("h2", "", "Original versus processed snapshot"));
    panel.append(node("p", "muted-text", `Execution ${item.execution_id} · ${item.status} · Original event ${item.original_event_id}`));
    const grid = node("div", "comparison-grid");
    const before = node("section", "comparison-pane"); before.append(node("h3", "", "Original event (immutable)"), node("pre", "json-view", JSON.stringify(item.before_state, null, 2)));
    const after = node("section", "comparison-pane"); after.append(node("h3", "", "Processed simulation snapshot"), node("pre", "json-view", JSON.stringify(item.after_state, null, 2)));
    grid.append(before, after); panel.append(grid); panel.scrollIntoView({ block: "nearest" });
  }

  async function loadAudit() {
    const data = await api(scoped("/api/audit?limit=500"));
    const tbody = $("audit-rows"); tbody.replaceChildren();
    if (!data.events.length) { tbody.append(buildTableRow(["No audit events recorded", "—", "—", "—", "—", "—"])); return; }
    data.events.forEach((item) => {
      const details = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "View details";
      let value = item.details; try { value = JSON.stringify(JSON.parse(item.details), null, 2); } catch { value = String(item.details); }
      details.append(summary, node("pre", "json-view", value));
      tbody.append(buildTableRow([node("span", "mono", formatDate(item.occurred_at)), item.action, item.actor, item.dataset_id || "—", `${item.resource_type} · ${item.resource_id || "—"}`, details]));
    });
  }

  async function loadReports() {
    const data = await api(scoped("/api/reports/summary"));
    const host = $("report-content"); host.replaceChildren();
    const overview = data.overview;
    const summary = node("div", "metric-strip");
    summary.append(metric("Events", overview.total_events, state.datasetId || "All datasets"), metric("Critical + high", overview.critical_high_events, "Stored severity"), metric("Findings", overview.total_findings, "Recorded agent findings"), metric("Pending approvals", overview.pending_approvals, "Current proposal state"));
    host.append(summary);
    host.append(node("p", "muted-text", `Report generated ${formatDate(data.generated_at)}. Ground-truth evaluation: ${data.ground_truth_evaluation_available ? "available" : data.ground_truth_evaluation_note}`));
    const grid = node("div", "analysis-grid");
    const sev = node("section", "panel"); const head = node("div", "panel-heading"); const title = node("div"); title.append(node("h2", "", "Severity statistics"), node("span", "panel-subtitle", "Database event counts")); head.append(title); const bars=node("div","bar-list");renderBars(bars,overview.severity_distribution,{severity:true});sev.append(head,bars);
    const cats=node("section","panel");const ch=node("div","panel-heading");const ct=node("div");ct.append(node("h2","","Source categories"),node("span","panel-subtitle","Database event counts"));ch.append(ct);const cb=node("div","bar-list");renderBars(cb,overview.category_distribution,{limit:10});cats.append(ch,cb);grid.append(sev,cats);host.append(grid);
    const agentRows = data.agent_performance.map((item) => [item.agent_name, formatNumber(item.findings), item.avg_confidence === null ? "—" : `${Math.round(item.avg_confidence * 100)}%`]);
    const section=node("section","section-block");section.append(node("h2","","Agent performance (recorded findings)"));section.append(renderSimpleTable(["Agent", "Findings", "Average confidence"],agentRows,"No agent findings are recorded."));host.append(section);
    const executionRows=data.remediation_executions.map((item)=>[item.label,formatNumber(item.count)]);const executionSection=node("section","section-block");executionSection.append(node("h2","","Simulation results"));executionSection.append(renderSimpleTable(["Outcome", "Count"],executionRows,"No simulation executions are recorded."));host.append(executionSection);
    if (data.ground_truth_evaluation_available && data.ground_truth_evaluation) {
      const evaluation = data.ground_truth_evaluation;
      const evaluationSection = node("section", "section-block");
      evaluationSection.append(node("h2", "", "Ground-truth evaluation (aggregate only)"));
      evaluationSection.append(renderSimpleTable(
        ["Metric", "Value"],
        [["Evaluated events", formatNumber(evaluation.evaluated_events)], ["Detection accuracy", `${(evaluation.detection_accuracy * 100).toFixed(1)}%`], ["Precision", evaluation.precision === null ? "—" : `${(evaluation.precision * 100).toFixed(1)}%`], ["Recall", evaluation.recall === null ? "—" : `${(evaluation.recall * 100).toFixed(1)}%`]],
        "No aggregate evaluation metrics are available.",
      ));
      evaluationSection.append(node("p", "muted-text", "Ground-truth event labels remain hidden; this section displays aggregate metrics only."));
      host.append(evaluationSection);
    }
    const jsonLink=$("export-json"),csvLink=$("export-csv");
    const suffix=state.datasetId?`&dataset_id=${encodeURIComponent(state.datasetId)}`:"";
    jsonLink.href=`/api/reports/export?format=json${suffix}`;csvLink.href=`/api/reports/export?format=csv${suffix}`;
  }

  async function loadSettings() {
    const data = await api("/api/settings");
    const host = $("settings-content"); host.replaceChildren();
    const panel=node("section","panel");const heading=node("div","panel-heading");const title=node("div");title.append(node("h2","","Application configuration"),node("span","panel-subtitle","Secrets are not returned by this endpoint"));heading.append(title);const fields=node("dl","data-grid");
    addDataField(fields,"Application version",data.application_version);addDataField(fields,"Storage",data.storage);addDataField(fields,"Database file",data.database_file);addDataField(fields,"Database size",`${formatNumber(data.database_size_bytes)} bytes`);addDataField(fields,"Datasets",formatNumber(data.dataset_count));addDataField(fields,"Stored events",formatNumber(data.event_count));addDataField(fields,"AI provider",data.ai_provider);addDataField(fields,"API credentials",data.api_credentials_configured?"Configured (value hidden)":"Not configured");addDataField(fields,"Dataset scope",state.datasetId||"All datasets");addDataField(fields,"Theme preference",document.documentElement.dataset.theme);panel.append(heading,fields);host.append(panel);
    const datasetSection=node("section","section-block");datasetSection.append(node("h2","","Dataset configuration"));
    const datasetRows=(data.available_datasets||[]).map((item)=>[item.name,node("span","mono",item.dataset_id),item.provenance,formatNumber(item.event_count)]);
    datasetSection.append(renderSimpleTable(["Dataset","ID","Provenance","Manifest events"],datasetRows,"No dataset manifests are available."));host.append(datasetSection);
  }

  async function refreshFooter() {
    try { const settings=await api("/api/settings"); $("footer-version").textContent=`Version ${settings.application_version} · ${settings.storage}`; }
    catch { $("footer-version").textContent="Local API unavailable"; }
  }

  function setupControls() {
    document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", (event) => { event.preventDefault(); setPage(link.dataset.page); }));
    $("global-dataset").addEventListener("change", (event) => setDataset(event.target.value));
    $("theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.dataset.theme;
      setTheme(current === "dark" ? "plum" : current === "plum" ? "light" : "dark");
    });
    $("sidebar-collapse").addEventListener("click", () => {
      document.body.classList.toggle("collapsed");
      const expanded = !document.body.classList.contains("collapsed");
      $("sidebar-collapse").setAttribute("aria-expanded", String(expanded));
      $("sidebar-collapse").setAttribute("aria-label", expanded ? "Collapse sidebar" : "Expand sidebar");
      $("sidebar-collapse").title = expanded ? "Collapse sidebar" : "Expand sidebar";
      localStorage.setItem("sop-sidebar-collapsed", String(!expanded));
    });
    $("mobile-menu").addEventListener("click", () => { document.body.classList.toggle("mobile-nav-open"); $("mobile-menu").setAttribute("aria-expanded", String(document.body.classList.contains("mobile-nav-open"))); });
    $("start-investigation").addEventListener("click", () => startInvestigation($("investigator-name").value, $("investigator-name")));
    $("dataset-file").addEventListener("change", (event) => { const [file] = event.target.files || []; if (file) importDatasetFile(file); });
    $("dataset-file").parentElement.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); $("dataset-file").click(); } });
    $("finding-severity").addEventListener("change", () => loadFindings().catch((error) => showNotice(error.message,"error")));
    $("finding-search").addEventListener("input", debounce(() => loadFindings().catch((error) => showNotice(error.message,"error")), 180));
    $("approval-filter").addEventListener("change", () => loadApprovals().catch((error) => showNotice(error.message,"error")));
    document.addEventListener("keydown", (event) => { if (event.key === "Escape") { document.body.classList.remove("mobile-nav-open"); $("mobile-menu").setAttribute("aria-expanded", "false"); } });
    window.addEventListener("hashchange", () => {
      const requestedPage = location.hash.replace(/^#/, "");
      if (document.getElementById(`page-${requestedPage}`)) setPage(requestedPage);
    });
  }

  function debounce(callback, wait) {
    let timer;
    return (...args) => { window.clearTimeout(timer); timer=window.setTimeout(() => callback(...args),wait); };
  }

  async function init() {
    setTheme(localStorage.getItem("sop-theme") || "dark");
    if (localStorage.getItem("sop-sidebar-collapsed") === "true") document.body.classList.add("collapsed");
    setupControls();
    await initializeDatasets();
    await refreshFooter();
    const requestedPage = location.hash.replace(/^#/, "");
    const allowedPages = new Set(["overview","datasets","investigations","findings","approvals","processed","audit","reports","settings"]);
    setPage(allowedPages.has(requestedPage) ? requestedPage : "overview");
    if (location.protocol === "file:") {
      showNotice("Static preview only. For live data and actions, start the local app with python -m uvicorn backend.api:app --host 127.0.0.1, then open http://127.0.0.1:8000/.", "error");
    }
  }

  init();
})();
