// Log Threat Analyzer - browser side.
// Talks to the API only (docs/DESIGN.md, section 5). Never builds HTML from data:
// every value from the server (e.g. a filename) is inserted with textContent,
// so a file named "<script>..." is shown as text and never runs (prevents XSS).
"use strict";

const $ = (id) => document.getElementById(id);

// ---------- talking to the API ----------

async function api(path, options = {}) {
  const response = await fetch(path, options);
  let body = null;
  try {
    body = await response.json();
  } catch {
    // no JSON body
  }
  if (!response.ok) {
    throw new Error(errorMessage(response.status, body));
  }
  return { status: response.status, body };
}

function errorMessage(status, body) {
  if (body && typeof body.detail === "string") {
    return body.detail;
  }
  if (body && Array.isArray(body.detail)) {
    // 422 validation errors from FastAPI: [{loc: [...], msg: "..."}]
    return body.detail.map((d) => `${d.loc[d.loc.length - 1]}: ${d.msg}`).join("; ");
  }
  return `Request failed (HTTP ${status})`;
}

// ---------- dates and times ----------

// ISO 8601 with the browser's own offset, e.g. "2026-11-12T00:00:00+02:00",
// so "12 November" means 12 November where the user is, not in UTC.
function isoWithOffset(date) {
  const pad = (n) => String(Math.abs(n)).padStart(2, "0");
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? "+" : "-";
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}` +
    `${sign}${pad(Math.trunc(offsetMinutes / 60))}:${pad(offsetMinutes % 60)}`;
}

// The server sends UTC ("...Z"); show it in the user's local time.
function localTime(isoUtc) {
  return new Date(isoUtc).toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
}

// ---------- small DOM helpers (textContent only) ----------

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  td.dir = "auto";   // a Hebrew filename is shown right-to-left
  if (className) td.className = className;
  return td;
}

function badge(text, className) {
  const span = document.createElement("span");
  span.className = `badge ${className}`;
  span.textContent = text;
  return span;
}

function setMessage(element, text, kind = "") {
  element.textContent = text;
  element.className = `message ${kind}`.trim();
}

// ---------- lists of analyses (history and search) ----------

function renderRuns(tbody, messageElement, runs, emptyText) {
  tbody.replaceChildren();
  setMessage(messageElement, runs.length === 0 ? emptyText : "");

  for (const run of runs) {
    const row = document.createElement("tr");
    row.dataset.runId = run.id;

    const statusCell = document.createElement("td");
    statusCell.append(badge(run.status, run.status));

    const actionCell = document.createElement("td");
    const viewButton = document.createElement("button");
    viewButton.type = "button";
    viewButton.className = "link";
    viewButton.textContent = "View";
    viewButton.addEventListener("click", () => showRun(run.id));
    actionCell.append(viewButton);

    row.append(
      cell(localTime(run.created_at)),
      cell(run.filename, "filename"),
      statusCell,
      cell(run.lines_parsed ?? "-"),
      cell(run.alert_count),
      actionCell,
    );
    tbody.append(row);
  }
}

async function loadHistory() {
  try {
    // no parameters -> the server returns the last 2 days (decision D15)
    const { body } = await api("/api/analyses");
    renderRuns($("history-rows"), $("history-message"), body, "No analyses in the last 2 days.");
  } catch (error) {
    setMessage($("history-message"), error.message, "error");
  }
}

async function searchByDate(event) {
  event.preventDefault();
  const value = $("search-date").value;            // "YYYY-MM-DD"
  if (!value) return;

  const [year, month, day] = value.split("-").map(Number);
  const from = new Date(year, month - 1, day);     // local midnight
  const to = new Date(year, month - 1, day + 1);   // next local midnight (end is exclusive)
  const params = new URLSearchParams({ from: isoWithOffset(from), to: isoWithOffset(to) });  // encodes "+" as %2B

  setMessage($("search-message"), "Searching...");
  try {
    const { body } = await api(`/api/analyses?${params}`);
    renderRuns($("search-rows"), $("search-message"), body,
      `No analyses on ${from.toLocaleDateString()}.`);
  } catch (error) {
    $("search-rows").replaceChildren();
    setMessage($("search-message"), error.message, "error");
  }
}

// ---------- details of one analysis ----------

function renderDetails(run, alerts) {
  const summary = $("details-summary");
  summary.replaceChildren();
  const add = (label, value) => {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    if (value instanceof Node) dd.append(value); else dd.textContent = value;
    summary.append(dt, dd);
  };
  add("File", run.filename);
  add("Analyzed", localTime(run.created_at));
  add("Status", badge(run.status, run.status));
  add("Log lines recognized", run.lines_parsed ?? "-");
  add("Settings", `window ${run.settings.time_window_seconds}s, ` +
    `brute force ≥ ${run.settings.brute_force_threshold}, scanning ≥ ${run.settings.scanning_threshold}`);
  if (run.error_message) add("Error", run.error_message);

  const tbody = $("alert-rows");
  tbody.replaceChildren();
  for (const alert of alerts) {
    const typeCell = document.createElement("td");
    typeCell.append(badge(alert.threat_type, "threat"));
    const row = document.createElement("tr");
    row.append(typeCell, cell(alert.ip_address), cell(localTime(alert.detected_at)), cell(alert.details));
    tbody.append(row);
  }

  if (run.status === "failed") {
    setMessage($("details-message"), "This analysis failed, so it has no results.", "error");
  } else if (alerts.length === 0) {
    setMessage($("details-message"), "No threats found: the log was read and nothing suspicious was detected.");
  } else {
    setMessage($("details-message"), `${alerts.length} alert(s).`);
  }

  for (const row of document.querySelectorAll("tr[data-run-id]")) {
    row.classList.toggle("selected", row.dataset.runId === String(run.id));
  }
  $("details").hidden = false;
}

async function showRun(runId) {
  setMessage($("details-message"), "Loading...");
  $("details").hidden = false;
  try {
    const [run, alerts] = await Promise.all([
      api(`/api/analyses/${runId}`),
      api(`/api/analyses/${runId}/alerts`),
    ]);
    renderDetails(run.body, alerts.body);
    $("details").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setMessage($("details-message"), error.message, "error");
  }
}

// ---------- upload ----------

async function uploadFile(event) {
  event.preventDefault();
  const file = $("file").files[0];
  if (!file) {
    setMessage($("upload-message"), "Choose a log file first.", "error");
    return;
  }

  const form = new FormData();
  form.append("file", file);
  for (const name of ["time_window_seconds", "brute_force_threshold", "scanning_threshold"]) {
    form.append(name, $(name).value);
  }

  const button = $("upload-button");
  button.disabled = true;
  setMessage($("upload-message"), `Analyzing ${file.name}...`);
  try {
    const { body } = await api("/api/analyses", { method: "POST", body: form });
    if (body.reused) {
      setMessage($("upload-message"),
        `This file was already analyzed with the same settings on ${localTime(body.created_at)}. ` +
        "Showing the saved result.", "notice");
    } else {
      setMessage($("upload-message"),
        `Done: ${body.lines_parsed} log lines, ${body.alert_count} alert(s).`);
    }
    renderDetails(body, body.alerts);
    $("details").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setMessage($("upload-message"), error.message, "error");
  } finally {
    button.disabled = false;
    loadHistory();   // a new run, or a failed one, appears in the history
  }
}

// ---------- start ----------

document.addEventListener("DOMContentLoaded", () => {
  $("upload-form").addEventListener("submit", uploadFile);
  $("search-form").addEventListener("submit", searchByDate);
  $("refresh-history").addEventListener("click", loadHistory);
  $("search-date").value = isoWithOffset(new Date()).slice(0, 10);   // today, local
  loadHistory();
});
