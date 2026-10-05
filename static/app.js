"use strict";

const TOKEN = document.querySelector('meta[name="ds-token"]').content;
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];

const CATEGORIES = {
  downloads: "Downloads & installers",
  duplicates: "Duplicates",
  caches: "Caches & temp files",
  dev: "Developer leftovers",
  ai: "AI models",
  system: "Windows & drivers",
  appdata: "Unrecognised app data",
  large: "Large files",
  bin: "Recycle Bin",
};
const GROUPS = [
  ["safe", "Safe to clean", "Caches, leftovers and copies — removing these can't lose anything you need."],
  ["review", "Worth a look", "Probably junk, but glance at the list before removing it."],
  ["keep", "Leave these alone", "Big, but deleting them would break something or lose data."],
];
const ACTIONS = {
  recycle: "🗑️ Goes to the Recycle Bin — you can restore it",
  delete: "⚡ Deleted permanently — it's rebuilt or re-downloaded when needed",
  delete_contents: "🧹 Emptied — apps rebuild their caches automatically",
  ollama_rm: "🧠 Removed through Ollama — `ollama pull` brings it back",
  empty_bin: "🗑️ Empties the Recycle Bin — permanent",
  disk_cleanup: "🪟 Windows handles these — DiskSage opens Disk Cleanup for you",
  none: "ℹ️ Nothing to clean here — just so you know",
};
const CONFIRM_LABELS = {
  recycle: "Move to the Recycle Bin",
  delete: "Delete permanently (rebuilt / re-downloaded when needed)",
  delete_contents: "Empty caches and temp folders",
  ollama_rm: "Remove Ollama models",
  empty_bin: "Empty the Recycle Bin (permanent)",
};
const CLEANABLE = new Set(Object.keys(CONFIRM_LABELS));

// ---------------------------------------------------------------- helpers

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function fmtSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n >= 100 || i < 2 ? Math.round(n) : n.toFixed(1)} ${units[i]}`;
}

function plural(n, word) {
  return `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;
}

/** Escaped text with `code`, **bold**, and simple bullet / numbered lists. */
function richText(text) {
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  const out = [];
  let list = null;
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    const bullet = line.match(/^[-*•]\s+(.*)/);
    const numbered = line.match(/^\d+[.)]\s+(.*)/);
    const kind = bullet ? "ul" : numbered ? "ol" : null;
    if (kind) {
      if (list !== kind) { if (list) out.push(`</${list}>`); out.push(`<${kind}>`); list = kind; }
      out.push(`<li>${inline((bullet || numbered)[1])}</li>`);
      continue;
    }
    if (list) { out.push(`</${list}>`); list = null; }
    if (line) out.push(`<p>${inline(line.replace(/^#+\s*/, ""))}</p>`);
  }
  if (list) out.push(`</${list}>`);
  return out.join("");
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { "X-DiskSage-Token": TOKEN };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

let toastTimer;
function toast(message, kind = "") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast ${kind}`;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.hidden = true), kind === "error" ? 6000 : 3500);
}

// ---------------------------------------------------------------- tabs

$$(".tab").forEach((tab) =>
  tab.addEventListener("click", () => {
    $$(".tab").forEach((t) => t.classList.toggle("active", t === tab));
    $$(".tabpanel").forEach((p) => (p.hidden = p.id !== `tab-${tab.dataset.tab}`));
    if (tab.dataset.tab === "apps" && !appsState.loaded) loadApps();
    if (tab.dataset.tab === "ask") $("#chatInput").focus();
  })
);

// ---------------------------------------------------------------- status + drives

function renderDrives(drives) {
  $("#drives").innerHTML = drives
    .map((d) => {
      const pct = d.total ? Math.round((d.used / d.total) * 100) : 0;
      return `<div class="card drive">
        <div class="drive-head"><strong>${esc(d.name)} drive</strong><span class="muted">${fmtSize(d.free)} free of ${fmtSize(d.total)}</span></div>
        <div class="bar"><div class="bar-fill ${pct > 90 ? "hot" : ""}" style="width:${pct}%"></div></div>
      </div>`;
    })
    .join("");
}

async function loadStatus() {
  try {
    const s = await api("/api/status");
    renderDrives(s.drives);
    const warn = $("#ollamaWarning");
    if (!s.ollama) {
      warn.innerHTML = "<strong>Ollama isn't running.</strong> The scan still works, but the AI explanations need it — start the Ollama app and scan again.";
      warn.hidden = false;
    } else if (!s.model_ready) {
      warn.innerHTML = `<strong>The model isn't downloaded yet.</strong> Run <code>ollama pull ${esc(s.model)}</code> to get AI explanations.`;
      warn.hidden = false;
    } else {
      warn.hidden = true;
    }
  } catch (err) {
    toast(err.message, "error");
  }
}

// ---------------------------------------------------------------- scan

const scan = {
  data: null,        // latest snapshot (findings kept from the last full one)
  version: -1,
  renderedVersion: -1,
  selection: new Map(), // finding id -> Set(item index)
  open: new Set(),
  timer: null,
};

async function startScan() {
  scan.selection.clear();
  scan.open.clear();
  $("#cleanResult").hidden = true;
  try {
    applySnapshot(await api("/api/scan", { method: "POST" }));
    poll();
  } catch (err) {
    toast(err.message, "error");
  }
}

function poll() {
  clearTimeout(scan.timer);
  const phase = scan.data?.phase;
  if (phase !== "scanning" && phase !== "analyzing") return;
  scan.timer = setTimeout(async () => {
    try {
      applySnapshot(await api(`/api/scan?since=${scan.version}`));
    } catch (err) {
      toast(err.message, "error");
    }
    poll();
  }, phase === "analyzing" ? 1500 : 500);
}

function applySnapshot(snap) {
  if (snap.findings === null && scan.data) snap.findings = scan.data.findings;
  scan.data = snap;
  scan.version = snap.version;
  renderScan();
}

function findingById(id) {
  return scan.data?.findings?.find((f) => f.id === id);
}

function renderScan() {
  const s = scan.data;
  const phase = s?.phase || "idle";
  $("#scanIntro").hidden = phase !== "idle";
  $("#progress").hidden = phase !== "scanning";
  $("#results").hidden = !(phase === "analyzing" || phase === "done");

  if (phase === "scanning") {
    $("#progressStep").textContent = s.step || "Starting…";
    $("#progressBar").style.width = `${Math.round((s.step_index / s.steps.length) * 100)}%`;
    $("#progressSteps").innerHTML = s.steps
      .map((label, i) => `<li class="${i < s.step_index ? "done" : i === s.step_index ? "current" : "todo"}">${esc(label)}</li>`)
      .join("");
    return;
  }
  if (phase === "idle") return;

  $("#safeTotal").textContent = fmtSize(s.totals.safe);
  $("#reviewTotal").textContent = fmtSize(s.totals.review);
  renderAI(s);
  $("#scanNotes").innerHTML = (s.notes || []).map((n) => `<li>${esc(n)}</li>`).join("") +
    (s.errors || []).map((e) => `<li>Skipped a check: ${esc(e)}</li>`).join("");

  if (scan.renderedVersion !== scan.version) {
    renderGroups();
    scan.renderedVersion = scan.version;
  }
  updateActionBar();
}

function renderAI(s) {
  const box = $("#aiSummary");
  const ai = s.ai;
  const count = s.findings?.length || 0;
  box.className = "ai-summary";
  if (ai.status === "running") {
    box.classList.add("pending");
    box.innerHTML = `<div class="ai-label"><span class="spinner" style="width:14px;height:14px;border-width:2px"></span> Local AI is reviewing</div>
      Scanned in ${s.scan_seconds}s. ${esc(document.querySelector("#modelBadge").textContent)} is now reading all ${count} findings on your GPU — explanations appear in a moment. You can already start picking.`;
  } else if (ai.status === "done") {
    box.innerHTML = `<div class="ai-label">AI review · ${esc($("#modelBadge").textContent)} · ${ai.seconds} s on this PC</div>
      <p>${esc(ai.summary)}</p>${ai.top_tip ? `<p class="tip">👉 ${esc(ai.top_tip)}</p>` : ""}`;
  } else if (ai.status === "error") {
    box.classList.add("error");
    box.innerHTML = `<div class="ai-label">AI review unavailable</div><p>${esc(ai.error)}</p>
      <p class="muted">The scan results below still work — they just use the scanner's own explanations.</p>`;
  } else {
    box.innerHTML = count ? "" : "<p>Nothing worth cleaning was found. Nice and tidy!</p>";
  }
}

const selectable = (f, item) => CLEANABLE.has(f.action) && !item.removed && !item.blocked;

function itemRow(f, item, sel) {
  const age = item.age_days != null ? ` · ${item.age_days} days old` : "";
  const aiPill = item.ai_verdict ? `<span class="pill ${item.ai_verdict}">AI: ${item.ai_verdict}</span> ` : "";
  const notes = [
    item.note && `<span class="scan-note">${esc(item.note)}</span>`,
    item.ai_note && `<span class="ai-note">${aiPill}${aiPill ? "" : "AI: "}${esc(item.ai_note)}</span>`,
    item.blocked && `<span class="blocked-note">⛔ ${esc(item.blocked)}</span>`,
  ].filter(Boolean).join(" · ");
  return `<li class="${item.removed ? "removed" : ""}">
    ${selectable(f, item) ? `<input type="checkbox" class="item-check" data-idx="${item.index}" ${sel.has(item.index) ? "checked" : ""} aria-label="Select">` : '<span class="check-spacer"></span>'}
    <div class="item-main">
      <div class="item-path">${esc(item.path)}</div>
      ${notes || age ? `<div class="item-note">${notes}${notes ? "" : age.slice(3)}</div>` : ""}
    </div>
    <span class="item-size">${item.removed ? "done" : fmtSize(item.size)}</span>
  </li>`;
}

function findingCard(f) {
  const sel = scan.selection.get(f.id) || new Set();
  const live = f.items.filter((i) => !i.removed);
  const cleanable = f.items.some((i) => selectable(f, i));
  const aiPending = scan.data.ai.status === "running" || (f.kind === "unrecognized" && scan.data.ai.identify === "running");
  const open = scan.open.has(f.id);
  const reason = f.ai_reason || f.detail;
  const tags = [];
  if (f.ai_reason) tags.push('<span class="pill ai" title="Explained by the local AI">AI</span>');
  else if (aiPending) tags.push('<span class="pill ai pending">AI…</span>');
  if (f.verdict !== f.scanner_verdict) tags.push(`<span class="pill ${f.verdict}" title="The AI asked for more caution">AI: be careful</span>`);
  if (!live.length) tags.push('<span class="pill safe">Cleaned ✓</span>');

  const shown = f.items.slice(0, 300);
  const hiddenCount = f.total_items - shown.length;
  return `<article class="card finding v-${f.verdict} ${open ? "open" : ""} ${live.length ? "" : "done"}" data-id="${esc(f.id)}">
    <div class="finding-head">
      ${cleanable ? `<input type="checkbox" class="finding-check" aria-label="Select all">` : '<span class="check-spacer"></span>'}
      <div class="finding-main">
        <div class="finding-title"><h3>${esc(f.title)}</h3>${tags.join("")}</div>
        <div class="cat">${esc(CATEGORIES[f.category] || f.category)}</div>
        <p class="reason">${esc(reason)}</p>
      </div>
      <div class="finding-size"><strong>${fmtSize(f.size)}</strong><small>${plural(live.length, "item")}</small></div>
      <span class="chev">▸</span>
    </div>
    <div class="finding-body" ${open ? "" : "hidden"}>
      ${f.ai_reason ? `<p class="scanner-note">Scanner: ${esc(f.detail)}</p>` : ""}
      <p class="action-note">${richText(ACTIONS[f.action] || "")}</p>
      ${f.action === "disk_cleanup" ? '<div><button class="btn small disk-cleanup-btn">Open Disk Cleanup</button></div>' : ""}
      <ul class="items">${shown.map((item) => itemRow(f, item, sel)).join("")}</ul>
      ${hiddenCount > 0 ? `<div class="more">…and ${plural(hiddenCount, "more item")} (included when you select the whole group)</div>` : ""}
    </div>
  </article>`;
}

function renderGroups() {
  const findings = scan.data.findings || [];
  $("#groups").innerHTML = GROUPS.map(([verdict, title, blurb]) => {
    const list = findings.filter((f) => f.verdict === verdict);
    if (!list.length) return "";
    const size = list.reduce((sum, f) => sum + f.cleanable_size, 0);
    return `<section class="group group-${verdict}">
      <div class="group-head"><h2>${title}</h2>${size ? `<span class="group-size">${fmtSize(size)}</span>` : ""}<p>${blurb}</p></div>
      ${list.map(findingCard).join("")}
    </section>`;
  }).join("");
  syncCheckboxes();
}

function syncCheckboxes() {
  for (const card of $$(".finding")) {
    const f = findingById(card.dataset.id);
    const box = $(".finding-check", card);
    if (!f || !box) continue;
    const sel = scan.selection.get(f.id) || new Set();
    const live = f.items.filter((i) => selectable(f, i));
    const count = live.filter((i) => sel.has(i.index)).length;
    box.checked = count > 0 && count === live.length;
    box.indeterminate = count > 0 && count < live.length;
    $$(".item-check", card).forEach((c) => (c.checked = sel.has(Number(c.dataset.idx))));
  }
}

function selectAll(f, on) {
  if (!on) { scan.selection.delete(f.id); return; }
  // Includes items beyond the 300 shown — the server knows them by index.
  const all = new Set();
  for (let i = 0; i < f.total_items; i++) {
    const item = f.items[i];
    if (!item || selectable(f, item)) all.add(i);
  }
  scan.selection.set(f.id, all);
}

$("#groups").addEventListener("click", async (e) => {
  const card = e.target.closest(".finding");
  if (!card) return;
  if (e.target.closest(".disk-cleanup-btn")) {
    try { await api("/api/disk-cleanup", { method: "POST" }); toast("Disk Cleanup is opening — choose “Clean up system files”."); }
    catch (err) { toast(err.message, "error"); }
    return;
  }
  if (e.target.closest("input")) return;
  if (!e.target.closest(".finding-head")) return;
  const id = card.dataset.id;
  const open = !scan.open.has(id);
  open ? scan.open.add(id) : scan.open.delete(id);
  card.classList.toggle("open", open);
  $(".finding-body", card).hidden = !open;
});

$("#groups").addEventListener("change", (e) => {
  const card = e.target.closest(".finding");
  const f = card && findingById(card.dataset.id);
  if (!f) return;
  if (e.target.classList.contains("finding-check")) {
    selectAll(f, e.target.checked);
  } else if (e.target.classList.contains("item-check")) {
    const sel = scan.selection.get(f.id) || new Set();
    const idx = Number(e.target.dataset.idx);
    e.target.checked ? sel.add(idx) : sel.delete(idx);
    scan.selection.set(f.id, sel);
  }
  syncCheckboxes();
  updateActionBar();
});

function selectionSummary() {
  const byAction = {};
  let bytes = 0;
  let count = 0;
  let risky = 0;
  for (const [id, sel] of scan.selection) {
    const f = findingById(id);
    if (!f || !sel.size) continue;
    for (const idx of sel) {
      const item = f.items[idx];
      if (item?.removed) continue;
      const size = item ? item.size : f.size / Math.max(f.count, 1);
      const a = (byAction[f.action] ||= { count: 0, bytes: 0 });
      a.count++;
      a.bytes += size;
      bytes += size;
      count++;
      if (f.verdict !== "safe") risky++;
    }
  }
  return { byAction, bytes, count, risky };
}

function updateActionBar() {
  const { bytes, count } = selectionSummary();
  $("#actionBar").hidden = count === 0;
  $("#selectionSize").textContent = fmtSize(bytes);
  $("#selectionCount").textContent = `selected · ${plural(count, "item")}`;
}

$("#selectSafeBtn").addEventListener("click", () => {
  for (const f of scan.data?.findings || []) {
    if (f.verdict === "safe" && f.cleanable_size) selectAll(f, true);
  }
  syncCheckboxes();
  updateActionBar();
});

$("#clearSelBtn").addEventListener("click", () => {
  scan.selection.clear();
  syncCheckboxes();
  updateActionBar();
});

$("#cleanBtn").addEventListener("click", () => {
  const { byAction, bytes, risky } = selectionSummary();
  const rows = Object.entries(byAction)
    .map(([action, a]) => `<li><span>${esc(CONFIRM_LABELS[action])} · ${plural(a.count, "item")}</span><strong>${fmtSize(a.bytes)}</strong></li>`)
    .join("");
  $("#confirmBody").innerHTML = `
    <ul class="confirm-list">${rows}</ul>
    ${risky ? `<div class="confirm-warn">⚠️ ${plural(risky, "item")} you picked ${risky === 1 ? "is" : "are"} marked “worth a look” or “leave alone”. Make sure you've checked ${risky === 1 ? "it" : "them"}.</div>` : ""}
    <p class="muted">About ${fmtSize(bytes)} in total. Files that are open in a program are skipped. Close your browsers and apps first to clear their caches completely.</p>`;
  $("#confirmDialog").showModal();
});

$("#confirmCancel").addEventListener("click", () => $("#confirmDialog").close());

$("#confirmOk").addEventListener("click", async () => {
  const btn = $("#confirmOk");
  btn.disabled = true;
  btn.textContent = "Cleaning…";
  const selections = [...scan.selection]
    .filter(([, sel]) => sel.size)
    .map(([finding_id, sel]) => ({ finding_id, items: [...sel] }));
  try {
    const res = await api("/api/clean", { method: "POST", body: { selections } });
    $("#confirmDialog").close();
    scan.selection.clear();
    applySnapshot(res.scan);
    renderDrives(res.drives);
    showCleanResult(res.report, res.recycle_bin);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Clean up";
  }
});

function showCleanResult(report, bin) {
  const card = $("#cleanResult");
  const parts = [];
  if (report.freed) parts.push(`<strong>${fmtSize(report.freed)}</strong> freed`);
  if (report.recycled) parts.push(`<strong>${fmtSize(report.recycled)}</strong> moved to the Recycle Bin`);
  const failures = report.failed.map((f) => `<li><code>${esc(f.path)}</code> — ${esc(f.error)}</li>`).join("");
  card.innerHTML = `
    <h3>${parts.length ? `Done! ${parts.join(" and ")}.` : "Nothing was removed."}</h3>
    ${report.recycled ? `<div class="row"><span class="muted">Recycle Bin space only comes back once the bin is emptied.</span>
      <button class="btn small" id="emptyBinBtn">Empty Recycle Bin (${fmtSize(bin.size)})</button></div>` : ""}
    ${report.in_use ? `<p class="muted">${plural(report.in_use, "file")} were in use and skipped — close the app and clean again to get those too.</p>` : ""}
    ${report.failed_count ? `<details><summary>${plural(report.failed_count, "item")} couldn't be removed</summary><ul>${failures}</ul></details>` : ""}`;
  card.hidden = false;
  card.scrollIntoView({ behavior: "smooth", block: "start" });
  $("#emptyBinBtn")?.addEventListener("click", emptyBin);
}

async function emptyBin() {
  if (!confirm("Empty the Recycle Bin? Everything in it is deleted permanently.")) return;
  try {
    const res = await api("/api/recycle-bin/empty", { method: "POST" });
    renderDrives(res.drives);
    toast(res.ok ? `Recycle Bin emptied — ${fmtSize(res.freed)} freed.` : "Windows couldn't empty the Recycle Bin.", res.ok ? "" : "error");
    $("#emptyBinBtn")?.remove();
  } catch (err) {
    toast(err.message, "error");
  }
}

$("#scanBtn").addEventListener("click", startScan);
$("#rescanBtn").addEventListener("click", startScan);

// ---------------------------------------------------------------- remove an app

const appsState = { loaded: false, list: [], current: null, selection: new Set() };

async function loadApps() {
  try {
    const data = await api("/api/apps");
    appsState.list = data.apps;
    appsState.loaded = true;
    renderAppList();
  } catch (err) {
    $("#appsList").innerHTML = `<p class="muted pad">${esc(err.message)}</p>`;
  }
}

function renderAppList() {
  const q = $("#appSearch").value.trim().toLowerCase();
  const list = appsState.list.filter((a) => !q || `${a.name} ${a.publisher}`.toLowerCase().includes(q));
  const currentId = appsState.current?.app.id;
  $("#appsList").innerHTML = list.length
    ? list.map((a) => `<button class="app-row ${a.id === currentId ? "active" : ""}" data-id="${esc(a.id)}">
        <span><span class="name">${esc(a.name)}</span><br><span class="sub">${esc([a.publisher, a.version].filter(Boolean).join(" · "))}</span></span>
        <span class="size">${a.size ? fmtSize(a.size) : ""}</span>
      </button>`).join("")
    : `<p class="muted pad">No apps match “${esc(q)}”.</p>`;
}

$("#appSearch").addEventListener("input", renderAppList);
$("#appsList").addEventListener("click", (e) => {
  const row = e.target.closest(".app-row");
  if (row) openApp(row.dataset.id);
});

async function openApp(id, keepAdvice = false) {
  const app = appsState.list.find((a) => a.id === id) || appsState.current?.app;
  const previous = appsState.current;
  appsState.selection.clear();
  if (!keepAdvice) {
    appsState.current = { app, installed: true, leftovers: null, advice: null };
    renderAppList();
    renderAppDetail();
  }
  try {
    const data = await api(`/api/apps/${id}/leftovers`, { method: "POST" });
    appsState.current = { ...data, advice: keepAdvice && previous ? previous.advice : "loading" };
    renderAppList();
    renderAppDetail();
    if (keepAdvice && previous?.advice && previous.advice !== "loading") return;
    try {
      const advice = await api(`/api/apps/${id}/advice`, { method: "POST" });
      if (appsState.current?.app.id === id) { appsState.current.advice = advice; renderAppDetail(); }
    } catch (err) {
      if (appsState.current?.app.id === id) { appsState.current.advice = { error: err.message }; renderAppDetail(); }
    }
  } catch (err) {
    toast(err.message, "error");
  }
}

function renderAdvice(advice) {
  if (!advice) return "";
  if (advice === "loading") {
    return `<div class="advice"><div class="ai-label muted"><span class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:-2px"></span> The local AI is working out the safest way to remove it…</div></div>`;
  }
  if (advice.error) return `<div class="notice warn">AI advice unavailable: ${esc(advice.error)}</div>`;
  return `<div class="advice">
    <p>${esc(advice.summary)}</p>
    ${advice.steps.length ? `<ol>${advice.steps.map((s) => `<li>${richText(s).replace(/^<p>|<\/p>$/g, "")}</li>`).join("")}</ol>` : ""}
    ${advice.shared_note ? `<p class="shared">🔗 ${esc(advice.shared_note)}</p>` : ""}
  </div>`;
}

function renderAppDetail() {
  const box = $("#appDetail");
  const cur = appsState.current;
  if (!cur) return;
  const { app } = cur;
  const meta = [app.publisher, app.version && `v${app.version}`, app.size && fmtSize(app.size), app.install_date && `installed ${app.install_date}`].filter(Boolean).join(" · ");

  let leftoversHtml = '<p class="muted">Looking for everything it keeps on your PC…</p>';
  if (cur.leftovers) {
    const folders = cur.advice && typeof cur.advice === "object" && !cur.advice.error ? cur.advice.folders || {} : {};
    const live = cur.leftovers.filter((l) => !l.removed && !l.protected);
    const selBytes = cur.leftovers.filter((l) => appsState.selection.has(l.index)).reduce((s, l) => s + l.size, 0);
    leftoversHtml = cur.leftovers.length
      ? `<ul class="items">${cur.leftovers.map((l) => {
          const ai = folders[l.index];
          const note = [
            l.protected ? `🔒 ${esc(l.protected)} — the uninstaller takes care of it` : `<span class="scan-note">${esc(l.note)}</span>`,
            ai ? `<span class="ai-note"><span class="pill ${ai.verdict}">${ai.verdict}</span> ${esc(ai.reason)}</span>` : "",
          ].filter(Boolean).join(" · ");
          const canPick = !l.removed && !l.protected;
          return `<li class="${l.removed ? "removed" : ""}">
            ${canPick ? `<input type="checkbox" class="leftover-check" data-idx="${l.index}" ${appsState.selection.has(l.index) ? "checked" : ""}>` : '<span class="check-spacer"></span>'}
            <div class="item-main"><div class="item-path">${esc(l.path)}</div><div class="item-note">${note}</div></div>
            <span class="item-size">${l.removed ? "done" : fmtSize(l.size)}</span>
          </li>`;
        }).join("")}</ul>
        ${live.length ? `<div class="leftover-actions">
          <button class="btn danger small" id="cleanLeftoversBtn" ${appsState.selection.size ? "" : "disabled"}>Move selected to Recycle Bin${selBytes ? ` (${fmtSize(selBytes)})` : ""}</button>
          <span class="muted">Restorable from the Recycle Bin. Registry entries are left alone on purpose.</span>
        </div>` : ""}`
      : '<p class="muted">No leftover folders found — nothing else to clean up for this app.</p>';
  }

  box.innerHTML = `
    <div class="app-header">
      <div>
        <h2>${esc(app.name)}</h2>
        <div class="app-meta">${esc(meta)}</div>
      </div>
      <div class="app-buttons">
        ${cur.installed ? '<button class="btn primary" id="uninstallBtn">Run its uninstaller</button>' : '<span class="pill safe">Uninstalled ✓</span>'}
        <button class="btn" id="recheckBtn">Check again</button>
      </div>
    </div>
    ${renderAdvice(cur.advice)}
    <div class="leftovers">
      <h3>Folders it keeps on your PC</h3>
      ${cur.installed && cur.leftovers?.length ? '<div class="notice warn" style="margin-bottom:8px">Uninstall it first — removing these while the app is installed can reset or break it. Then click “Check again”.</div>' : ""}
      ${leftoversHtml}
    </div>`;
}

$("#appDetail").addEventListener("change", (e) => {
  if (!e.target.classList.contains("leftover-check")) return;
  const idx = Number(e.target.dataset.idx);
  e.target.checked ? appsState.selection.add(idx) : appsState.selection.delete(idx);
  renderAppDetail();
});

$("#appDetail").addEventListener("click", async (e) => {
  const cur = appsState.current;
  if (!cur) return;
  if (e.target.id === "uninstallBtn") {
    if (!confirm(`Open ${cur.app.name}'s own uninstaller?\n\nFollow its steps, then come back and click “Check again” to clean what it leaves behind.`)) return;
    try {
      const res = await api(`/api/apps/${cur.app.id}/uninstall`, { method: "POST" });
      toast(res.ok ? "The uninstaller is open. When it's finished, click “Check again”." : "Windows couldn't start the uninstaller. Try Settings › Apps.", res.ok ? "" : "error");
    } catch (err) {
      toast(err.message, "error");
    }
  } else if (e.target.id === "recheckBtn") {
    openApp(cur.app.id, true);
  } else if (e.target.id === "cleanLeftoversBtn") {
    const items = [...appsState.selection];
    if (!confirm(`Move ${plural(items.length, "folder")} to the Recycle Bin?`)) return;
    try {
      const res = await api(`/api/apps/${cur.app.id}/clean`, { method: "POST", body: { items } });
      cur.leftovers = res.leftovers;
      appsState.selection.clear();
      renderAppDetail();
      const r = res.report;
      toast(r.failed_count ? `${plural(r.done, "folder")} moved, ${r.failed_count} couldn't be: ${r.failed[0].error}` : `Moved ${fmtSize(r.recycled)} to the Recycle Bin.`, r.failed_count ? "error" : "");
    } catch (err) {
      toast(err.message, "error");
    }
  }
});

// ---------------------------------------------------------------- ask

const chat = [];
const SUGGESTIONS = [
  "What's taking up the most space on my PC?",
  "How do I remove an app completely, with everything it leaves behind?",
  "Is it safe to delete the WinSxS folder?",
  "What's the difference between AppData Local and Roaming?",
];

$("#chatSuggestions").innerHTML = SUGGESTIONS.map((s) => `<button class="chip" type="button">${esc(s)}</button>`).join("");
$("#chatSuggestions").addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (chip) { $("#chatInput").value = chip.textContent; sendChat(); }
});

function addMessage(role, html, extraClass = "") {
  const el = document.createElement("div");
  el.className = `msg ${role}`;
  el.innerHTML = `<div class="bubble ${extraClass}">${html}</div>`;
  $("#chatLog").appendChild(el);
  el.scrollIntoView({ behavior: "smooth", block: "end" });
  return el;
}

async function sendChat() {
  const input = $("#chatInput");
  const question = input.value.trim();
  if (!question) return;
  input.value = "";
  $("#chatSend").disabled = true;
  addMessage("user", esc(question));
  const thinking = addMessage("assistant", "Thinking locally…", "thinking");
  try {
    const res = await api("/api/ask", { method: "POST", body: { question, history: chat.slice(-6) } });
    chat.push({ role: "user", content: question }, { role: "assistant", content: res.answer });
    thinking.querySelector(".bubble").className = "bubble";
    thinking.querySelector(".bubble").innerHTML = richText(res.answer);
  } catch (err) {
    thinking.querySelector(".bubble").textContent = `Sorry — ${err.message}`;
  } finally {
    $("#chatSend").disabled = false;
    input.focus();
  }
}

$("#chatForm").addEventListener("submit", (e) => { e.preventDefault(); sendChat(); });
$("#chatInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
});

// ---------------------------------------------------------------- privacy blur (for screenshots)

function setPrivacy(on) {
  document.body.classList.toggle("privacy", on);
  $("#privacyBtn").textContent = on ? "Show file names" : "Blur file names (for screenshots)";
  try { localStorage.setItem("disksage-privacy", on ? "1" : ""); } catch { /* storage unavailable */ }
}
$("#privacyBtn").addEventListener("click", () => setPrivacy(!document.body.classList.contains("privacy")));
try { if (localStorage.getItem("disksage-privacy")) setPrivacy(true); } catch { /* storage unavailable */ }

// ---------------------------------------------------------------- boot

loadStatus();
api("/api/scan").then((snap) => { applySnapshot(snap); poll(); }).catch(() => {});
