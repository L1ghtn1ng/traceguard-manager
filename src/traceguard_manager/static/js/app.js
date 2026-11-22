// TraceGuard Manager client script.
// Server data is only ever written with textContent, never as HTML.

const CSRF_COOKIE = "flasgo-csrf";
// Marks requests the page makes by itself, so they do not count as the person being active.
const BACKGROUND = { "x-tgm-background": "1" };

function csrfToken() {
  const prefix = `${CSRF_COOKIE}=`;
  const entry = document.cookie.split("; ").find((item) => item.startsWith(prefix));
  return entry ? entry.slice(prefix.length) : "";
}

function failure(message, data = {}) {
  const error = new Error(message);
  error.data = data;
  return error;
}

async function call(method, url, body) {
  const headers = { accept: "application/json", "x-csrf-token": csrfToken() };
  const options = { method, headers, credentials: "same-origin", redirect: "error" };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw failure("Could not reach the server. Check your connection and try again.");
  }
  let data = {};
  try {
    data = await response.json();
  } catch {
    // Non-JSON responses fall through to the status handling below.
  }
  if (response.ok) return data;
  // The CSRF token is tied to the session cookie. Once the browser has dropped an expired
  // cookie the token no longer matches, and the refusal is a bare 403 rather than a 401.
  const tokenRefused = response.status === 403 && typeof data.error !== "string";
  if (url !== "/auth/login" && (response.status === 401 || (tokenRefused && (await sessionIsOver())))) {
    if (url === "/auth/logout") return { redirect: "/login" }; // already signed out
    sessionEnded();
    throw failure("Your session has ended. Sign in again to continue.");
  }
  if (tokenRefused) throw failure("This page is out of date. Reload it and try again.");
  if (response.status === 429) throw failure("Too many attempts. Wait a moment and try again.");
  throw failure(typeof data.error === "string" ? data.error : "The request failed. Try again.", data);
}

function readStored(storage, key) {
  try {
    return storage.getItem(key);
  } catch {
    return null; // storage can be blocked; every use of it is optional
  }
}

function writeStored(storage, key, value) {
  try {
    storage.setItem(key, value);
  } catch {
    // See readStored.
  }
}

// ---- ended sessions -------------------------------------------------------

let liveSource = null;
let signedOut = false;

function setLiveState(state, label) {
  const indicator = document.getElementById("live-indicator");
  if (!indicator) return;
  indicator.dataset.state = state;
  indicator.querySelector(".live-label").textContent = label;
}

// Say so and offer the way back, rather than navigating away from a half-written note.
function sessionEnded() {
  if (signedOut) return;
  signedOut = true;
  liveSource?.close();
  const here = window.location.pathname + window.location.search;
  const target = here === "/" ? "/login" : `/login?next=${encodeURIComponent(here)}`;
  const banner = document.getElementById("session-banner");
  if (!banner) {
    window.location.assign(target);
    return;
  }
  banner.querySelector("a").href = target;
  banner.hidden = false;
  setLiveState("ended", "Signed out");
}

async function sessionIsOver() {
  try {
    const response = await fetch("/auth/session", { headers: { accept: "application/json" }, credentials: "same-origin" });
    return response.status === 401;
  } catch {
    return false; // a network failure says nothing about the session
  }
}

// ---- toasts ---------------------------------------------------------------

const TOAST_MS = 8000;

function toast({ title, detail = "", level = "", href = "", error = false }) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const node = document.createElement("div");
  node.className = `toast${error ? " toast-error" : ""}${level ? ` level-${level}` : ""}`;
  const bar = document.createElement("span");
  bar.className = "toast-bar";
  const text = document.createElement(href ? "a" : "span");
  text.className = "toast-body";
  if (href) text.href = href;
  const strong = document.createElement("strong");
  strong.textContent = title;
  text.append(strong);
  if (detail) {
    const small = document.createElement("small");
    small.textContent = detail;
    text.append(small);
  }
  const close = document.createElement("button");
  close.type = "button";
  close.className = "toast-close";
  close.setAttribute("aria-label", "Dismiss");
  close.textContent = "×";
  close.addEventListener("click", () => node.remove());
  node.append(bar, text, close);
  host.append(node);
  while (host.children.length > 4) host.firstElementChild.remove();

  // The countdown stops while the pointer or the keyboard focus is on the toast.
  let timer = window.setTimeout(() => node.remove(), TOAST_MS);
  const hold = () => window.clearTimeout(timer);
  const release = () => {
    hold();
    timer = window.setTimeout(() => node.remove(), TOAST_MS / 2);
  };
  node.addEventListener("mouseenter", hold);
  node.addEventListener("mouseleave", release);
  node.addEventListener("focusin", hold);
  node.addEventListener("focusout", release);
}

// ---- dialogs --------------------------------------------------------------

function confirmAction(message) {
  const dialog = document.getElementById("confirm-dialog");
  if (!dialog) return Promise.resolve(window.confirm(message));
  dialog.querySelector("#confirm-message").textContent = message;
  dialog.returnValue = "cancel";
  dialog.showModal();
  return new Promise((resolve) => {
    dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
  });
}

function showOnly(dialog) {
  document.querySelectorAll("dialog[open]").forEach((open) => open.close());
  dialog.showModal();
}

const CONNECT_POLL_MS = 3000;

// Say when the agent has actually connected with the token, instead of leaving people to guess.
function watchConnection(dialog, agentId) {
  const state = dialog.querySelector("#token-state");
  const text = dialog.querySelector("#token-state-text");
  if (!state || !text || !agentId) return;
  state.dataset.state = "waiting";
  text.textContent = "Waiting for the agent to connect with this token…";
  const timer = window.setInterval(async () => {
    try {
      const response = await fetch(`/agents/${encodeURIComponent(agentId)}/state`, {
        headers: { accept: "application/json", ...BACKGROUND },
        credentials: "same-origin",
      });
      if (!response.ok) return;
      const data = await response.json();
      if (data.connected) {
        state.dataset.state = "connected";
        text.textContent = "Connected. The agent is reporting with this token.";
        window.clearInterval(timer);
      }
    } catch {
      // Try again on the next tick.
    }
  }, CONNECT_POLL_MS);
  dialog.addEventListener("close", () => window.clearInterval(timer), { once: true });
}

function showToken(data) {
  const dialog = document.getElementById("token-dialog");
  if (!dialog) return;
  dialog.querySelector("#token-agent").textContent = data.name;
  dialog.querySelector("#token-snippet").textContent =
    `TRACEGUARD_EVENT_EXPORT_URL=${window.location.origin}/api/v1/events\n` +
    `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer ${data.token}\n` +
    `TRACEGUARD_EVENT_EXPORT_EVENTS=alerts\n` +
    `TRACEGUARD_EVENT_SCHEMA=traceguard\n` +
    `# Optional: take commands from this console (TraceGuard 1.9+)\n` +
    `# TRACEGUARD_COMMAND_URL=${window.location.origin}/api/v1/commands\n` +
    `# Optional: fetch the signed policy assigned here, with the key from Policies\n` +
    `# TRACEGUARD_POLICY_URL=${window.location.origin}/api/v1/policy\n` +
    `# TRACEGUARD_POLICY_AUTHORIZATION=Bearer ${data.token}\n` +
    `# TRACEGUARD_POLICY_SIGNING_KEY=/etc/traceguard/manager-policy.pub`;
  showOnly(dialog);
  watchConnection(dialog, data.id);
}

function showSecret(data) {
  const dialog = document.getElementById("secret-dialog");
  if (!dialog || typeof data.secret !== "string") {
    window.location.reload(); // only signed webhooks have a secret to show
    return;
  }
  dialog.querySelector("#secret-channel").textContent = data.name;
  dialog.querySelector("#secret-value").textContent = data.secret;
  showOnly(dialog);
}

function showRecoveryCodes(data) {
  const dialog = document.getElementById("recovery-dialog");
  if (!dialog || !Array.isArray(data.recovery_codes)) return;
  dialog.querySelector("#recovery-codes").textContent = data.recovery_codes.join("\n");
  // Leaving without saving them would lock the person out later, so Escape does not close this.
  dialog.addEventListener("cancel", (event) => event.preventDefault());
  showOnly(dialog);
}

function finish(then, data, source) {
  switch (then) {
    case "redirect":
      window.location.assign(typeof data.redirect === "string" && data.redirect.startsWith("/") ? data.redirect : "/");
      break;
    case "reload":
      window.location.reload();
      break;
    case "token":
      showToken(data);
      break;
    case "secret":
      showSecret(data);
      break;
    case "recovery":
      showRecoveryCodes(data);
      break;
    case "toast":
      toast({ title: source?.dataset.toast || "Saved." });
      break;
    default:
      break;
  }
}

// ---- forms and action buttons ---------------------------------------------

function formPayload(form, submitter) {
  const payload = {};
  for (const field of form.elements) {
    if (!field.name || field.disabled || field.tagName === "BUTTON") continue;
    if (field.type === "checkbox") payload[field.name] = field.checked;
    else if (field.hasAttribute("data-json-list")) payload[field.name] = [field.value];
    else payload[field.name] = field.value;
  }
  if (submitter?.name) payload[submitter.name] = submitter.value;
  return payload;
}

function showFormError(form, message) {
  const box = form.querySelector(".form-error");
  if (!box) {
    toast({ title: message, error: true });
    return;
  }
  box.textContent = message;
  box.hidden = !message;
}

// The second step of sign-in only appears for accounts that have it turned on.
function askForCode(form, { required = true } = {}) {
  const step = form.querySelector("[data-two-step]");
  const input = step?.querySelector("input");
  if (!step || !input) return false;
  step.hidden = false;
  input.disabled = false;
  input.required = required;
  input.focus();
  input.select();
  form.querySelector("[data-show-two-step]")?.remove();
  return true;
}

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-api]");
  if (!form) return;
  event.preventDefault();
  if (!form.reportValidity()) return;
  if (form.dataset.confirm && !(await confirmAction(form.dataset.confirm))) return;
  const buttons = form.querySelectorAll("button");
  showFormError(form, "");
  buttons.forEach((button) => (button.disabled = true));
  try {
    const data = await call(form.dataset.method || "POST", form.dataset.api, formPayload(form, event.submitter));
    if (form.dataset.reset) form.reset();
    finish(form.dataset.then, data, form);
  } catch (error) {
    showFormError(form, error.message);
    if (!(error.data?.mfa_required && askForCode(form))) form.querySelector('input[type="password"]')?.select();
  } finally {
    buttons.forEach((button) => (button.disabled = false));
  }
});

// ---- bulk selection -------------------------------------------------------

function rowChecks() {
  return [...document.querySelectorAll(".row-check")];
}

function selectedIds() {
  return rowChecks()
    .filter((box) => box.checked)
    .map((box) => box.value);
}

function updateBulk() {
  const bar = document.getElementById("bulk-bar");
  if (!bar) return;
  const boxes = rowChecks();
  const checked = boxes.filter((box) => box.checked).length;
  const total = Number(bar.dataset.total) || 0;
  const whole = checked > 0 && checked === boxes.length;
  if (!whole) delete bar.dataset.all;
  const everything = bar.dataset.all === "1";
  bar.hidden = checked === 0;
  bar.querySelector("#bulk-count").textContent = String(everything ? total : checked);
  const all = bar.querySelector("#bulk-all");
  if (all) all.hidden = !(whole && total > boxes.length && !everything);
  const assign = bar.querySelector("[data-bulk-assign]");
  if (assign) assign.hidden = everything; // ownership is given alert by alert, not by filter
}

async function bulkStatus(status, ids) {
  const bar = document.getElementById("bulk-bar");
  const everything = !ids && bar?.dataset.all === "1";
  const chosen = ids ?? selectedIds();
  if (!everything && !chosen.length) return;
  if (everything && !(await confirmAction(`Mark all ${bar.dataset.total} matching alerts as ${status}?`))) return;
  try {
    await call("POST", "/alerts/status", everything ? { filter: JSON.parse(bar.dataset.filter || "{}"), status } : { ids: chosen, status });
    window.location.reload();
  } catch (error) {
    toast({ title: error.message, error: true });
  }
}

async function bulkAssign(ids) {
  const chosen = ids ?? selectedIds();
  if (!chosen.length) return;
  try {
    await call("POST", "/alerts/assign", { ids: chosen, assignee: "me" });
    window.location.reload();
  } catch (error) {
    toast({ title: error.message, error: true });
  }
}

document.addEventListener("click", async (event) => {
  // A locked account still opens for its password and code given together.
  const twoStep = event.target.closest("[data-show-two-step]");
  if (twoStep) {
    const form = twoStep.closest("form");
    if (form) askForCode(form, { required: false });
    return;
  }

  const opener = event.target.closest("[data-open-dialog]");
  if (opener) {
    const dialog = document.getElementById(opener.dataset.openDialog);
    if (!dialog) return;
    const form = dialog.querySelector("form[data-api]");
    if (form && opener.dataset.dialogAction) form.dataset.api = opener.dataset.dialogAction;
    const label = dialog.querySelector("[data-dialog-label-target]");
    if (label) label.textContent = opener.dataset.dialogLabel || "";
    form?.reset();
    if (form) showFormError(form, "");
    dialog.showModal();
    return;
  }

  const closer = event.target.closest("[data-close-dialog]");
  if (closer) {
    closer.closest("dialog")?.close();
    if (closer.dataset.then === "reload") window.location.reload();
    return;
  }

  const back = event.target.closest("a[data-back]");
  if (back) {
    // Arriving from the list: go back to it as it was, filters and page included.
    const plainClick = event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey;
    let from = null;
    try {
      from = new URL(document.referrer);
    } catch {
      // No referrer: follow the link.
    }
    if (plainClick && from && from.origin === window.location.origin && from.pathname === back.pathname) {
      event.preventDefault();
      window.history.back();
    }
    return;
  }

  const copier = event.target.closest("[data-copy]");
  if (copier) {
    const source = document.querySelector(copier.dataset.copy);
    try {
      await navigator.clipboard.writeText(source?.textContent ?? "");
      toast({ title: "Copied to clipboard." });
    } catch {
      toast({ title: "Copy failed. Select the text and copy it manually.", error: true });
    }
    return;
  }

  if (event.target.closest("[data-toggle-sidebar]")) {
    document.body.classList.toggle("nav-open");
    return;
  }

  if (event.target.closest("#bulk-all")) {
    document.getElementById("bulk-bar").dataset.all = "1";
    updateBulk();
    return;
  }

  const bulk = event.target.closest("[data-bulk-status]");
  if (bulk) {
    await bulkStatus(bulk.dataset.bulkStatus);
    return;
  }

  if (event.target.closest("[data-bulk-assign]")) {
    await bulkAssign();
    return;
  }

  if (event.target.closest("[data-notify-toggle]")) {
    await toggleDesktopNotifications();
    return;
  }

  const action = event.target.closest("[data-post]");
  if (action) {
    if (action.dataset.confirm && !(await confirmAction(action.dataset.confirm))) return;
    action.disabled = true;
    try {
      const body = action.dataset.body ? JSON.parse(action.dataset.body) : undefined;
      const data = await call(action.dataset.method || "POST", action.dataset.post, body);
      finish(action.dataset.then, data, action);
    } catch (error) {
      toast({ title: error.message, error: true });
    } finally {
      action.disabled = false;
    }
  }
});

document.addEventListener("change", async (event) => {
  // A select that saves as soon as it changes: a role, an owner, a channel's severity.
  const select = event.target.closest("select[data-submit]");
  if (select) {
    try {
      const body = { ...JSON.parse(select.dataset.body || "{}"), [select.dataset.field]: select.value };
      await call(select.dataset.method || "POST", select.dataset.submit, body);
      if (select.dataset.then === "reload") window.location.reload();
      else toast({ title: select.dataset.toast || "Saved." });
    } catch (error) {
      toast({ title: error.message, error: true });
      window.setTimeout(() => window.location.reload(), 1200);
    }
    return;
  }

  const kind = event.target.closest("select[data-channel-kind]");
  if (kind) {
    const form = kind.closest("form");
    const email = kind.value === "email";
    form.querySelector("[data-channel-target-label]").textContent = email ? "Send to" : "URL";
    form.querySelector('input[name="target"]').placeholder = email ? "oncall@example.com, soc@example.com" : "https://hooks.example.com/...";
    form.querySelector("[data-channel-target-help]").textContent = email
      ? "One or more addresses, separated by commas."
      : "Must be an https:// address. Only its host name is shown after it is saved.";
    return;
  }

  if (event.target.matches("[data-notify-critical]")) {
    writeStored(window.localStorage, NOTIFY_CRITICAL_KEY, event.target.checked ? "1" : "");
    return;
  }

  if (event.target.id === "select-all") {
    rowChecks().forEach((box) => (box.checked = event.target.checked));
  }
  if (event.target.id === "select-all" || event.target.classList.contains("row-check")) updateBulk();
});

// ---- times in the viewer's own zone ---------------------------------------

const exactTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  timeZoneName: "short",
});
const hourLabel = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

function relativeTime(date) {
  const seconds = Math.max(Math.floor((Date.now() - date.getTime()) / 1000), 0);
  for (const [size, unit] of [
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ]) {
    if (seconds >= size) return `${Math.floor(seconds / size)}${unit} ago`;
  }
  return seconds < 10 ? "just now" : `${seconds}s ago`;
}

function refreshTimes() {
  for (const node of document.querySelectorAll("time[datetime]")) {
    const date = new Date(node.dateTime);
    if (Number.isNaN(date.getTime())) continue;
    if (node.hasAttribute("data-relative")) {
      node.textContent = relativeTime(date);
      node.title = exactTime.format(date);
    } else if (node.hasAttribute("data-local")) {
      node.textContent = exactTime.format(date); // the UTC time stays in the tooltip
    }
  }
  for (const label of document.querySelectorAll("[data-hour]")) {
    label.textContent = hourLabel.format(new Date(Number(label.dataset.hour) * 3600 * 1000));
  }
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  for (const note of document.querySelectorAll("[data-zone-note]")) {
    note.textContent = zone ? `times in ${zone}` : "times in your time zone";
  }
}

// ---- finding your way around the alert list -------------------------------

const LIST_KEY = "tgm.alertList";
let cursorId = null;

function alertRows() {
  return [...document.querySelectorAll("table[data-alert-rows] tbody tr[data-alert-id]")];
}

// Remember the list being looked at, so an alert opened from it can offer previous and next.
function rememberAlertList() {
  const rows = alertRows();
  if (!rows.length) return;
  const record = { url: window.location.pathname + window.location.search, ids: rows.map((row) => row.dataset.alertId) };
  writeStored(window.sessionStorage, LIST_KEY, JSON.stringify(record));
}

function setUpAlertNavigation() {
  const nav = document.querySelector("[data-alert-nav]");
  if (!nav) return;
  let list = null;
  try {
    list = JSON.parse(readStored(window.sessionStorage, LIST_KEY) || "null");
  } catch {
    return;
  }
  const index = Array.isArray(list?.ids) ? list.ids.indexOf(nav.dataset.alertNav) : -1;
  if (index < 0) return;
  const link = (name, id) => {
    const node = nav.querySelector(`[data-nav="${name}"]`);
    if (id) node.href = `/alerts/${encodeURIComponent(id)}`;
    else node.classList.add("is-disabled");
  };
  link("previous", list.ids[index - 1]);
  link("next", list.ids[index + 1]);
  nav.querySelector('[data-nav="position"]').textContent = `${index + 1} of ${list.ids.length}`;
  nav.hidden = false;
  const back = document.querySelector("a[data-back]");
  if (back && typeof list.url === "string" && list.url.startsWith("/alerts")) back.href = list.url;
}

function moveCursor(step) {
  const rows = alertRows();
  if (!rows.length) return;
  const current = rows.findIndex((row) => row.dataset.alertId === cursorId);
  const next = rows[Math.min(Math.max(current + step, 0), rows.length - 1)];
  cursorId = next.dataset.alertId;
  showCursor();
  next.scrollIntoView({ block: "nearest" });
}

function showCursor() {
  for (const row of alertRows()) row.classList.toggle("is-cursor", row.dataset.alertId === cursorId);
}

function cursorRow() {
  return alertRows().find((row) => row.dataset.alertId === cursorId) ?? null;
}

// ---- keyboard shortcuts ---------------------------------------------------

const GO_TO = { o: "/", a: "/alerts?status=open", f: "/agents" };
const STATUS_KEYS = { a: "acknowledged", r: "resolved", o: "open" };
let goPending = 0;

document.addEventListener("keydown", (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const target = event.target;
  const typing = target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
  if (typing || document.querySelector("dialog[open]")) return;
  const key = event.key;

  if (goPending && Date.now() - goPending < 1500 && GO_TO[key]) {
    goPending = 0;
    window.location.assign(GO_TO[key]);
    return;
  }
  goPending = key === "g" ? Date.now() : 0;
  if (key === "g") return;

  if (key === "?") {
    document.getElementById("shortcuts-dialog")?.showModal();
    return;
  }
  if (key === "/") {
    const search = document.querySelector("[data-search]");
    if (search) {
      event.preventDefault();
      search.focus();
      search.select();
    }
    return;
  }

  // On an alert: act through the buttons that are on the page, so shortcuts can do nothing the page cannot.
  if (document.querySelector("[data-alert-nav]")) {
    const nav = { j: "next", k: "previous" }[key];
    if (nav) document.querySelector(`[data-nav="${nav}"][href]`)?.click();
    else if (key === "u") document.querySelector("a[data-back]")?.click();
    else document.querySelector(`[data-shortcut="${CSS.escape(key)}"]`)?.click();
    return;
  }

  if (!alertRows().length) return;
  if (key === "j" || key === "k") {
    moveCursor(key === "j" ? 1 : -1);
    return;
  }
  const row = cursorRow();
  if (key === "Enter" && row) {
    row.querySelector("a.row-link")?.click();
    return;
  }
  if (key === "x" && row) {
    const box = row.querySelector(".row-check");
    if (box) {
      box.checked = !box.checked;
      updateBulk();
    }
    return;
  }
  if (!document.getElementById("bulk-bar")) return; // read-only roles have no triage actions
  const chosen = selectedIds().length ? undefined : row ? [row.dataset.alertId] : null;
  if (chosen === null) return;
  if (STATUS_KEYS[key]) bulkStatus(STATUS_KEYS[key], chosen);
  else if (key === "m") bulkAssign(chosen);
});

// ---- desktop notifications and the tab title ------------------------------

const NOTIFY_KEY = "tgm.desktopNotifications";
const NOTIFY_CRITICAL_KEY = "tgm.desktopNotificationsCriticalOnly";
const pageTitle = document.title;
let unseen = 0;

function desktopNotificationsOn() {
  return "Notification" in window && Notification.permission === "granted" && readStored(window.localStorage, NOTIFY_KEY) === "on";
}

function showNotificationSettings() {
  const card = document.querySelector("[data-desktop-notifications]");
  if (!card || !("Notification" in window)) return;
  card.hidden = false;
  const on = desktopNotificationsOn();
  card.querySelector("[data-notify-toggle]").textContent = on ? "Turn off" : "Turn on";
  card.querySelector("[data-notify-critical]").checked = readStored(window.localStorage, NOTIFY_CRITICAL_KEY) === "1";
  card.querySelector("[data-notify-state]").textContent =
    Notification.permission === "denied"
      ? "This browser is blocking notifications from this site. Allow them in the browser's site settings first."
      : on
        ? "On for this browser. New alerts are shown as notifications while a dashboard tab is open in the background."
        : "Show new alerts as notifications from this browser while a dashboard tab is open.";
}

async function toggleDesktopNotifications() {
  if (!("Notification" in window)) return;
  if (desktopNotificationsOn()) {
    writeStored(window.localStorage, NOTIFY_KEY, "off");
  } else if ((await Notification.requestPermission()) === "granted") {
    writeStored(window.localStorage, NOTIFY_KEY, "on");
  }
  showNotificationSettings();
}

function announce(alert) {
  if (!document.hidden) return; // the toast is enough when the tab is being looked at
  unseen += 1;
  document.title = `(${unseen}) ${pageTitle}`;
  if (!desktopNotificationsOn()) return;
  const urgent = alert.level === "critical" || alert.level === "high";
  if (readStored(window.localStorage, NOTIFY_CRITICAL_KEY) === "1" && !urgent) return;
  try {
    const notification = new Notification(String(alert.title ?? "New alert"), {
      body: `${alert.severity ?? ""} · ${alert.hostname ?? ""}`,
      tag: String(alert.id),
    });
    notification.addEventListener("click", () => {
      window.focus();
      window.location.assign(`/alerts/${encodeURIComponent(alert.id)}`);
    });
  } catch {
    // Some browsers only allow notifications from a service worker; the title count still shows.
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.hidden) return;
  unseen = 0;
  document.title = pageTitle;
  refreshContent();
});

// ---- live updates ---------------------------------------------------------

let refreshTimer = 0;

function userIsBusy() {
  const active = document.activeElement;
  const typing = active && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName);
  return typing || document.querySelector("dialog[open]") || document.querySelector(".row-check:checked");
}

function afterContentChange() {
  refreshTimes();
  rememberAlertList();
  showCursor();
  updateBulk();
}

async function refreshContent() {
  const content = document.getElementById("content");
  if (!content?.dataset.liveRefresh || userIsBusy() || signedOut) return;
  try {
    const response = await fetch(window.location.href, {
      headers: { accept: "text/html", ...BACKGROUND },
      credentials: "same-origin",
    });
    if (response.redirected && new URL(response.url).pathname === "/login") {
      sessionEnded();
      return;
    }
    if (!response.ok || response.redirected) return;
    const next = new DOMParser().parseFromString(await response.text(), "text/html").getElementById("content");
    if (next && !userIsBusy()) {
      content.replaceChildren(...next.childNodes);
      afterContentChange();
    }
  } catch {
    // The next event or a manual reload will bring the page up to date.
  }
}

const STREAM_RETRY_MS = 15000;

function startLiveUpdates() {
  if (!document.body.dataset.live || !("EventSource" in window) || signedOut) return;
  const source = new EventSource("/stream");
  liveSource = source;
  source.addEventListener("open", () => setLiveState("live", "Live"));
  source.addEventListener("error", async () => {
    setLiveState("idle", "Reconnecting");
    // While the browser is still retrying there is nothing to do. It gives up for
    // good when the server refuses the stream, which is what an ended session does.
    if (source.readyState !== EventSource.CLOSED || signedOut) return;
    if (await sessionIsOver()) sessionEnded();
    else window.setTimeout(startLiveUpdates, STREAM_RETRY_MS);
  });
  source.addEventListener("alert", (event) => {
    let alert;
    try {
      alert = JSON.parse(event.data);
    } catch {
      return;
    }
    toast({
      title: String(alert.title ?? "New alert"),
      detail: `${alert.severity ?? ""} · ${alert.hostname ?? ""}`,
      level: ["critical", "high", "medium", "low"].includes(alert.level) ? alert.level : "",
      href: `/alerts/${encodeURIComponent(alert.id)}`,
    });
    announce(alert);
    window.clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(refreshContent, 600);
  });
}

window.addEventListener("beforeunload", () => liveSource?.close());

// Pages whose content changes without an alert arriving (agent status, "5m ago") reload themselves.
const refreshEvery = Number(document.getElementById("content")?.dataset.refreshEvery);
if (refreshEvery > 0) {
  window.setInterval(() => {
    if (!document.hidden) refreshContent();
  }, refreshEvery * 1000);
}
window.setInterval(refreshTimes, 30000);

// Opened from a link that asks for a dialog, such as the overview's "Enrol an agent".
const autoDialog = document.querySelector("dialog[data-auto-open]");
if (autoDialog) {
  autoDialog.showModal();
  window.history.replaceState(null, "", window.location.pathname); // a reload must not reopen it
}

refreshTimes();
rememberAlertList();
setUpAlertNavigation();
showNotificationSettings();
startLiveUpdates();

// ---- agent commands -------------------------------------------------------

// Refreshing policy needs no target or duration, so those fields step aside.
function syncCommandForm(select) {
  const form = select.closest("form");
  const needsTarget = select.value !== "refresh_policy";
  for (const selector of ["[data-command-target]", "[data-command-duration]"]) {
    const field = form?.querySelector(selector);
    if (!field) continue;
    field.hidden = !needsTarget;
    field.querySelectorAll("input, select").forEach((input) => {
      input.disabled = !needsTarget;
      if (input.tagName === "INPUT") input.required = needsTarget;
    });
  }
}

document.addEventListener("change", (event) => {
  const select = event.target.closest("[data-command-action]");
  if (select) syncCommandForm(select);
});
document.querySelectorAll("[data-command-action]").forEach(syncCommandForm);
