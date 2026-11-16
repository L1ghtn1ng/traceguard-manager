// TraceGuard Manager client script.
// Server data is only ever written with textContent, never as HTML.

const CSRF_COOKIE = "flasgo-csrf";

function csrfToken() {
  const prefix = `${CSRF_COOKIE}=`;
  const entry = document.cookie.split("; ").find((item) => item.startsWith(prefix));
  return entry ? entry.slice(prefix.length) : "";
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
    throw new Error("Could not reach the server. Check your connection and try again.");
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
    throw new Error("Your session has ended. Sign in again to continue.");
  }
  if (tokenRefused) throw new Error("This page is out of date. Reload it and try again.");
  if (response.status === 429) throw new Error("Too many attempts. Wait a moment and try again.");
  throw new Error(typeof data.error === "string" ? data.error : "The request failed. Try again.");
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

function toast({ title, detail = "", level = "", href = "", error = false }) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const node = document.createElement(href ? "a" : "div");
  node.className = `toast${error ? " toast-error" : ""}${level ? ` level-${level}` : ""}`;
  if (href) node.href = href;
  const bar = document.createElement("span");
  bar.className = "toast-bar";
  const text = document.createElement("span");
  text.className = "toast-body";
  const strong = document.createElement("strong");
  strong.textContent = title;
  text.append(strong);
  if (detail) {
    const small = document.createElement("small");
    small.textContent = detail;
    text.append(small);
  }
  node.append(bar, text);
  host.append(node);
  while (host.children.length > 4) host.firstElementChild.remove();
  window.setTimeout(() => node.remove(), 8000);
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

function showToken(data) {
  const dialog = document.getElementById("token-dialog");
  if (!dialog) return;
  dialog.querySelector("#token-agent").textContent = data.name;
  dialog.querySelector("#token-snippet").textContent =
    `TRACEGUARD_EVENT_EXPORT_URL=${window.location.origin}/api/v1/events\n` +
    `TRACEGUARD_EVENT_EXPORT_AUTHORIZATION=Bearer ${data.token}`;
  document.querySelectorAll("dialog[open]").forEach((open) => open.close());
  dialog.showModal();
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

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-api]");
  if (!form) return;
  event.preventDefault();
  if (!form.reportValidity()) return;
  const buttons = form.querySelectorAll("button");
  showFormError(form, "");
  buttons.forEach((button) => (button.disabled = true));
  try {
    const data = await call(form.dataset.method || "POST", form.dataset.api, formPayload(form, event.submitter));
    if (form.dataset.reset) form.reset();
    finish(form.dataset.then, data, form);
  } catch (error) {
    showFormError(form, error.message);
    form.querySelector('input[type="password"]')?.select();
  } finally {
    buttons.forEach((button) => (button.disabled = false));
  }
});

document.addEventListener("click", async (event) => {
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

  const bulk = event.target.closest("[data-bulk-status]");
  if (bulk) {
    const ids = [...document.querySelectorAll(".row-check:checked")].map((box) => box.value);
    if (!ids.length) return;
    try {
      await call("POST", "/alerts/status", { ids, status: bulk.dataset.bulkStatus });
      window.location.reload();
    } catch (error) {
      toast({ title: error.message, error: true });
    }
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
  const select = event.target.closest("select[data-patch]");
  if (select) {
    try {
      await call("PATCH", select.dataset.patch, { [select.dataset.field]: select.value });
      toast({ title: "Role updated." });
    } catch (error) {
      toast({ title: error.message, error: true });
      window.setTimeout(() => window.location.reload(), 1200);
    }
    return;
  }

  if (event.target.id === "select-all") {
    document.querySelectorAll(".row-check").forEach((box) => (box.checked = event.target.checked));
  }
  if (event.target.id === "select-all" || event.target.classList.contains("row-check")) {
    const count = document.querySelectorAll(".row-check:checked").length;
    const bar = document.getElementById("bulk-bar");
    if (bar) {
      bar.hidden = count === 0;
      bar.querySelector("#bulk-count").textContent = String(count);
    }
  }
});

// ---- live updates ---------------------------------------------------------

let refreshTimer = 0;

function userIsBusy() {
  const active = document.activeElement;
  const typing = active && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName);
  return typing || document.querySelector("dialog[open]") || document.querySelector(".row-check:checked");
}

async function refreshContent() {
  const content = document.getElementById("content");
  if (!content?.dataset.liveRefresh || userIsBusy()) return;
  try {
    const response = await fetch(window.location.href, { headers: { accept: "text/html" }, credentials: "same-origin" });
    if (response.redirected && new URL(response.url).pathname === "/login") {
      sessionEnded();
      return;
    }
    if (!response.ok || response.redirected) return;
    const next = new DOMParser().parseFromString(await response.text(), "text/html").getElementById("content");
    if (next && !userIsBusy()) content.replaceChildren(...next.childNodes);
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
    window.clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(refreshContent, 600);
  });
}

window.addEventListener("beforeunload", () => liveSource?.close());

// Opened from a link that asks for a dialog, such as the overview's "Enrol an agent".
const autoDialog = document.querySelector("dialog[data-auto-open]");
if (autoDialog) {
  autoDialog.showModal();
  window.history.replaceState(null, "", window.location.pathname); // a reload must not reopen it
}

startLiveUpdates();
