const CTL = "/data/adb/modules/selhide/bin/selhide_ctl.sh";
const allowedCommands = new Set([
  "web-status",
  "toggle-hiding",
  "enable-autoload",
  "disable-autoload",
  "shutdown",
  "apply-mode-sync",
  "apply-mode-manual",
  "apply-sync-now",
  "apply-add",
  "apply-remove",
  "apply-clear",
]);

const elements = {
  modeCard: document.querySelector("#mode-card"),
  modeTitle: document.querySelector("#mode-title"),
  modeCopy: document.querySelector("#mode-copy"),
  module: document.querySelector("#module-state"),
  autoload: document.querySelector("#autoload-state"),
  trial: document.querySelector("#trial-state"),
  guard: document.querySelector("#guard-state"),
  bridge: document.querySelector("#bridge-state"),
  output: document.querySelector("#console-output"),
  kernel: document.querySelector("#kernel-release"),
  lastState: document.querySelector("#last-state"),
  toggleHiding: document.querySelector("#toggle-hiding"),
  toggleAutoload: document.querySelector("#toggle-autoload"),
  autoloadAction: document.querySelector("#autoload-action"),
  refresh: document.querySelector("#refresh"),
  shutdown: document.querySelector("#shutdown"),
  applyMode: document.querySelector("#apply-mode"),
  applyCopy: document.querySelector("#apply-copy"),
  applyEntries: document.querySelector("#apply-entries"),
  applyForm: document.querySelector("#apply-form"),
  packageInput: document.querySelector("#package-input"),
  applyAdd: document.querySelector("#apply-add"),
  applyModeToggle: document.querySelector("#apply-mode-toggle"),
  applySync: document.querySelector("#apply-sync"),
  applyClear: document.querySelector("#apply-clear"),
};

let status = null;
let busy = false;

function hasBridge() {
  return Boolean(globalThis.ksu && typeof globalThis.ksu.exec === "function");
}

function parseResult(raw) {
  const text = String(raw ?? "");
  const marker = "__SELHIDE_RC__=";
  const markerAt = text.lastIndexOf(marker);
  if (markerAt < 0) return { code: 255, output: text.trim() };
  const code = Number.parseInt(text.slice(markerAt + marker.length), 10);
  return { code, output: text.slice(0, markerAt).trim() };
}

function normalizePackage(value) {
  const packageName = String(value ?? "").trim();
  if (!/^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$/.test(packageName)) {
    throw new Error("Enter a valid Android package name");
  }
  return packageName;
}

function execute(command, argument = "") {
  if (!allowedCommands.has(command)) throw new Error("Unsupported command");
  if (!hasBridge()) throw new Error("No KernelSU-compatible root bridge found");
  const suffix = argument ? ` ${normalizePackage(argument)}` : "";
  const shell = `${CTL} ${command}${suffix} 2>&1; rc=$?; printf '\n__SELHIDE_RC__=%s\n' "$rc"`;
  return parseResult(globalThis.ksu.exec(shell));
}

function parseStatus(output) {
  return output.split(/\r?\n/).reduce((result, line) => {
    const split = line.indexOf("=");
    if (split > 0) result[line.slice(0, split)] = line.slice(split + 1);
    return result;
  }, {});
}

function setBusy(next) {
  busy = next;
  document.body.classList.toggle("busy", next);
  render();
}

function selectedPackages() {
  return String(status?.apply_packages || "").split(",").filter(Boolean);
}

function renderApplyList(blocked) {
  const syncMode = status?.apply_mode !== "manual";
  const packages = selectedPackages();
  elements.applyMode.textContent = syncMode ? "SYNC / LOCKED" : "MANUAL";
  elements.applyCopy.textContent = syncMode
    ? "Continuously mirrors Magisk's denylist. Editing is locked."
    : "A denylist snapshot that can be edited without changing Magisk.";
  elements.applyModeToggle.textContent = syncMode ? "Use editable snapshot" : "Follow Magisk denylist";
  elements.applyModeToggle.disabled = blocked || !status;
  elements.applySync.disabled = blocked || !status || !syncMode;
  elements.applyClear.disabled = blocked || !status || syncMode || packages.length === 0;
  elements.packageInput.disabled = blocked || !status || syncMode;
  elements.applyAdd.disabled = blocked || !status || syncMode;

  elements.applyEntries.replaceChildren();
  if (packages.length === 0) {
    const empty = document.createElement("p");
    empty.className = "apply-empty";
    empty.textContent = "No packages selected.";
    elements.applyEntries.append(empty);
    return;
  }
  for (const packageName of packages) {
    const row = document.createElement("div");
    row.className = "apply-entry";
    const name = document.createElement("code");
    name.textContent = packageName;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.textContent = "Remove";
    remove.disabled = blocked || syncMode;
    remove.addEventListener("click", () => runControl(
      "apply-remove",
      `${packageName} removed from the manual list.`,
      packageName,
    ));
    row.append(name, remove);
    elements.applyEntries.append(row);
  }
}

function render() {
  const connected = hasBridge();
  elements.bridge.textContent = connected ? (busy ? "BUSY" : "ONLINE") : "UNAVAILABLE";
  const blocked = !connected || busy;
  elements.refresh.disabled = blocked;
  elements.toggleHiding.disabled = blocked || !status || status.safe_mode === "1";
  elements.toggleAutoload.disabled = blocked || !status || status.safe_mode === "1";
  elements.shutdown.disabled = blocked || !status;
  if (!status) return;
  renderApplyList(blocked);

  const loaded = status.module_loaded === "1";
  const active = status.hiding_runtime === "active";
  const paused = status.hiding_runtime === "passthrough" || status.hiding_desired === "passthrough";
  elements.modeCard.classList.remove("active", "paused", "off");
  if (loaded && active) {
    elements.modeCard.classList.add("active");
    elements.modeTitle.textContent = "Hiding active";
    elements.modeCopy.textContent = "SELinux queries receive the clean policy view.";
  } else if (paused) {
    elements.modeCard.classList.add("paused");
    elements.modeTitle.textContent = "Pass-through";
    elements.modeCopy.textContent = loaded ? "Hooks remain attached, but original policy answers pass through." : "The next load will start with hiding paused.";
  } else {
    elements.modeCard.classList.add("off");
    elements.modeTitle.textContent = "Module detached";
    elements.modeCopy.textContent = "No SelHide kernel module is currently loaded.";
  }

  elements.module.textContent = loaded ? "ATTACHED" : "DETACHED";
  elements.autoload.textContent = status.autoload === "1" ? "ON" : "OFF";
  elements.trial.textContent = status.trial_current === "1" ? "CURRENT" : "REQUIRED";
  elements.guard.textContent = status.safe_mode === "1" ? "SAFE MODE" : status.panic_guard === "1" ? "ARMED" : "CLEAR";
  elements.autoloadAction.textContent = status.autoload === "1" ? "Disable boot loading" : "Enable after valid trial";
  elements.kernel.textContent = `kernel: ${status.kernel || "unknown"}`;
  elements.lastState.textContent = `state: ${status.last_state || "unknown"}`;
}

function report(message) {
  elements.output.textContent = message || "Command completed.";
}

async function refreshStatus() {
  if (busy) return;
  if (!hasBridge()) {
    report("This page needs KernelSU Manager or a compatible Magisk WebUI host such as WebUI X.");
    render();
    return;
  }
  setBusy(true);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const result = execute("web-status");
    if (result.code !== 0) throw new Error(result.output || `status failed: ${result.code}`);
    status = parseStatus(result.output);
    report("Live status received from selhide_ctl.sh.");
  } catch (error) {
    report(`ERROR: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

async function runControl(command, successMessage, argument = "") {
  if (busy) return;
  setBusy(true);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const result = execute(command, argument);
    if (result.code !== 0) throw new Error(result.output || `${command} failed: ${result.code}`);
    report(result.output || successMessage);
    const latest = execute("web-status");
    if (latest.code === 0) status = parseStatus(latest.output);
  } catch (error) {
    report(`ERROR: ${error.message}`);
  } finally {
    setBusy(false);
  }
}

elements.toggleHiding.addEventListener("click", () => runControl("toggle-hiding", "Policy view changed."));
elements.toggleAutoload.addEventListener("click", () => {
  const command = status?.autoload === "1" ? "disable-autoload" : "enable-autoload";
  runControl(command, "Autoload state changed.");
});
elements.refresh.addEventListener("click", refreshStatus);
elements.shutdown.addEventListener("click", () => {
  if (globalThis.confirm("Disable autoload and unload SelHide now?")) {
    runControl("shutdown", "SelHide shut down.");
  }
});
elements.applyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  let packageName;
  try {
    packageName = normalizePackage(elements.packageInput.value);
  } catch (error) {
    report(`ERROR: ${error.message}`);
    return;
  }
  runControl("apply-add", `${packageName} added to the manual list.`, packageName);
  elements.packageInput.value = "";
});
elements.applyModeToggle.addEventListener("click", () => {
  const syncMode = status?.apply_mode !== "manual";
  const command = syncMode ? "apply-mode-manual" : "apply-mode-sync";
  const message = syncMode ? "Editable Magisk denylist snapshot created." : "Continuous Magisk denylist sync enabled.";
  runControl(command, message);
});
elements.applySync.addEventListener("click", () => runControl("apply-sync-now", "Magisk denylist synchronized."));
elements.applyClear.addEventListener("click", () => {
  if (globalThis.confirm("Clear the entire manual apply list?")) {
    runControl("apply-clear", "Manual apply list cleared.");
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refreshStatus();
});

refreshStatus();
