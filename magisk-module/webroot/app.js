const CTL = "/data/adb/modules/selhide/bin/selhide_ctl.sh";
const LANGUAGE_KEY = "selhide-language";
const allowedCommands = new Set([
  "web-status",
  "trial",
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
const packageCommands = new Set(["apply-add", "apply-remove"]);

const messages = {
  en: {
    documentTitle: "SelHide Control",
    switchLanguage: "Switch interface language",
    eyebrow: "SELINUX POLICY LENS",
    controlRoom: "Control Room",
    lede: "Keep the kernel module attached. Switch its policy view without a reload.",
    runtimeMode: "Runtime mode",
    connecting: "Connecting",
    waitingBridge: "Waiting for the root command bridge.",
    statusLabel: "SelHide status",
    metricModule: "MODULE",
    metricAutoload: "AUTOLOAD",
    metricTrial: "TRIAL",
    metricGuard: "GUARD",
    applicationScope: "Application scope",
    magiskDenylist: "Magisk denylist",
    readingSet: "Reading the selected package set.",
    packageName: "Package name",
    packagePlaceholder: "com.example.app",
    add: "Add",
    switchListMode: "Switch list mode",
    syncNow: "Sync now",
    clearManual: "Clear manual list",
    scopeNote: "Filtering uses Android appId. It spans users, and packages sharing one UID are selected together.",
    togglePolicy: "Toggle policy view",
    pauseResume: "Pause or resume without unloading",
    autoload: "Autoload",
    changeBootState: "Change boot state",
    refresh: "Refresh",
    readLiveState: "Read live state",
    shutdown: "Disable autoload and unload module",
    receiver: "RECEIVER",
    checking: "CHECKING",
    noCommand: "No command issued.",
    busy: "BUSY",
    online: "ONLINE",
    unavailable: "UNAVAILABLE",
    syncLocked: "SYNC / LOCKED",
    manual: "MANUAL",
    syncDescription: "Continuously mirrors Magisk's denylist. Editing is locked.",
    manualDescription: "A denylist snapshot that can be edited without changing Magisk.",
    editableSnapshot: "Use editable snapshot",
    followMagisk: "Follow Magisk denylist",
    noPackages: "No packages selected.",
    remove: "Remove",
    removed: "{package} removed from the manual list.",
    hidingActive: "Hiding active",
    hidingActiveCopy: "SELinux queries receive the clean policy view.",
    passthrough: "Pass-through",
    passthroughLoadedCopy: "Hooks remain attached, but original policy answers pass through.",
    passthroughNextCopy: "The next load will start with hiding paused.",
    moduleDetached: "Module detached",
    moduleDetachedCopy: "No SelHide kernel module is currently loaded.",
    attached: "ATTACHED",
    detached: "DETACHED",
    on: "ON",
    off: "OFF",
    current: "CURRENT",
    required: "REQUIRED",
    safeMode: "SAFE MODE",
    armed: "ARMED",
    clear: "CLEAR",
    disableBoot: "Disable boot loading",
    runTrial: "Run guarded {seconds}s trial",
    enableValidated: "Enable after valid trial",
    kernel: "kernel: {value}",
    state: "state: {value}",
    unknown: "unknown",
    commandCompleted: "Command completed.",
    invalidPackage: "Enter a valid Android package name",
    invalidTrial: "Invalid trial duration",
    unsupportedCommand: "Unsupported command",
    noBridge: "No KernelSU-compatible root bridge found",
    hostRequired: "This page needs KernelSU Manager or a compatible Magisk WebUI host such as WebUI X.",
    statusFailed: "status failed: {code}",
    statusReceived: "Live status received from selhide_ctl.sh.",
    error: "ERROR: {message}",
    genericFailed: "{command} failed: {code}",
    policyChanged: "Policy view changed.",
    autoloadChanged: "Autoload state changed.",
    autoloadTrialRequired: "Autoload is locked because this exact KO, loader, and clean policy have not passed a guarded trial.",
    trialConfirm: "Run a guarded {seconds}-second trial now? Keep this WebUI host open and run DirtySepolicy during the trial. SelHide will unload before the trial is recorded as passed.",
    trialPending: "Guarded {seconds}s trial is running. Keep this WebUI host open and run DirtySepolicy now. SelHide will unload automatically.",
    trialPassed: "Guarded trial passed and SelHide unloaded. Press Autoload again to enable boot loading.",
    shutdownConfirm: "Disable autoload and unload SelHide now?",
    shutdownDone: "SelHide shut down.",
    packageAdded: "{package} added to the manual list.",
    snapshotCreated: "Editable Magisk denylist snapshot created.",
    syncEnabled: "Continuous Magisk denylist sync enabled.",
    syncDone: "Magisk denylist synchronized.",
    clearConfirm: "Clear the entire manual apply list?",
    clearDone: "Manual apply list cleared.",
  },
  "zh-CN": {
    documentTitle: "SelHide 控制中心",
    switchLanguage: "切换界面语言",
    eyebrow: "SELINUX 策略视图",
    controlRoom: "控制中心",
    lede: "保持内核模块挂载，无需重新加载即可切换策略视图。",
    runtimeMode: "运行模式",
    connecting: "正在连接",
    waitingBridge: "正在等待 Root 命令桥接。",
    statusLabel: "SelHide 状态",
    metricModule: "模块",
    metricAutoload: "自动加载",
    metricTrial: "试运行",
    metricGuard: "保护",
    applicationScope: "应用范围",
    magiskDenylist: "Magisk 排除列表",
    readingSet: "正在读取已选应用。",
    packageName: "应用包名",
    packagePlaceholder: "com.example.app",
    add: "添加",
    switchListMode: "切换列表模式",
    syncNow: "立即同步",
    clearManual: "清空手动列表",
    scopeNote: "筛选基于 Android appId，会跨用户生效；共享同一 UID 的应用将被同时选中。",
    togglePolicy: "切换策略视图",
    pauseResume: "无需卸载即可暂停或恢复",
    autoload: "自动加载",
    changeBootState: "更改开机加载状态",
    refresh: "刷新",
    readLiveState: "读取实时状态",
    shutdown: "关闭自动加载并卸载模块",
    receiver: "接收器",
    checking: "检查中",
    noCommand: "尚未执行命令。",
    busy: "忙碌",
    online: "在线",
    unavailable: "不可用",
    syncLocked: "同步 / 已锁定",
    manual: "手动",
    syncDescription: "持续同步 Magisk 排除列表，当前不可编辑。",
    manualDescription: "可独立编辑的排除列表快照，不会修改 Magisk 设置。",
    editableSnapshot: "使用可编辑快照",
    followMagisk: "跟随 Magisk 排除列表",
    noPackages: "尚未选择应用。",
    remove: "移除",
    removed: "已从手动列表移除 {package}。",
    hidingActive: "隐藏已启用",
    hidingActiveCopy: "SELinux 查询将读取干净策略视图。",
    passthrough: "透传模式",
    passthroughLoadedCopy: "Hook 仍保持挂载，但会透传原始策略结果。",
    passthroughNextCopy: "下次加载时将保持隐藏暂停。",
    moduleDetached: "模块未挂载",
    moduleDetachedCopy: "当前未加载 SelHide 内核模块。",
    attached: "已挂载",
    detached: "未挂载",
    on: "开启",
    off: "关闭",
    current: "有效",
    required: "需要执行",
    safeMode: "安全模式",
    armed: "已布防",
    clear: "正常",
    disableBoot: "关闭开机加载",
    runTrial: "执行 {seconds} 秒安全试运行",
    enableValidated: "验证后启用",
    kernel: "内核：{value}",
    state: "状态：{value}",
    unknown: "未知",
    commandCompleted: "命令执行完毕。",
    invalidPackage: "请输入有效的 Android 应用包名",
    invalidTrial: "试运行时长无效",
    unsupportedCommand: "不支持的命令",
    noBridge: "未找到兼容 KernelSU 的 Root 命令桥接",
    hostRequired: "此页面需要 KernelSU 管理器，或 WebUI X 等兼容的 Magisk WebUI 宿主。",
    statusFailed: "读取状态失败：{code}",
    statusReceived: "已从 selhide_ctl.sh 获取实时状态。",
    error: "错误：{message}",
    genericFailed: "{command} 执行失败：{code}",
    policyChanged: "策略视图已切换。",
    autoloadChanged: "自动加载状态已更新。",
    autoloadTrialRequired: "自动加载仍被锁定：当前 KO、加载器与干净策略尚未通过安全试运行。",
    trialConfirm: "现在执行 {seconds} 秒安全试运行吗？请保持 WebUI 宿主开启，并在试运行期间启动 DirtySepolicy。试运行被记录为通过前，SelHide 会先自动卸载。",
    trialPending: "{seconds} 秒安全试运行正在进行。请保持 WebUI 宿主开启并立即运行 DirtySepolicy，SelHide 随后会自动卸载。",
    trialPassed: "安全试运行已通过，SelHide 已卸载。请再次点击“自动加载”以启用开机加载。",
    shutdownConfirm: "现在关闭自动加载并卸载 SelHide 吗？",
    shutdownDone: "SelHide 已关闭。",
    packageAdded: "已将 {package} 添加到手动列表。",
    snapshotCreated: "已创建可编辑的 Magisk 排除列表快照。",
    syncEnabled: "已启用 Magisk 排除列表持续同步。",
    syncDone: "Magisk 排除列表已同步。",
    clearConfirm: "确定清空整个手动应用列表吗？",
    clearDone: "手动应用列表已清空。",
  },
};

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
  languageToggle: document.querySelector("#language-toggle"),
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

function storedLanguage() {
  try {
    const stored = globalThis.localStorage?.getItem(LANGUAGE_KEY);
    return Object.prototype.hasOwnProperty.call(messages, stored) ? stored : null;
  } catch (_error) {
    return null;
  }
}

function detectLanguage() {
  const stored = storedLanguage();
  if (stored) return stored;
  const candidates = [
    ...(Array.isArray(globalThis.navigator?.languages) ? globalThis.navigator.languages : []),
    globalThis.navigator?.language,
  ];
  return candidates.some((candidate) => String(candidate || "").toLowerCase().startsWith("zh"))
    ? "zh-CN"
    : "en";
}

let language = detectLanguage();
let status = null;
let busy = false;

function t(key, variables = {}) {
  const template = messages[language]?.[key] ?? messages.en[key] ?? key;
  return template.replace(/\{([A-Za-z]+)\}/g, (_match, name) => String(variables[name] ?? ""));
}

function applyLanguage() {
  document.documentElement.lang = language;
  document.title = t("documentTitle");
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.placeholder = t(element.dataset.i18nPlaceholder);
  });
  document.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
  });
  elements.languageToggle.textContent = language === "zh-CN" ? "EN" : "中文";
  elements.languageToggle.setAttribute("aria-label", t("switchLanguage"));
  render();
}

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
    throw new Error(t("invalidPackage"));
  }
  return packageName;
}

function normalizeTrialSeconds(value) {
  const seconds = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isInteger(seconds) || seconds < 5 || seconds > 600) {
    throw new Error(t("invalidTrial"));
  }
  return String(seconds);
}

function execute(command, argument = "") {
  if (!allowedCommands.has(command)) throw new Error(t("unsupportedCommand"));
  if (!hasBridge()) throw new Error(t("noBridge"));
  let normalizedArgument = "";
  if (argument !== "") {
    normalizedArgument = command === "trial"
      ? normalizeTrialSeconds(argument)
      : packageCommands.has(command) ? normalizePackage(argument) : "";
  }
  const suffix = normalizedArgument ? ` ${normalizedArgument}` : "";
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

function trialSeconds() {
  const seconds = Number.parseInt(status?.trial_seconds || "60", 10);
  return Number.isInteger(seconds) && seconds >= 5 && seconds <= 600 ? seconds : 60;
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
  elements.applyMode.textContent = syncMode ? t("syncLocked") : t("manual");
  elements.applyCopy.textContent = syncMode ? t("syncDescription") : t("manualDescription");
  elements.applyModeToggle.textContent = syncMode ? t("editableSnapshot") : t("followMagisk");
  elements.applyModeToggle.disabled = blocked || !status;
  elements.applySync.disabled = blocked || !status || !syncMode;
  elements.applyClear.disabled = blocked || !status || syncMode || packages.length === 0;
  elements.packageInput.disabled = blocked || !status || syncMode;
  elements.applyAdd.disabled = blocked || !status || syncMode;

  elements.applyEntries.replaceChildren();
  if (packages.length === 0) {
    const empty = document.createElement("p");
    empty.className = "apply-empty";
    empty.textContent = t("noPackages");
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
    remove.textContent = t("remove");
    remove.disabled = blocked || syncMode;
    remove.addEventListener("click", () => runControl(
      "apply-remove",
      t("removed", { package: packageName }),
      packageName,
    ));
    row.append(name, remove);
    elements.applyEntries.append(row);
  }
}

function render() {
  const connected = hasBridge();
  elements.bridge.textContent = connected ? (busy ? t("busy") : t("online")) : t("unavailable");
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
    elements.modeTitle.textContent = t("hidingActive");
    elements.modeCopy.textContent = t("hidingActiveCopy");
  } else if (paused) {
    elements.modeCard.classList.add("paused");
    elements.modeTitle.textContent = t("passthrough");
    elements.modeCopy.textContent = loaded ? t("passthroughLoadedCopy") : t("passthroughNextCopy");
  } else {
    elements.modeCard.classList.add("off");
    elements.modeTitle.textContent = t("moduleDetached");
    elements.modeCopy.textContent = t("moduleDetachedCopy");
  }

  elements.module.textContent = loaded ? t("attached") : t("detached");
  elements.autoload.textContent = status.autoload === "1" ? t("on") : t("off");
  elements.trial.textContent = status.trial_current === "1" ? t("current") : t("required");
  elements.guard.textContent = status.safe_mode === "1" ? t("safeMode") : status.panic_guard === "1" ? t("armed") : t("clear");
  elements.autoloadAction.textContent = status.autoload === "1"
    ? t("disableBoot")
    : status.trial_current === "1" ? t("enableValidated") : t("runTrial", { seconds: trialSeconds() });
  elements.kernel.textContent = t("kernel", { value: status.kernel || t("unknown") });
  elements.lastState.textContent = t("state", { value: status.last_state || t("unknown") });
}

function report(message) {
  elements.output.textContent = message || t("commandCompleted");
}

function commandError(command, result) {
  if (command === "enable-autoload" && result.code === 60) return t("autoloadTrialRequired");
  return result.output || t("genericFailed", { command, code: result.code });
}

async function refreshStatus() {
  if (busy) return;
  if (!hasBridge()) {
    report(t("hostRequired"));
    render();
    return;
  }
  setBusy(true);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const result = execute("web-status");
    if (result.code !== 0) throw new Error(result.output || t("statusFailed", { code: result.code }));
    status = parseStatus(result.output);
    report(t("statusReceived"));
  } catch (error) {
    report(t("error", { message: error.message }));
  } finally {
    setBusy(false);
  }
}

async function runControl(command, successMessage, argument = "", pendingMessage = "") {
  if (busy) return;
  setBusy(true);
  if (pendingMessage) report(pendingMessage);
  await new Promise((resolve) => setTimeout(resolve, 20));
  try {
    const result = execute(command, argument);
    if (result.code !== 0) throw new Error(commandError(command, result));
    report(successMessage || result.output || t("commandCompleted"));
    const latest = execute("web-status");
    if (latest.code === 0) status = parseStatus(latest.output);
  } catch (error) {
    report(t("error", { message: error.message }));
  } finally {
    setBusy(false);
  }
}

elements.languageToggle.addEventListener("click", () => {
  language = language === "zh-CN" ? "en" : "zh-CN";
  try {
    globalThis.localStorage?.setItem(LANGUAGE_KEY, language);
  } catch (_error) {
    // Some WebUI hosts disable persistent WebView storage; switching still works for this session.
  }
  applyLanguage();
});
elements.toggleHiding.addEventListener("click", () => runControl("toggle-hiding", t("policyChanged")));
elements.toggleAutoload.addEventListener("click", () => {
  if (status?.autoload === "1") {
    runControl("disable-autoload", t("autoloadChanged"));
    return;
  }
  if (status?.trial_current !== "1") {
    const seconds = trialSeconds();
    if (globalThis.confirm(t("trialConfirm", { seconds }))) {
      runControl(
        "trial",
        t("trialPassed"),
        String(seconds),
        t("trialPending", { seconds }),
      );
    }
    return;
  }
  runControl("enable-autoload", t("autoloadChanged"));
});
elements.refresh.addEventListener("click", refreshStatus);
elements.shutdown.addEventListener("click", () => {
  if (globalThis.confirm(t("shutdownConfirm"))) {
    runControl("shutdown", t("shutdownDone"));
  }
});
elements.applyForm.addEventListener("submit", (event) => {
  event.preventDefault();
  let packageName;
  try {
    packageName = normalizePackage(elements.packageInput.value);
  } catch (error) {
    report(t("error", { message: error.message }));
    return;
  }
  runControl("apply-add", t("packageAdded", { package: packageName }), packageName);
  elements.packageInput.value = "";
});
elements.applyModeToggle.addEventListener("click", () => {
  const syncMode = status?.apply_mode !== "manual";
  const command = syncMode ? "apply-mode-manual" : "apply-mode-sync";
  runControl(command, syncMode ? t("snapshotCreated") : t("syncEnabled"));
});
elements.applySync.addEventListener("click", () => runControl("apply-sync-now", t("syncDone")));
elements.applyClear.addEventListener("click", () => {
  if (globalThis.confirm(t("clearConfirm"))) {
    runControl("apply-clear", t("clearDone"));
  }
});

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refreshStatus();
});

applyLanguage();
refreshStatus();
