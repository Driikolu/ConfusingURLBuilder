import { buildPayload } from "./templater.js";
import { NAIVE_CHECKS, getCheck } from "./validators.js";
import { isIPv4, ipv4Variants } from "./ipEncode.js";

const FAMILY_LABELS = {
  userinfo: "Userinfo (@)",
  backslash: "Backslash",
  "scheme-slashes": "Scheme slashes",
  "hidden-in-suffix": "Hidden in fragment/query/path",
  whitespace: "Whitespace / control chars",
  "control-chars": "C0 control char sweep",
  "ipv6-bracket": "IPv6-bracket abuse",
  "separator-sweep": "Separator character sweep",
  unicode: "Unicode look-alikes",
};

function ecosystemOf(name) {
  if (name.startsWith("python-")) return "Python";
  if (name.startsWith("node-") || name.startsWith("bun-")) return "JavaScript / TypeScript";
  if (name.startsWith("go-")) return "Go";
  if (["java-uri", "java-url", "okhttp-httpurl", "spring-uricomponents", "apache-httpclient-uri", "android-uri"].includes(name))
    return "JVM / Android";
  if (name.startsWith("php-")) return "PHP";
  if (name.startsWith("ruby-")) return "Ruby";
  if (name.startsWith("dotnet-")) return ".NET";
  if (name.startsWith("rust-")) return "Rust";
  if (name === "perl-uri") return "Perl";
  if (name === "elixir-uri") return "Elixir";
  if (name === "lua-neturl") return "Lua";
  if (name === "swift-urlcomponents") return "Swift";
  if (name === "cpp-boost-url" || name === "uriparser-c") return "C / C++";
  if (name === "libcurl" || name === "wget-cli") return "CLI / native";
  return "Other";
}

const state = { techniques: null, matrix: null };
const els = {};

function $(id) {
  return document.getElementById(id);
}

async function loadData() {
  const [techRes, matrixRes] = await Promise.all([
    fetch("data/techniques.json", { cache: "no-store" }),
    fetch("data/technique-matrix.json", { cache: "no-store" }),
  ]);
  if (!techRes.ok || !matrixRes.ok) throw new Error("fetch failed");
  state.techniques = (await techRes.json()).techniques;
  state.matrix = await matrixRes.json();
}

function populateParserSelects() {
  const groups = {};
  for (const p of state.matrix.parsers) {
    const eco = ecosystemOf(p.name);
    (groups[eco] = groups[eco] || []).push(p);
  }
  const sortedEcos = Object.keys(groups).sort();

  els.requester.innerHTML = "";
  for (const eco of sortedEcos) {
    const og = document.createElement("optgroup");
    og.label = eco;
    for (const p of groups[eco].sort((a, b) => a.name.localeCompare(b.name))) {
      const opt = document.createElement("option");
      opt.value = p.name;
      opt.textContent = p.name;
      opt.title = p.description;
      og.appendChild(opt);
    }
    els.requester.appendChild(og);
  }
  els.requester.value = "python-urllib3";

  els.validator.innerHTML = "";
  const naiveGroup = document.createElement("optgroup");
  naiveGroup.label = "Naive string check (no real parsing)";
  for (const c of NAIVE_CHECKS) {
    const opt = document.createElement("option");
    opt.value = "naive:" + c.id;
    opt.textContent = c.label;
    opt.title = c.description;
    naiveGroup.appendChild(opt);
  }
  const customOpt = document.createElement("option");
  customOpt.value = "custom:regex";
  customOpt.textContent = "Custom regex…";
  customOpt.title = "Test your own regex against the full payload string";
  naiveGroup.appendChild(customOpt);
  els.validator.appendChild(naiveGroup);

  for (const eco of sortedEcos) {
    const og = document.createElement("optgroup");
    og.label = "Real parser (differential) — " + eco;
    for (const p of groups[eco].sort((a, b) => a.name.localeCompare(b.name))) {
      const opt = document.createElement("option");
      opt.value = "parser:" + p.name;
      opt.textContent = p.name;
      opt.title = p.description;
      og.appendChild(opt);
    }
    els.validator.appendChild(og);
  }
  els.validator.value = "naive:contains";
}

function currentInputs() {
  return {
    scheme: els.scheme.value,
    allowedHost: els.allowedHost.value.trim(),
    allowedPort: els.allowedPort.value.trim(),
    targetHost: els.targetHost.value.trim(),
    targetPort: els.targetPort.value.trim(),
    path: els.path.value.trim() || "/",
  };
}

function copyButton(text) {
  const btn = document.createElement("button");
  btn.className = "copy-btn";
  btn.type = "button";
  btn.textContent = "Copy";
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = "Copy"), 1200);
  });
  return btn;
}

// Verdict is computed against the *canonical* probe hostnames baked into the
// matrix (matrix.probe.allowedHost / targetHost), then generalized to the
// user's actual inputs - the probe never saw the real hostnames, only the
// structural position they'd occupy.
function computeVerdict(technique, level, payload, validatorValue, inputs) {
  const probe = state.matrix.probe;

  if (validatorValue === "custom:regex") {
    const pattern = els.customRegexPattern.value;
    if (!pattern) return { status: "error", detail: "enter a regex pattern above" };
    let re;
    try {
      re = new RegExp(pattern, els.customRegexFlags.value.trim());
    } catch (e) {
      return { status: "error", detail: `invalid regex: ${e.message}` };
    }
    const matches = re.test(payload);
    const passes = els.customRegexInvert.checked ? !matches : matches;
    return passes
      ? { status: "bypass", detail: `${matches ? "matches" : "does not match"} your regex` }
      : { status: "blocked", detail: `${matches ? "matches" : "does not match"} your regex` };
  }

  if (validatorValue.startsWith("naive:")) {
    const check = getCheck(validatorValue.slice(6));
    const passes = check.test(payload, inputs.allowedHost, inputs.scheme);
    return passes
      ? { status: "bypass", detail: `passes "${check.label}"` }
      : { status: "blocked", detail: `fails "${check.label}"` };
  }

  const validatorName = validatorValue.slice("parser:".length);
  const valEntry = state.matrix.results[technique.id]?.[validatorName];
  const lvl = valEntry?.levels?.[level];
  if (!lvl || !lvl.ok) {
    return { status: "error", detail: `${validatorName} fails to parse this payload` };
  }
  const h = (lvl.host || "").replace(/\.$/, "").toLowerCase();
  if (h === probe.allowedHost.toLowerCase()) {
    return { status: "bypass", detail: `${validatorName} resolves host to the allowed side` };
  }
  if (h === probe.targetHost.toLowerCase()) {
    return { status: "blocked", detail: `${validatorName} resolves host to the target side (correctly detected)` };
  }
  return { status: "ambiguous", detail: `${validatorName} resolves host to ${lvl.host || "(none)"} (neither side)` };
}

function computeRows(requesterName, validatorValue, inputs) {
  const rows = [];
  for (const t of state.techniques) {
    const reqEntry = state.matrix.results[t.id]?.[requesterName];
    if (!reqEntry || !reqEntry.supported) continue;
    const level = reqEntry.bestLevel;
    const payload = buildPayload(t, level, inputs);
    const verdict = computeVerdict(t, level, payload, validatorValue, inputs);
    rows.push({ technique: t, level, payload, verdict });
  }
  const order = { bypass: 0, ambiguous: 1, blocked: 2, error: 3 };
  rows.sort((a, b) => order[a.verdict.status] - order[b.verdict.status] || a.technique.name.localeCompare(b.technique.name));
  return rows;
}

function renderRow(row) {
  const tr = document.createElement("tr");
  tr.className = "row-" + row.verdict.status;

  const nameTd = document.createElement("td");
  nameTd.className = "col-name";
  const nameEl = document.createElement("div");
  nameEl.className = "tech-name";
  nameEl.textContent = row.technique.name;
  nameEl.title = row.technique.description;
  const famEl = document.createElement("div");
  famEl.className = "tech-family";
  famEl.textContent = FAMILY_LABELS[row.technique.family] || row.technique.family;
  nameTd.appendChild(nameEl);
  nameTd.appendChild(famEl);
  tr.appendChild(nameTd);

  const payloadTd = document.createElement("td");
  payloadTd.className = "col-payload";
  const payloadRow = document.createElement("div");
  payloadRow.className = "payload-row";
  const code = document.createElement("code");
  code.className = "payload";
  code.textContent = row.payload;
  payloadRow.appendChild(code);
  payloadRow.appendChild(copyButton(row.payload));
  const open = document.createElement("a");
  open.href = row.payload;
  open.target = "_blank";
  open.rel = "noopener noreferrer";
  open.className = "open-btn";
  open.textContent = "Open ↗";
  payloadRow.appendChild(open);
  payloadTd.appendChild(payloadRow);
  tr.appendChild(payloadTd);

  const fixTd = document.createElement("td");
  fixTd.className = "col-fix";
  fixTd.textContent = row.level > 0 ? `+${row.level}× ../` : "none";
  tr.appendChild(fixTd);

  const verdictTd = document.createElement("td");
  verdictTd.className = "col-verdict";
  const badge = document.createElement("span");
  badge.className = "badge badge-" + row.verdict.status;
  badge.textContent =
    { bypass: "BYPASS", blocked: "BLOCKED", ambiguous: "AMBIGUOUS", error: "ERROR" }[row.verdict.status];
  verdictTd.appendChild(badge);
  const detail = document.createElement("div");
  detail.className = "verdict-detail";
  detail.textContent = row.verdict.detail;
  verdictTd.appendChild(detail);
  tr.appendChild(verdictTd);

  return tr;
}

// One payload per technique per *distinct* path-correction level seen for
// any of the 32 parsers (plus level 0 as a baseline for techniques with no
// supported parser at all) - unfiltered by bypass/verdict status. Meant for
// blind fuzzing when the target's tech stack isn't known.
function buildAllPayloads(inputs) {
  const lines = [];
  for (const t of state.techniques) {
    const levels = new Set([0]);
    const perParser = state.matrix.results[t.id] || {};
    for (const entry of Object.values(perParser)) {
      if (entry.supported) levels.add(entry.bestLevel);
    }
    for (const level of [...levels].sort((a, b) => a - b)) {
      lines.push(buildPayload(t, level, inputs));
    }
  }
  return lines;
}

function renderAllPayloadsPanel() {
  const inputs = currentInputs();
  if (!inputs.allowedHost || !inputs.targetHost) {
    els.allPayloads.value = "";
    els.allPayloadsCount.textContent = "Enter an allowed host and a target host above.";
    return;
  }
  const lines = buildAllPayloads(inputs);
  els.allPayloads.value = lines.join("\n");
  const withEmbeddedNewline = lines.filter((l) => /[\r\n]/.test(l)).length;
  els.allPayloadsCount.textContent =
    `${lines.length} payloads from all ${state.techniques.length} known techniques - ` +
    `includes ones that don't work for any tested parser. Unfiltered, no requester/validator needed.` +
    (withEmbeddedNewline
      ? ` Note: ${withEmbeddedNewline} of them contain a literal CR/LF and will visually span extra lines below.`
      : "");
}

function render() {
  const inputs = currentInputs();
  if (!inputs.allowedHost || !inputs.targetHost) {
    els.tbody.innerHTML = "";
    els.summary.textContent = "Enter at least an allowed host and a target host.";
    return;
  }

  const requesterName = els.requester.value;
  const validatorValue = els.validator.value;
  const rows = computeRows(requesterName, validatorValue, inputs).filter((r) => r.verdict.status === "bypass");

  els.tbody.innerHTML = "";
  for (const row of rows) els.tbody.appendChild(renderRow(row));

  if (rows.length === 0) {
    els.summary.textContent = "No working payload for this configuration in our database.";
    return;
  }

  els.summary.textContent = `${rows.length} working payload${rows.length === 1 ? "" : "s"} found.`;
}

function renderIpPanel() {
  const val = els.ipInput.value.trim();
  els.ipOutput.innerHTML = "";
  if (!isIPv4(val)) {
    if (val) els.ipOutput.innerHTML = '<p class="empty">Not a valid IPv4 address.</p>';
    return;
  }
  const variants = ipv4Variants(val);
  const list = document.createElement("div");
  list.className = "ip-variants";
  for (const v of variants) {
    const row = document.createElement("div");
    row.className = "ip-variant-row";
    const label = document.createElement("span");
    label.className = "ip-label";
    label.textContent = v.label;
    const code = document.createElement("code");
    code.textContent = v.value;
    row.appendChild(label);
    row.appendChild(code);
    row.appendChild(copyButton(v.value));

    const useAsTarget = document.createElement("button");
    useAsTarget.type = "button";
    useAsTarget.className = "use-btn";
    useAsTarget.textContent = "→ target";
    useAsTarget.addEventListener("click", () => {
      els.targetHost.value = v.value.replace(/^\[|\]$/g, "");
      render();
    });
    row.appendChild(useAsTarget);

    list.appendChild(row);
  }
  els.ipOutput.appendChild(list);
}

async function init() {
  els.scheme = $("scheme");
  els.allowedHost = $("allowedHost");
  els.allowedPort = $("allowedPort");
  els.targetHost = $("targetHost");
  els.targetPort = $("targetPort");
  els.path = $("path");
  els.requester = $("requester");
  els.validator = $("validator");
  els.tbody = $("resultsBody");
  els.summary = $("summary");
  els.ipInput = $("ipInput");
  els.ipOutput = $("ipOutput");
  els.loadError = $("loadError");
  els.allPayloads = $("allPayloads");
  els.allPayloadsCount = $("allPayloadsCount");
  els.copyAllBtn = $("copyAllBtn");
  els.customRegexBlock = $("customRegexBlock");
  els.customRegexPattern = $("customRegexPattern");
  els.customRegexFlags = $("customRegexFlags");
  els.customRegexInvert = $("customRegexInvert");

  try {
    await loadData();
  } catch (e) {
    els.loadError.style.display = "block";
    console.error(e);
    return;
  }

  populateParserSelects();

  const rerender = () => {
    render();
    renderAllPayloadsPanel();
  };
  for (const el of [els.scheme, els.allowedHost, els.allowedPort, els.targetHost, els.targetPort, els.path, els.requester, els.validator]) {
    el.addEventListener("input", rerender);
    el.addEventListener("change", rerender);
  }
  for (const el of [els.customRegexPattern, els.customRegexFlags, els.customRegexInvert]) {
    el.addEventListener("input", render);
    el.addEventListener("change", render);
  }
  els.validator.addEventListener("change", () => {
    els.customRegexBlock.style.display = els.validator.value === "custom:regex" ? "flex" : "none";
  });
  els.ipInput.addEventListener("input", renderIpPanel);
  els.copyAllBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(els.allPayloads.value);
    } catch {
      els.allPayloads.select();
      document.execCommand("copy");
    }
    els.copyAllBtn.textContent = "Copied!";
    setTimeout(() => (els.copyAllBtn.textContent = "Copy all"), 1200);
  });

  rerender();
}

init();
