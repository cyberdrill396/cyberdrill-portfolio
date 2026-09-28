const $ = id => document.getElementById(id);

const iface = $("interface");
const packetBody = $("packets");
const search = $("search");
const protocolFilter = $("protocol");
const displayFilterInput = $("display-filter");
const chart = $("traffic-chart");
const chartContext = chart.getContext("2d");
const packetArchive = [];
const packetById = new Map();
const rateSamples = Array(60).fill(0);
const maxPackets = 10000;
const maxRows = 500;

let ws;
let totalPackets = 0;
let totalBytes = 0;
let packetsThisSecond = 0;
let packetKeySequence = 0;
let captureRunning = false;
let capturePaused = false;
let hasTraffic = false;

function connect() {
  ws = new WebSocket(`ws://${location.host}`);
  ws.onopen = () => {
    $("connection").textContent = "Online";
    $("connection").className = "connection online";
  };
  ws.onclose = () => {
    $("connection").textContent = "Offline";
    $("connection").className = "connection";
    window.setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = event => {
    let message;
    try { message = JSON.parse(event.data); }
    catch { showNotice("Received an unreadable message from the capture service."); return; }

    if (message.type === "hello") {
      updateStatus(message.running, message.paused, message.device);
      displayFilterInput.value = message.displayFilter || "";
      setDisplayFilterStatus(message.displayFilter ? "Active" : "TShark display filter");
    }
    else if (message.type === "interfaces") populateInterfaces(message.interfaces || []);
    else if (message.type === "packet") addPacket(message.packet);
    else if (message.type === "status") {
      updateStatus(message.running, message.paused, message.device);
      if (message.displayFilter != null) {
        displayFilterInput.value = message.displayFilter;
        setDisplayFilterStatus(message.displayFilter ? "Active" : "TShark display filter");
      }
    } else if (message.type === "filter") {
      displayFilterInput.value = message.displayFilter || "";
      setDisplayFilterStatus(message.displayFilter ? "Saved for next capture" : "TShark display filter");
    } else if (message.type === "filter-check") {
      handleFilterCheck(message);
    } else if (message.type === "clear-packets") {
      clearCapture();
    } else if (message.type === "error") {
      if (message.code === "INVALID_DISPLAY_FILTER") setDisplayFilterStatus("Invalid filter", "invalid");
      showNotice(message.message);
    }
  };
}

function populateInterfaces(interfaces) {
  const previous = iface.value;
  iface.replaceChildren();
  if (!interfaces.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "No interfaces found";
    iface.append(option);
    return;
  }
  for (const item of interfaces) {
    const option = document.createElement("option");
    option.value = item.index;
    const addresses = item.addresses?.length ? `  /  ${item.addresses.join(", ")}` : "";
    option.textContent = `${item.description || item.name}${addresses}`;
    iface.append(option);
  }
  if (interfaces.some(item => item.index === previous)) iface.value = previous;
}

function updateStatus(running, paused, device) {
  captureRunning = Boolean(running);
  capturePaused = Boolean(paused);
  $("start").disabled = captureRunning;
  $("stop").disabled = !captureRunning;
  $("pause").disabled = !captureRunning;
  iface.disabled = captureRunning;
  $("pause-label").textContent = capturePaused ? "Resume" : "Pause";
  $("pause-symbol").textContent = capturePaused ? "▶" : "Ⅱ";
  $("status").textContent = !captureRunning ? "Idle" : capturePaused ? "Paused" : "Capturing";
  $("state-indicator").className = `state-indicator${captureRunning ? " active" : ""}${capturePaused ? " paused" : ""}`;
  if (device) $("active-interface").textContent = device;
  else if (!captureRunning) $("active-interface").textContent = "None";
  if (captureRunning) hideNotice();
}

function send(message) {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify(message));
}

function showNotice(message) {
  const notice = $("notice");
  notice.textContent = message;
  notice.hidden = false;
}

function hideNotice() { $("notice").hidden = true; }

function setDisplayFilterStatus(message, state = "") {
  const status = $("display-filter-status");
  status.textContent = message;
  status.className = `display-filter-status${state ? ` ${state}` : ""}`;
}

function requestDisplayFilterValidation() {
  const expression = displayFilterInput.value.trim();
  setDisplayFilterStatus("Checking filter...");
  send({ type: "validate-display-filter", expression });
}

function handleFilterCheck(message) {
  if (!message.valid) {
    setDisplayFilterStatus("Invalid filter", "invalid");
    showNotice(message.error || "The display filter is not valid.");
    return;
  }

  if (captureRunning && totalPackets > 0 &&
      !window.confirm("Applying a display filter restarts capture and clears the current packet list. Continue?")) {
    setDisplayFilterStatus("Filter unchanged");
    return;
  }

  hideNotice();
  setDisplayFilterStatus(captureRunning ? "Restarting capture..." : "Saving filter...");
  send({ type: "apply-display-filter", expression: message.expression });
}

function addPacket(packet, { live = true } = {}) {
  if (!packet || packet.id == null) return;
  if (live) hasTraffic = true;
  packetArchive.push(packet);
  totalPackets++;
  totalBytes += Number(packet.length) || 0;
  if (live) packetsThisSecond++;
  if (packetArchive.length > maxPackets) {
    packetArchive.shift();
  }

  $("total").textContent = totalPackets.toLocaleString();
  $("bytes").textContent = formatBytes(totalBytes);
  $("empty").hidden = true;

  const row = document.createElement("tr");
  const packetKey = String(++packetKeySequence);
  packetById.set(packetKey, packet);
  row.dataset.packetKey = packetKey;
  row.tabIndex = 0;
  row.setAttribute("aria-label", `${packet.protocol} packet from ${packet.srcIp || "unknown"} to ${packet.dstIp || "unknown"}`);
  const values = [packet.frame ?? packet.id, new Date(packet.timestamp).toLocaleTimeString(),
    endpoint(packet.srcIp, packet.srcPort), endpoint(packet.dstIp, packet.dstPort), formatBytes(packet.length),
    `${packet.host || ""}${packet.path || ""}` || "—", packet.info || "—"];
  const numberCell = row.insertCell();
  numberCell.textContent = String(values[0]);
  numberCell.className = "frame-number";
  row.insertCell().textContent = values[1];
  const protocolCell = row.insertCell();
  protocolCell.textContent = packet.protocol || "OTHER";
  protocolCell.className = `protocol-text ${protocolClass(packet.protocol)}`;
  for (const value of values.slice(2)) row.insertCell().textContent = String(value);
  row.addEventListener("click", () => selectPacket(packet, row));
  row.addEventListener("keydown", event => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectPacket(packet, row); }
  });
  packetBody.append(row);
  while (packetBody.children.length > maxRows) {
    const oldestRow = packetBody.firstElementChild;
    packetById.delete(oldestRow.dataset.packetKey);
    oldestRow.remove();
  }
  applyFilters();
  if ($("autoScroll").checked) {
    const table = packetBody.closest(".table-wrap");
    table.scrollTop = table.scrollHeight;
  }
}

function endpoint(address, port) {
  if (!address) return "—";
  return port == null ? address : `${address}:${port}`;
}

function protocolClass(protocol) {
  return `proto-${String(protocol || "OTHER").replace(/[^a-z0-9]/gi, "").toUpperCase()}`;
}

function packetMatches(packet, query, selectedProtocol) {
  const searchable = [packet.id, packet.frame, packet.timestamp, packet.protocol, packet.srcIp, packet.dstIp,
    packet.srcPort, packet.dstPort, packet.host, packet.path, packet.length, packet.info, packet.interface,
    ...(packet.layers || []).flatMap(layer => [layer.name, ...layer.fields.flat()])].join(" ").toLowerCase();
  return (!query || searchable.includes(query)) &&
    (selectedProtocol === "ALL" || (selectedProtocol === "OTHER"
      ? !["TCP", "UDP", "ICMP", "ICMPV6", "ARP"].includes(packet.protocol)
      : packet.protocol === selectedProtocol));
}

function applyFilters() {
  const query = search.value.trim().toLowerCase();
  const selectedProtocol = protocolFilter.value;
  let visible = 0;
  for (const row of packetBody.children) {
    const packet = packetById.get(row.dataset.packetKey);
    const matches = packet && packetMatches(packet, query, selectedProtocol);
    row.hidden = !matches;
    if (matches) visible++;
  }
  $("visible-count").textContent = visible.toLocaleString();
  $("table-summary").textContent = `${visible.toLocaleString()} visible / ${totalPackets.toLocaleString()} total`;
}

function selectPacket(packet, row) {
  packetBody.querySelector("tr.selected")?.classList.remove("selected");
  row.classList.add("selected");
  $("detail-empty").hidden = true;
  $("detail-layers").hidden = false;
  $("detail-protocol").textContent = packet.protocol || "OTHER";
  $("detail-protocol").className = `protocol-chip ${protocolClass(packet.protocol)}`;
  const layers = packet.layers?.length ? packet.layers : [{
    name: "Packet summary",
    fields: [
      ["Frame", packet.frame ?? packet.id], ["Timestamp", new Date(packet.timestamp).toLocaleString()],
      ["Protocol", packet.protocol || "OTHER"], ["Source", endpoint(packet.srcIp, packet.srcPort)],
      ["Destination", endpoint(packet.dstIp, packet.dstPort)], ["Length", `${packet.length} bytes`],
      ["Interface", packet.interface || "—"], ["Summary", packet.info || "—"]
    ]
  }];
  const container = $("detail-layers");
  container.replaceChildren();
  for (const [index, layer] of layers.entries()) {
    const section = document.createElement("details");
    section.className = "protocol-layer";
    section.open = index === 0;
    const heading = document.createElement("summary");
    heading.textContent = `${layer.name} (${layer.fields.length})`;
    const fields = document.createElement("dl");
    fields.className = "layer-fields";
    for (const [label, value] of layer.fields) {
      const term = document.createElement("dt");
      const description = document.createElement("dd");
      term.textContent = label;
      description.textContent = String(value);
      fields.append(term, description);
    }
    section.append(heading, fields);
    container.append(section);
  }
}

function clearCapture() {
  packetArchive.length = 0;
  packetById.clear();
  packetBody.replaceChildren();
  totalPackets = 0;
  totalBytes = 0;
  packetsThisSecond = 0;
  hasTraffic = false;
  rateSamples.fill(0);
  $("total").textContent = "0";
  $("bytes").textContent = "0 B";
  $("pps").textContent = "0";
  $("empty").hidden = false;
  $("detail-empty").hidden = false;
  $("detail-layers").hidden = true;
  $("detail-protocol").textContent = "—";
  $("detail-protocol").className = "protocol-chip";
  $("chart-empty").hidden = false;
  applyFilters();
  drawChart();
}

function exportCapture(format) {
  const query = search.value.trim().toLowerCase();
  const selectedProtocol = protocolFilter.value;
  const records = packetArchive.filter(packet => packetMatches(packet, query, selectedProtocol));
  if (!records.length) { showNotice("There are no matching packets to export."); return; }
  let content;
  let mimeType;
  let extension;
  if (format === "json") {
    content = JSON.stringify(records, null, 2);
    mimeType = "application/json";
    extension = "json";
  } else {
    const columns = ["id", "frame", "timestamp", "protocol", "srcIp", "srcPort", "dstIp", "dstPort", "host", "path", "length", "info", "interface"];
    content = [columns.join(","), ...records.map(packet => columns.map(column => csvCell(packet[column])).join(","))].join("\r\n");
    mimeType = "text/csv;charset=utf-8";
    extension = "csv";
  }
  downloadFile(content, mimeType, extension);
}

function saveCapture() {
  if (!packetArchive.length) {
    showNotice("There are no packets to save yet.");
    return;
  }
  const capture = {
    format: "packetscope-capture",
    version: 1,
    savedAt: new Date().toISOString(),
    packets: packetArchive
  };
  downloadFile(JSON.stringify(capture, null, 2), "application/json", "json");
}

function downloadFile(content, mimeType, extension) {
  const url = URL.createObjectURL(new Blob([content], { type: mimeType }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `packets-${new Date().toISOString().replace(/[:.]/g, "-")}.${extension}`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index++) {
    const character = text[index];
    if (character === '"') {
      if (quoted && text[index + 1] === '"') {
        value += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (character === "," && !quoted) {
      row.push(value);
      value = "";
    } else if ((character === "\n" || character === "\r") && !quoted) {
      if (character === "\r" && text[index + 1] === "\n") index++;
      row.push(value);
      if (row.some(cell => cell.trim())) rows.push(row);
      row = [];
      value = "";
    } else {
      value += character;
    }
  }
  row.push(value);
  if (row.some(cell => cell.trim())) rows.push(row);
  if (quoted) throw new Error("The CSV file has an unterminated quoted field.");
  if (rows.length < 2) return [];

  const aliases = { srcip: "srcIp", srcport: "srcPort", dstip: "dstIp", dstport: "dstPort" };
  const headings = rows[0].map(name => {
    const key = name.trim().replace(/^\uFEFF/, "").toLowerCase();
    return aliases[key] || key;
  });
  return rows.slice(1).map(cells => Object.fromEntries(
    headings.map((heading, index) => [heading, cells[index] ?? ""]
  )));
}

function normalizeImportedPacket(packet, index) {
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) return null;
  const protocol = String(packet.protocol || "").trim().toUpperCase();
  const length = Number(packet.length);
  if (!protocol || !Number.isFinite(length) || length < 0) return null;
  const timestampValue = packet.timestamp ? new Date(packet.timestamp) : new Date();
  const timestamp = Number.isNaN(timestampValue.getTime()) ? new Date().toISOString() : timestampValue.toISOString();
  const parsePort = value => {
    if (value == null || value === "") return null;
    const port = Number(value);
    return Number.isInteger(port) && port >= 0 && port <= 65535 ? port : null;
  };
  return {
    id: `import-${index + 1}`,
    frame: packet.frame ?? packet.id ?? index + 1,
    timestamp,
    protocol,
    srcIp: String(packet.srcIp || ""),
    dstIp: String(packet.dstIp || ""),
    srcPort: parsePort(packet.srcPort),
    dstPort: parsePort(packet.dstPort),
    host: String(packet.host || ""),
    path: String(packet.path || ""),
    length,
    info: String(packet.info || ""),
    interface: String(packet.interface || "Imported file")
  };
}

async function importCapture(file) {
  if (!file) return;
  try {
    const text = await file.text();
    let records;
    if (file.name.toLowerCase().endsWith(".csv")) {
      records = parseCsv(text);
    } else {
      const data = JSON.parse(text);
      records = Array.isArray(data) ? data : data.packets || data.records;
    }
    if (!Array.isArray(records)) throw new Error("Choose a packet JSON array, saved capture, or CSV export.");

    const imported = records.slice(0, maxPackets)
      .map(normalizeImportedPacket)
      .filter(Boolean);
    if (!imported.length) throw new Error("No valid packet records were found in that file.");

    if (captureRunning) send({ type: "stop" });
    clearCapture();
    search.value = "";
    protocolFilter.value = "ALL";
    for (const packet of imported) addPacket(packet, { live: false });
    showNotice(`Imported ${imported.length.toLocaleString()} packet${imported.length === 1 ? "" : "s"}.`);
  } catch (error) {
    showNotice(`Import failed: ${error.message}`);
  } finally {
    $("import-file").value = "";
  }
}

function csvCell(value) { return `"${String(value ?? "").replaceAll('"', '""')}"`; }

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`;
  return `${(value / 1024 ** 3).toFixed(2)} GB`;
}

function drawChart() {
  const bounds = chart.getBoundingClientRect();
  if (!bounds.width || !bounds.height) return;
  const ratio = window.devicePixelRatio || 1;
  chart.width = Math.round(bounds.width * ratio);
  chart.height = Math.round(bounds.height * ratio);
  chartContext.setTransform(ratio, 0, 0, ratio, 0, 0);
  const width = bounds.width;
  const height = bounds.height;
  const left = 38;
  const right = width - 8;
  const top = 9;
  const bottom = height - 23;
  const maxRate = Math.max(4, ...rateSamples);
  chartContext.clearRect(0, 0, width, height);
  chartContext.font = '10px "Cascadia Code", Consolas, monospace';
  chartContext.textBaseline = "middle";
  for (let line = 0; line <= 3; line++) {
    const y = top + (bottom - top) * line / 3;
    chartContext.strokeStyle = "rgba(173, 191, 178, 0.12)";
    chartContext.beginPath();
    chartContext.moveTo(left, y);
    chartContext.lineTo(right, y);
    chartContext.stroke();
    chartContext.fillStyle = "#77837a";
    chartContext.textAlign = "right";
    chartContext.fillText(String(Math.round(maxRate * (3 - line) / 3)), left - 8, y);
  }
  const points = rateSamples.map((sample, index) => ({
    x: left + (right - left) * index / (rateSamples.length - 1),
    y: bottom - (bottom - top) * sample / maxRate
  }));
  const fill = chartContext.createLinearGradient(0, top, 0, bottom);
  fill.addColorStop(0, "rgba(177, 238, 75, 0.2)");
  fill.addColorStop(1, "rgba(177, 238, 75, 0)");
  chartContext.beginPath();
  chartContext.moveTo(points[0].x, bottom);
  for (const point of points) chartContext.lineTo(point.x, point.y);
  chartContext.lineTo(points.at(-1).x, bottom);
  chartContext.closePath();
  chartContext.fillStyle = fill;
  chartContext.fill();
  chartContext.beginPath();
  points.forEach((point, index) => index === 0 ? chartContext.moveTo(point.x, point.y) : chartContext.lineTo(point.x, point.y));
  chartContext.strokeStyle = "#b1ee4b";
  chartContext.lineWidth = 2;
  chartContext.stroke();
  chartContext.fillStyle = "#77837a";
  chartContext.textAlign = "left";
  chartContext.fillText("60s ago", left, height - 8);
  chartContext.textAlign = "right";
  chartContext.fillText("now", right, height - 8);
}

$("start").addEventListener("click", () => {
  if (!iface.value) { showNotice("Select a network interface before starting capture."); return; }
  hideNotice();
  send({ type: "start", device: iface.value });
});
$("stop").addEventListener("click", () => send({ type: "stop" }));
$("pause").addEventListener("click", () => send({ type: "pause", paused: !capturePaused }));
$("refresh").addEventListener("click", () => send({ type: "interfaces" }));
$("clear").addEventListener("click", clearCapture);
$("export-csv").addEventListener("click", () => exportCapture("csv"));
$("export-json").addEventListener("click", () => exportCapture("json"));
$("save-capture").addEventListener("click", saveCapture);
$("import-capture").addEventListener("click", () => $("import-file").click());
$("import-file").addEventListener("change", event => importCapture(event.target.files[0]));
$("apply-display-filter").addEventListener("click", requestDisplayFilterValidation);
$("clear-display-filter").addEventListener("click", () => {
  displayFilterInput.value = "";
  requestDisplayFilterValidation();
});
displayFilterInput.addEventListener("keydown", event => {
  if (event.key === "Enter") requestDisplayFilterValidation();
});
for (const button of document.querySelectorAll("[data-filter]")) {
  button.addEventListener("click", () => {
    displayFilterInput.value = button.dataset.filter;
    requestDisplayFilterValidation();
  });
}
search.addEventListener("input", applyFilters);
protocolFilter.addEventListener("change", applyFilters);
window.addEventListener("resize", drawChart);
window.addEventListener("keydown", event => {
  if (event.key === "/" && !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    search.focus();
  }
});

window.setInterval(() => {
  const rate = packetsThisSecond;
  packetsThisSecond = 0;
  rateSamples.push(rate);
  rateSamples.shift();
  $("pps").textContent = rate.toLocaleString();
  $("chart-empty").hidden = hasTraffic;
  drawChart();
}, 1000);

connect();
drawChart();