const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const { execFile, spawn } = require("child_process");
const { promisify } = require("util");
const { WebSocketServer } = require("ws");

const execFileAsync = promisify(execFile);
const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT) || 8080;
const PUBLIC_DIR = path.join(__dirname, "public");
const TSHARK_CANDIDATES = [
  process.env.TSHARK_PATH,
  "C:\\Program Files\\Wireshark\\tshark.exe",
  "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
  "tshark"
].filter(Boolean);

let tsharkPath = null;
let captureProcess = null;
let captureDevice = null;
let running = false;
let paused = false;
let packetCount = 0;
let displayFilter = "";
const clients = new Set();
const CAPTURE_FIELDS = [
  "frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol",
  "ip.src", "ipv6.src", "arp.src.proto_ipv4", "ip.dst", "ipv6.dst", "arp.dst.proto_ipv4",
  "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "icmp.type", "_ws.col.Info",
  "frame.protocols", "eth.src", "eth.dst", "eth.type", "vlan.id", "ip.ttl", "ip.id",
  "tcp.flags", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.checksum", "udp.length",
  "dns.qry.name", "dns.qry.type", "http.request.method", "http.host", "tls.handshake.type",
  "arp.opcode", "arp.src.hw_mac", "arp.dst.hw_mac", "icmp.code", "icmpv6.type", "icmpv6.code",
  "dns.resp.name", "dns.a", "dns.aaaa", "tls.handshake.extensions_server_name",
  "tls.handshake.extensions_alpn_str", "http.request.uri", "http.response.code", "tcp.stream",
  "udp.stream", "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment",
  "ipv6.hlim", "ip.dsfield"
];

function broadcast(message) {
  const text = JSON.stringify(message);
  for (const ws of clients) {
    if (ws.readyState === 1) ws.send(text);
  }
}

async function findTshark() {
  if (tsharkPath) return tsharkPath;

  for (const candidate of TSHARK_CANDIDATES) {
    try {
      await execFileAsync(candidate, ["--version"], { windowsHide: true, timeout: 5000 });
      tsharkPath = candidate;
      return tsharkPath;
    } catch {
      // Continue through standard Wireshark install locations and PATH.
    }
  }

  throw new Error("Wireshark's tshark.exe was not found. Install Wireshark with Npcap, or set TSHARK_PATH to tshark.exe.");
}

async function listInterfaces() {
  const executable = await findTshark();
  const { stdout } = await execFileAsync(executable, ["-D"], { windowsHide: true, timeout: 10000 });
  const adapters = os.networkInterfaces();
  return stdout.split(/\r?\n/).flatMap(line => {
    const match = line.trim().match(/^(\d+)\.\s+(.+?)(?:\s+\(([^()]*)\))?$/);
    if (!match) return [];

    const name = match[2].trim();
    const description = (match[3] || name).trim();
    const addresses = adapters[description] || adapters[name] || [];
    return [{
      index: match[1],
      name,
      description,
      addresses: addresses.map(address => address.address).filter(Boolean)
    }];
  });
}

async function validateDisplayFilter(filter) {
  if (!filter) return;
  if (filter.length > 1024) throw new Error("Display filters must be 1,024 characters or fewer.");
  const executable = await findTshark();
  try {
    await execFileAsync(executable, ["-r", "NUL", "-Y", filter, "-T", "fields", "-e", "frame.number"], {
      windowsHide: true,
      timeout: 5000
    });
  } catch (error) {
    const output = [error.stderr, error.stdout, error.message].filter(Boolean).join(" ");
    if (/special file|non-regular file/i.test(output)) return;
    throw new Error(`Invalid Wireshark display filter: ${output.trim()}`);
  }
}

function parseFields(line) {
  const fields = [];
  let value = "";
  let quoted = false;

  for (let index = 0; index < line.length; index++) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        value += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (character === "\t" && !quoted) {
      fields.push(value);
      value = "";
    } else {
      value += character;
    }
  }

  fields.push(value);
  return fields;
}

function safeHttpPath(uri) {
  if (!uri) return "";
  try {
    if (/^[a-z][a-z\d+.-]*:\/\//i.test(uri)) return new URL(uri).pathname;
  } catch {
    return "[invalid URI]";
  }
  return uri.split(/[?#]/, 1)[0];
}

function safePacketInfo(info) {
  return info
    .replace(/\b(https?):\/\/[^\s/@]*@/gi, "$1://[redacted]@")
    .replace(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)/gi, (_, method, uri) => `${method} ${safeHttpPath(uri)}`)
    .replace(/\b(authorization|proxy-authorization|cookie|set-cookie)\s*:.+$/i, "$1: [redacted]");
}

function parsePacket(line) {
  const fields = parseFields(line);
  if (fields.length < CAPTURE_FIELDS.length) return null;
  const values = Object.fromEntries(CAPTURE_FIELDS.map((field, index) => [field, fields[index] || ""]));
  const frameNumber = values["frame.number"];
  const epoch = values["frame.time_epoch"];
  const length = values["frame.len"];
  const seconds = Number(epoch);
  const packetProtocol = values["_ws.col.Protocol"].trim().toUpperCase() || "OTHER";
  const sourcePort = values["tcp.srcport"] || values["udp.srcport"];
  const destinationPort = values["tcp.dstport"] || values["udp.dstport"];
  const sourceIp = values["ip.src"] || values["ipv6.src"] || values["arp.src.proto_ipv4"];
  const destinationIp = values["ip.dst"] || values["ipv6.dst"] || values["arp.dst.proto_ipv4"];
  const host = values["http.host"] || values["tls.handshake.extensions_server_name"] || values["dns.qry.name"] || values["dns.resp.name"];
  const httpPath = safeHttpPath(values["http.request.uri"]);
  const layers = [
    { name: "Frame", fields: [["Frame number", frameNumber], ["Captured length", `${length} bytes`], ["Decoded protocols", values["frame.protocols"]]] },
    { name: "Ethernet II", fields: [["Source", values["eth.src"]], ["Destination", values["eth.dst"]], ["Type", values["eth.type"]]] },
    { name: "802.1Q VLAN", fields: [["VLAN ID", values["vlan.id"]]] },
    { name: "Internet Protocol", fields: [["Source", values["ip.src"]], ["Destination", values["ip.dst"]], ["TTL", values["ip.ttl"]], ["Identification", values["ip.id"]], ["DS field", values["ip.dsfield"]]] },
    { name: "Internet Protocol Version 6", fields: [["Source", values["ipv6.src"]], ["Destination", values["ipv6.dst"]], ["Hop limit", values["ipv6.hlim"]]] },
    { name: "Address Resolution Protocol", fields: [["Operation", values["arp.opcode"]], ["Sender MAC", values["arp.src.hw_mac"]], ["Target MAC", values["arp.dst.hw_mac"]], ["Sender IP", values["arp.src.proto_ipv4"]], ["Target IP", values["arp.dst.proto_ipv4"]]] },
    { name: "Transmission Control Protocol", fields: [["Source port", values["tcp.srcport"]], ["Destination port", values["tcp.dstport"]], ["Stream", values["tcp.stream"]], ["Flags", values["tcp.flags"]], ["Sequence", values["tcp.seq"]], ["Acknowledgment", values["tcp.ack"]], ["Window", values["tcp.window_size"]], ["Checksum", values["tcp.checksum"]], ["Retransmission", values["tcp.analysis.retransmission"] ? "Yes" : ""], ["Duplicate ACK", values["tcp.analysis.duplicate_ack"] ? "Yes" : ""], ["Lost segment", values["tcp.analysis.lost_segment"] ? "Yes" : ""]] },
    { name: "User Datagram Protocol", fields: [["Source port", values["udp.srcport"]], ["Destination port", values["udp.dstport"]], ["Stream", values["udp.stream"]], ["Length", values["udp.length"]]] },
    { name: "Domain Name System", fields: [["Query name", values["dns.qry.name"]], ["Query type", values["dns.qry.type"]], ["Response name", values["dns.resp.name"]], ["IPv4 answer", values["dns.a"]], ["IPv6 answer", values["dns.aaaa"]]] },
    { name: "Hypertext Transfer Protocol", fields: [["Request method", values["http.request.method"]], ["Host", values["http.host"]], ["Path", safeHttpPath(values["http.request.uri"])], ["Response code", values["http.response.code"]]] },
    { name: "Transport Layer Security", fields: [["Handshake type", values["tls.handshake.type"]], ["Server name", values["tls.handshake.extensions_server_name"]], ["ALPN", values["tls.handshake.extensions_alpn_str"]]] },
    { name: "Internet Control Message Protocol", fields: [["Type", values["icmp.type"]], ["Code", values["icmp.code"]], ["IPv6 type", values["icmpv6.type"]], ["IPv6 code", values["icmpv6.code"]]] }
  ].map(layer => ({ ...layer, fields: layer.fields.filter(([, value]) => value) }))
    .filter(layer => layer.fields.length);

  return {
    id: ++packetCount,
    frame: Number(frameNumber) || packetCount,
    timestamp: Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString() : new Date().toISOString(),
    protocol: packetProtocol,
    srcIp: sourceIp,
    dstIp: destinationIp,
    srcPort: sourcePort ? Number(sourcePort) : null,
    dstPort: destinationPort ? Number(destinationPort) : null,
    length: Number(length) || 0,
    host,
    path: httpPath,
    info: safePacketInfo(values["_ws.col.Info"] || (values["icmp.type"] ? `ICMP type ${values["icmp.type"]}` : "")),
    interface: captureDevice ? captureDevice.description : "",
    layers
  };
}

function stopCapture() {
  const child = captureProcess;
  captureProcess = null;
  running = false;
  paused = false;
  captureDevice = null;
  if (child && !child.killed) child.kill();
}

async function startCapture(deviceIndex, filter = displayFilter, preserveCount = false) {
  stopCapture();
  const interfaces = await listInterfaces();
  const selected = interfaces.find(item => item.index === String(deviceIndex));
  if (!selected) throw new Error("That interface is no longer available. Refresh the interface list and try again.");

  const executable = await findTshark();
  if (!preserveCount) packetCount = 0;
  captureDevice = selected;
  broadcast({ type: "clear-packets" });
  const args = [
    "-l", "-n", "-i", selected.index,
    "-f", "ip or ip6 or arp",
    ...(filter ? ["-Y", filter] : []),
    "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f",
    ...CAPTURE_FIELDS.flatMap(field => ["-e", field])
  ];

  const child = spawn(executable, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  captureProcess = child;
  running = true;
  paused = false;

  let remainder = "";
  let errorOutput = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", chunk => {
    remainder += chunk;
    const lines = remainder.split(/\r?\n/);
    remainder = lines.pop();
    if (paused || captureProcess !== child) return;

    for (const line of lines) {
      if (!line) continue;
      try {
        const packet = parsePacket(line);
        if (packet) broadcast({ type: "packet", packet });
      } catch (error) {
        broadcast({ type: "error", message: `Could not parse a captured packet: ${error.message}` });
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", chunk => { errorOutput = (errorOutput + chunk).slice(-4000); });
  child.on("error", error => {
    if (captureProcess !== child) return;
    stopCapture();
    broadcast({ type: "error", message: `Could not start tshark: ${error.message}` });
    broadcast({ type: "status", running: false, paused: false });
  });
  child.on("close", code => {
    if (captureProcess !== child) return;
    captureProcess = null;
    running = false;
    paused = false;
    captureDevice = null;
    if (code !== 0 && errorOutput.trim()) {
      broadcast({ type: "error", message: `Capture stopped: ${errorOutput.trim()}` });
    }
    broadcast({ type: "status", running: false, paused: false });
  });

  broadcast({ type: "status", running: true, paused: false, device: selected.description, displayFilter: filter });
}

async function applyDisplayFilter(expression) {
  const filter = String(expression || "").trim();
  if (filter.length > 1024) throw new Error("Display filters must be 1,024 characters or fewer.");
  await validateDisplayFilter(filter);
  const activeIndex = running ? captureDevice?.index : null;
  displayFilter = filter;
  if (activeIndex) {
    await startCapture(activeIndex, filter, true);
  } else {
    broadcast({ type: "filter", displayFilter });
  }
}

const server = http.createServer((req, res) => {
  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(req.url, `http://${HOST}`).pathname);
  } catch {
    res.writeHead(400);
    return res.end("Bad request");
  }
  if (urlPath === "/") urlPath = "/index.html";

  const filePath = path.resolve(PUBLIC_DIR, `.${urlPath}`);
  if (filePath !== PUBLIC_DIR && !filePath.startsWith(`${PUBLIC_DIR}${path.sep}`)) {
    res.writeHead(403);
    return res.end("Forbidden");
  }

  fs.readFile(filePath, (error, data) => {
    if (error) {
      res.writeHead(404);
      return res.end("Not found");
    }
    const types = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "application/javascript; charset=utf-8"
    };
    res.writeHead(200, { "Content-Type": types[path.extname(filePath)] || "application/octet-stream", "Cache-Control": "no-store" });
    res.end(data);
  });
});

const wss = new WebSocketServer({ server, maxPayload: 1024 * 1024 });
wss.on("connection", ws => {
  clients.add(ws);
  ws.send(JSON.stringify({ type: "hello", running, paused, device: captureDevice?.description || null, displayFilter }));
  listInterfaces().then(interfaces => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: "interfaces", interfaces }));
  }).catch(error => {
    if (ws.readyState === 1) ws.send(JSON.stringify({ type: "error", message: error.message }));
  });

  ws.on("message", raw => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      ws.send(JSON.stringify({ type: "error", message: "Invalid command." }));
      return;
    }

    if (message.type === "interfaces") {
      listInterfaces().then(interfaces => ws.send(JSON.stringify({ type: "interfaces", interfaces })))
        .catch(error => ws.send(JSON.stringify({ type: "error", message: error.message })));
    } else if (message.type === "start") {
      startCapture(message.device).catch(error => ws.send(JSON.stringify({ type: "error", message: error.message })));
    } else if (message.type === "validate-display-filter") {
      const expression = String(message.expression || "").trim();
      validateDisplayFilter(expression).then(() => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "filter-check", valid: true, expression }));
      }).catch(error => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "filter-check", valid: false, expression, error: error.message }));
      });
    } else if (message.type === "apply-display-filter") {
      applyDisplayFilter(message.expression).catch(error => {
        if (ws.readyState === 1) ws.send(JSON.stringify({ type: "error", code: "INVALID_DISPLAY_FILTER", message: error.message }));
      });
    } else if (message.type === "stop") {
      stopCapture();
      broadcast({ type: "status", running: false, paused: false });
    } else if (message.type === "pause" && running) {
      paused = Boolean(message.paused);
      broadcast({ type: "status", running, paused, device: captureDevice?.description || null });
    }
  });

  ws.on("close", () => clients.delete(ws));
});

function listen(port = PORT) {
  return new Promise((resolve, reject) => {
    const onError = error => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      const address = server.address();
      console.log(`PacketScope is ready at http://${HOST}:${address.port}`);
      resolve(address);
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, HOST);
  });
}

function close() {
  stopCapture();
  for (const client of wss.clients) client.close(1001, "PacketScope is closing");
  wss.close();
  return new Promise(resolve => {
    if (server.listening) server.close(resolve);
    else resolve();
  });
}

if (require.main === module) {
  listen().then(() => {
    console.log("Capture requires Wireshark/tshark and Npcap. Press Ctrl+C to stop.");
  }).catch(error => {
    console.error("Could not start PacketScope:", error.message);
    process.exitCode = 1;
  });

  const shutdown = () => close().finally(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

module.exports = { listen, close, server };