const { spawn } = require("child_process");
const { close, listen } = require("./server");

async function launch() {
  try {
    const address = await listen();
    const url = `http://127.0.0.1:${address.port}/`;
    const browser = spawn("cmd.exe", ["/c", "start", "", url], {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });
    browser.unref();
    console.log("PacketScope is running. Close this window to stop the local server.");
  } catch (error) {
    console.error(`PacketScope could not start: ${error.message}`);
    process.exitCode = 1;
  }
}

process.on("SIGINT", () => close().finally(() => process.exit(0)));
process.on("SIGTERM", () => close().finally(() => process.exit(0)));
launch();