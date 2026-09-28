# PacketScope: Live Packet Monitor

## Requirements

1. Windows 10/11
2. Wireshark for Windows, including `tshark.exe`
3. Npcap installed with Wireshark or from the official Npcap distribution

The app uses Wireshark's `tshark.exe` to access Npcap. It does not load a Node.js native capture addon, so it avoids `cap.node` ABI errors. Wireshark is checked in the standard install folders and `PATH`; set `TSHARK_PATH` if it is installed elsewhere. The local Windows bundle uses the installed Node.js 26.10.0 runtime.

## Windows Deployment

Install Wireshark with Npcap on the capture computer. Build the install bundle with:

```powershell
npm install --ignore-scripts
npm run package:win
```

Extract the generated `release/PacketScope-Windows-*.zip` and run `install.cmd`. This installs to your user profile and creates Start Menu and Desktop shortcuts without administrator elevation. The shortcut opens the local dashboard in your default browser. PacketScope does not install Node.js or Npcap; Node.js 26.10.0, Wireshark/tshark, and capture permissions are required on the target PC.

## Install

To run the browser-based development version, open PowerShell in the project folder:

```powershell
npm install
```

Then start:

```powershell
npm start
```

Open:

```text
http://127.0.0.1:8080
```

To open the local dashboard and run the capture server together, use `npm run launch`.

Select the Wi-Fi or Ethernet adapter and start capture. If your system restricts packet capture, open the terminal with the required permissions.

## What it captures

The dashboard provides:

- Live TCP, UDP, ICMP/ICMPv6, ARP, and other decoded traffic
- Wi-Fi/Ethernet interface discovery and selection
- Source/destination addresses and ports, frame size, timestamps, and packet summaries
- Wireshark display filters, validated by `tshark`, plus protocol filtering and free-text search
- Expandable frame, Ethernet/VLAN, IP, TCP/UDP, DNS, HTTP, TLS, ARP, and ICMP field details
- DNS answers, TLS server names/ALPN, HTTP host/path, stream IDs, and TCP retransmission indicators
- Pause/resume, clear capture, and a packet menu for saving/importing JSON captures plus filtered CSV/JSON export
- A rolling 60-second packet-rate graph and decoded packet details

The browser keeps up to 10,000 packet records in memory and displays the latest 500 rows.
Import accepts PacketScope JSON capture files, JSON packet arrays, and CSV files exported by the app.
Changing a display filter during capture asks for confirmation, then restarts capture and clears the current packet list. When capture is stopped, the validated filter is saved for the next capture.
HTTP query strings and URL user-info are removed from displayed paths, and authorization/cookie summaries are redacted. The app does not collect passwords or usernames.

## Windows/Npcap notes

If the interface list is empty or capture fails:

- Verify Wireshark and Npcap are installed.
- Confirm `tshark.exe` runs in PowerShell, or set `TSHARK_PATH` to its full path.
- Run PowerShell with the permissions required by your Npcap installation.
- Make sure the selected adapter is active.

## Scope

This is intended for monitoring systems/networks you own or are authorized to administer. It does not decrypt TLS/HTTPS traffic and does not attempt to bypass network security controls.
