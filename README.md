# Wi-Fi Sentinel
**Automated Wireless Vulnerability Assessment Tool**

## Overview
Wi-Fi Sentinel is a passive wireless reconnaissance and threat detection tool. It captures 802.11 beacon frames to enumerate nearby networks, analyzes their security posture, and detects deauthentication attacks in real time. A dark, SIEM-style web UI streams live results over SSE, and a plugin system lets teammates add new analysis features without touching core code.

## Features
- **Network Enumeration** — discovers SSIDs, BSSIDs, channels, and signal strength passively
- **Protocol Analysis** — distinguishes WPA3 (SAE), WPA2 (PSK), WEP, and Open networks via RSN IE parsing
- **Standard Detection** — identifies 802.11ax / ac / n / a / b/g from HT, VHT, and HE capability IEs
- **Threat Detection** — detects deauthentication frames and flood attacks in real time
- **Live Web UI** — dark terminal aesthetic, SSE-powered live table, threat feed, and detail drawer
- **Plugin System** — drop a `.py` file in `backend/plugins/` to enrich network data with no core changes
- **REST API** — all data available as JSON; `/api/stream` for SSE event feed
- **CSV Export** — download a full report of discovered networks as a spreadsheet
- **Column Sorting** — click any table header to sort ascending or descending
- **Signal Sparklines** — live SVG signal history graph in the network detail drawer
- **Search & Filter** — real-time search bar filters by SSID, BSSID, security type, or standard
- **Flagged-Only View** — one-click toggle to show only WEP and Open networks
- **Channel Distribution Chart** — live bar chart showing how many networks are on each Wi-Fi channel
- **Dark/Light Mode** — toggle between dark terminal theme and light mode

## Project Structure
```
wifi-sentinel/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── backend/
│   ├── sentinel.py        # Scapy capture library (no side effects on import)
│   ├── server.py          # Flask REST API + SSE server
│   └── plugins/           # Drop-in feature modules
│       ├── __init__.py    # PluginManager
│       └── example_plugin.py
└── frontend/
    ├── index.html
    ├── style.css
    └── app.js
```

## Requirements
- Docker + Docker Compose
- A wireless adapter capable of **monitor mode**
- Linux host for live capture (macOS supported for UI development only)

## Running

### Linux (live capture)
```bash
# Put your adapter into monitor mode first
sudo airmon-ng start wlan0   # creates wlan0mon

docker compose --profile linux up --build
```

### macOS (UI / development)
```bash
docker compose --profile mac up --build
```

Then open **http://localhost:5001** (macOS) or **http://localhost:5000** (Linux).


### Local Demo Simulation (No Hardware Required)
If you do not have a monitor-mode adapter, you can run a local simulation to test the UI with mock data and simulated attacks.

1. Run the UI development profile: `docker compose --profile mac up --build`
2. Open **http://localhost:5001** (or **http://localhost:5000** if on Linux).
3. Select **"Demo Simulation (Local)"** from the Interface dropdown.
4. Click **Start Scan** to view staggered network discovery, live signal jitter, and timed threat alerts.


## API Reference
| Method | Route | Description |
|---|---|---|
| GET | `/api/interfaces` | List available wireless interfaces |
| POST | `/api/scan/start` | Start scan `{"interface": "wlan0mon"}` |
| POST | `/api/scan/stop` | Stop scan |
| GET | `/api/networks` | All discovered networks (plugin-enriched) |
| GET | `/api/threats` | All deauth/flood log entries |
| GET | `/api/stream` | SSE event stream |
| GET | `/api/report` | Full JSON report with summary |
| GET | `/api/plugins` | Loaded plugins and any load errors |

## Adding a Plugin
See [CONTRIBUTING.md](CONTRIBUTING.md) for full instructions. The short version:
1. Copy `backend/plugins/example_plugin.py` to a new file
2. Set `PLUGIN_NAME` and implement `on_network(network) -> dict`
3. Any key you add to the network dict appears in the UI and API automatically
4. Restart the container

## Potential Features
See [FEATURES.md](FEATURES.md) for a list of plugin ideas, UI enhancements, and larger features teammates can pick up.

---

## Course Themes

This project integrates four themes from the course:

**1. Wireless Technologies & 802.11 Standards (Week 1)**
Wi-Fi Sentinel identifies the specific 802.11 generation of each discovered
network by inspecting capability Information Elements inside beacon frames.
HE Capability (tag 255, extension 35) indicates 802.11ax (Wi-Fi 6), VHT
Capability (tag 191) indicates 802.11ac (Wi-Fi 5), and HT Capability (tag 45)
indicates 802.11n (Wi-Fi 4). This directly implements the 802.11b/g/n/ac/ax
standard differentiation covered in Week 1.

**2. WPA2/WPA3 Protocols & Security Misconceptions (Week 5)**
The tool performs manual RSN Information Element parsing to distinguish WPA3
(AKM suite type 8 — Simultaneous Authentication of Equals) from WPA2 (AKM
suite type 2 — Pre-Shared Key). Scapy's built-in helper cannot make this
distinction. Networks using WEP or no encryption are automatically flagged
as insecure, directly addressing the security misconceptions topic. Hidden
SSIDs are detected and labeled rather than ignored.

**3. Availability Issues & Deauthentication Attacks (Week 8)**
The tool passively monitors for 802.11 deauthentication management frames,
which are the primary vector for Wi-Fi denial of service attacks. A flood
detection system tracks deauth frame counts per source MAC address and
escalates to a flood warning when a single source crosses a configurable
threshold, identifying active jamming or disconnection attacks in real time.

**4. Wireless Penetration Testing & Reconnaissance (Week 6)**
Wi-Fi Sentinel automates the passive reconnaissance phase of a wireless
penetration test. It enumerates nearby networks without associating with any
of them, logs MAC addresses, detects hidden SSIDs, identifies security
posture, and records channel and signal strength — all standard first-phase
recon objectives. The tool is explicitly scoped to passive capture only,
consistent with authorized assessment methodology.

---

## Design Decisions & Trade-offs

**Scapy for raw frame parsing**
We chose Scapy because it provides direct access to the raw Information
Elements inside each beacon frame, allowing us to parse RSN IE bytes manually
and detect WPA3 correctly. The trade-off is that Scapy requires root privileges
and a monitor-mode capable adapter, locking live capture to Linux.

**Server-Sent Events instead of WebSockets**
Data flow is strictly one-directional — the server pushes updates to the
browser. SSE is simpler than WebSockets, uses plain HTTP, and works through
proxies without additional configuration. The trade-off is no bidirectional
channel, so client actions like starting a scan go through separate POST
requests.

**Plugin architecture**
Features are implemented as drop-in Python files in the plugins/ folder. Each
plugin receives network data, enriches it, and returns it. A crashing plugin
is caught and skipped without affecting the pipeline. The trade-off is that
plugins execute sequentially, so a slow plugin adds latency to every network
event.

**In-memory state with SQLite persistence**
Active scan data is held in memory for fast access and real-time streaming.
Completed sessions are persisted to a SQLite database so historical scans
survive server restarts. The trade-off of pure memory state during a scan is
that a crash mid-scan loses that session's data.

**Docker with host networking on Linux**
Running with network_mode: host and CAP_NET_RAW gives Scapy direct access to
the host's wireless hardware without privilege escalation complexity inside the
container. The trade-off is this only works on Linux — the Mac profile falls
back to port mapping and loses raw capture capability.

---

## Challenges & Lessons Learned

**WPA3 detection**
Scapy's network_stats() helper does not reliably detect WPA3. We had to
implement manual RSN IE byte parsing to correctly identify SAE (WPA3) versus
PSK (WPA2) networks. This required understanding the RSN IE structure at the
byte level — version, group cipher suite, pairwise cipher count and suites,
then AKM suite count and suite list.

**Hardware requirements**
Raw 802.11 frame capture requires monitor mode, which is only available on
Linux with a compatible adapter. This was a significant constraint during
development on macOS. We addressed it by building a demo simulation mode that
generates realistic fake scan data so the full UI can be tested without
hardware.

**Real-time streaming architecture**
Synchronizing Scapy's packet capture thread with Flask's HTTP server required
careful use of a thread-safe queue. The SSE endpoint blocks on the queue and
yields events as they arrive, while the packet handler thread pushes events in.
Getting this right without race conditions or dropped events was the main
threading challenge.

**Plugin isolation**
Early versions of the plugin system would crash the entire pipeline if one
plugin raised an exception. We added per-plugin try/except wrapping so a
broken plugin is logged and skipped without affecting the rest of the chain.
