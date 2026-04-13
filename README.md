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
