# Potential Features

## Plugin ideas (backend/plugins/ only, no core changes needed)
- **Vendor lookup** — resolve BSSID OUI to manufacturer name using the `manuf` library
- **GPS tagging** — attach GPS coordinates to each network using `gpsd` or a USB GPS dongle
- **Hostname resolution** — attempt reverse DNS on the BSSID (limited but sometimes useful)
- **Network scoring** — assign a 1-10 security score to each network based on protocol + signal

## UI enhancements (frontend/ only)
- **CSV / JSON export** — download button that hits /api/report
- **Channel distribution chart** — bar chart of networks per channel using Chart.js
- **Signal history graph** — sparkline per network showing signal over time
- **Dark/light mode toggle**
- **Filter / search bar** — filter table by SSID, security type, or standard
- **Flagged-only view** — one-click filter to show only WEP/Open networks

## Backend / API enhancements (server.py)
- **Scan history** — persist scan sessions to SQLite, compare across runs
- **Alert webhooks** — POST to a Discord or Slack webhook when a flood attack is detected
- **Authentication** — add a simple password to the web UI so it's not open to the LAN
- **PCAP export** — save raw captured frames to a .pcap file for Wireshark analysis

## Bigger features
- **Probe request tracking** — log which devices are looking for which networks
- **Rogue AP detection** — flag networks whose BSSID doesn't match known vendor patterns for that SSID
- **Multi-interface support** — scan on multiple interfaces simultaneously
