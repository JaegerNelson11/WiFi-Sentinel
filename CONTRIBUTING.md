# Contributing to Wi-Fi Sentinel

## Adding a Plugin

Plugins live in `backend/plugins/`. Each plugin is a single `.py` file.

### Minimum requirements
- `PLUGIN_NAME`: a string
- `on_network(network: dict) -> dict`: receives each discovered network, returns it (enriched or unchanged)

### Optional hooks
- `PLUGIN_DESCRIPTION`: string shown in the UI sidebar
- `on_start()`: called when scanning begins
- `on_stop()`: called when scanning stops

### How to create one
1. Copy `backend/plugins/example_plugin.py` to a new file, e.g. `backend/plugins/my_feature.py`
2. Set `PLUGIN_NAME` and implement `on_network()`
3. Any key you add to the network dict automatically appears in the UI and API — no other files need to be touched
4. Restart the container — plugins are loaded at startup

### Adding new API routes
Add routes directly to `backend/server.py`. The Flask `app` object is module-level.

### Adding new UI elements
- HTML structure goes in `frontend/index.html`
- Styles go in `frontend/style.css`
- Logic goes in `frontend/app.js`

Frontend files are volume-mounted — changes apply without rebuilding the image.

### Network dict fields (as of current build)
| Field | Type | Description |
|---|---|---|
| SSID | str | Network name |
| BSSID | str | Access point MAC address |
| Security | str | WPA3 / WPA2 / WEP (Insecure) / Open |
| Standard | str | 802.11ax / ac / n / b/g |
| Channel | int or None | WiFi channel number |
| Signal | int or None | Signal strength in dBm |
| flagged | bool | True if WEP or Open |
