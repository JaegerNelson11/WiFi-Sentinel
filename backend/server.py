import json
import os
import queue
import sys

from flask import Flask, Response, jsonify, request, send_from_directory, stream_with_context
from flask_cors import CORS

# Ensure backend/ is on the path so sentinel imports cleanly regardless of cwd
sys.path.insert(0, os.path.dirname(__file__))
import sentinel
from plugins import PluginManager

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
DEMO_MODE = os.environ.get("DEMO", "").lower() in ("1", "true", "yes")

app = Flask(__name__, static_folder=None)
CORS(app, origins="*")

plugin_manager = PluginManager(os.path.join(os.path.dirname(__file__), "plugins"))
plugin_manager.load_plugins()

event_queue: queue.Queue = queue.Queue()


def event_callback(event: dict):
    event_queue.put(event)


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------
@app.get("/api/interfaces")
def get_interfaces():
    if DEMO_MODE:
        return jsonify(["demo"])
    return jsonify(sentinel.get_interfaces())


# ---------------------------------------------------------------------------
# Scan control
# ---------------------------------------------------------------------------
@app.post("/api/scan/start")
def scan_start():
    body = request.get_json(silent=True) or {}
    interface = body.get("interface", "")
    sentinel.reset()
    if DEMO_MODE or interface == "demo":
        sentinel.start_demo(callback=event_callback)
    else:
        sentinel.start_scan(interface, callback=event_callback)
    plugin_manager.call_on_start()
    return jsonify({"status": "started", "interface": interface})


@app.post("/api/scan/stop")
def scan_stop():
    sentinel.stop_scan()
    plugin_manager.call_on_stop()
    return jsonify({"status": "stopped"})


# ---------------------------------------------------------------------------
# Data endpoints
# ---------------------------------------------------------------------------
def _flagged(network: dict) -> dict:
    security = network.get("Security", "")
    return {**network, "flagged": "WEP" in security or "Open" in security}


@app.get("/api/networks")
def get_networks():
    enriched = [plugin_manager.run_on_network(_flagged(n)) for n in sentinel.networks.values()]
    return jsonify(enriched)


@app.get("/api/threats")
def get_threats():
    return jsonify(list(sentinel.deauth_logs))


@app.get("/api/report")
def get_report():
    networks = [_flagged(n) for n in sentinel.networks.values()]
    flagged_count = sum(1 for n in networks if n["flagged"])
    return jsonify({
        "summary": {
            "total": len(networks),
            "flagged": flagged_count,
            "threats": len(sentinel.deauth_logs),
        },
        "networks": networks,
        "threats": list(sentinel.deauth_logs),
    })


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------
@app.get("/api/plugins")
def get_plugins():
    return jsonify({
        "plugins": plugin_manager.get_loaded(),
        "errors": plugin_manager.get_errors(),
    })


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------
@app.get("/api/stream")
def stream():
    def generate():
        while True:
            try:
                event = event_queue.get(timeout=15)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield ": heartbeat\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Frontend static files
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(FRONTEND_DIR, filename)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
