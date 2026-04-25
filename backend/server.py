import json
import os
import queue
import secrets
import sys
from datetime import timedelta

from flask import Flask, Response, jsonify, redirect, request, send_from_directory, session, stream_with_context
from flask_cors import CORS

# Ensure backend/ is on the path so sentinel imports cleanly regardless of cwd
sys.path.insert(0, os.path.dirname(__file__))
import sentinel
import auth
from plugins import PluginManager

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")
DEMO_MODE = os.environ.get("DEMO", "").lower() in ("1", "true", "yes")
ALLOW_REGISTRATION = os.environ.get("SENTINEL_ALLOW_REGISTRATION", "1").lower() in ("1", "true", "yes")
PUBLIC_FILES = {"login.html", "login.js", "style.css"}

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("SENTINEL_SECRET") or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(days=7)
CORS(app, origins="*", supports_credentials=True)

auth.init_db()
auth.bootstrap_admin()

plugin_manager = PluginManager(os.path.join(os.path.dirname(__file__), "plugins"))
plugin_manager.load_plugins()

event_queue: queue.Queue = queue.Queue()


def event_callback(event: dict):
    event_queue.put(event)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
def auth_login():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not auth.verify_user(username, password):
        return jsonify({"error": "invalid credentials"}), 401
    session.permanent = True
    session["user"] = username
    return jsonify({"user": username})


@app.post("/api/auth/register")
def auth_register():
    if not ALLOW_REGISTRATION:
        return jsonify({"error": "registration is disabled"}), 403
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if len(username) < 3:
        return jsonify({"error": "username must be at least 3 characters"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    try:
        auth.create_user(username, password)
    except Exception:
        return jsonify({"error": "username already taken"}), 409
    session.permanent = True
    session["user"] = username
    return jsonify({"user": username})


@app.post("/api/auth/logout")
def auth_logout():
    session.clear()
    return jsonify({"status": "logged out"})


@app.get("/api/auth/me")
def auth_me():
    user = auth.current_user()
    if not user:
        return jsonify({"error": "not authenticated"}), 401
    return jsonify({"user": user})


@app.get("/api/auth/config")
def auth_config():
    return jsonify({"allow_registration": ALLOW_REGISTRATION})


# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------
@app.get("/api/interfaces")
@auth.login_required
def get_interfaces():
    if DEMO_MODE:
        return jsonify(["demo"])
    return jsonify(sentinel.get_interfaces())


# ---------------------------------------------------------------------------
# Scan control
# ---------------------------------------------------------------------------
@app.post("/api/scan/start")
@auth.login_required
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
@auth.login_required
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
@auth.login_required
def get_networks():
    enriched = [plugin_manager.run_on_network(_flagged(n)) for n in sentinel.networks.values()]
    return jsonify(enriched)


@app.get("/api/threats")
@auth.login_required
def get_threats():
    return jsonify(list(sentinel.deauth_logs))


@app.get("/api/report")
@auth.login_required
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
@auth.login_required
def get_plugins():
    return jsonify({
        "plugins": plugin_manager.get_loaded(),
        "errors": plugin_manager.get_errors(),
    })


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------
@app.get("/api/stream")
@auth.login_required
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
@app.get("/login")
def login_page():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.get("/")
def index():
    if not auth.current_user():
        return redirect("/login")
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    if filename not in PUBLIC_FILES and not auth.current_user():
        return redirect("/login")
    return send_from_directory(FRONTEND_DIR, filename)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
