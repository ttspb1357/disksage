"""
DiskSage — finds the junk on your PC, explained by an AI that never leaves it.

Run:  python app.py      (then open http://127.0.0.1:8765 — it opens automatically)

A local, open-weight model (via Ollama) reviews what the scanner finds. File
names and paths are only ever sent to 127.0.0.1.
"""

import os
import secrets
import shutil
import threading
import webbrowser

from flask import Flask, abort, jsonify, render_template, request

from cleaner import actions, installed, llm, winapi
from cleaner.paths import Paths
from cleaner.scan import ScanJob

PORT = int(os.environ.get("DISKSAGE_PORT", "8765"))
# A local server that can delete files is an attack surface. Every API call must
# carry this token, which only our own page knows, so other websites open in
# your browser can't send requests to it.
TOKEN = secrets.token_urlsafe(24)

app = Flask(__name__)
paths = Paths.detect()


def drives_info():
    out = []
    for drive in [paths.system_drive, *paths.other_drives]:
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            continue
        out.append({"name": drive[:2], "total": usage.total, "used": usage.used, "free": usage.free})
    return out


job = ScanJob(paths, drives_info)
apps_by_id = {}
leftovers_by_app = {}


@app.before_request
def guard():
    # Only answer requests addressed to localhost (blocks DNS-rebinding tricks).
    if request.host not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
        abort(403)
    if request.path.startswith("/api/") and request.headers.get("X-DiskSage-Token") != TOKEN:
        abort(403)


def public_app(a):
    return {k: a[k] for k in ("id", "name", "version", "publisher", "install_location", "size", "install_date")}


def bin_info():
    size, count = winapi.recycle_bin_info()
    return {"size": size, "count": count}


@app.get("/")
def index():
    return render_template("index.html", token=TOKEN, model=llm.MODEL)


@app.get("/api/status")
def status():
    models = llm.list_models()
    return jsonify({
        "model": llm.MODEL,
        "ollama": models is not None,
        "model_ready": bool(models) and any(m.get("name") == llm.MODEL for m in models),
        "drives": drives_info(),
        "recycle_bin": bin_info(),
    })


@app.post("/api/scan")
def start_scan():
    job.start()
    return jsonify(job.snapshot())


@app.get("/api/scan")
def scan_status():
    since = request.args.get("since", type=int)
    return jsonify(job.snapshot(since))


@app.post("/api/clean")
def clean():
    data = request.get_json(silent=True) or {}
    report = job.clean(data.get("selections") or [])
    return jsonify({"report": report, "scan": job.snapshot(), "drives": drives_info(), "recycle_bin": bin_info()})


@app.post("/api/recycle-bin/empty")
def empty_bin():
    size = winapi.recycle_bin_info()[0]
    ok = winapi.empty_recycle_bin()
    return jsonify({"ok": ok, "freed": size if ok else 0, "drives": drives_info(), "recycle_bin": bin_info()})


@app.post("/api/disk-cleanup")
def disk_cleanup():
    return jsonify({"ok": winapi.shell_open("cleanmgr.exe")})


@app.get("/api/apps")
def list_apps():
    apps = installed.installed_apps()
    apps_by_id.update({a["id"]: a for a in apps})
    return jsonify({"apps": [public_app(a) for a in apps]})


def _leftover_dicts(items):
    return [
        {
            "index": i, "path": paths.display(it.path), "size": it.size, "note": it.note,
            "protected": it.meta.get("protected"), "removed": it.removed,
        }
        for i, it in enumerate(items)
    ]


@app.post("/api/apps/<app_id>/leftovers")
def app_leftovers(app_id):
    target = apps_by_id.get(app_id)
    if not target:
        return jsonify({"error": "Unknown app — refresh the list."}), 404
    current = installed.installed_apps()
    still_installed = any(a["id"] == app_id for a in current)
    items = installed.find_leftovers(target, paths, current or list(apps_by_id.values()))
    leftovers_by_app[app_id] = (items, still_installed)
    return jsonify({"app": public_app(target), "installed": still_installed, "leftovers": _leftover_dicts(items)})


@app.post("/api/apps/<app_id>/advice")
def app_advice(app_id):
    target = apps_by_id.get(app_id)
    if not target or app_id not in leftovers_by_app:
        return jsonify({"error": "Look up the app's leftovers first."}), 400
    items, still_installed = leftovers_by_app[app_id]
    try:
        return jsonify(llm.app_advice(target, items, still_installed, paths))
    except llm.LLMError as exc:
        return jsonify({"error": str(exc)}), 503


@app.post("/api/apps/<app_id>/uninstall")
def uninstall(app_id):
    target = apps_by_id.get(app_id)
    if not target:
        return jsonify({"error": "Unknown app."}), 404
    return jsonify({"ok": actions.run_uninstaller(target)})


@app.post("/api/apps/<app_id>/clean")
def clean_leftovers(app_id):
    if app_id not in leftovers_by_app:
        return jsonify({"error": "Look up the app's leftovers first."}), 400
    items, _ = leftovers_by_app[app_id]
    report = actions.Report(paths)
    for idx in (request.get_json(silent=True) or {}).get("items") or []:
        if isinstance(idx, int) and 0 <= idx < len(items) and not items[idx].removed:
            actions.apply("recycle", items[idx], paths, report)
    return jsonify({"report": report.to_dict(), "leftovers": _leftover_dicts(items), "recycle_bin": bin_info()})


@app.post("/api/ask")
def ask():
    data = request.get_json(silent=True) or {}
    question = str(data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "Type a question first."}), 400
    apps = list(apps_by_id.values()) or installed.installed_apps()
    try:
        answer = llm.ask(question, data.get("history") or [], job.context_text(drives_info(), apps))
    except llm.LLMError as exc:
        return jsonify({"error": str(exc)}), 503
    return jsonify({"answer": answer})


if __name__ == "__main__":
    url = f"http://127.0.0.1:{PORT}"
    print(f"\n  DiskSage is running at {url}  (model: {llm.MODEL})\n  Press Ctrl+C to stop.\n")
    if not os.environ.get("DISKSAGE_NO_BROWSER"):
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
