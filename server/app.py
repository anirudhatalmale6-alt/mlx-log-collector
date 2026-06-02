import os
import json
import hashlib
import secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, send_from_directory, abort

app = Flask(__name__)

UPLOAD_DIR = "/opt/mlx-logs/uploads"
API_KEY = os.environ.get("MLX_LOG_API_KEY", "")
ADMIN_TOKEN = os.environ.get("MLX_LOG_ADMIN_TOKEN", "")

os.makedirs(UPLOAD_DIR, exist_ok=True)


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key or key != API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get("token", "") or request.headers.get("X-Admin-Token", "")
        if not token or token != ADMIN_TOKEN:
            return abort(403)
        return f(*args, **kwargs)
    return decorated


def get_logs():
    logs = []
    for fname in os.listdir(UPLOAD_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(UPLOAD_DIR, fname)) as f:
                logs.append(json.load(f))
    logs.sort(key=lambda x: x.get("submitted", ""), reverse=True)
    return logs


def format_size(b):
    if b < 1024:
        return f"{b} B"
    if b < 1048576:
        return f"{b/1024:.1f} KB"
    return f"{b/1048576:.1f} MB"


def build_dashboard(logs, token):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    va_set = set(l.get("va_name", "") for l in logs)
    today_count = sum(1 for l in logs if l.get("submitted", "").startswith(today))

    rows = ""
    for l in logs:
        va = l.get("va_name", "unknown")
        specs = l.get("pc_specs", "-")
        sub = l.get("submitted", "")
        try:
            dt = datetime.fromisoformat(sub)
            date_str = dt.strftime("%b %d, %Y %I:%M %p")
        except Exception:
            date_str = sub
        size = format_size(l.get("size", 0))
        fc = l.get("file_count", "-")
        fn = l.get("filename", "")
        rows += f"""<tr>
<td style="font-weight:600;color:#58a6ff">{va}</td>
<td style="font-size:12px;color:#8b949e;max-width:300px">{specs}</td>
<td style="color:#8b949e">{date_str}</td>
<td style="color:#8b949e;font-family:monospace">{size}</td>
<td>{fc}</td>
<td style="white-space:nowrap"><a href="/logs/api/download/{fn}?token={token}" style="display:inline-block;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:500;text-decoration:none;background:#238636;color:#fff">Download</a></td>
</tr>"""

    if not logs:
        rows = '<tr><td colspan="6" style="text-align:center;padding:60px 20px;color:#8b949e">No logs yet. Logs will appear here when VAs run the collector tool.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MLX Log Collector</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh}}
.header{{background:linear-gradient(135deg,#1a1e2e 0%,#252a3a 100%);border-bottom:1px solid #30363d;padding:20px 30px;display:flex;align-items:center;justify-content:space-between}}
.header h1{{font-size:22px;font-weight:600;color:#58a6ff}}
.stats{{display:flex;gap:20px}}
.stat{{text-align:center}}
.sv{{font-size:24px;font-weight:700;color:#58a6ff}}
.sl{{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:1px}}
.container{{max-width:1200px;margin:0 auto;padding:30px}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;border:1px solid #30363d}}
th{{background:#1a1e2e;padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#8b949e;border-bottom:1px solid #30363d}}
td{{padding:12px 16px;border-bottom:1px solid #21262d;font-size:14px}}
tr:hover td{{background:#1c2028}}
.rf{{display:inline-block;margin-bottom:20px;padding:8px 16px;background:#30363d;color:#e1e4e8;border-radius:6px;text-decoration:none;font-size:14px}}
.rf:hover{{background:#3d444d}}
</style>
</head>
<body>
<div class="header">
<h1>MLX Log Collector</h1>
<div class="stats">
<div class="stat"><div class="sv">{len(logs)}</div><div class="sl">Total Logs</div></div>
<div class="stat"><div class="sv">{len(va_set)}</div><div class="sl">VAs</div></div>
<div class="stat"><div class="sv">{today_count}</div><div class="sl">Today</div></div>
</div>
</div>
<div class="container">
<a class="rf" href="/logs?token={token}">Refresh</a>
<table>
<thead><tr><th>VA Name</th><th>PC Specs</th><th>Submitted</th><th>Size</th><th>Files</th><th>Actions</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</body>
</html>"""


@app.route("/")
@require_admin
def dashboard():
    token = request.args.get("token", "")
    logs = get_logs()
    return build_dashboard(logs, token)


@app.route("/api/upload", methods=["POST"])
@require_api_key
def upload():
    if "file" not in request.files:
        return jsonify({"error": "no file"}), 400

    f = request.files["file"]
    va_name = request.form.get("va_name", "unknown").strip()
    pc_specs = request.form.get("pc_specs", "").strip()
    file_count = request.form.get("file_count", "0")

    now = datetime.now(timezone.utc)
    safe_name = "".join(c for c in va_name if c.isalnum() or c in "-_ ").strip() or "unknown"
    filename = f"{safe_name}_{now.strftime('%Y%m%d_%H%M%S')}.zip"
    filepath = os.path.join(UPLOAD_DIR, filename)
    f.save(filepath)

    meta = {
        "va_name": va_name,
        "pc_specs": pc_specs,
        "file_count": int(file_count),
        "submitted": now.isoformat(),
        "size": os.path.getsize(filepath),
        "filename": filename,
    }
    meta_path = filepath.replace(".zip", ".json")
    with open(meta_path, "w") as mf:
        json.dump(meta, mf)

    return jsonify({"status": "ok", "filename": filename}), 200


@app.route("/api/list")
@require_admin
def list_logs():
    logs = []
    for fname in os.listdir(UPLOAD_DIR):
        if fname.endswith(".json"):
            with open(os.path.join(UPLOAD_DIR, fname)) as f:
                logs.append(json.load(f))
    logs.sort(key=lambda x: x.get("submitted", ""), reverse=True)
    return jsonify({"logs": logs})


@app.route("/api/download/<filename>")
@require_admin
def download(filename):
    safe = os.path.basename(filename)
    if not os.path.exists(os.path.join(UPLOAD_DIR, safe)):
        return abort(404)
    return send_from_directory(UPLOAD_DIR, safe, as_attachment=True)


@app.route("/api/delete/<filename>", methods=["DELETE"])
@require_admin
def delete(filename):
    safe = os.path.basename(filename)
    fpath = os.path.join(UPLOAD_DIR, safe)
    mpath = fpath.replace(".zip", ".json")
    if os.path.exists(fpath):
        os.remove(fpath)
    if os.path.exists(mpath):
        os.remove(mpath)
    return jsonify({"status": "deleted"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5090, debug=False)
