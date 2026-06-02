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


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MLX Log Collector</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e1e4e8; min-height: 100vh; }
.header { background: linear-gradient(135deg, #1a1e2e 0%, #252a3a 100%); border-bottom: 1px solid #30363d; padding: 20px 30px; display: flex; align-items: center; justify-content: space-between; }
.header h1 { font-size: 22px; font-weight: 600; color: #58a6ff; }
.header .stats { display: flex; gap: 20px; }
.stat { text-align: center; }
.stat-value { font-size: 24px; font-weight: 700; color: #58a6ff; }
.stat-label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
.container { max-width: 1200px; margin: 0 auto; padding: 30px; }
.search-bar { width: 100%; padding: 12px 16px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; color: #e1e4e8; font-size: 14px; margin-bottom: 20px; outline: none; }
.search-bar:focus { border-color: #58a6ff; }
.search-bar::placeholder { color: #484f58; }
table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }
th { background: #1a1e2e; padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; border-bottom: 1px solid #30363d; }
td { padding: 12px 16px; border-bottom: 1px solid #21262d; font-size: 14px; }
tr:hover td { background: #1c2028; }
tr:last-child td { border-bottom: none; }
.va-name { font-weight: 600; color: #58a6ff; }
.date { color: #8b949e; }
.size { color: #8b949e; font-family: monospace; }
.btn { display: inline-block; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 500; text-decoration: none; cursor: pointer; border: none; }
.btn-download { background: #238636; color: #fff; }
.btn-download:hover { background: #2ea043; }
.btn-delete { background: #da3633; color: #fff; margin-left: 6px; }
.btn-delete:hover { background: #f85149; }
.btn-refresh { background: #30363d; color: #e1e4e8; padding: 8px 16px; font-size: 14px; }
.btn-refresh:hover { background: #3d444d; }
.empty { text-align: center; padding: 60px 20px; color: #8b949e; }
.empty h2 { color: #58a6ff; margin-bottom: 10px; }
.pc-specs { font-size: 12px; color: #8b949e; max-width: 300px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge-new { background: rgba(88,166,255,0.15); color: #58a6ff; }
.badge-old { background: rgba(139,148,158,0.15); color: #8b949e; }
.actions { white-space: nowrap; }
</style>
</head>
<body>
<div class="header">
    <h1>MLX Log Collector</h1>
    <div class="stats">
        <div class="stat"><div class="stat-value" id="totalLogs">-</div><div class="stat-label">Total Logs</div></div>
        <div class="stat"><div class="stat-value" id="totalVAs">-</div><div class="stat-label">VAs</div></div>
        <div class="stat"><div class="stat-value" id="todayLogs">-</div><div class="stat-label">Today</div></div>
    </div>
</div>
<div class="container">
    <input type="text" class="search-bar" id="search" placeholder="Search by VA name, date, or PC specs...">
    <table>
        <thead>
            <tr>
                <th>VA Name</th>
                <th>PC Specs</th>
                <th>Submitted</th>
                <th>Size</th>
                <th>Files</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="logTable"></tbody>
    </table>
    <div class="empty" id="emptyState" style="display:none;">
        <h2>No logs yet</h2>
        <p>Logs will appear here when VAs run the collector tool.</p>
    </div>
</div>
<script>
const TOKEN = new URLSearchParams(window.location.search).get('token');
async function loadLogs() {
    const res = await fetch('/logs/api/list?token=' + TOKEN);
    const data = await res.json();
    const logs = data.logs || [];
    document.getElementById('totalLogs').textContent = logs.length;
    const vas = new Set(logs.map(l => l.va_name));
    document.getElementById('totalVAs').textContent = vas.size;
    const today = new Date().toISOString().split('T')[0];
    document.getElementById('todayLogs').textContent = logs.filter(l => l.submitted.startsWith(today)).length;
    renderTable(logs);
}
function renderTable(logs) {
    const tbody = document.getElementById('logTable');
    const empty = document.getElementById('emptyState');
    if (!logs.length) { tbody.innerHTML = ''; empty.style.display = 'block'; return; }
    empty.style.display = 'none';
    tbody.innerHTML = logs.map(l => {
        const age = (Date.now() - new Date(l.submitted).getTime()) / 3600000;
        const badge = age < 24 ? '<span class="badge badge-new">NEW</span>' : '';
        const specs = l.pc_specs || '-';
        return '<tr>' +
            '<td class="va-name">' + esc(l.va_name) + ' ' + badge + '</td>' +
            '<td class="pc-specs">' + esc(specs) + '</td>' +
            '<td class="date">' + formatDate(l.submitted) + '</td>' +
            '<td class="size">' + formatSize(l.size) + '</td>' +
            '<td>' + (l.file_count || '-') + '</td>' +
            '<td class="actions">' +
                '<a class="btn btn-download" href="/logs/api/download/' + encodeURIComponent(l.filename) + '?token=' + TOKEN + '">Download</a>' +
                '<button class="btn btn-delete" onclick="deleteLog(\'' + esc(l.filename) + '\')">Delete</button>' +
            '</td></tr>';
    }).join('');
}
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleDateString('en-US', {month:'short',day:'numeric',year:'numeric'}) + ' ' +
           d.toLocaleTimeString('en-US', {hour:'2-digit',minute:'2-digit'});
}
function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes/1024).toFixed(1) + ' KB';
    return (bytes/1048576).toFixed(1) + ' MB';
}
async function deleteLog(filename) {
    if (!confirm('Delete this log?')) return;
    await fetch('/logs/api/delete/' + encodeURIComponent(filename) + '?token=' + TOKEN, {method:'DELETE'});
    loadLogs();
}
document.getElementById('search').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    document.querySelectorAll('#logTable tr').forEach(tr => {
        tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
});
loadLogs();
setInterval(loadLogs, 30000);
</script>
</body>
</html>"""


@app.route("/")
@require_admin
def dashboard():
    return render_template_string(DASHBOARD_HTML)


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
