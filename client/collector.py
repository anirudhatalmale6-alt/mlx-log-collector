"""
MLX Log Collector
Collects Multilogin X logs and PC specs, uploads to central dashboard.
"""

import os
import sys
import json
import platform
import subprocess
import zipfile
import tempfile
import ctypes
from pathlib import Path
from datetime import datetime

try:
    import requests
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "--quiet"])
    import requests

SERVER_URL = "https://nickets.xyz/logs/api/upload"
API_KEY = "Qc4qiZ26c2uVI8SBoAGw30VCOhm7fYEcDc3KSr6zmLk"


def get_windows_username():
    return os.environ.get("USERNAME", os.environ.get("USER", "unknown"))


def find_mlx_directories():
    """Find all possible MLX log locations on Windows."""
    user_home = Path.home()
    candidates = [
        user_home / "mlx" / "logs",
        user_home / "mlx",
        user_home / ".multilogin" / "logs",
        user_home / "AppData" / "Local" / "Multilogin X" / "logs",
        user_home / "AppData" / "Roaming" / "Multilogin X" / "logs",
        user_home / "AppData" / "Local" / "Multilogin X",
        user_home / "AppData" / "Roaming" / "Multilogin X",
    ]
    for drive in ["C:", "D:", "E:"]:
        candidates.append(Path(drive) / "mlx" / "logs")
        candidates.append(Path(drive) / "mlx")

    found = []
    for p in candidates:
        if p.exists() and p.is_dir():
            found.append(p)
    return found


def collect_log_files(mlx_dirs):
    """Collect all log files from MLX directories."""
    log_extensions = {".log", ".json", ".txt", ".csv"}
    files = []
    for d in mlx_dirs:
        for root, dirs, filenames in os.walk(str(d)):
            for fname in filenames:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in log_extensions or "log" in fname.lower() or "machine_info" in fname.lower():
                    try:
                        size = fpath.stat().st_size
                        if size < 100 * 1024 * 1024:  # skip files > 100MB
                            files.append(fpath)
                    except OSError:
                        pass
    return files


def get_pc_specs():
    """Collect PC specifications."""
    specs = {
        "hostname": platform.node(),
        "os": f"{platform.system()} {platform.release()} {platform.version()}",
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "username": get_windows_username(),
    }

    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "cpu", "get", "name", "/value"],
                capture_output=True, text=True, timeout=10, creationflags=0x08000000
            )
            for line in result.stdout.strip().split("\n"):
                if line.startswith("Name="):
                    specs["cpu"] = line.split("=", 1)[1].strip()
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["wmic", "memorychip", "get", "capacity", "/value"],
                capture_output=True, text=True, timeout=10, creationflags=0x08000000
            )
            total = 0
            for line in result.stdout.strip().split("\n"):
                if line.startswith("Capacity="):
                    try:
                        total += int(line.split("=")[1].strip())
                    except ValueError:
                        pass
            if total:
                specs["ram"] = f"{total // (1024**3)} GB"
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["wmic", "path", "win32_videocontroller", "get", "name", "/value"],
                capture_output=True, text=True, timeout=10, creationflags=0x08000000
            )
            gpus = []
            for line in result.stdout.strip().split("\n"):
                if line.startswith("Name="):
                    gpus.append(line.split("=", 1)[1].strip())
            if gpus:
                specs["gpu"] = ", ".join(gpus)
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["wmic", "diskdrive", "get", "size,model", "/value"],
                capture_output=True, text=True, timeout=10, creationflags=0x08000000
            )
            specs["disk_raw"] = result.stdout.strip()[:200]
        except Exception:
            pass

        try:
            result = subprocess.run(
                ["wmic", "os", "get", "caption,version", "/value"],
                capture_output=True, text=True, timeout=10, creationflags=0x08000000
            )
            for line in result.stdout.strip().split("\n"):
                if line.startswith("Caption="):
                    specs["os_name"] = line.split("=", 1)[1].strip()
        except Exception:
            pass

    try:
        import locale
        specs["locale"] = locale.getdefaultlocale()[0] or "unknown"
    except Exception:
        pass

    try:
        import socket
        specs["local_ip"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass

    return specs


def format_specs_short(specs):
    """Format specs as a short summary string."""
    parts = []
    if "cpu" in specs:
        parts.append(specs["cpu"])
    elif "processor" in specs:
        parts.append(specs["processor"])
    if "ram" in specs:
        parts.append(specs["ram"])
    if "gpu" in specs:
        parts.append(specs["gpu"])
    if "os_name" in specs:
        parts.append(specs["os_name"])
    return " | ".join(parts) if parts else "Unknown"


def show_message(title, message, icon=0x40):
    """Show a Windows message box."""
    if platform.system() == "Windows":
        ctypes.windll.user32.MessageBoxW(0, message, title, icon)
    else:
        print(f"[{title}] {message}")


def main():
    try:
        va_name = get_windows_username()
        print(f"MLX Log Collector")
        print(f"VA: {va_name}")
        print(f"Collecting logs...")

        mlx_dirs = find_mlx_directories()
        if not mlx_dirs:
            show_message("MLX Log Collector",
                         "Could not find MLX logs folder.\n\n"
                         "Make sure Multilogin X is installed and has been opened at least once.",
                         0x10)
            return

        print(f"Found MLX directories: {[str(d) for d in mlx_dirs]}")

        log_files = collect_log_files(mlx_dirs)
        if not log_files:
            show_message("MLX Log Collector",
                         "No log files found in MLX folder.\n\n"
                         "Make sure Multilogin X has been used recently.",
                         0x10)
            return

        print(f"Found {len(log_files)} log files")
        print("Collecting PC specs...")
        specs = get_pc_specs()
        specs_short = format_specs_short(specs)
        print(f"Specs: {specs_short}")

        print("Creating zip...")
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name

        with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fpath in log_files:
                try:
                    rel = fpath.relative_to(fpath.parents[len(fpath.parents) - 3])
                except (ValueError, IndexError):
                    rel = fpath.name
                zf.write(str(fpath), str(rel))

            zf.writestr("_pc_specs.json", json.dumps(specs, indent=2))

        zip_size = os.path.getsize(tmp_path)
        print(f"Zip created: {zip_size / 1024:.1f} KB")
        print("Uploading...")

        with open(tmp_path, "rb") as f:
            resp = requests.post(
                SERVER_URL,
                files={"file": (f"{va_name}_logs.zip", f, "application/zip")},
                data={
                    "va_name": va_name,
                    "pc_specs": specs_short,
                    "file_count": str(len(log_files)),
                },
                headers={"X-API-Key": API_KEY},
                timeout=120,
            )

        os.unlink(tmp_path)

        if resp.status_code == 200:
            print("Upload successful!")
            show_message("MLX Log Collector",
                         f"Logs uploaded successfully!\n\n"
                         f"Files: {len(log_files)}\n"
                         f"Size: {zip_size / 1024:.1f} KB\n\n"
                         f"You can close this window.",
                         0x40)
        else:
            print(f"Upload failed: {resp.status_code} {resp.text}")
            show_message("MLX Log Collector",
                         f"Upload failed!\n\nError: {resp.text}\n\nPlease contact your manager.",
                         0x10)

    except Exception as e:
        print(f"Error: {e}")
        show_message("MLX Log Collector",
                     f"An error occurred:\n\n{str(e)}\n\nPlease contact your manager.",
                     0x10)


if __name__ == "__main__":
    main()
