# -*- coding: utf-8 -*-
import sys
import os

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass
import threading
import uuid
import time
import hashlib
import subprocess
import re
import socket
import urllib.parse
from flask import Flask, request, jsonify, send_from_directory, render_template_string, redirect

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

PATCH_DIR = os.path.join(CURRENT_DIR, "bin", "patch")
if os.path.exists(PATCH_DIR) and PATCH_DIR not in sys.path:
    sys.path.insert(0, PATCH_DIR)

import updater
import custom_dns
if os.environ.get('CUSTOM_DNS', '1') == '1':
    custom_dns.enable_google_dns()

def get_ffmpeg_dir():
    if hasattr(sys, '_MEIPASS') and os.path.exists(os.path.join(sys._MEIPASS, 'ffmpeg.exe')):
        return sys._MEIPASS
    exe_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else CURRENT_DIR
    for c in [exe_dir, os.path.join(exe_dir, 'bin'), CURRENT_DIR, os.path.join(CURRENT_DIR, 'bin')]:
        if os.path.exists(os.path.join(c, 'ffmpeg.exe')):
            return c
    import shutil
    sys_ff = shutil.which('ffmpeg')
    if sys_ff:
        return os.path.dirname(sys_ff)
    return None

ff_dir = get_ffmpeg_dir()
if ff_dir and ff_dir not in os.environ.get('PATH', ''):
    os.environ['PATH'] = ff_dir + os.path.pathsep + os.environ.get('PATH', '')

def get_ffmpeg_binary():
    d = get_ffmpeg_dir()
    if d and os.path.exists(os.path.join(d, 'ffmpeg.exe')):
        return os.path.join(d, 'ffmpeg.exe')
    return 'ffmpeg'

def safe_mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0

import yt_dlp

DOWNLOAD_DIR = os.path.join(CURRENT_DIR, "Downloads")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Security helpers (ป้องกัน Path Traversal / SSRF / Local File Read)
# ---------------------------------------------------------------------------
import ipaddress

# ซ่อนหน้าต่าง Console ของ FFmpeg บน Windows
SUBPROCESS_FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

def safe_download_path(filename):
    """คืน path จริงของไฟล์ภายใน DOWNLOAD_DIR เท่านั้น ถ้าพยายามหลุดออกนอกโฟลเดอร์จะคืน None"""
    if not filename or not isinstance(filename, str) or "\x00" in filename:
        return None
    base = os.path.realpath(DOWNLOAD_DIR)
    target = os.path.realpath(os.path.join(base, filename))
    try:
        if os.path.commonpath([base, target]) != base or target == base:
            return None
    except ValueError:
        return None
    return target

def sanitize_filename(name, default="media_file", max_len=120):
    """ลบอักขระอันตรายและตัวคั่น path ออกจากชื่อไฟล์"""
    name = os.path.basename((name or "").replace("\\", "/"))
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(" .")
    if not name or name in (".", ".."):
        name = default
    b, e = os.path.splitext(name)
    e = re.sub(r'[^A-Za-z0-9.]', '', e)[:10]
    return (b[:max_len].strip() or default) + e

def is_safe_remote_url(url):
    """อนุญาตเฉพาะ http/https ไปยังโฮสต์สาธารณะ (กัน file:// และการยิงเข้าเครือข่ายภายใน)"""
    try:
        p = urllib.parse.urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    host = p.hostname.strip("[]").lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost") or host.endswith(".local"):
        return False
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except Exception:
        addrs = set()
        try:
            addrs.add(str(ipaddress.ip_address(host)))
        except ValueError:
            return True  # resolve ไม่ได้ ปล่อยให้ downloader จัดการ error เอง
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True

def is_local_request(req):
    """ตรวจว่าคำขอมาจากเครื่องตัวเอง (ใช้กับ API ที่มีผลต่อระบบ)"""
    return (req.remote_addr or "") in ("127.0.0.1", "::1")

# Zero-Storage Policy: ลบไฟล์ชั่วคราวทิ้งอัตโนมัติ ไม่เก็บไว้บนเซิร์ฟเวอร์
ZERO_STORAGE_MODE = os.environ.get('ZERO_STORAGE', '1') == '1' # ค่าเริ่มต้น: เปิดใช้งาน (ลบไฟล์อัตโนมัติ)
FILE_TTL_SECONDS = int(os.environ.get('FILE_TTL_SECONDS', 180)) # อายุไฟล์สูงสุด 3 นาที (180 วิ)

def get_lan_ip():
    """ดึง IP วง LAN ของเครื่อง เพื่อให้มือถือใน Wi-Fi เดียวกันสแกน QR Code แล้วดาวน์โหลดไฟล์ได้ทันที"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

class FloodProtector:
    """
    ระบบป้องกันการฟลัด (Anti-Flood & Rate Limiting System)
    - Cooldown: บังคับเว้นระยะห่างอย่างน้อย 3 วินาทีต่อคำขอจาก IP เดียวกัน
    - Rate Limit: จำกัดไม่เกิน 6 คำขอดาวน์โหลดต่อ 1 นาทีต่อ IP (Sliding Window)
    - Per-IP Concurrency: จำกัด 1 งานดาวน์โหลดต่อ 1 IP พร้อมกัน
    - Global Concurrency: จำกัด 4 งานดาวน์โหลดพร้อมกันทั้งระบบ (ป้องกัน CPU/RAM 100%)
    - Temporary Jail (Auto-Ban): พักการใช้งาน IP ชั่วคราว 5 นาทีหากฝ่าฝืนซ้ำๆ
    - Bandwidth Protection: จำกัดการดาวน์โหลดไฟล์ .exe ไม่เกิน 2 ครั้งต่อนาทีต่อ IP
    - Memory Safe: มีระบบทำความสะอาดแคช IP เก่าอัตโนมัติ
    """
    def __init__(self):
        self.lock = threading.Lock()
        self.cooldown_seconds = 3
        self.max_requests_per_minute = 6
        self.max_concurrent_per_ip = 1
        self.max_global_concurrent = 4
        self.ban_duration_seconds = 300
        self.ban_strike_threshold = 8

        self.last_request_time = {}          # ip -> float
        self.request_history = {}            # ip -> list of float
        self.active_tasks_by_ip = {}         # ip -> set of task_ids
        self.banned_until = {}               # ip -> float
        self.violation_counts = {}           # ip -> int
        self.global_active_tasks = set()     # set of task_ids
        self.app_download_history = {}       # ip -> list of float

    def get_client_ip(self, req):
        # รองรับ Cloudflare proxy
        cf_ip = req.headers.get('CF-Connecting-IP')
        if cf_ip:
            return cf_ip.strip()
        # รองรับ X-Forwarded-For
        xff = req.headers.get('X-Forwarded-For')
        if xff:
            return xff.split(',')[0].strip()
        return req.remote_addr or '127.0.0.1'

    def check_download_allowed(self, ip):
        now = time.time()
        with self.lock:
            # 1. ตรวจสอบการถูกพักการใช้งาน (Jail)
            ban_time = self.banned_until.get(ip, 0)
            if now < ban_time:
                remaining_sec = int(ban_time - now)
                return False, f"🚫 ตรวจพบพฤติกรรมส่งคำขอผิดปกติ (Flood/Spam) ระบบระงับการเข้าถึงชั่วคราว กรุณารออีก {remaining_sec} วินาที", 429

            # 2. ตรวจสอบ Cooldown (ห้ามกดย้ำรัวๆ)
            last_time = self.last_request_time.get(ip, 0)
            elapsed = now - last_time
            if elapsed < self.cooldown_seconds:
                wait_sec = round(self.cooldown_seconds - elapsed, 1)
                self._record_violation(ip, now)
                return False, f"⏳ กรุณารอสักครู่ (เว้นระยะ {wait_sec} วินาที) ก่อนส่งคำขอดาวน์โหลดใหม่", 429

            # 3. ตรวจสอบ Sliding Window Rate Limit (ไม่เกิน 6 ครั้งต่อนาที)
            history = self.request_history.get(ip, [])
            history = [t for t in history if now - t < 60]
            self.request_history[ip] = history
            if len(history) >= self.max_requests_per_minute:
                self._record_violation(ip, now)
                return False, f"⚠️ คุณส่งคำขอดาวน์โหลดถี่เกินไป (จำกัดไม่เกิน {self.max_requests_per_minute} ครั้ง/นาที) กรุณารอสักครู่", 429

            # 4. ตรวจสอบจำนวนงานที่ IP นี้กำลังทำอยู่ (Concurrent per IP)
            active_ip_tasks = self.active_tasks_by_ip.get(ip, set())
            if len(active_ip_tasks) >= self.max_concurrent_per_ip:
                return False, "⏳ คุณมีงานดาวน์โหลดที่กำลังประมวลผลอยู่ กรุณารอให้งานก่อนหน้าเสร็จสิ้นก่อนเริ่มงานใหม่ครับ", 429

            # 5. ตรวจสอบจำนวนงานรวมทั้งเซิร์ฟเวอร์ (Global Concurrency)
            if len(self.global_active_tasks) >= self.max_global_concurrent:
                return False, "⚠️ ขณะนี้เซิร์ฟเวอร์กำลังประมวลผลงานดาวน์โหลดเต็มพิกัด กรุณารอสักครู่แล้วลองใหม่อีกครั้งครับ", 503

            # ผ่านการตรวจสอบ บันทึกเวลา
            self.last_request_time[ip] = now
            history.append(now)
            self.request_history[ip] = history
            return True, "", 200

    def register_task(self, ip, task_id):
        with self.lock:
            if ip not in self.active_tasks_by_ip:
                self.active_tasks_by_ip[ip] = set()
            self.active_tasks_by_ip[ip].add(task_id)
            self.global_active_tasks.add(task_id)

    def unregister_task(self, ip, task_id):
        with self.lock:
            if ip in self.active_tasks_by_ip:
                self.active_tasks_by_ip[ip].discard(task_id)
                if not self.active_tasks_by_ip[ip]:
                    self.active_tasks_by_ip.pop(ip, None)
            self.global_active_tasks.discard(task_id)

    def check_app_download_allowed(self, ip):
        now = time.time()
        with self.lock:
            if now < self.banned_until.get(ip, 0):
                return False, "Access blocked due to excessive requests."
            history = self.app_download_history.get(ip, [])
            history = [t for t in history if now - t < 60]
            self.app_download_history[ip] = history
            if len(history) >= 2:
                return False, "ดาวน์โหลดโปรแกรมบ่อยเกินไป กรุณารอ 1 นาทีแล้วลองใหม่ครับ"
            history.append(now)
            return True, ""

    def _record_violation(self, ip, now):
        cnt = self.violation_counts.get(ip, 0) + 1
        self.violation_counts[ip] = cnt
        if cnt >= self.ban_strike_threshold:
            self.banned_until[ip] = now + self.ban_duration_seconds
            print(f"[Anti-Flood] IP {ip} temporarily banned for {self.ban_duration_seconds}s (Strikes: {cnt})")

    def cleanup_old_records(self):
        now = time.time()
        with self.lock:
            for ip in list(self.request_history.keys()):
                valid = [t for t in self.request_history[ip] if now - t < 120]
                if valid:
                    self.request_history[ip] = valid
                else:
                    self.request_history.pop(ip, None)
                    self.last_request_time.pop(ip, None)
                    if ip in self.violation_counts and now >= self.banned_until.get(ip, 0):
                        self.violation_counts.pop(ip, None)
            for ip in list(self.app_download_history.keys()):
                valid = [t for t in self.app_download_history[ip] if now - t < 120]
                if valid:
                    self.app_download_history[ip] = valid
                else:
                    self.app_download_history.pop(ip, None)

flood_protector = FloodProtector()

def auto_cleanup_worker():
    """
    Background Thread:
    1. ลบไฟล์สื่อชั่วคราวที่แปลงเสร็จแล้วแต่เกินเวลา TTL (3 นาที) ตาม Zero-Storage Policy
    2. ทำความสะอาดประวัติแคช Anti-Flood เพื่อประหยัดหน่วยความจำ
    3. กวาดล้างงาน Tasks เก่าในหน่วยความจำที่เสร็จเกิน 10 นาที
    """
    while True:
        try:
            time.sleep(20)
            now = time.time()
            # 1. Purge files (รองรับ .mp3, .mp4, .m4a, .m4r, .gif)
            if ZERO_STORAGE_MODE and os.path.exists(DOWNLOAD_DIR):
                for f in os.listdir(DOWNLOAD_DIR):
                    if f.endswith(('.mp3', '.mp4', '.m4a', '.m4r', '.gif', '.webm', '.part', '.ytdl', '.temp')):
                        p = os.path.join(DOWNLOAD_DIR, f)
                        if os.path.isfile(p):
                            try:
                                if now - os.path.getmtime(p) > FILE_TTL_SECONDS:
                                    os.remove(p)
                                    md5_p = f"{p}.md5"
                                    if os.path.exists(md5_p):
                                        os.remove(md5_p)
                                    print(f"[Zero-Storage] Auto-purged expired file: {f}")
                            except Exception:
                                pass
            # 2. Cleanup Anti-Flood memory
            flood_protector.cleanup_old_records()

            # 3. Cleanup completed tasks older than 10 mins
            for tid in list(tasks.keys()):
                t_obj = tasks.get(tid)
                if t_obj:
                    c_time = t_obj.get('created_at', now)
                    s = t_obj.get('status')
                    if s in ('finished', 'error') and (now - c_time > 600):
                        tasks.pop(tid, None)
        except Exception:
            pass

threading.Thread(target=auto_cleanup_worker, daemon=True).start()

def resolve_music_streaming_url(url):
    """
    ตรวจจับลิงก์ที่ติด DRM เช่น Spotify, Apple Music 
    แล้วดึงชื่อเพลง+ศิลปินมาแปลงเป็นคำค้นหา YouTube อัตโนมัติ เพื่อให้ดาวน์โหลดได้โดยไม่ติด DRM!
    """
    try:
        if "open.spotify.com" in url:
            import urllib.request
            import urllib.parse
            import json
            oembed_url = "https://open.spotify.com/oembed?url=" + urllib.parse.quote(url)
            req = urllib.request.Request(oembed_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=updater.get_ssl_context()) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                title = data.get('title')
                if title:
                    return f"ytsearch1:{title} official audio"
        elif "music.apple.com" in url:
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=updater.get_ssl_context()) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                m = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                if m:
                    clean_t = m.group(1).split(' - Apple Music')[0].split(' on Apple Music')[0].strip()
                    return f"ytsearch1:{clean_t} audio"
    except Exception:
        pass
    return url

def compute_and_save_md5(file_path, url=""):
    try:
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        file_md5 = hasher.hexdigest()
        return file_md5
    except Exception as e:
        print(f"Error computing MD5: {e}")
        return None

def parse_time_str(t_str):
    if not t_str or not str(t_str).strip():
        return None
    parts = str(t_str).strip().split(':')
    try:
        if len(parts) == 1:
            return float(parts[0])
        elif len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        elif len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    except Exception:
        return None
    return None

app = Flask(__name__)
tasks = {}

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Universal Media Downloader - ดาวน์โหลด MP3 & MP4 ทุกเว็บ</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico?v=lightning2">
    <link rel="shortcut icon" type="image/x-icon" href="/favicon.ico?v=lightning2">
    <link rel="apple-touch-icon" href="/favicon.ico?v=lightning2">
    <meta name="theme-color" content="#080c14">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="Media Downloader">
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #6366f1;
            --primary-gradient: linear-gradient(135deg, #3b82f6 0%, #6366f1 50%, #8b5cf6 100%);
            --primary-hover: #4f46e5;
            --success: #10b981;
            --bg: #080c14;
            --card-bg: rgba(17, 24, 39, 0.72);
            --card-border: rgba(255, 255, 255, 0.08);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Prompt', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        body {
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 50% -10%, rgba(99, 102, 241, 0.22) 0%, transparent 60%),
                radial-gradient(circle at 90% 20%, rgba(59, 130, 246, 0.12) 0%, transparent 45%),
                radial-gradient(circle at 10% 70%, rgba(139, 92, 246, 0.1) 0%, transparent 50%);
            background-attachment: fixed;
            color: var(--text-main);
            min-height: 100vh;
            padding: 32px 16px 50px 16px;
            display: flex;
            flex-direction: column;
            align-items: center;
            -webkit-font-smoothing: antialiased;
        }
        .container {
            width: 100%;
            max-width: 720px;
        }

        /* Top Bar */
        .top-toolbar {
            width: 100%;
            display: flex;
            justify-content: flex-end;
            margin-bottom: 12px;
        }
        .btn-sound-toggle {
            background: rgba(255, 255, 255, 0.06);
            border: 1px solid rgba(255, 255, 255, 0.12);
            color: #cbd5e1;
            padding: 6px 14px;
            border-radius: 99px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            backdrop-filter: blur(8px);
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .btn-sound-toggle:hover {
            background: rgba(255, 255, 255, 0.12);
            color: #ffffff;
            border-color: rgba(99, 102, 241, 0.4);
        }

        /* Header */
        .header {
            text-align: center;
            margin-bottom: 26px;
            position: relative;
        }
        .header-logo-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 62px;
            height: 62px;
            border-radius: 20px;
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.22), rgba(245, 158, 11, 0.05));
            border: 1px solid rgba(245, 158, 11, 0.45);
            box-shadow: 0 0 25px rgba(245, 158, 11, 0.35);
            font-size: 30px;
            margin-bottom: 12px;
            animation: floatBadge 3.5s ease-in-out infinite;
        }
        @keyframes floatBadge {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-5px); }
        }
        .header h1 {
            font-size: 32px;
            font-weight: 800;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #ffffff 20%, #e2e8f0 55%, #93c5fd 85%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }
        .header p {
            color: #94a3b8;
            font-size: 14.5px;
            max-width: 580px;
            margin: 0 auto;
            line-height: 1.5;
        }
        .platform-chips {
            margin-top: 14px;
            display: flex;
            justify-content: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .chip {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid rgba(255, 255, 255, 0.08);
            color: #cbd5e1;
            padding: 5px 12px;
            border-radius: 99px;
            font-size: 12px;
            font-weight: 500;
            backdrop-filter: blur(8px);
            transition: all 0.2s;
        }
        .chip:hover {
            background: rgba(255, 255, 255, 0.09);
            border-color: rgba(255, 255, 255, 0.2);
            transform: translateY(-1px);
            color: #ffffff;
        }

        /* Clipboard Floating Banner */
        .clipboard-banner {
            display: none;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.25) 0%, rgba(139, 92, 246, 0.2) 100%);
            border: 1px solid rgba(99, 102, 241, 0.45);
            border-radius: 16px;
            padding: 12px 18px;
            margin-bottom: 20px;
            backdrop-filter: blur(16px);
            box-shadow: 0 10px 25px -5px rgba(99, 102, 241, 0.35);
            animation: slideDown 0.3s ease-out;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .clipboard-banner-text {
            font-size: 13.5px;
            color: #e0e7ff;
            display: flex;
            align-items: center;
            gap: 8px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .btn-clipboard-action {
            background: #6366f1;
            color: #ffffff;
            border: none;
            padding: 6px 14px;
            border-radius: 10px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s;
        }
        .btn-clipboard-action:hover {
            background: #4f46e5;
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.6);
        }

        /* App Download Banner */
        .app-download-banner {
            background: linear-gradient(135deg, rgba(30, 58, 138, 0.35) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(99, 102, 241, 0.3);
            border-radius: 20px;
            padding: 16px 20px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            backdrop-filter: blur(16px);
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        }
        .app-banner-left {
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .app-banner-icon {
            width: 44px;
            height: 44px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.15);
            padding: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
            object-fit: contain;
        }
        .app-banner-title {
            font-size: 15.5px;
            font-weight: 700;
            color: #ffffff;
            line-height: 1.3;
        }
        .app-banner-desc {
            font-size: 12px;
            color: #94a3b8;
            margin-top: 3px;
        }
        .btn-app-download {
            background: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%);
            color: #ffffff;
            font-weight: 600;
            padding: 10px 18px;
            border-radius: 12px;
            text-decoration: none;
            white-space: nowrap;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
            transition: all 0.25s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 13.5px;
        }
        .btn-app-download:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 22px rgba(99, 102, 241, 0.6);
            color: #ffffff;
        }

        /* Main Card */
        .card {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-radius: 24px;
            padding: 28px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 50px -10px rgba(99, 102, 241, 0.15);
            border: 1px solid var(--card-border);
            margin-bottom: 24px;
        }
        .input-group {
            display: flex;
            gap: 10px;
            margin-bottom: 14px;
        }
        .url-input {
            flex: 1;
            padding: 15px 18px;
            background: rgba(11, 15, 25, 0.85);
            border: 1.5px solid rgba(255, 255, 255, 0.12);
            border-radius: 16px;
            font-size: 15px;
            color: #f8fafc;
            outline: none;
            transition: all 0.25s;
        }
        .url-input::placeholder {
            color: #64748b;
        }
        .url-input:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.22), 0 0 25px rgba(99, 102, 241, 0.3);
            background: rgba(15, 23, 42, 0.95);
        }
        .btn {
            border: none;
            cursor: pointer;
            transition: all 0.25s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            text-decoration: none;
        }
        .btn-paste {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.14);
            color: #e2e8f0;
            border-radius: 14px;
            padding: 12px 20px;
            font-size: 14.5px;
            font-weight: 600;
        }
        .btn-paste:hover {
            background: rgba(255, 255, 255, 0.15);
            border-color: rgba(255, 255, 255, 0.25);
            color: #ffffff;
            transform: translateY(-1px);
        }
        .btn-search {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.25) 0%, rgba(139, 92, 246, 0.2) 100%);
            border: 1px solid rgba(99, 102, 241, 0.45);
            color: #c7d2fe;
            border-radius: 14px;
            padding: 12px 18px;
            font-size: 14.5px;
            font-weight: 600;
        }
        .btn-search:hover {
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.45) 0%, rgba(139, 92, 246, 0.4) 100%);
            border-color: rgba(99, 102, 241, 0.7);
            color: #ffffff;
            box-shadow: 0 0 15px rgba(99, 102, 241, 0.4);
            transform: translateY(-1px);
        }

        /* Server Status Pill */
        .server-status-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.28);
            border-radius: 99px;
            padding: 6px 16px;
            font-size: 12px;
            color: #a7f3d0;
            margin-top: 14px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px rgba(16, 185, 129, 0.12);
        }
        .status-pulse-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #10b981;
            box-shadow: 0 0 8px #10b981;
            animation: pulseGlow 1.8s infinite;
        }
        @keyframes pulseGlow {
            0%, 100% { opacity: 1; transform: scale(1); box-shadow: 0 0 8px #10b981; }
            50% { opacity: 0.4; transform: scale(0.85); box-shadow: 0 0 2px #10b981; }
        }
        .status-sep {
            color: rgba(255, 255, 255, 0.2);
        }

        /* Mode Tabs */
        .mode-tabs {
            display: flex;
            background: rgba(0, 0, 0, 0.35);
            padding: 4px;
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            margin-bottom: 20px;
            gap: 6px;
        }
        .mode-tab {
            flex: 1;
            padding: 10px 14px;
            border: none;
            background: transparent;
            color: #94a3b8;
            font-size: 13.5px;
            font-weight: 600;
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.25s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .mode-tab:hover {
            color: #ffffff;
            background: rgba(255, 255, 255, 0.05);
        }
        .mode-tab.active {
            color: #ffffff;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.4) 0%, rgba(139, 92, 246, 0.35) 100%);
            border: 1px solid rgba(99, 102, 241, 0.5);
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.3);
        }

        /* Instant Search Results Box */
        .search-results-box {
            display: none;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(99, 102, 241, 0.35);
            border-radius: 18px;
            padding: 14px;
            margin-top: 14px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.5);
            animation: fadeIn 0.3s ease;
        }
        .search-item-card {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            border-radius: 12px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            margin-bottom: 8px;
            transition: all 0.2s;
            cursor: pointer;
        }
        .search-item-card:last-child { margin-bottom: 0; }
        .search-item-card:hover {
            background: rgba(99, 102, 241, 0.15);
            border-color: rgba(99, 102, 241, 0.4);
            transform: translateX(3px);
        }
        .search-thumb {
            width: 72px;
            height: 48px;
            border-radius: 8px;
            object-fit: cover;
            border: 1px solid rgba(255, 255, 255, 0.1);
            flex-shrink: 0;
        }
        .search-info {
            flex: 1;
            min-width: 0;
            text-align: left;
        }
        .search-title {
            font-size: 13.5px;
            font-weight: 600;
            color: #f8fafc;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .search-meta {
            font-size: 11.5px;
            color: #94a3b8;
            margin-top: 3px;
            display: flex;
            gap: 8px;
        }
        .btn-select-search {
            padding: 6px 12px;
            background: #6366f1;
            color: #fff;
            border: none;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            white-space: nowrap;
            transition: all 0.2s;
            flex-shrink: 0;
        }
        .btn-select-search:hover {
            background: #4f46e5;
            box-shadow: 0 0 10px rgba(99, 102, 241, 0.5);
        }

        /* Batch Queue Section */
        .batch-mode-section {
            display: none;
        }
        .batch-textarea {
            width: 100%;
            height: 120px;
            padding: 14px 16px;
            background: rgba(11, 15, 25, 0.85);
            border: 1.5px solid rgba(255, 255, 255, 0.12);
            border-radius: 16px;
            font-size: 13.5px;
            color: #f8fafc;
            outline: none;
            resize: vertical;
            line-height: 1.5;
            transition: all 0.25s;
            margin-bottom: 14px;
            box-sizing: border-box;
        }
        .batch-textarea:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 4px rgba(99, 102, 241, 0.22);
        }
        .batch-queue-monitor {
            display: none;
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 18px;
            padding: 18px;
            margin-top: 18px;
        }
        .batch-item-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 10px 12px;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 12px;
            margin-bottom: 8px;
            font-size: 13px;
        }
        .batch-badge {
            font-size: 11px;
            font-weight: 600;
            padding: 3px 8px;
            border-radius: 6px;
            white-space: nowrap;
        }
        .batch-badge.pending { background: rgba(148, 163, 184, 0.15); color: #94a3b8; }
        .batch-badge.running { background: rgba(59, 130, 246, 0.2); color: #93c5fd; animation: pulseGlow 1s infinite; }
        .batch-badge.done { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; }
        .batch-badge.error { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
        .btn-primary {
            background: linear-gradient(135deg, #2563eb 0%, #4f46e5 50%, #7c3aed 100%);
            color: #ffffff;
            width: 100%;
            padding: 16px;
            font-size: 16.5px;
            font-weight: 700;
            letter-spacing: 0.2px;
            border-radius: 16px;
            box-shadow: 0 10px 30px -5px rgba(79, 70, 229, 0.5);
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        .btn-primary:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 15px 35px -5px rgba(79, 70, 229, 0.7);
            background: linear-gradient(135deg, #1d4ed8 0%, #4338ca 50%, #6d28d9 100%);
        }
        .btn-primary:disabled {
            background: #334155;
            color: #94a3b8;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* Quick sample links */
        .quick-links {
            display: flex;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }
        .quick-btn {
            background: rgba(99, 102, 241, 0.1);
            color: #a5b4fc;
            border: 1px solid rgba(99, 102, 241, 0.25);
            padding: 6px 13px;
            border-radius: 10px;
            font-size: 12.5px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .quick-btn:hover {
            background: rgba(99, 102, 241, 0.22);
            border-color: rgba(99, 102, 241, 0.5);
            color: #ffffff;
            transform: translateY(-1px);
        }

        /* 4-Column Format selection */
        .format-selection {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-bottom: 20px;
        }
        .format-option {
            background: rgba(15, 23, 42, 0.6);
            border: 1.5px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 12px 10px;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 6px;
            cursor: pointer;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            user-select: none;
            position: relative;
        }
        .format-option:hover {
            border-color: rgba(99, 102, 241, 0.4);
            background: rgba(15, 23, 42, 0.85);
            transform: translateY(-2px);
        }
        .format-option input[type="radio"] {
            position: absolute;
            top: 8px;
            right: 8px;
            accent-color: #6366f1;
            width: 15px;
            height: 15px;
        }
        .format-option:has(input[type="radio"]:checked) {
            border-color: #6366f1;
            background: linear-gradient(135deg, rgba(99, 102, 241, 0.25) 0%, rgba(59, 130, 246, 0.12) 100%);
            box-shadow: 0 0 25px rgba(99, 102, 241, 0.3);
        }
        .format-icon {
            font-size: 22px;
            margin-bottom: 2px;
        }
        .format-name {
            font-weight: 700;
            font-size: 13.5px;
            color: #f1f5f9;
        }
        .format-desc {
            font-size: 11px;
            color: #94a3b8;
            line-height: 1.3;
        }

        /* Smart Audio FX Studio */
        .fx-studio-box {
            background: linear-gradient(135deg, rgba(30, 27, 75, 0.4) 0%, rgba(15, 23, 42, 0.6) 100%);
            border: 1.5px solid rgba(139, 92, 246, 0.35);
            border-radius: 18px;
            padding: 16px 18px;
            margin-bottom: 20px;
            backdrop-filter: blur(12px);
            transition: all 0.3s;
        }
        .fx-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
        }
        .fx-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 700;
            font-size: 14.5px;
            color: #c4b5fd;
        }
        .fx-badge {
            background: rgba(168, 85, 247, 0.2);
            border: 1px solid rgba(168, 85, 247, 0.4);
            color: #f0abfc;
            padding: 2px 8px;
            border-radius: 99px;
            font-size: 11px;
            font-weight: 600;
        }
        .fx-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 8px;
        }
        .fx-pill {
            background: rgba(15, 23, 42, 0.7);
            border: 1.5px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 10px 10px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            flex-direction: column;
            gap: 3px;
            user-select: none;
            position: relative;
        }
        .fx-pill:hover {
            border-color: rgba(168, 85, 247, 0.5);
            background: rgba(15, 23, 42, 0.9);
        }
        .fx-pill input[type="radio"] {
            display: none;
        }
        .fx-pill:has(input[type="radio"]:checked) {
            border-color: #a855f7;
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.28) 0%, rgba(99, 102, 241, 0.15) 100%);
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.35);
        }
        .fx-pill-name {
            font-size: 12.5px;
            font-weight: 700;
            color: #f8fafc;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .fx-pill-desc {
            font-size: 10.5px;
            color: #94a3b8;
            line-height: 1.25;
        }

        /* Time range cut */
        .time-cut-container {
            background: rgba(15, 23, 42, 0.5);
            border: 1.5px dashed rgba(255, 255, 255, 0.12);
            border-radius: 16px;
            padding: 14px 18px;
            margin-bottom: 22px;
            transition: all 0.2s;
        }
        .time-cut-container:hover {
            border-color: rgba(99, 102, 241, 0.4);
        }
        .time-cut-label {
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            color: #e2e8f0;
            user-select: none;
        }
        .time-cut-label input {
            accent-color: #6366f1;
            width: 17px;
            height: 17px;
        }
        .time-inputs-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            margin-top: 12px;
        }
        .time-field {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .time-field label {
            font-size: 12px;
            font-weight: 600;
            color: #94a3b8;
        }
        .time-field input {
            padding: 10px 14px;
            border: 1.5px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            font-size: 14px;
            outline: none;
            background: rgba(11, 15, 25, 0.8);
            color: #f8fafc;
            font-family: monospace, sans-serif;
            transition: all 0.2s;
        }
        .time-field input:focus {
            border-color: #6366f1;
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.25);
        }
        .time-hint {
            font-size: 11.5px;
            color: #94a3b8;
            margin-top: 8px;
            line-height: 1.5;
        }

        /* Neon Audio Visualizer Canvas */
        .visualizer-wrapper {
            margin: 14px 0 10px 0;
            border-radius: 12px;
            overflow: hidden;
            background: rgba(8, 12, 20, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 52px;
            position: relative;
        }
        #visualizerCanvas {
            width: 100%;
            height: 100%;
            display: block;
        }

        /* Progress section */
        .progress-box {
            display: none;
            margin-top: 22px;
            padding: 20px;
            background: rgba(15, 23, 42, 0.75);
            border-radius: 16px;
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05);
        }
        .progress-bar-bg {
            background: rgba(255, 255, 255, 0.08);
            height: 10px;
            border-radius: 99px;
            overflow: hidden;
            margin: 12px 0 8px 0;
        }
        .progress-bar-fill {
            background: linear-gradient(90deg, #3b82f6, #6366f1, #a855f7, #ec4899);
            height: 100%;
            width: 0%;
            transition: width 0.3s;
            border-radius: 99px;
            box-shadow: 0 0 15px rgba(168, 85, 247, 0.6);
        }
        .status-text {
            font-size: 14px;
            font-weight: 500;
            color: #f1f5f9;
            display: flex;
            justify-content: space-between;
        }

        /* Result card */
        .result-box {
            display: none;
            margin-top: 22px;
            padding: 24px;
            background: linear-gradient(135deg, rgba(6, 78, 59, 0.35) 0%, rgba(6, 95, 70, 0.15) 100%);
            border: 1px solid rgba(16, 185, 129, 0.4);
            border-radius: 18px;
            box-shadow: 0 15px 35px -10px rgba(0, 0, 0, 0.5), 0 0 40px rgba(16, 185, 129, 0.2);
            animation: fadeIn 0.3s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.98); }
            to { opacity: 1; transform: scale(1); }
        }
        .result-header-row {
            display: flex;
            gap: 16px;
            align-items: flex-start;
            margin-bottom: 14px;
        }
        .result-thumb {
            width: 80px;
            height: 80px;
            border-radius: 12px;
            object-fit: cover;
            border: 1.5px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.4);
            background: #0f172a;
            flex-shrink: 0;
            display: none;
        }
        .result-info {
            flex: 1;
            min-width: 0;
        }
        .result-title {
            color: #34d399;
            font-weight: 700;
            font-size: 17px;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .result-file-name {
            color: #f8fafc;
            font-size: 14.5px;
            word-break: break-all;
            margin-bottom: 6px;
            font-weight: 600;
            line-height: 1.4;
        }
        .result-actions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 14px;
        }
        .btn-download-direct {
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            color: white;
            flex: 1.2;
            min-width: 180px;
            font-weight: 700;
            border-radius: 14px;
            padding: 13px 18px;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);
            font-size: 14px;
        }
        .btn-download-direct:hover {
            box-shadow: 0 6px 22px rgba(16, 185, 129, 0.6);
            transform: translateY(-2px);
        }
        .btn-qr-action {
            background: linear-gradient(135deg, #4338ca 0%, #6366f1 100%);
            color: white;
            flex: 1;
            min-width: 160px;
            font-weight: 600;
            border-radius: 14px;
            padding: 13px 18px;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
            font-size: 14px;
        }
        .btn-qr-action:hover {
            box-shadow: 0 6px 22px rgba(99, 102, 241, 0.6);
            transform: translateY(-2px);
        }
        .btn-thumb-action {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: #e2e8f0;
            border-radius: 14px;
            padding: 13px 16px;
            font-size: 13.5px;
            font-weight: 600;
            white-space: nowrap;
        }
        .btn-thumb-action:hover {
            background: rgba(255, 255, 255, 0.16);
            color: #ffffff;
            transform: translateY(-2px);
        }

        /* Audio player */
        audio {
            width: 100%;
            margin-top: 10px;
            border-radius: 10px;
        }

        /* Anti-Flood & Rate Limit Notice Box (Bottom) */
        .antiflood-box {
            background: linear-gradient(135deg, rgba(30, 58, 138, 0.25) 0%, rgba(15, 23, 42, 0.6) 100%);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-left: 4px solid #3b82f6;
            border-radius: 16px;
            padding: 16px 20px;
            margin-top: 22px;
            font-size: 13px;
            color: #bfdbfe;
            backdrop-filter: blur(12px);
        }
        .antiflood-header {
            font-weight: 700;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: #93c5fd;
            font-size: 13.5px;
        }

        /* Unsupported Sites Box */
        .unsupported-box {
            background: linear-gradient(135deg, rgba(120, 53, 15, 0.25) 0%, rgba(15, 23, 42, 0.6) 100%);
            border: 1px solid rgba(245, 158, 11, 0.3);
            border-left: 4px solid #f59e0b;
            border-radius: 16px;
            padding: 16px 20px;
            margin-top: 20px;
            font-size: 13px;
            color: #fde68a;
            backdrop-filter: blur(12px);
        }
        .unsupported-header {
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
            color: #fcd34d;
            font-size: 13.5px;
            margin-bottom: 8px;
        }
        .unsupported-list {
            display: grid;
            gap: 5px;
            padding-left: 4px;
            font-size: 12.5px;
        }
        .unsupported-item {
            display: flex;
            gap: 6px;
        }
        .unsupported-tag {
            color: #f87171;
            font-weight: 600;
            white-space: nowrap;
        }

        /* Modal Popup */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(3, 7, 18, 0.82);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            padding: 16px;
        }
        .modal-box {
            background: rgba(15, 23, 42, 0.96);
            border: 1px solid rgba(255, 255, 255, 0.12);
            border-radius: 24px;
            width: 100%;
            max-width: 580px;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 25px 60px rgba(0, 0, 0, 0.85), 0 0 60px rgba(99, 102, 241, 0.2);
            animation: modalFadeIn 0.25s ease-out;
            color: #f1f5f9;
        }
        @keyframes modalFadeIn {
            from { opacity: 0; transform: scale(0.96); }
            to { opacity: 1; transform: scale(1); }
        }
        .modal-header {
            padding: 22px 26px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .modal-header h3 {
            font-size: 18.5px;
            color: #ffffff;
            font-weight: 700;
        }
        .modal-body {
            padding: 22px 26px;
            color: #cbd5e1;
            font-size: 14px;
            line-height: 1.6;
        }
        .modal-footer {
            padding: 18px 26px;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            background: rgba(11, 15, 25, 0.8);
            border-radius: 0 0 24px 24px;
        }
        .policy-section {
            margin-bottom: 18px;
        }
        .policy-section h4 {
            font-size: 15px;
            color: #93c5fd;
            margin-bottom: 4px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .policy-section p {
            font-size: 13px;
            color: #94a3b8;
        }

        /* QR Code Modal Specifics */
        .qr-card-center {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            gap: 14px;
        }
        .qr-image-container {
            background: #ffffff;
            padding: 14px;
            border-radius: 20px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5), 0 0 30px rgba(99, 102, 241, 0.35);
            display: inline-block;
        }
        .qr-image-container img {
            display: block;
            width: 220px;
            height: 220px;
            border-radius: 8px;
        }
        .qr-wifi-badge {
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid rgba(99, 102, 241, 0.35);
            color: #c7d2fe;
            padding: 6px 14px;
            border-radius: 99px;
            font-size: 12.5px;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }

        /* Footer */
        .site-footer {
            margin-top: 36px;
            text-align: center;
            font-size: 12.5px;
            color: #64748b;
            border-top: 1px solid rgba(255, 255, 255, 0.08);
            padding-top: 24px;
            width: 100%;
        }
        .footer-links {
            display: flex;
            justify-content: center;
            gap: 16px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }
        .footer-link {
            color: #818cf8;
            text-decoration: none;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }
        .footer-link:hover {
            color: #c7d2fe;
            text-decoration: underline;
        }

        /* Why Choose Us Section */
        .why-us-section {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.7) 0%, rgba(17, 24, 39, 0.85) 100%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            padding: 26px 24px;
            margin-bottom: 24px;
            box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(20px);
        }
        .why-us-header {
            text-align: center;
            margin-bottom: 20px;
        }
        .why-us-title {
            font-size: 20px;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 30%, #93c5fd 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 6px;
        }
        .why-us-subtitle {
            font-size: 13px;
            color: #94a3b8;
        }
        .why-us-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 14px;
        }
        .why-us-card {
            background: rgba(11, 15, 25, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 16px;
            padding: 16px;
            display: flex;
            gap: 14px;
            transition: all 0.25s;
        }
        .why-us-card:hover {
            border-color: rgba(99, 102, 241, 0.35);
            background: rgba(15, 23, 42, 0.8);
            transform: translateY(-2px);
        }
        .why-us-icon-box {
            width: 42px;
            height: 42px;
            border-radius: 12px;
            background: rgba(99, 102, 241, 0.15);
            border: 1px solid rgba(99, 102, 241, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
        }
        .why-us-card-title {
            font-size: 14px;
            font-weight: 700;
            color: #f1f5f9;
            margin-bottom: 4px;
        }
        .why-us-card-desc {
            font-size: 12px;
            color: #94a3b8;
            line-height: 1.45;
        }

        @media (max-width: 650px) {
            .why-us-grid {
                grid-template-columns: 1fr;
            }
            .app-download-banner {
                flex-direction: column;
                align-items: stretch;
                text-align: center;
            }
            .app-banner-left {
                flex-direction: column;
                text-align: center;
            }
            .btn-app-download {
                justify-content: center;
            }
            .format-selection {
                grid-template-columns: repeat(2, 1fr);
            }
            .card {
                padding: 20px;
            }
            .result-header-row {
                flex-direction: column;
                align-items: center;
                text-align: center;
            }
            .result-thumb {
                width: 110px;
                height: 110px;
            }
        }
        @keyframes pulseBadge {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.15); opacity: 0.85; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Top Toolbar -->
        <div class="top-toolbar" style="gap: 10px;">
            <button type="button" id="btnUpdatePatchNav" class="btn-sound-toggle" onclick="openUpdateModal()" title="ตรวจสอบและติดตั้งแพทช์แก้ทาง YouTube/TikTok ล่าสุด">
                <span id="patchIconNav">⚡</span>
                <span id="patchLabelNav">แพทช์: กำลังเช็ค...</span>
                <span id="patchBadgeNav" style="display:none; background:#ef4444; color:#fff; font-size:10px; font-weight:700; padding:2px 7px; border-radius:10px; margin-left:4px; animation: pulseBadge 1.5s infinite;">NEW</span>
            </button>
        </div>

        <!-- Header -->
        <div class="header">
            <div class="header-logo-badge">⚡</div>
            <h1>Universal Media Downloader</h1>
            <p>ดาวน์โหลดเพลง วิดีโอ ภาพปก และเสียงเรียกเข้าคุณภาพสูงสุดจากทุกแพลตฟอร์มทั่วโลก</p>
            <div class="platform-chips">
                <span class="chip">🔴 YouTube</span>
                <span class="chip">⬛ TikTok</span>
                <span class="chip">🔵 Facebook</span>
                <span class="chip">🟣 Instagram</span>
                <span class="chip">🐦 Twitter / X</span>
                <span class="chip">🟠 SoundCloud</span>
                <span class="chip">📺 Bilibili</span>
                <span class="chip">🟣 Twitch</span>
                <span class="chip">🔗 ลิงก์ตรงทุกเว็บ</span>
            </div>
            <div class="server-status-pill">
                <span class="status-pulse-dot"></span>
                <span>เซิร์ฟเวอร์พร้อมทำงานสูงสุด (Gigabit Engine)</span>
                <span class="status-sep">•</span>
                <span id="headerPatchPill" style="color: #38bdf8; font-weight: 600;">⚡ Patch...</span>
                <span class="status-sep">•</span>
                <span style="color: #10b981; font-weight: 600;">🛡️ Google DNS (8.8.8.8)</span>
                <span class="status-sep">•</span>
                <span>Ultra HD 320 kbps</span>
            </div>
        </div>

        <!-- New Patch Alert Notification Bar -->
        <div id="newPatchAlertBanner" style="display:none; background: linear-gradient(90deg, rgba(239, 68, 68, 0.18), rgba(249, 115, 22, 0.18)); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 14px; padding: 12px 18px; margin-bottom: 20px; align-items: center; justify-content: space-between; backdrop-filter: blur(12px); box-shadow: 0 4px 20px rgba(239, 68, 68, 0.15);">
            <div style="display: flex; align-items: center; gap: 12px; font-size: 13.5px; color: #fecaca;">
                <span style="font-size: 20px;">🔥</span>
                <span><b>แจ้งเตือนแพทช์ใหม่!</b> มีการปล่อยอัปเดตเอนจิ้น <b id="newPatchNameAlert" style="color: #fed7aa; background: rgba(249, 115, 22, 0.25); padding: 2px 8px; border-radius: 6px;">...</b> เพื่อแก้ทาง YouTube/TikTok ให้ดาวน์โหลดได้ลื่นไหล</span>
            </div>
            <button type="button" onclick="openUpdateModal()" class="btn btn-primary" style="padding: 6px 16px; font-size: 12.5px; width: auto; white-space: nowrap; font-weight: 700;">
                ⚡ ติดตั้งแพทช์ทันที
            </button>
        </div>

        <!-- Clipboard Auto-detect Floating Banner -->
        <div id="clipboardBanner" class="clipboard-banner">
            <div class="clipboard-banner-text">
                <span style="font-size: 18px;">⚡</span>
                <span>ตรวจพบคลิปบอร์ด: <b id="clipboardUrlPreview" style="color: #ffffff;">...</b></span>
            </div>
            <button type="button" class="btn-clipboard-action" onclick="useDetectedClipboard()">วางทันที</button>
        </div>

        <!-- App Download Banner (Enhanced Highlights) -->
        <div class="app-download-banner">
            <div class="app-banner-left">
                <img src="/favicon.ico?v=lightning2" class="app-banner-icon" alt="Universal Media Downloader">
                <div>
                    <div class="app-banner-title">💻 แนะนำ: โปรแกรมคอมพิวเตอร์ (Windows Desktop Pro)</div>
                    <div class="app-banner-desc">ทำงานออฟไลน์ได้ 100% • โหลดคลิปยาว 2-4 ชม. ไม่มีหลุด • มี FFmpeg แท้ในตัว • บันทึกลงโฟลเดอร์เครื่องถาวร</div>
                    <div style="display: flex; gap: 6px; margin-top: 6px; flex-wrap: wrap;">
                        <span style="font-size: 11px; background: rgba(59, 130, 246, 0.2); color: #93c5fd; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(59, 130, 246, 0.3);">⚡ ไร้โฆษณา</span>
                        <span style="font-size: 11px; background: rgba(16, 185, 129, 0.2); color: #6ee7b7; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(16, 185, 129, 0.3);">📂 เซฟลงคอมถาวร</span>
                        <span style="font-size: 11px; background: rgba(168, 85, 247, 0.2); color: #e9d5ff; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(168, 85, 247, 0.3);">🚀 ความเร็วเต็มสปีด</span>
                        <span style="font-size: 11px; background: rgba(245, 158, 11, 0.2); color: #fde68a; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(245, 158, 11, 0.3);">📦 ไฟล์เดียวจบ ไม่ต้องติดตั้ง</span>
                    </div>
                </div>
            </div>
            <a href="/download-app" class="btn btn-app-download" title="ดาวน์โหลดโปรแกรมสำหรับใช้งานบนคอมพิวเตอร์">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
                <span id="appDownloadBtnText">ดาวน์โหลดโปรแกรม (.exe)</span>
            </a>
        </div>

        <div class="card">
            <!-- Mode Switcher Tabs -->
            <div class="mode-tabs">
                <button type="button" class="mode-tab active" id="tabSingle" onclick="switchMode('single')">
                    ⚡ โหลดด่วน / ค้นหาเพลง
                </button>
                <button type="button" class="mode-tab" id="tabBatch" onclick="switchMode('batch')">
                    📑 คิวโหลดหลายเพลง (Multi-Link Queue)
                </button>
            </div>

            <!-- SINGLE / SEARCH MODE SECTION -->
            <div id="singleModeSection">
                <!-- URL Input -->
                <div class="input-group">
                    <div style="position: relative; flex: 1; display: flex; align-items: center;">
                        <input type="text" id="urlInput" class="url-input" placeholder="วางลิงก์ (YouTube, TikTok, FB) หรือพิมพ์ชื่อเพลงเพื่อค้นหา..." autofocus style="width: 100%; padding-right: 40px;">
                        <button type="button" id="clearUrlBtn" onclick="clearUrlInput()" title="ล้างข้อความ" style="display: none; position: absolute; right: 12px; background: rgba(255,255,255,0.12); border: none; color: #94a3b8; width: 26px; height: 26px; border-radius: 50%; cursor: pointer; align-items: center; justify-content: center; font-size: 13px; transition: all 0.2s;">✕</button>
                    </div>
                    <button type="button" class="btn btn-search" id="searchBtn" onclick="triggerSearchOrDownload()" title="ค้นหาเพลงด่วน">🔍 ค้นหา</button>
                    <button type="button" class="btn btn-paste" onclick="pasteClipboard()">📋 วาง</button>
                </div>

                <!-- Instant Search Results Box -->
                <div id="searchResultsBox" class="search-results-box">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <div style="font-size: 13px; font-weight: 700; color: #cbd5e1;">🔍 ผลการค้นหาเพลง:</div>
                        <button type="button" onclick="closeSearchResults()" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 13px;">✕ ปิด</button>
                    </div>
                    <div id="searchResultsList"></div>
                </div>

                <!-- Quick sample buttons -->
                <div class="quick-links">
                    <span style="font-size: 13px; color: var(--text-muted); align-self: center;">ลิงก์ลองโหลด:</span>
                    <button class="quick-btn" onclick="setSample('https://www.youtube.com/watch?v=jNQXAC9IVRw')">⚡ คลิปทดสอบ (19 วิ)</button>
                    <button class="quick-btn" onclick="setSample('https://www.youtube.com/watch?v=bM7SZ5SBzyY')">🎵 Alan Walker - Fade</button>
                </div>
            </div>

            <!-- BATCH QUEUE MODE SECTION -->
            <div id="batchModeSection" class="batch-mode-section">
                <div style="margin-bottom: 8px; font-size: 13px; color: #cbd5e1; font-weight: 600;">
                    📑 วางลิงก์ที่ต้องการดาวน์โหลด (1 บรรทัด ต่อ 1 ลิงก์ สูงสุด 5 ลิงก์):
                </div>
                <textarea id="batchUrlsInput" class="batch-textarea" placeholder="https://www.youtube.com/watch?v=...&#10;https://www.tiktok.com/@user/video/...&#10;https://www.facebook.com/watch/..."></textarea>
            </div>

            <!-- 4-Format Options -->
            <div class="format-selection">
                <label class="format-option" onclick="onFormatChanged('mp3')">
                    <input type="radio" name="format" value="mp3" checked>
                    <div class="format-icon">🎵</div>
                    <span class="format-name">MP3 (320k)</span>
                    <span class="format-desc">เสียงสตูดิโอ + ฝังรูปปก</span>
                </label>
                <label class="format-option" onclick="onFormatChanged('mp4')">
                    <input type="radio" name="format" value="mp4">
                    <div class="format-icon">🎬</div>
                    <span class="format-name">MP4 วิดีโอ</span>
                    <span class="format-desc">ภาพคมชัดระดับ HD</span>
                </label>
                <label class="format-option" onclick="onFormatChanged('m4r')">
                    <input type="radio" name="format" value="m4r">
                    <div class="format-icon">🔔</div>
                    <span class="format-name">M4R เสียงเรียกเข้า</span>
                    <span class="format-desc">สำหรับ iPhone / iOS</span>
                </label>
                <label class="format-option" onclick="onFormatChanged('gif')">
                    <input type="radio" name="format" value="gif">
                    <div class="format-icon">🎞️</div>
                    <span class="format-name">GIF มีมเคลื่อนไหว</span>
                    <span class="format-desc">ตัดไฮไลท์ส่งในแชท</span>
                </label>
            </div>

            <!-- Smart Audio FX Studio Box (Shows on MP3 / M4R) -->
            <div id="fxStudioBox" class="fx-studio-box">
                <div class="fx-header">
                    <div class="fx-title">
                        <span>🎛️</span>
                        <span>สตูดิโอปรับแต่งเสียงพิเศษ (Smart Audio FX)</span>
                    </div>
                    <span class="fx-badge">Real-time FFmpeg</span>
                </div>
                <div class="fx-grid">
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="none" checked>
                        <span class="fx-pill-name">⚡ ต้นฉบับ 320k</span>
                        <span class="fx-pill-desc">เสียงตรงตามไฟล์เดิม ไม่แต่ง</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="bass_boost">
                        <span class="fx-pill-name">🔥 Bass Boost</span>
                        <span class="fx-pill-desc">เร่งย่านต่ำ +8dB ตึ้บในรถ</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="mega_bass">
                        <span class="fx-pill-name">💥 Mega Bass</span>
                        <span class="fx-pill-desc">เบสลึกกระหึ่ม +14dB</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="slowed_reverb">
                        <span class="fx-pill-name">🌧️ Slowed + Reverb</span>
                        <span class="fx-pill-desc">สไตล์ TikTok Lofi ฟังสบาย</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="8d_audio">
                        <span class="fx-pill-name">🎧 8D Surround</span>
                        <span class="fx-pill-desc">เสียงหมุน 360° (ใส่หูฟัง)</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="vocal_boost">
                        <span class="fx-pill-name">🎙️ Vocal Booster</span>
                        <span class="fx-pill-desc">เร่งเสียงพูด/ร้อง ให้คมชัด</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="karaoke_cut">
                        <span class="fx-pill-name">🎤 คาราโอเกะ (ตัดเสียงร้อง)</span>
                        <span class="fx-pill-desc">ตัดเสียงร้องตรงกลาง ทำดนตรีเปล่า</span>
                    </label>
                    <label class="fx-pill">
                        <input type="radio" name="audio_fx" value="volume_boost">
                        <span class="fx-pill-name">🔊 เร่งเสียง 200%</span>
                        <span class="fx-pill-desc">เพิ่มความดัง +6dB ชัดเจนไม่แตก</span>
                    </label>
                </div>
            </div>

            <!-- Time Range Cut Option -->
            <div class="time-cut-container">
                <label class="time-cut-label">
                    <input type="checkbox" id="enableTimeCut" onchange="toggleTimeCut()">
                    <span>✂️ เลือกตัดเฉพาะช่วงเวลาที่ต้องการ (Time Range / Ringtone / GIF)</span>
                </label>
                <div id="timeInputsRow" class="time-inputs-row" style="display: none;">
                    <div class="time-field">
                        <label>⏱️ เวลาเริ่มต้น (Start):</label>
                        <input type="text" id="startTimeInput" placeholder="00:00" value="00:00">
                    </div>
                    <div class="time-field">
                        <label>⏱️ เวลาสิ้นสุด (End):</label>
                        <input type="text" id="endTimeInput" placeholder="เช่น 00:30 หรือปล่อยว่าง">
                    </div>
                </div>
                <div id="timeHint" class="time-hint" style="display: none;">
                    💡 ระบุเป็น <b>นาที:วินาที</b> เช่น <code>01:20</code> (1 นาที 20 วินาที) หรือเป็น <b>วินาที</b> เช่น <code>80</code> (สำหรับทำเสียงเรียกเข้าแนะนำ 30-40 วินาที, GIF แนะนำ 3-8 วินาที)
                </div>
            </div>

            <!-- Download Button (Single Mode) -->
            <button id="downloadBtn" class="btn btn-primary" onclick="startDownload()">
                🚀 เริ่มดาวน์โหลดและแปลงไฟล์ทันที
            </button>

            <!-- Download Button (Batch Mode) -->
            <button id="batchDownloadBtn" class="btn btn-primary" onclick="startBatchQueue()" style="display: none; background: linear-gradient(135deg, #059669 0%, #10b981 100%);">
                🚀 เริ่มดาวน์โหลดทุกเพลงในคิว (Sequential Queue)
            </button>

            <!-- Progress Box & Visualizer -->
            <div id="progressBox" class="progress-box">
                <div class="status-text">
                    <span id="statusLabel">กำลังเชื่อมต่อ...</span>
                    <span id="percentLabel">0%</span>
                </div>
                <div class="progress-bar-bg">
                    <div id="progressBar" class="progress-bar-fill"></div>
                </div>
                <div id="detailLabel" style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">...</div>

                <!-- Dynamic Neon Visualizer -->
                <div class="visualizer-wrapper">
                    <canvas id="visualizerCanvas" width="600" height="52"></canvas>
                </div>
            </div>

            <!-- Result Box -->
            <div id="resultBox" class="result-box">
                <div class="result-header-row">
                    <img id="resultThumbImg" class="result-thumb" src="" alt="Thumbnail">
                    <div class="result-info">
                        <div class="result-title">🎉 แปลงไฟล์สำเร็จเรียบร้อย!</div>
                        <div id="resultFileName" class="result-file-name">ชื่อเพลง.mp3</div>
                        <div id="resultMd5Row" style="font-size: 12px; color: #a7f3d0; margin-bottom: 6px; font-family: monospace; word-break: break-all;">🔑 <b>MD5 Checksum:</b> <span id="resultMd5">-</span></div>
                    </div>
                </div>
                
                <div id="audioContainer" style="display: none;">
                    <audio id="audioPlayer" controls crossorigin="anonymous"></audio>
                </div>

                <div class="result-actions">
                    <a id="directDownloadLink" class="btn btn-download-direct" href="#" download onclick="handleDirectDownload()">
                        📥 บันทึกลงเครื่องทันที
                    </a>
                    <button type="button" id="qrPhoneBtn" class="btn btn-qr-action" onclick="openQrModal()">
                        📱 สแกนโหลดใส่มือถือ
                    </button>
                    <button type="button" id="thumbDownloadBtn" class="btn btn-thumb-action" style="display: none;" onclick="downloadThumbnailHD()">
                        🖼️ โหลดรูปปก HD
                    </button>
                </div>

                <div id="zeroStorageNotice" style="display: none; font-size: 13px; color: #047857; background: #ecfdf5; padding: 10px 14px; border-radius: 10px; margin-top: 12px; border: 1px solid #a7f3d0; text-align: center;"></div>
                <div style="margin-top: 12px; font-size: 12px; color: #6ee7b7; display: flex; align-items: center; gap: 6px;">
                    <span>🛡️ <b>Zero-Storage Policy:</b> ไฟล์จะถูกส่งมอบให้คุณโดยตรงและลบออกจากเซิร์ฟเวอร์ทันที ปลอดภัย ไร้ร่องรอย 100%</span>
                </div>
            </div>

            <!-- Batch Queue Monitor -->
            <div id="batchQueueMonitor" class="batch-queue-monitor">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div style="font-size: 14px; font-weight: 700; color: #f8fafc;">📑 ความคืบหน้าคิวดาวน์โหลด:</div>
                    <div id="batchProgressCounter" style="font-size: 12.5px; font-weight: 600; color: #93c5fd;">0 / 0 เพลง</div>
                </div>
                <div class="progress-bar-bg" style="margin-bottom: 14px;">
                    <div id="batchProgressBar" class="progress-bar-fill" style="width: 0%; background: linear-gradient(90deg, #10b981, #06b6d4);"></div>
                </div>
                <div id="batchItemsList"></div>
            </div>
        </div>

        <!-- Why Choose Us Section -->
        <div class="why-us-section">
            <div class="why-us-header">
                <div class="why-us-title">✨ ทำไมต้องเลือก Universal Media Downloader?</div>
                <div class="why-us-subtitle">จุดเด่นที่ทำให้เราแตกต่างและเหนือกว่าเว็บไซต์ดาวน์โหลดทั่วไป</div>
            </div>
            <div class="why-us-grid">
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.35);">🚫</div>
                    <div>
                        <div class="why-us-card-title">ไร้โฆษณากวนใจ & ปลอดภัย 100%</div>
                        <div class="why-us-card-desc">หมดปัญหาปุ่มดาวน์โหลดปลอม ไวรัส สแปม หรือโฆษณาแท็บเด้ง 18+ เว็บเราสะอาด สบายตา และปลอดภัยสูงสุด</div>
                    </div>
                </div>
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(59, 130, 246, 0.15); border-color: rgba(59, 130, 246, 0.35);">🎵</div>
                    <div>
                        <div class="why-us-card-title">เสียงสตูดิโอ 320 kbps + ฝังปกแท้</div>
                        <div class="why-us-card-desc">ถอดรหัสบิตเรตสูงสุด 320 kbps ด้วย FFmpeg Engine พร้อมดึงรูปปกชัด 4K และชื่อศิลปินฝังลงในไฟล์ทันที</div>
                    </div>
                </div>
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(168, 85, 247, 0.15); border-color: rgba(168, 85, 247, 0.35);">🎛️</div>
                    <div>
                        <div class="why-us-card-title">สตูดิโอแต่งเสียงพิเศษ (Smart Audio FX)</div>
                        <div class="why-us-card-desc">แปลงเพลงเป็น 8D Audio มิติ 360°, Bass Boost เบสหนักในรถ, หรือ Slowed + Reverb ชิลล์สไตล์ TikTok ในคลิกเดียว</div>
                    </div>
                </div>
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.35);">📱</div>
                    <div>
                        <div class="why-us-card-title">สแกน QR Code เพลงเข้ามือถือทันที</div>
                        <div class="why-us-card-desc">แปลงเสร็จเอามือถือสแกน QR Code ผ่าน Wi-Fi โหลดเข้าเครื่องทันที ไม่ต้องต่อสาย USB หรือส่งเข้า LINE ให้เปลืองเน็ต</div>
                    </div>
                </div>
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.35);">🔒</div>
                    <div>
                        <div class="why-us-card-title">รักษาความเป็นส่วนตัว (Zero-Storage)</div>
                        <div class="why-us-card-desc">เซิร์ฟเวอร์ไม่เก็บไฟล์สื่อและไม่บันทึกประวัติส่วนตัว ลบทิ้งอัตโนมัติทันทีหลังส่งมอบ ปลอดภัย ไร้ร่องรอย 100%</div>
                    </div>
                </div>
                <div class="why-us-card">
                    <div class="why-us-icon-box" style="background: rgba(236, 72, 153, 0.15); border-color: rgba(236, 72, 153, 0.35);">✂️</div>
                    <div>
                        <div class="why-us-card-title">ตัดท่อนฮุก + เสียงเรียกเข้า iOS + GIF</div>
                        <div class="why-us-card-desc">ระบุเวลาตัดช่วงที่ชอบ ทำเสียงเรียกเข้า iPhone (.m4r) หรือทำภาพมีมเคลื่อนไหวสั้น (.gif) ส่งแชทได้ครบในที่เดียว</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Anti-Flood & Rate Limit Notice Box (Bottom) -->
        <div class="antiflood-box">
            <div class="antiflood-header">
                <span>🛡️</span>
                <span>คำชี้แจงระบบป้องกันการฟลัด & รักษาเสถียรภาพ (Anti-Flood Protection):</span>
            </div>
            <div style="line-height: 1.6; font-size: 12.5px;">
                <div>• <b>ดาวน์โหลดได้ทีละ 1 งานต่อท่าน:</b> เพื่อรักษาความเร็วในการแปลงไฟล์ให้ทุกคน กรุณารอให้งานก่อนหน้าเสร็จสิ้นจึงจะเริ่มงานใหม่ได้</div>
                <div>• <b>เว้นระยะห่าง 3 วินาที & ไม่เกิน 6 ครั้ง/นาที:</b> ป้องกันการกดย้ำปุ่มรัวๆ หรือการใช้สคริปต์สแปมยิงถล่มเซิร์ฟเวอร์</div>
                <div>• <b>ระบบพักการใช้งานชั่วคราว (Auto-Jail):</b> หากตรวจพบการยิงคำขอถี่ยิบผิดปกติเกินเกณฑ์ ระบบจะระงับการเข้าถึงอัตโนมัติ 5 นาที</div>
            </div>
        </div>

        <!-- Unsupported Sites Notice Box (Bottom) -->
        <div class="unsupported-box" style="margin-top: 24px;">
            <div class="unsupported-header">
                <span>⚠️</span>
                <span>หมายเหตุสำคัญ: บริการนี้ไม่รองรับเว็บไซต์ที่มีการเข้ารหัสลิขสิทธิ์ DRM หรือสื่อที่ต้องสมัครสมาชิก</span>
            </div>
            <div class="unsupported-list">
                <div class="unsupported-item">
                    <span class="unsupported-tag">❌ สตรีมมิ่งติด DRM:</span>
                    <span>Netflix, Prime Video, Disney+ Hotstar, HBO Max, Apple TV+, Hulu, WeTV, iQIYI (มีระบบ Widevine/PlayReady เข้ารหัสป้องกัน)</span>
                </div>
                <div class="unsupported-item">
                    <span class="unsupported-tag">❌ เพลงที่เข้ารหัสบนหน้าเว็บ:</span>
                    <span>Suno AI, Udio (สร้างไฟล์แบบสตรีมมิ่งเฉพาะหน้าเว็บ แนะนำกดปุ่มดาวน์โหลดบนหน้าเว็บของ Suno/Udio โดยตรง)</span>
                </div>
                <div class="unsupported-item">
                    <span class="unsupported-tag">❌ โพสต์ส่วนตัว/ต้องล็อกอิน:</span>
                    <span>โพสต์ Facebook กลุ่มปิด/เพื่อนเท่านั้น, บัญชี Private IG/X</span>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer class="site-footer">
            <div class="footer-links">
                <a class="footer-link" onclick="openPolicyModal()">📜 นโยบายการให้บริการ & Zero-Storage Policy</a>
                <span>•</span>
                <a class="footer-link" onclick="openUnsupportedModal()">⚠️ รายการเว็บไซต์ที่ไม่รองรับ</a>
                <span>•</span>
                <a class="footer-link" href="/download-app">💻 โปรแกรม Windows (.exe)</a>
            </div>
            <div style="color: #94a3b8; font-size: 12px; line-height: 1.6;">
                ระบบทำงานแบบ Transient Conduit (ทางผ่านข้อมูลชั่วคราว) • ไม่มีการจัดเก็บ บันทึก หรือทำซ้ำสื่อใดๆ บนเซิร์ฟเวอร์<br>
                เคารพกฎหมายลิขสิทธิ์และสิทธิ์ของเจ้าของผลงานตามมาตรฐาน DMCA สากล
            </div>
        </footer>
    </div>

    <!-- QR Code to Phone Modal Popup -->
    <div id="qrModal" class="modal-overlay" onclick="if(event.target===this) closeQrModal()">
        <div class="modal-box" style="max-width: 440px;">
            <div class="modal-header">
                <span style="font-size: 26px;">📱</span>
                <div>
                    <h3 style="margin: 0;">สแกนโหลดใส่มือถือทันที</h3>
                    <div style="font-size: 12px; color: #94a3b8;">ดาวน์โหลดไร้สาย ไม่ต้องต่อสาย ไม่ต้องเข้าเว็บใหม่</div>
                </div>
            </div>
            <div class="modal-body">
                <div class="qr-card-center">
                    <div class="qr-image-container">
                        <img id="qrImageElement" src="" alt="QR Code">
                    </div>
                    <div class="qr-wifi-badge">
                        <span>📶</span>
                        <span>Wi-Fi เดียวกัน: <b id="qrLanIpLabel">-</b></span>
                    </div>

                    <!-- Live countdown badge -->
                    <div style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.35); color: #fde68a; padding: 5px 14px; border-radius: 99px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;">
                        <span>⏳</span>
                        <span>ลิงก์พร้อมโหลดอีก: <b id="qrModalCountdown" style="color: #ffffff;">03:00</b> นาที</span>
                    </div>

                    <div style="font-size: 12.5px; color: #cbd5e1; line-height: 1.5; text-align: left; background: rgba(11, 15, 25, 0.6); padding: 10px 14px; border-radius: 12px; width: 100%; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-weight: 700; color: #93c5fd; margin-bottom: 4px;">💡 วิธีใช้งานบนมือถือ:</div>
                        <div>• <b>iPhone (iOS):</b> เปิดแอป "กล้อง" ส่อง QR Code แล้วแตะแถบสีเหลืองเพื่อเปิด</div>
                        <div>• <b>Android:</b> เปิดกล้อง หรือ Google Lens สแกนแล้วแตะลิงก์เพื่อบันทึกไฟล์</div>
                    </div>
                </div>
            </div>
            <div class="modal-footer" style="justify-content: space-between;">
                <button type="button" class="btn" style="background: rgba(255,255,255,0.08); color: #cbd5e1;" onclick="copyMobileUrl()">📋 คัดลอกลิงก์</button>
                <button type="button" class="btn btn-primary" style="padding: 10px 22px; width: auto;" onclick="closeQrModal()">ปิดหน้าต่าง</button>
            </div>
        </div>
    </div>

    <!-- Update Patch Modal Popup -->
    <div id="updateModal" class="modal-overlay" onclick="if(event.target===this) closeUpdateModal()">
        <div class="modal-box" style="max-width: 480px;">
            <div class="modal-header">
                <span style="font-size: 26px;">🔄</span>
                <div>
                    <h3 style="margin: 0; color: #ffffff;">ระบบอัปเดตแพทช์ดาวน์โหลด (Engine Patch)</h3>
                    <div style="font-size: 12px; color: #94a3b8;">อัปเดตเอนจิ้นแก้ทางระบบต้านบอทของ YouTube / TikTok ล่าสุด</div>
                </div>
            </div>
            <div class="modal-body">
                <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 14px; padding: 14px; margin-bottom: 16px; font-size: 13px;">
                    <div style="margin-bottom: 6px; color: #cbd5e1;">• <b>เวอร์ชันระบบ (App Version):</b> v2.1.0</div>
                    <div id="modalYtdlpVer" style="color: #93c5fd;">• <b>เวอร์ชันแพทช์เอนจิ้นปัจจุบัน:</b> กำลังดึงข้อมูล...</div>
                </div>
                <div id="updateStatusText" style="font-size: 13px; color: #94a3b8; margin-bottom: 12px; line-height: 1.5;">
                    เมื่อ YouTube หรือ TikTok มีการปรับเปลี่ยนโค้ด คุณสามารถกดปุ่มด้านล่างเพื่อดึงแพทช์ล่าสุดมาติดตั้งได้ทันทีภายใน 5 วินาที
                </div>
                <div class="progress-bar-bg" id="updateProgressWrapper" style="display: none; margin-bottom: 16px;">
                    <div id="updateProgressBar" class="progress-bar-fill" style="width: 0%; background: linear-gradient(90deg, #3b82f6, #10b981);"></div>
                </div>
            </div>
            <div class="modal-footer" style="gap: 10px;">
                <button type="button" id="btnStartUpdate" class="btn btn-primary" style="padding: 10px 20px; width: auto;" onclick="doUpdateEngine()">
                    ⚡ ติดตั้งแพทช์ล่าสุดทันที
                </button>
                <button type="button" class="btn" style="background: rgba(255, 255, 255, 0.1); color: #cbd5e1; width: auto;" onclick="closeUpdateModal()">ปิด</button>
            </div>
        </div>
    </div>

    <!-- Unsupported Sites Modal Popup -->
    <div id="unsupportedModal" class="modal-overlay" onclick="if(event.target===this) closeUnsupportedModal()">
        <div class="modal-box">
            <div class="modal-header">
                <span style="font-size: 26px;">🚫</span>
                <div>
                    <h3 style="margin: 0; color: #f87171;">ไม่สามารถดาวน์โหลดจากเว็บไซต์นี้ได้</h3>
                    <div style="font-size: 12px; color: #94a3b8;" id="unsupportedSiteName">ระบบตรวจพบคอนเทนต์ที่มีการป้องกันลิขสิทธิ์พิเศษ</div>
                </div>
            </div>
            <div class="modal-body">
                <div style="background: rgba(185, 28, 28, 0.15); border: 1px solid rgba(239, 68, 68, 0.35); border-radius: 12px; padding: 14px; margin-bottom: 16px; color: #fca5a5; font-size: 13.5px;">
                    <b>สาเหตุที่ไม่สามารถดาวน์โหลดได้:</b>
                    <ul style="margin: 8px 0 0 18px; padding: 0;" id="unsupportedModalReason">
                        <li>เว็บไซต์นี้ใช้ระบบป้องกัน <b>DRM (Digital Rights Management)</b> เช่น Widevine หรือ PlayReady</li>
                        <li>เป็นบริการสตรีมมิ่งที่ต้องสมัครสมาชิกหรือเสียค่าบริการ (Subscription/Paid Service)</li>
                        <li>ระบบยึดมั่นในนโยบายไม่ถอดรหัส ไม่ละเมิด และไม่บายพาสระบบความปลอดภัยของเจ้าของสิทธิ์</li>
                    </ul>
                </div>
                <div style="font-size: 13px; color: #cbd5e1; line-height: 1.6;">
                    💡 <b>คำแนะนำสำหรับผู้ใช้งาน:</b>
                    <p style="margin: 6px 0 0 0;">
                        • แนะนำให้รับชมหรือใช้ฟังก์ชันดาวน์โหลดแบบออฟไลน์ผ่านแอปพลิเคชันอย่างเป็นทางการของผู้ให้บริการโดยตรง<br>
                        • สำหรับ Suno AI สามารถคลิกปุ่ม <b>... (จุดสามจุด) ➔ Download Audio</b> บนหน้าเว็บ Suno ได้ฟรี<br>
                        • ลิงก์ที่ระบบรองรับ: YouTube, TikTok, Facebook (สาธารณะ), IG, Twitter/X, SoundCloud, Bilibili และวิดีโอจากเว็บทั่วไป
                    </p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn" style="background: rgba(255, 255, 255, 0.1); color: #cbd5e1;" onclick="closeUnsupportedModal()">รับทราบและปิดหน้านี้</button>
            </div>
        </div>
    </div>

    <!-- Policy & Terms Modal Popup -->
    <div id="policyModal" class="modal-overlay" onclick="if(event.target===this) closePolicyModal()">
        <div class="modal-box" style="max-width: 620px;">
            <div class="modal-header">
                <span style="font-size: 26px;">🛡️</span>
                <div>
                    <h3 style="margin: 0; color: #ffffff;">นโยบายการให้บริการ & Zero-Storage Policy</h3>
                    <div style="font-size: 12px; color: #94a3b8;">Terms of Service, Zero-Storage & DMCA Compliance</div>
                </div>
            </div>
            <div class="modal-body">
                <div class="policy-section">
                    <h4>🔒 1. นโยบาย Zero-Storage ถาวร (Transient Conduit)</h4>
                    <p>
                        ระบบนี้ถูกออกแบบขึ้นโดยยึดหลัก <b>"ไม่มีการเก็บข้อมูลสื่อใดๆ บนเครื่องหรือเซิร์ฟเวอร์" (Zero Permanent Storage)</b> ระบบทำหน้าที่เป็นเพียงสะพานทางผ่านชั่วคราว (Ephemeral Pipe) ในการแปลงฟอร์แมตตามคำสั่งของผู้ใช้ ไฟล์ที่ถูกแปลงจะถูกสตรีมส่งตรงไปยังเบราว์เซอร์ของผู้ใช้ และระบบจะลบไฟล์ต้นทางทิ้งทันทีหลังส่งมอบ หรือถูกลบอัตโนมัติภายใน 180 วินาที ไม่มีประวัติการดาวน์โหลด ไม่มีการทำแคช และไม่มีการเปิดให้บุคคลภายนอกเข้าถึงไฟล์ได้ เพื่อป้องกันการกลั่นแกล้งหรือการนำไฟล์ไปใช้ผิดวัตถุประสงค์โดยเด็ดขาด
                    </p>
                </div>

                <div class="policy-section">
                    <h4>⚖️ 2. การเคารพสิทธิในทรัพย์สินทางปัญญา (Copyright & DRM)</h4>
                    <p>
                        ระบบปฏิบัติตามมาตรฐานสากลและกฎหมายลิขสิทธิ์ (รวมถึง DMCA) อย่างเคร่งครัด <b>ระบบปฏิเสธการดาวน์โหลดคอนเทนต์ที่มีระบบปกป้องลิขสิทธิ์ดิจิทัล (DRM)</b> เช่น Widevine, FairPlay หรือ PlayReady (อาทิ Netflix, Prime Video, Disney+, HBO Max ฯลฯ) รวมถึงสื่อที่มีการป้องกันเชิงเทคนิค โดยไม่มีการบายพาส ถอดรหัส หรือเจาะระบบความปลอดภัยใดๆ ทั้งสิ้น
                    </p>
                </div>

                <div class="policy-section">
                    <h4>👤 3. การใช้งานส่วนบุคคลและการใช้งานที่เป็นธรรม (Personal & Fair Use)</h4>
                    <p>
                        เครื่องมือนี้จัดทำขึ้นเพื่อการใช้งานส่วนบุคคล (Personal Use) หรือการใช้งานที่เป็นธรรม (Fair Use) เช่น การสำรองข้อมูลสื่อสาธารณะเพื่อการศึกษา หรือการรับฟังเพื่อความบันเทิงส่วนบุคคลเท่านั้น ห้ามมิให้นำสื่อที่แปลงแล้วไปใช้ในเชิงพาณิชย์ เผยแพร่ต่อโดยไม่ได้รับอนุญาต หรือกระทำการใดๆ ที่ละเมิดสิทธิของเจ้าของผลงาน
                    </p>
                </div>

                <div class="policy-section">
                    <h4>📋 4. ข้อจำกัดความรับผิดชอบ (Limitation of Liability)</h4>
                    <p>
                        ผู้ใช้งานเป็นผู้ระบุ URL หรือลิงก์ที่ต้องการแปลงด้วยตนเองแต่เพียงผู้เดียว ผู้ใช้งานต้องตรวจสอบและรับรองว่าตนมีสิทธิ์ในการเข้าถึงและดาวน์โหลดเนื้อหาดังกล่าว ผู้ให้บริการไม่มีส่วนเกี่ยวข้อง ไม่ได้เป็นเจ้าของ และไม่รับผิดชอบต่อเนื้อหาภายนอกหรือความเสียหายใดๆ ที่เกิดจากการนำสื่อไปใช้งานผิดวัตถุประสงค์
                    </p>
                </div>

                <div class="policy-section">
                    <h4>⚡ 5. ระบบป้องกันการฟลัดและรักษาเสถียรภาพ (Anti-Flood & Fair Use)</h4>
                    <p>
                        เพื่อรักษาเสถียรภาพและความพร้อมใช้งานของเซิร์ฟเวอร์สำหรับผู้ใช้ทุกคน ระบบมีกลไกควบคุมปริมาณการใช้งาน (Rate Limiting) ดังนี้:<br>
                        • <b>Concurrency:</b> จำกัดการดาวน์โหลดและแปลงไฟล์ 1 งานต่อผู้ใช้ในเวลาเดียวกัน<br>
                        • <b>Cooldown:</b> เว้นระยะห่างการส่งคำขอดาวน์โหลดอย่างน้อย 3 วินาที และไม่เกิน 6 ครั้งต่อนาที<br>
                        • <b>Auto-Jail:</b> หากตรวจพบเจตนายิงคำขอแบบอัตโนมัติ (Bot / Script Spam) หรือกดย้ำซ้ำๆ เกินเกณฑ์ ระบบจะระงับการเข้าถึงของ IP ดังกล่าวชั่วคราวเป็นเวลา 5 นาทีโดยอัตโนมัติ
                    </p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-primary" onclick="closePolicyModal()">ข้าพเจ้ายอมรับและเข้าใจข้อกำหนด</button>
            </div>
        </div>
    </div>

    <!-- Custom Alert Modal (No browser IP header) -->
    <div id="customAlertModal" class="modal-overlay" onclick="if(event.target===this) closeCustomAlert()">
        <div class="modal-box" style="max-width: 480px;">
            <div class="modal-header">
                <span id="customAlertIcon" style="font-size: 26px;">⚡</span>
                <div>
                    <h3 id="customAlertTitle" style="margin: 0;">การแจ้งเตือน</h3>
                </div>
            </div>
            <div class="modal-body" id="customAlertMessage" style="font-size: 14px; line-height: 1.6; white-space: pre-line;">
                ข้อความแจ้งเตือน
            </div>
            <div class="modal-footer">
                <button type="button" id="customAlertBtn" class="btn btn-primary" style="padding: 10px 26px; font-size: 14px; width: auto;" onclick="closeCustomAlert()">ตกลง</button>
            </div>
        </div>
    </div>

    <script>
        // Server network info
        const SERVER_LAN_IP = "{{ lan_ip }}";
        const SERVER_PORT = "{{ server_port }}";
        let lastTaskData = null;
        let detectedClipboardUrl = "";

        // Audio context for media playback visualization
        let audioCtx = null;

        function getAudioContext() {
            if (!audioCtx) {
                const AudioCtxClass = window.AudioContext || window.webkitAudioContext;
                if (AudioCtxClass) {
                    audioCtx = new AudioCtxClass();
                }
            }
            if (audioCtx && audioCtx.state === 'suspended') {
                audioCtx.resume();
            }
            return audioCtx;
        }

        // Custom modal alerts (prevent native 127.0.0.1:5050 says)
        function showAlert(msg, title = "⚡ การแจ้งเตือน", icon = "⚡") {
            const modal = document.getElementById('customAlertModal');
            document.getElementById('customAlertTitle').innerText = title;
            document.getElementById('customAlertIcon').innerText = icon;
            document.getElementById('customAlertMessage').innerText = msg;
            modal.style.display = 'flex';
            const btn = document.getElementById('customAlertBtn');
            if (btn) btn.focus();
        }

        function closeCustomAlert() {
            document.getElementById('customAlertModal').style.display = 'none';
        }

        window.alert = function(msg) {
            showAlert(msg);
        };

        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeCustomAlert();
                closePolicyModal();
                closeUnsupportedModal();
                closeQrModal();
            }
        });

        // DRM / Unsupported domains list
        const UNSUPPORTED_DOMAINS = [
            { pattern: /primevideo\.com/i, name: "Amazon Prime Video", reason: "เนื้อหามีระบบป้องกัน Widevine DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /netflix\.com/i, name: "Netflix", reason: "เนื้อหามีระบบป้องกัน Widevine DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /disneyplus\.com/i, name: "Disney+ / Disney+ Hotstar", reason: "เนื้อหามีระบบป้องกัน Widevine DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /hbomax\.com|max\.com/i, name: "HBO Max / Max", reason: "เนื้อหามีระบบป้องกัน Widevine DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /tv\.apple\.com/i, name: "Apple TV+", reason: "เนื้อหามีระบบป้องกัน FairPlay DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /hulu\.com/i, name: "Hulu", reason: "เนื้อหามีระบบป้องกัน Widevine DRM และเป็นบริการสตรีมมิ่งแบบเสียค่าสมาชิก" },
            { pattern: /wetv\.vip/i, name: "WeTV", reason: "ซีรีส์/รายการมีระบบเข้ารหัส DRM สำหรับสมาชิก VIP" },
            { pattern: /iqiyi\.com/i, name: "iQIYI", reason: "ซีรีส์/รายการมีระบบเข้ารหัส DRM สำหรับสมาชิก VIP" },
            { pattern: /suno\.(com|ai)/i, name: "Suno AI", reason: "Suno AI มีระบบสตรีมมิ่งเข้ารหัสบนหน้าเว็บ แนะนำให้คลิก '...' บนหน้าเพลงใน Suno แล้วกด 'Download Audio' โดยตรงได้เลยครับ" },
            { pattern: /udio\.com/i, name: "Udio AI", reason: "Udio ใช้ระบบเข้ารหัสเสียง แนะนำให้กดปุ่ม Download บนหน้าเว็บ Udio โดยตรงครับ" }
        ];

        function checkUnsupportedUrl(url) {
            if (!url) return null;
            for (const site of UNSUPPORTED_DOMAINS) {
                if (site.pattern.test(url)) {
                    return site;
                }
            }
            return null;
        }

        function showUnsupportedPopup(site) {
            document.getElementById('unsupportedSiteName').innerText = site.name;
            document.getElementById('unsupportedModalReason').innerHTML = `
                <li><b>${site.name}</b>: ${site.reason}</li>
                <li>ระบบยึดมั่นในนโยบายไม่ถอดรหัส ไม่ละเมิดลิขสิทธิ์ และไม่บายพาสระบบความปลอดภัย DRM</li>
            `;
            document.getElementById('unsupportedModal').style.display = 'flex';
        }

        function closeUnsupportedModal() {
            document.getElementById('unsupportedModal').style.display = 'none';
        }

        function openUnsupportedModal() {
            document.getElementById('unsupportedSiteName').innerText = "รายการแพลตฟอร์มที่ติดระบบ DRM / เข้ารหัส";
            document.getElementById('unsupportedModalReason').innerHTML = `
                <li><b>แพลตฟอร์มสตรีมมิ่ง:</b> Prime Video, Netflix, Disney+, HBO Max, Apple TV+, Hulu, WeTV, iQIYI</li>
                <li><b>ระบบ AI Audio เข้ารหัส:</b> Suno AI, Udio (แนะนำกดปุ่ม Download บนเว็บของผู้ให้บริการโดยตรง)</li>
                <li><b>โพสต์ส่วนตัว:</b> โพสต์ Facebook ปิด/เพื่อนเท่านั้น, บัญชี Private Instagram/X</li>
            `;
            document.getElementById('unsupportedModal').style.display = 'flex';
        }

        async function openUpdateModal() {
            document.getElementById('updateModal').style.display = 'flex';
            document.getElementById('updateStatusText').innerHTML = "🔍 กำลังตรวจสอบแพทช์ล่าสุดจากเซิร์ฟเวอร์...";
            document.getElementById('updateProgressWrapper').style.display = 'none';
            const btn = document.getElementById('btnStartUpdate');
            btn.disabled = true;
            btn.innerText = "⏳ กำลังตรวจสอบ...";

            try {
                const res = await fetch('/api/engine-version');
                const data = await res.json();
                document.getElementById('modalYtdlpVer').innerHTML = `• <b>เวอร์ชันแพทช์เอนจิ้นปัจจุบัน:</b> ${data.version || 'ปกติ'}`;
                if (data.has_update) {
                    document.getElementById('updateStatusText').innerHTML = `<span style="color:#93c5fd; font-weight:600;">⚡ พบแพทช์เวอร์ชันใหม่ (${data.latest_version}) พร้อมให้อัปเดต</span>`;
                    btn.disabled = false;
                    btn.innerText = "⚡ ติดตั้งแพทช์ล่าสุดทันที";
                } else {
                    document.getElementById('updateStatusText').innerHTML = `<span style="color:#6ee7b7; font-weight:600;">✅ ปัจจุบันเป็นแพทช์ล่าสุดแล้ว (${data.version}) ไม่ต้องทำการติดตั้ง</span>`;
                    btn.disabled = true;
                    btn.innerText = "✓ เป็นแพทช์ล่าสุดแล้ว";
                }
            } catch (e) {
                document.getElementById('modalYtdlpVer').innerHTML = `• <b>เวอร์ชันแพทช์เอนจิ้นปัจจุบัน:</b> ตรวจสอบไม่สำเร็จ`;
                document.getElementById('updateStatusText').innerHTML = `<span style="color:#fca5a5;">⚠️ ไม่สามารถเชื่อมต่อเพื่อตรวจสอบแพทช์ได้</span>`;
                btn.disabled = false;
                btn.innerText = "🔄 ลองตรวจสอบใหม่";
                btn.onclick = openUpdateModal;
            }
        }

        function closeUpdateModal() {
            document.getElementById('updateModal').style.display = 'none';
        }

        async function doUpdateEngine() {
            const btn = document.getElementById('btnStartUpdate');
            const statusText = document.getElementById('updateStatusText');
            const pWrap = document.getElementById('updateProgressWrapper');
            const pBar = document.getElementById('updateProgressBar');

            btn.disabled = true;
            btn.innerText = "⏳ กำลังอัปเดต...";
            pWrap.style.display = 'block';
            pBar.style.width = '30%';
            statusText.innerText = "กำลังเชื่อมต่อเซิร์ฟเวอร์และดาวน์โหลดแพทช์...";

            try {
                pBar.style.width = '70%';
                const res = await fetch('/api/update-engine', { method: 'POST' });
                const data = await res.json();
                pBar.style.width = '100%';
                if (data.ok) {
                    statusText.innerHTML = `<span style="color:#6ee7b7; font-weight:700;">✅ ปัจจุบันเป็นแพทช์ล่าสุดแล้ว (${data.new_version}) ไม่ต้องทำการติดตั้ง</span>`;
                    document.getElementById('modalYtdlpVer').innerHTML = `• <b>เวอร์ชันแพทช์เอนจิ้นปัจจุบัน:</b> ${data.new_version} (ล่าสุด)`;
                    btn.disabled = true;
                    btn.innerText = "✓ เป็นแพทช์ล่าสุดแล้ว";
                    setTimeout(checkPatchStatusSilently, 500);
                } else {
                    statusText.innerHTML = `<span style="color:#fca5a5;">❌ เกิดข้อผิดพลาด: ${escapeHtml(String(data.error || 'ไม่สามารถอัปเดตได้'))}</span>`;
                    btn.innerText = "ลองใหม่อีกครั้ง";
                    btn.disabled = false;
                }
            } catch (e) {
                statusText.innerHTML = `<span style="color:#fca5a5;">❌ การเชื่อมต่อล้มเหลว: ${escapeHtml(String(e))}</span>`;
                btn.innerText = "ลองใหม่อีกครั้ง";
                btn.disabled = false;
            }
        }

        function openPolicyModal() {
            document.getElementById('policyModal').style.display = 'flex';
        }

        function closePolicyModal() {
            document.getElementById('policyModal').style.display = 'none';
        }

        // Silent Patch Status Checker & Notification
        async function checkPatchStatusSilently() {
            try {
                const res = await fetch('/api/engine-version');
                const data = await res.json();
                const curVer = data.version || 'v2.1.0';
                
                const patchLabel = document.getElementById('patchLabelNav');
                const patchIcon = document.getElementById('patchIconNav');
                const patchBadge = document.getElementById('patchBadgeNav');
                const headerPill = document.getElementById('headerPatchPill');
                
                if (headerPill) {
                    headerPill.innerText = `⚡ ${curVer}`;
                }

                if (data.has_update) {
                    if (patchLabel) patchLabel.innerHTML = `🔥 มีแพทช์ใหม่ ${data.latest_version}!`;
                    if (patchIcon) patchIcon.innerText = '🔥';
                    if (patchBadge) patchBadge.style.display = 'inline-block';
                    
                    const alertBanner = document.getElementById('newPatchAlertBanner');
                    const alertName = document.getElementById('newPatchNameAlert');
                    if (alertBanner && alertName) {
                        alertName.innerText = data.latest_version;
                        alertBanner.style.display = 'flex';
                    }
                    
                    if (!document.title.startsWith('(มีแพทช์ใหม่!)')) {
                        document.title = `(🔥 มีแพทช์ใหม่ ${data.latest_version}!) ${document.title}`;
                    }
                } else {
                    if (patchLabel) patchLabel.innerText = `แพทช์: ${curVer}`;
                    if (patchIcon) patchIcon.innerText = '⚡';
                    if (patchBadge) patchBadge.style.display = 'none';
                    const alertBanner = document.getElementById('newPatchAlertBanner');
                    if (alertBanner) alertBanner.style.display = 'none';
                }
            } catch (e) {
                const patchLabel = document.getElementById('patchLabelNav');
                if (patchLabel) patchLabel.innerText = 'อัปเดตแพทช์';
            }
        }
        setTimeout(checkPatchStatusSilently, 600);

        // Clipboard auto-detect
        async function checkClipboardForUrl() {
            try {
                if (!navigator.clipboard || !navigator.clipboard.readText) return;
                const text = await navigator.clipboard.readText();
                if (text && text.trim().startsWith('http')) {
                    const clean = text.trim();
                    const curVal = document.getElementById('urlInput').value.trim();
                    if (clean !== curVal && clean !== detectedClipboardUrl) {
                        detectedClipboardUrl = clean;
                        document.getElementById('clipboardUrlPreview').innerText = clean.length > 50 ? clean.substring(0, 47) + '...' : clean;
                        document.getElementById('clipboardBanner').style.display = 'flex';
                    }
                }
            } catch (e) {}
        }

        function useDetectedClipboard() {
            if (detectedClipboardUrl) {
                document.getElementById('urlInput').value = detectedClipboardUrl;
                document.getElementById('clipboardBanner').style.display = 'none';
                const unsupported = checkUnsupportedUrl(detectedClipboardUrl);
                if (unsupported) {
                    showUnsupportedPopup(unsupported);
                }
            }
        }

        window.addEventListener('focus', checkClipboardForUrl);
        setTimeout(checkClipboardForUrl, 1000);

        async function pasteClipboard() {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    const cleanText = text.trim();
                    document.getElementById('urlInput').value = cleanText;
                    const unsupported = checkUnsupportedUrl(cleanText);
                    if (unsupported) {
                        showUnsupportedPopup(unsupported);
                    }
                }
            } catch (err) {
                alert("กรุณากดคลิกขวาที่ช่องแล้วเลือก วาง (Paste) หรือกด Ctrl+V ครับ");
            }
        }

        function setSample(url) {
            document.getElementById('urlInput').value = url;
            document.getElementById('clipboardBanner').style.display = 'none';
        }

        // Format switch handler
        function onFormatChanged(fmt) {
            const fxBox = document.getElementById('fxStudioBox');
            if (fmt === 'mp3' || fmt === 'm4r') {
                fxBox.style.display = 'block';
            } else {
                fxBox.style.display = 'none';
            }
            // Auto preset for Ringtone and GIF
            if (fmt === 'm4r' || fmt === 'gif') {
                document.getElementById('enableTimeCut').checked = true;
                toggleTimeCut();
                if (fmt === 'm4r' && !document.getElementById('endTimeInput').value) {
                    document.getElementById('endTimeInput').value = "00:30";
                } else if (fmt === 'gif' && !document.getElementById('endTimeInput').value) {
                    document.getElementById('endTimeInput').value = "00:06";
                }
            }
        }

        // Real-time URL check on typing or pasting
        document.getElementById('urlInput').addEventListener('input', function() {
            const val = this.value.trim();
            const clearBtn = document.getElementById('clearUrlBtn');
            if (clearBtn) {
                clearBtn.style.display = this.value.length > 0 ? 'flex' : 'none';
            }
            const unsupported = checkUnsupportedUrl(val);
            if (unsupported) {
                showUnsupportedPopup(unsupported);
            }
        });

        function clearUrlInput() {
            const input = document.getElementById('urlInput');
            input.value = "";
            const clearBtn = document.getElementById('clearUrlBtn');
            if (clearBtn) clearBtn.style.display = 'none';
            input.focus();
        }

        document.getElementById('urlInput').addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                triggerSearchOrDownload();
            }
        });

        function switchMode(mode) {
            const tabSingle = document.getElementById('tabSingle');
            const tabBatch = document.getElementById('tabBatch');
            const secSingle = document.getElementById('singleModeSection');
            const secBatch = document.getElementById('batchModeSection');
            const btnSingle = document.getElementById('downloadBtn');
            const btnBatch = document.getElementById('batchDownloadBtn');
            const batchMonitor = document.getElementById('batchQueueMonitor');

            if (mode === 'single') {
                tabSingle.classList.add('active');
                tabBatch.classList.remove('active');
                secSingle.style.display = 'block';
                secBatch.style.display = 'none';
                btnSingle.style.display = 'inline-flex';
                btnBatch.style.display = 'none';
                batchMonitor.style.display = 'none';
            } else {
                tabBatch.classList.add('active');
                tabSingle.classList.remove('active');
                secSingle.style.display = 'none';
                secBatch.style.display = 'block';
                btnSingle.style.display = 'none';
                btnBatch.style.display = 'inline-flex';
                closeSearchResults();
            }
        }

        function triggerSearchOrDownload() {
            const val = document.getElementById('urlInput').value.trim();
            if (!val) {
                alert("กรุณากรอกชื่อเพลงหรือวางลิงก์ที่ต้องการดาวน์โหลดก่อนครับ");
                return;
            }
            if (val.startsWith('http://') || val.startsWith('https://')) {
                closeSearchResults();
                startDownload();
            } else {
                searchSongs(val);
            }
        }

        async function searchSongs(query) {
            const resultsBox = document.getElementById('searchResultsBox');
            const resultsList = document.getElementById('searchResultsList');
            resultsBox.style.display = 'block';
            resultsList.innerHTML = `<div style="text-align: center; padding: 18px 0; color: #93c5fd; font-size: 13.5px;">
                <span style="display:inline-block; animation: pulseGlow 1s infinite;">⏳</span> กำลังค้นหาเพลง "${escapeHtml(query)}" จาก YouTube...
            </div>`;

            try {
                const res = await fetch('/api/search?q=' + encodeURIComponent(query));
                const data = await res.json();
                if (!data.results || data.results.length === 0) {
                    resultsList.innerHTML = `<div style="text-align: center; padding: 14px 0; color: #fca5a5; font-size: 13px;">❌ ไม่พบเพลงที่ตรงกับคำค้นหา กรุณาลองพิมพ์ชื่ออื่นครับ</div>`;
                    return;
                }

                let html = '';
                data.results.forEach(item => {
                    const safeTitle = escapeHtml(item.title);
                    const safeUploader = escapeHtml(item.uploader);
                    html += `
                        <div class="search-item-card" onclick="selectSearchResult('${item.url}')">
                            <img class="search-thumb" src="${escapeHtml(item.thumbnail)}" alt="Thumb" onerror="this.src='/favicon.ico'">
                            <div class="search-info">
                                <div class="search-title" title="${safeTitle}">${safeTitle}</div>
                                <div class="search-meta">
                                    <span>👤 ${safeUploader}</span>
                                    ${item.duration ? `<span>⏱️ ${item.duration}</span>` : ''}
                                </div>
                            </div>
                            <button type="button" class="btn-select-search" onclick="event.stopPropagation(); selectSearchResult('${item.url}')">
                                ⚡ โหลดเพลงนี้
                            </button>
                        </div>
                    `;
                });
                resultsList.innerHTML = html;
            } catch (err) {
                resultsList.innerHTML = `<div style="text-align: center; padding: 14px 0; color: #fca5a5; font-size: 13px;">เกิดข้อผิดพลาดในการเชื่อมต่อ: ${escapeHtml(String(err))}</div>`;
            }
        }

        function closeSearchResults() {
            const box = document.getElementById('searchResultsBox');
            if (box) box.style.display = 'none';
        }

        function selectSearchResult(url) {
            document.getElementById('urlInput').value = url;
            const clearBtn = document.getElementById('clearUrlBtn');
            if (clearBtn) clearBtn.style.display = 'flex';
            closeSearchResults();
            startDownload();
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        // Sequential Batch Queue Engine
        let isBatchRunning = false;
        async function startBatchQueue() {
            if (isBatchRunning) return;
            const text = document.getElementById('batchUrlsInput').value.trim();
            if (!text) {
                alert("กรุณาวางลิงก์ที่ต้องการดาวน์โหลด (1 บรรทัดต่อ 1 ลิงก์) ก่อนครับ");
                return;
            }
            const rawUrls = text.split('\n').map(l => l.trim()).filter(l => l.startsWith('http://') || l.startsWith('https://'));
            if (rawUrls.length === 0) {
                alert("ไม่พบลิงก์เว็บไซต์ที่ถูกต้อง (ต้องขึ้นต้นด้วย http:// หรือ https://) ครับ");
                return;
            }
            if (rawUrls.length > 5) {
                alert("เพื่อความเสถียรสูงสุดของระบบ กรุณาดาวน์โหลดครั้งละไม่เกิน 5 ลิงก์ครับ (หากต้องการโหลดคลิปยาวหลายสิบคลิป แนะนำใช้โปรแกรมคอมพิวเตอร์ Windows Desktop Pro)");
                return;
            }
            isBatchRunning = true;
            const format = document.querySelector('input[name="format"]:checked').value;
            const fxEl = document.querySelector('input[name="audio_fx"]:checked');
            const audioFx = fxEl ? fxEl.value : 'none';

            const btn = document.getElementById('batchDownloadBtn');
            btn.disabled = true;
            btn.innerHTML = "⏳ กำลังรันคิวดาวน์โหลด...";

            const monitor = document.getElementById('batchQueueMonitor');
            const listEl = document.getElementById('batchItemsList');
            const barEl = document.getElementById('batchProgressBar');
            const counterEl = document.getElementById('batchProgressCounter');

            monitor.style.display = 'block';
            counterEl.innerText = `0 / ${rawUrls.length} เพลง`;
            barEl.style.width = '0%';

            let itemsHtml = '';
            rawUrls.forEach((u, i) => {
                const shortUrl = u.length > 45 ? u.substring(0, 42) + '...' : u;
                itemsHtml += `
                    <div id="batchItemRow_${i}" class="batch-item-row">
                        <div style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                            <span style="font-weight:700; color:#e2e8f0; margin-right:6px;">#${i+1}</span>
                            <span id="batchItemTitle_${i}" style="color:#cbd5e1;">${escapeHtml(shortUrl)}</span>
                        </div>
                        <div id="batchItemStatus_${i}">
                            <span class="batch-badge pending">⏳ รอดำเนินการ</span>
                        </div>
                    </div>
                `;
            });
            listEl.innerHTML = itemsHtml;

            let completedCount = 0;
            for (let i = 0; i < rawUrls.length; i++) {
                const url = rawUrls[i];
                const statusBox = document.getElementById(`batchItemStatus_${i}`);
                const titleBox = document.getElementById(`batchItemTitle_${i}`);

                statusBox.innerHTML = `<span class="batch-badge running">⚡ กำลังดาวน์โหลดและแปลง...</span>`;

                try {
                    const postRes = await fetch('/api/download', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url, format: format, audio_fx: audioFx })
                    });
                    const postData = await postRes.json();
                    if (!postRes.ok || postData.error) {
                        statusBox.innerHTML = `<span class="batch-badge error">❌ ผิดพลาด: ${escapeHtml(postData.error || 'ดาวน์โหลดไม่สำเร็จ')}</span>`;
                        continue;
                    }

                    // Poll task status
                    const taskId = postData.task_id;
                    let finished = false;
                    while (!finished) {
                        await new Promise(r => setTimeout(r, 1200));
                        const stRes = await fetch('/api/status/' + taskId);
                        const stData = await stRes.json();
                        if (stData.status === 'finished') {
                            finished = true;
                            completedCount++;
                            const fn = stData.filename || 'media_file';
                            titleBox.innerText = fn;
                            statusBox.innerHTML = `
                                <span class="batch-badge done">✅ เสร็จสิ้น</span>
                                <a href="/files/${encodeURIComponent(fn)}" download="${escapeHtml(fn)}" class="btn-select-search" style="margin-left:8px; text-decoration:none;">📥 บันทึก</a>
                            `;
                            // Trigger auto-download
                            const tempLink = document.createElement('a');
                            tempLink.href = `/files/${encodeURIComponent(fn)}`;
                            tempLink.download = fn;
                            document.body.appendChild(tempLink);
                            tempLink.click();
                            document.body.removeChild(tempLink);
                        } else if (stData.status === 'error') {
                            finished = true;
                            statusBox.innerHTML = `<span class="batch-badge error">❌ ล้มเหลว</span>`;
                        } else {
                            const p = Math.round(stData.percent || 0);
                            statusBox.innerHTML = `<span class="batch-badge running">⚡ ${stData.status === 'converting' ? 'แปลงไฟล์...' : p + '%'}</span>`;
                        }
                    }
                } catch (e) {
                    statusBox.innerHTML = `<span class="batch-badge error">❌ การเชื่อมต่อขัดข้อง</span>`;
                }

                // Update total progress
                const totalPct = Math.round(((i + 1) / rawUrls.length) * 100);
                barEl.style.width = totalPct + '%';
                counterEl.innerText = `${i + 1} / ${rawUrls.length} เพลง`;
                await new Promise(r => setTimeout(r, 1000));
            }
            btn.disabled = false;
            btn.innerHTML = "🎉 คิวดาวน์โหลดเสร็จสิ้นทั้งหมดแล้ว!";
            setTimeout(() => {
                btn.innerHTML = "🚀 เริ่มดาวน์โหลดทุกเพลงในคิว (Sequential Queue)";
            }, 6000);
            isBatchRunning = false;
        }

        let currentTaskId = null;
        let pollTimer = null;
        let visualizerAnimId = null;

        function toggleTimeCut() {
            const enabled = document.getElementById('enableTimeCut').checked;
            document.getElementById('timeInputsRow').style.display = enabled ? 'grid' : 'none';
            document.getElementById('timeHint').style.display = enabled ? 'block' : 'none';
        }

        // Neon Audio Visualizer Engine
        const canvas = document.getElementById('visualizerCanvas');
        const ctxCanvas = canvas ? canvas.getContext('2d') : null;
        let visualizerMode = 'idle'; // 'idle', 'pulse', 'audio'
        let audioSourceNode = null;
        let analyserNode = null;

        function startVisualizerPulse() {
            visualizerMode = 'pulse';
            if (visualizerAnimId) cancelAnimationFrame(visualizerAnimId);
            animateVisualizer();
        }

        function stopVisualizerPulse() {
            visualizerMode = 'idle';
        }

        function animateVisualizer() {
            if (!ctxCanvas) return;
            const width = canvas.width;
            const height = canvas.height;
            ctxCanvas.clearRect(0, 0, width, height);

            const numBars = 36;
            const barWidth = width / numBars - 3;
            const timeNow = Date.now() * 0.005;

            if (visualizerMode === 'audio' && analyserNode) {
                const dataArray = new Uint8Array(analyserNode.frequencyBinCount);
                analyserNode.getByteFrequencyData(dataArray);
                for (let i = 0; i < numBars; i++) {
                    const dataIdx = Math.floor(i * (dataArray.length / numBars) * 0.6);
                    const val = dataArray[dataIdx] || 0;
                    const barHeight = Math.max(4, (val / 255) * height * 0.9);
                    const x = i * (barWidth + 3);
                    const y = height - barHeight;

                    const grad = ctxCanvas.createLinearGradient(0, height, 0, 0);
                    grad.addColorStop(0, '#3b82f6');
                    grad.addColorStop(0.5, '#a855f7');
                    grad.addColorStop(1, '#ec4899');

                    ctxCanvas.fillStyle = grad;
                    ctxCanvas.shadowBlur = 10;
                    ctxCanvas.shadowColor = '#a855f7';
                    ctxCanvas.fillRect(x, y, barWidth, barHeight);
                }
            } else if (visualizerMode === 'pulse') {
                for (let i = 0; i < numBars; i++) {
                    const wave1 = Math.sin(timeNow + i * 0.25) * 0.5 + 0.5;
                    const wave2 = Math.cos(timeNow * 1.5 - i * 0.18) * 0.5 + 0.5;
                    const combined = (wave1 + wave2) / 2;
                    const barHeight = Math.max(4, combined * (height * 0.85));
                    const x = i * (barWidth + 3);
                    const y = height - barHeight;

                    const grad = ctxCanvas.createLinearGradient(0, height, 0, 0);
                    grad.addColorStop(0, '#06b6d4');
                    grad.addColorStop(0.5, '#6366f1');
                    grad.addColorStop(1, '#f43f5e');

                    ctxCanvas.fillStyle = grad;
                    ctxCanvas.shadowBlur = 8;
                    ctxCanvas.shadowColor = '#6366f1';
                    ctxCanvas.fillRect(x, y, barWidth, barHeight);
                }
            } else {
                // Idle calm line
                ctxCanvas.fillStyle = 'rgba(255, 255, 255, 0.15)';
                ctxCanvas.shadowBlur = 0;
                for (let i = 0; i < numBars; i++) {
                    const x = i * (barWidth + 3);
                    ctxCanvas.fillRect(x, height - 3, barWidth, 3);
                }
                return;
            }

            visualizerAnimId = requestAnimationFrame(animateVisualizer);
        }

        function hookAudioPlayerVisualizer() {
            const player = document.getElementById('audioPlayer');
            if (!player) return;
            try {
                const actx = getAudioContext();
                if (!actx) return;
                if (!audioSourceNode) {
                    audioSourceNode = actx.createMediaElementSource(player);
                    analyserNode = actx.createAnalyser();
                    analyserNode.fftSize = 128;
                    audioSourceNode.connect(analyserNode);
                    analyserNode.connect(actx.destination);
                }
                player.onplay = () => {
                    visualizerMode = 'audio';
                    if (visualizerAnimId) cancelAnimationFrame(visualizerAnimId);
                    animateVisualizer();
                };
                player.onpause = () => {
                    visualizerMode = 'idle';
                };
                player.onended = () => {
                    visualizerMode = 'idle';
                };
            } catch (e) {}
        }

        // Start download flow
        async function startDownload() {
            const url = document.getElementById('urlInput').value.trim();
            if (!url) {
                alert("กรุณาวางลิงก์ที่ต้องการดาวน์โหลดก่อนครับ");
                return;
            }

            const unsupported = checkUnsupportedUrl(url);
            if (unsupported) {
                showUnsupportedPopup(unsupported);
                return;
            }

            const format = document.querySelector('input[name="format"]:checked').value;
            const fxEl = document.querySelector('input[name="audio_fx"]:checked');
            const audioFx = fxEl ? fxEl.value : 'none';
            const enableCut = document.getElementById('enableTimeCut').checked;
            const startTime = enableCut ? document.getElementById('startTimeInput').value.trim() : "";
            const endTime = enableCut ? document.getElementById('endTimeInput').value.trim() : "";

            const btn = document.getElementById('downloadBtn');
            const progressBox = document.getElementById('progressBox');
            const resultBox = document.getElementById('resultBox');

            btn.disabled = true;
            btn.innerHTML = "⏳ กำลังดำเนินการ...";
            progressBox.style.display = "block";
            resultBox.style.display = "none";
            document.getElementById('progressBar').style.width = "0%";
            document.getElementById('percentLabel').innerText = "0%";
            document.getElementById('statusLabel').innerText = "กำลังดึงข้อมูลสื่อ...";
            document.getElementById('detailLabel').innerText = "...";

            startVisualizerPulse();

            try {
                const res = await fetch('/api/download', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        url: url, 
                        format: format,
                        audio_fx: audioFx,
                        start_time: startTime,
                        end_time: endTime
                    })
                });
                const data = await res.json();
                if (data.error || !res.ok) {
                    alert(data.error || "เกิดข้อผิดพลาดในการส่งคำขอ");
                    progressBox.style.display = "none";
                    stopVisualizerPulse();
                    resetButton();
                    return;
                }

                currentTaskId = data.task_id;
                pollStatus();
            } catch (err) {
                alert("เชื่อมต่อเซิร์ฟเวอร์ไม่ได้: " + err);
                progressBox.style.display = "none";
                stopVisualizerPulse();
                resetButton();
            }
        }

        function pollStatus() {
            if (pollTimer) clearTimeout(pollTimer);
            pollTimer = setTimeout(async () => {
                try {
                    const res = await fetch('/api/status/' + currentTaskId);
                    const task = await res.json();

                    if (task.status === 'downloading') {
                        const pct = Math.round(task.percent || 0);
                        const dlMb = task.downloaded_mb || "";
                        const totalMb = task.total_mb ? ` / ${task.total_mb}` : "";
                        
                        if (pct > 0) {
                            document.getElementById('progressBar').style.width = pct + '%';
                            document.getElementById('percentLabel').innerText = pct + '%';
                            document.getElementById('statusLabel').innerText = `กำลังดาวน์โหลด... (${dlMb}${totalMb})`;
                        } else {
                            document.getElementById('progressBar').style.width = '100%';
                            document.getElementById('percentLabel').innerText = dlMb || "กำลังเชื่อมต่อ...";
                            document.getElementById('statusLabel').innerText = "กำลังเชื่อมต่อและดึงข้อมูล...";
                        }
                        document.getElementById('detailLabel').innerText = (task.speed ? `ความเร็ว: ${task.speed} ` : "") + (task.eta ? `(เหลือ ${task.eta})` : "");
                        pollStatus();
                    } else if (task.status === 'converting') {
                        document.getElementById('progressBar').style.width = '100%';
                        document.getElementById('percentLabel').innerText = '100%';
                        document.getElementById('statusLabel').innerText = "กำลังแปลงไฟล์และประมวลผลเอฟเฟกต์...";
                        document.getElementById('detailLabel').innerText = "กำลังเรนเดอร์ด้วย FFmpeg Engine...";
                        pollStatus();
                    } else if (task.status === 'finished') {
                        lastTaskData = task;
                        stopVisualizerPulse();

                        document.getElementById('progressBox').style.display = "none";
                        document.getElementById('resultBox').style.display = "block";
                        document.getElementById('resultFileName').innerText = task.filename || task.title;
                        document.getElementById('resultMd5').innerText = task.md5 || '-';

                        // Show thumbnail if available
                        const thumbImg = document.getElementById('resultThumbImg');
                        const thumbBtn = document.getElementById('thumbDownloadBtn');
                        if (task.thumbnail_url) {
                            thumbImg.src = task.thumbnail_url;
                            thumbImg.style.display = "block";
                            thumbBtn.style.display = "inline-flex";
                        } else {
                            thumbImg.style.display = "none";
                            thumbBtn.style.display = "none";
                        }

                        const fileUrl = '/files/' + encodeURIComponent(task.filename);
                        const directLink = document.getElementById('directDownloadLink');
                        directLink.href = fileUrl;
                        directLink.download = task.filename;
                        directLink.innerHTML = "📥 ดาวน์โหลดอีกครั้ง";

                        // Audio preview
                        const fnLower = (task.filename || '').toLowerCase();
                        if (fnLower.endsWith('.mp3') || fnLower.endsWith('.m4a') || fnLower.endsWith('.m4r')) {
                            const audioContainer = document.getElementById('audioContainer');
                            const audioPlayer = document.getElementById('audioPlayer');
                            audioPlayer.src = fileUrl;
                            audioContainer.style.display = "block";
                            hookAudioPlayerVisualizer();
                        } else {
                            document.getElementById('audioContainer').style.display = "none";
                        }

                        // สั่งให้เบราว์เซอร์ดาวน์โหลดไฟล์ลงเครื่องทันทีโดยอัตโนมัติ
                        setTimeout(() => {
                            directLink.click();
                        }, 250);

                        resetButton();
                        document.getElementById('urlInput').value = "";
                    } else if (task.status === 'error') {
                        stopVisualizerPulse();
                        alert("การดาวน์โหลดล้มเหลว: " + task.error);
                        document.getElementById('progressBox').style.display = "none";
                        resetButton();
                    }
                } catch (err) {
                    pollStatus();
                }
            }, 500);
        }

        function resetButton() {
            const btn = document.getElementById('downloadBtn');
            btn.disabled = false;
            btn.innerHTML = "🚀 เริ่มดาวน์โหลดและแปลงไฟล์ทันที";
        }

        function handleDirectDownload() {
            const statusEl = document.getElementById('zeroStorageNotice');
            if (statusEl) {
                statusEl.innerHTML = "✅ กำลังดาวน์โหลดไฟล์ลงเครื่อง... (ไฟล์จะพร้อมให้มือถือสแกนและลบอัตโนมัติใน 3 นาที ตามนโยบาย Zero-Storage)";
                statusEl.style.display = "block";
            }
        }

        // QR Code Modal for Mobile
        let qrCountdownInterval = null;

        function openQrModal() {
            if (!lastTaskData || !lastTaskData.filename) {
                alert("ไม่พบข้อมูลไฟล์สำหรับสร้าง QR Code ครับ");
                return;
            }

            const lanIp = lastTaskData.lan_ip || SERVER_LAN_IP || window.location.hostname;
            const port = lastTaskData.port || SERVER_PORT || window.location.port || '5050';
            const protocol = window.location.protocol;
            
            // สร้าง URL ที่พาเข้าหน้า Mobile Landing Page พิเศษสำหรับมือถือ
            const mobileOrigin = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
                ? `${protocol}//${lanIp}:${port}` : window.location.origin;
            const mobileUrl = `${mobileOrigin}/m/${encodeURIComponent(lastTaskData.filename)}`;
            lastTaskData.mobile_download_url = mobileUrl;

            document.getElementById('qrLanIpLabel').innerText = `${lanIp}:${port}`;
            
            // ใช้ QR Server API คุณภาพสูง + ขอบมน
            const qrApiUrl = `https://api.qrserver.com/v1/create-qr-code/?size=250x250&margin=8&data=${encodeURIComponent(mobileUrl)}`;
            document.getElementById('qrImageElement').src = qrApiUrl;

            // Live Countdown Timer (3 นาที = 180 วิ)
            if (qrCountdownInterval) clearInterval(qrCountdownInterval);
            let remainingSec = 180;
            const updateClock = () => {
                const m = Math.floor(remainingSec / 60);
                const s = remainingSec % 60;
                const el = document.getElementById('qrModalCountdown');
                if (el) el.innerText = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
                if (remainingSec <= 0) {
                    clearInterval(qrCountdownInterval);
                    if (el) el.innerText = "หมดอายุ (Zero-Storage)";
                }
                remainingSec--;
            };
            updateClock();
            qrCountdownInterval = setInterval(updateClock, 1000);

            document.getElementById('qrModal').style.display = 'flex';
        }

        function closeQrModal() {
            if (qrCountdownInterval) clearInterval(qrCountdownInterval);
            document.getElementById('qrModal').style.display = 'none';
        }

        async function copyMobileUrl() {
            if (lastTaskData && lastTaskData.mobile_download_url) {
                try {
                    await navigator.clipboard.writeText(lastTaskData.mobile_download_url);
                    alert("✅ คัดลอกลิงก์สำหรับมือถือเรียบร้อยแล้ว สามารถนำไปเปิดในเบราว์เซอร์ของมือถือได้ทันทีครับ!");
                } catch (e) {
                    alert("ลิงก์: " + lastTaskData.mobile_download_url);
                }
            }
        }

        // HD Thumbnail Downloader
        function downloadThumbnailHD() {
            if (!lastTaskData || !lastTaskData.thumbnail_url) {
                alert("ไม่พบรูปหน้าปกสำหรับดาวน์โหลดครับ");
                return;
            }
            const dlUrl = `/api/download-thumbnail?url=${encodeURIComponent(lastTaskData.thumbnail_url)}&title=${encodeURIComponent(lastTaskData.title || 'thumbnail')}`;
            const a = document.createElement('a');
            a.href = dlUrl;
            a.download = (lastTaskData.title || 'thumbnail') + '_cover.jpg';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        async function loadAppInfo() {
            try {
                const res = await fetch('/api/app-info');
                const data = await res.json();
                if (data.exists) {
                    const btn = document.getElementById('appDownloadBtnText');
                    if (btn) btn.innerText = `ดาวน์โหลดโปรแกรม (.exe) ~${data.size_mb} MB`;
                }
            } catch (e) {}
        }

        // Initial call
        loadAppInfo();
    </script>
</body>
</html>
"""

@app.route('/favicon.ico')
def favicon():
    resp = send_from_directory(CURRENT_DIR, 'app_icon.ico', mimetype='image/vnd.microsoft.icon')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp

@app.route('/')
def index():
    port = int(os.environ.get('PORT', 5050))
    lan_ip = get_lan_ip()
    return render_template_string(HTML_TEMPLATE, lan_ip=lan_ip, server_port=port)

@app.route('/files/<path:filename>')
def serve_file(filename):
    file_path = safe_download_path(filename)
    if not file_path or not os.path.isfile(file_path):
        return (
            "<!DOCTYPE html><html lang='th'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>ไฟล์หมดอายุ - Zero-Storage Policy</title>"
            "<style>body{background:#080c14;color:#f8fafc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;text-align:center;}"
            ".box{background:rgba(17,24,39,0.85);border:1px solid rgba(255,255,255,0.1);padding:32px 24px;border-radius:20px;max-width:480px;box-shadow:0 20px 40px rgba(0,0,0,0.6);}"
            "h2{color:#f59e0b;margin-bottom:12px;}p{color:#94a3b8;font-size:14px;line-height:1.6;}"
            ".btn{display:inline-block;margin-top:18px;padding:12px 24px;background:#6366f1;color:#fff;border-radius:12px;text-decoration:none;font-weight:600;}</style></head>"
            "<body><div class='box'><div style='font-size:40px;margin-bottom:10px;'>⏳</div>"
            "<h2>ไฟล์หมดอายุการดาวน์โหลดแล้ว</h2>"
            "<p>ตามนโยบาย Zero-Storage Policy เพื่อความปลอดภัย ไฟล์ที่แปลงเสร็จจะมีอายุพร้อมดาวน์โหลดชั่วคราว 3 นาที (180 วินาที) และถูกลบทิ้งจากเซิร์ฟเวอร์โดยอัตโนมัติ</p>"
            "<a href='/' class='btn'>⚡ กลับหน้าหลักเพื่อดาวน์โหลดใหม่</a></div></body></html>"
        ), 404

    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=True)

@app.route('/stream/<path:filename>')
def stream_file(filename):
    file_path = safe_download_path(filename)
    if not file_path or not os.path.isfile(file_path):
        return "File not found", 404
    return send_from_directory(DOWNLOAD_DIR, filename, as_attachment=False)

MOBILE_PAGE_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{ filename }} - Universal Media Downloader</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico?v=lightning2">
    <link rel="apple-touch-icon" href="/favicon.ico?v=lightning2">
    <meta name="theme-color" content="#080c14">
    <link href="https://fonts.googleapis.com/css2?family=Prompt:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #080c14;
            --card-bg: rgba(17, 24, 39, 0.85);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Prompt', sans-serif; }
        body {
            background-color: var(--bg);
            background-image: 
                radial-gradient(circle at 50% 0%, rgba(99, 102, 241, 0.25) 0%, transparent 65%),
                radial-gradient(circle at 10% 80%, rgba(139, 92, 246, 0.15) 0%, transparent 50%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px 16px 40px 16px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .m-container { width: 100%; max-width: 440px; text-align: center; }
        .m-badge {
            width: 54px; height: 54px; border-radius: 18px;
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.25), rgba(245, 158, 11, 0.05));
            border: 1px solid rgba(245, 158, 11, 0.45);
            box-shadow: 0 0 25px rgba(245, 158, 11, 0.35);
            font-size: 26px; display: inline-flex; align-items: center; justify-content: center;
            margin-bottom: 12px;
        }
        .m-title { font-size: 20px; font-weight: 800; margin-bottom: 6px; }
        .m-card {
            background: var(--card-bg);
            backdrop-filter: blur(24px);
            border: 1px solid var(--card-border);
            border-radius: 24px;
            padding: 24px 20px;
            box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7);
            margin-top: 14px;
        }
        .m-thumb {
            width: 140px; height: 140px; border-radius: 16px; object-fit: cover;
            border: 2px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            margin: 0 auto 16px auto; display: block;
        }
        .m-filename {
            font-size: 15px; font-weight: 700; color: #f8fafc; word-break: break-all;
            margin-bottom: 12px; line-height: 1.4;
        }
        .m-timer {
            display: inline-flex; align-items: center; gap: 6px;
            background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3);
            color: #fde68a; font-size: 12px; font-weight: 600; padding: 4px 12px;
            border-radius: 99px; margin-bottom: 16px;
        }
        .btn-m-download {
            display: block; width: 100%; padding: 15px 20px;
            background: linear-gradient(135deg, #059669 0%, #10b981 100%);
            color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 700;
            border-radius: 16px; box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
            margin-bottom: 10px;
        }
        .btn-m-share {
            display: flex; align-items: center; justify-content: center; gap: 8px;
            width: 100%; padding: 12px 18px;
            background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.35);
            color: #c7d2fe; font-size: 14px; font-weight: 600;
            border-radius: 14px; margin-bottom: 12px; cursor: pointer;
            transition: all 0.2s;
        }
        .btn-m-share:active {
            transform: scale(0.98);
            background: rgba(99, 102, 241, 0.28);
        }
        .btn-m-home {
            display: inline-block; padding: 10px 18px;
            background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.12);
            color: #cbd5e1; text-decoration: none; font-size: 13px; font-weight: 600;
            border-radius: 12px;
        }
        audio { width: 100%; margin: 8px 0 16px 0; border-radius: 10px; }
    </style>
</head>
<body>
    <div class="m-container">
        <div class="m-badge">⚡</div>
        <div class="m-title">Universal Media Downloader</div>
        <p style="font-size: 13px; color: var(--text-muted);">พร้อมบันทึกลงโทรศัพท์มือถือของคุณ</p>

        <div class="m-card">
            {% if thumb_url %}
            <img class="m-thumb" src="{{ thumb_url }}" alt="Cover">
            {% endif %}
            <div class="m-filename">{{ filename }}</div>
            
            <div class="m-timer">
                <span>⏳</span>
                <span id="countdownLabel">ลิงก์พร้อมโหลดอีก 03:00 นาที</span>
            </div>

            {% if is_audio %}
            <div style="margin-bottom: 14px;">
                <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;">▶️ กดฟังตัวอย่างบนมือถือ:</div>
                <audio controls src="/stream/{{ filename }}"></audio>
            </div>
            {% endif %}

            <a href="{{ download_url }}" download="{{ filename }}" class="btn-m-download">
                📥 บันทึกลงเครื่องทันที (Save to Phone)
            </a>

            <button type="button" class="btn-m-share" onclick="shareMedia()">
                📤 แชร์ลิงก์นี้ให้เพื่อน (LINE / AirDrop)
            </button>

            <div style="margin-top: 14px; font-size: 11.5px; color: #94a3b8; line-height: 1.5; background: rgba(255,255,255,0.04); border-radius: 12px; padding: 10px 12px; text-align: left; border: 1px solid rgba(255,255,255,0.06);">
                <b style="color: #6ee7b7;">💡 ปลายทางหลังดาวน์โหลดบนมือถือ:</b><br>
                • <b>iPhone:</b> บันทึกลงแอป <b>"ไฟล์" (Files) ➔ "รายการดาวน์โหลด"</b> (หรือกดดูที่ปุ่ม ⬇️ บน Safari)<br>
                • <b>Android:</b> อยู่ในโฟลเดอร์ <b>"ดาวน์โหลด" (Downloads)</b> และเล่นผ่านแอปฟังเพลงได้ทันที
            </div>

            <div style="margin-top: 14px;">
                <a href="/" class="btn-m-home">⚡ แปลงเพลงอื่นเพิ่ม</a>
            </div>
        </div>

        <div style="margin-top: 20px; font-size: 11.5px; color: #64748b;">
            🛡️ Zero-Storage Policy • ปลอดภัย ไร้โฆษณา • ลบไฟล์ออกจากเซิร์ฟเวอร์อัตโนมัติ
        </div>
    </div>

    <script>
        let remainingSeconds = {{ remaining_seconds }};
        const timerLabel = document.getElementById('countdownLabel');
        const interval = setInterval(() => {
            remainingSeconds--;
            if (remainingSeconds <= 0) {
                clearInterval(interval);
                timerLabel.innerText = "ลิงก์หมดอายุแล้ว (Zero-Storage)";
            } else {
                const m = Math.floor(remainingSeconds / 60);
                const s = remainingSeconds % 60;
                timerLabel.innerText = `ลิงก์พร้อมโหลดอีก ${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')} นาที`;
            }
        }, 1000);

        function shareMedia() {
            if (navigator.share) {
                navigator.share({
                    title: '{{ filename }}',
                    text: 'ฟังและดาวน์โหลดเพลง {{ filename }} จาก Universal Media Downloader',
                    url: window.location.href
                }).catch(() => {});
            } else {
                navigator.clipboard.writeText(window.location.href).then(() => {
                    alert("คัดลอกลิงก์เรียบร้อยแล้ว! สามารถนำไปส่งต่อใน LINE หรือแชทได้ทันทีครับ");
                }).catch(() => {
                    alert("ลิงก์หน้าดาวน์โหลด: " + window.location.href);
                });
            }
        }
    </script>
</body>
</html>
"""

@app.route('/m/<path:filename>')
def mobile_landing_page(filename):
    file_path = safe_download_path(filename)
    if not file_path or not os.path.isfile(file_path):
        return (
            "<!DOCTYPE html><html lang='th'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>ไฟล์หมดอายุ - Zero-Storage Policy</title>"
            "<style>body{background:#080c14;color:#f8fafc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;text-align:center;}"
            ".box{background:rgba(17,24,39,0.85);border:1px solid rgba(255,255,255,0.1);padding:32px 24px;border-radius:20px;max-width:480px;box-shadow:0 20px 40px rgba(0,0,0,0.6);}"
            "h2{color:#f59e0b;margin-bottom:12px;}p{color:#94a3b8;font-size:14px;line-height:1.6;}"
            ".btn{display:inline-block;margin-top:18px;padding:12px 24px;background:#6366f1;color:#fff;border-radius:12px;text-decoration:none;font-weight:600;}</style></head>"
            "<body><div class='box'><div style='font-size:40px;margin-bottom:10px;'>⏳</div>"
            "<h2>ไฟล์หมดอายุการดาวน์โหลดแล้ว</h2>"
            "<p>ตามนโยบาย Zero-Storage Policy เพื่อความปลอดภัย ไฟล์ที่แปลงเสร็จจะมีอายุพร้อมดาวน์โหลดชั่วคราว 3 นาที (180 วินาที) และถูกลบทิ้งจากเซิร์ฟเวอร์โดยอัตโนมัติ</p>"
            "<a href='/' class='btn'>⚡ กลับหน้าหลักเพื่อดาวน์โหลดใหม่</a></div></body></html>"
        ), 404

    file_age = time.time() - os.path.getmtime(file_path)
    remaining_sec = max(1, int(FILE_TTL_SECONDS - file_age))

    thumb_url = ""
    for t in tasks.values():
        if t.get('filename') == filename:
            thumb_url = t.get('thumbnail_url', '')
            break

    is_audio = filename.lower().endswith(('.mp3', '.m4a', '.m4r'))
    download_url = f"/files/{urllib.parse.quote(filename)}"

    return render_template_string(
        MOBILE_PAGE_TEMPLATE,
        filename=filename,
        thumb_url=thumb_url,
        is_audio=is_audio,
        download_url=download_url,
        remaining_seconds=remaining_sec
    )

@app.route('/api/download-thumbnail')
def download_thumbnail():
    url = request.args.get('url', '').strip()
    title = request.args.get('title', 'thumbnail').strip()
    if not url:
        return "No thumbnail URL", 400
    if not is_safe_remote_url(url):
        return "Invalid thumbnail URL", 400
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15, context=updater.get_ssl_context()) as resp:
            data = resp.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                return "Thumbnail too large", 413
            safe_title = re.sub(r'[<>:"/\\|?*\n\r\t]', '_', title)[:60].strip() or "thumbnail"
            ascii_title = re.sub(r'[^\x20-\x7e]', '_', safe_title).strip() or "thumbnail"
            quoted_filename = urllib.parse.quote(f"{safe_title}_cover.jpg")
            resp_out = app.response_class(data, mimetype='image/jpeg')
            resp_out.headers['Content-Disposition'] = f'attachment; filename="{ascii_title}_cover.jpg"; filename*=UTF-8\'\'{quoted_filename}'
            return resp_out
    except Exception as e:
        return "Error downloading thumbnail", 500

@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    global ZERO_STORAGE_MODE
    ZERO_STORAGE_MODE = True
    return jsonify({"zero_storage": True})

@app.route('/download-app')
def download_app():
    ip = flood_protector.get_client_ip(request)
    allowed, err_msg = flood_protector.check_app_download_allowed(ip)
    if not allowed:
        return err_msg, 429
    release_url = os.environ.get('APP_DOWNLOAD_URL')
    if release_url:
        return redirect(release_url)
    for p in [os.path.join(CURRENT_DIR, "MP3_Downloader.exe"), os.path.join(CURRENT_DIR, "dist", "MP3_Downloader.exe")]:
        if os.path.exists(p):
            return send_from_directory(os.path.dirname(p), os.path.basename(p), as_attachment=True, download_name="MP3_Downloader.exe")
    return "ไม่พบไฟล์โปรแกรม MP3_Downloader.exe กรุณารัน Build_EXE.bat ก่อนครับ", 404

@app.route('/api/app-info')
def app_info():
    if os.environ.get('APP_DOWNLOAD_URL'):
        return jsonify({"exists": True, "filename": "MP3_Downloader.exe", "size_mb": 193.3, "download_url": "/download-app"})
    for p in [os.path.join(CURRENT_DIR, "MP3_Downloader.exe"), os.path.join(CURRENT_DIR, "dist", "MP3_Downloader.exe")]:
        if os.path.exists(p):
            size_mb = round(os.path.getsize(p) / (1024 * 1024), 1)
            return jsonify({
                "exists": True,
                "filename": "MP3_Downloader.exe",
                "size_mb": size_mb,
                "download_url": "/download-app"
            })
    return jsonify({"exists": False, "filename": "MP3_Downloader.exe", "size_mb": 0})

@app.route('/api/engine-version')
def api_engine_version():
    cur_v = updater.get_installed_ytdlp_version()
    chk = updater.check_for_updates()
    latest_v = chk.get("latest_version") or cur_v
    has_update = chk.get("has_update", False)
    cur_patch = updater.format_patch_version(cur_v)
    latest_patch = chk.get("latest_patch") or updater.format_patch_version(latest_v)
    return jsonify({
        "version": cur_patch,
        "latest_version": latest_patch,
        "raw_version": cur_v,
        "raw_latest_version": latest_v,
        "has_update": has_update,
        "app_version": updater.APP_VERSION,
        "check_ok": chk.get("ok", False)
    })

@app.route('/api/update-engine', methods=['POST'])
def api_update_engine():
    if not is_local_request(request):
        return jsonify({"ok": False, "error": "อัปเดตได้จากเครื่องเซิร์ฟเวอร์เท่านั้น"}), 403
    try:
        res = updater.download_and_apply_patch()
        return jsonify(res)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/search')
def api_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({"results": []})
    try:
        ydl_opts = {
            'extract_flat': True,
            'skip_download': True,
            'quiet': True,
            'no_warnings': True,
            'noplaylist': True,
            'socket_timeout': 10
        }
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            res = ydl.extract_info(f"ytsearch5:{query}", download=False)
            results = []
            for entry in res.get('entries', []):
                if not entry:
                    continue
                duration = entry.get('duration')
                dur_str = ""
                if duration:
                    m = int(duration) // 60
                    s = int(duration) % 60
                    dur_str = f"{m:02d}:{s:02d}"
                video_id = entry.get('id', '')
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', str(video_id)):
                    continue
                results.append({
                    "id": video_id,
                    "title": entry.get('title', 'Unknown Title'),
                    "uploader": entry.get('uploader') or entry.get('channel') or '',
                    "duration": dur_str,
                    "url": f"https://www.youtube.com/watch?v={video_id}",
                    "thumbnail": entry.get('thumbnail') or f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"
                })
            return jsonify({"results": results})
    except Exception as e:
        return jsonify({"error": str(e), "results": []}), 500

@app.route('/api/files')
def list_files():
    # ปิดการแสดงรายการไฟล์สาธารณะเพื่อความเป็นส่วนตัวและป้องกันผู้ไม่หวังดี
    return jsonify([])

@app.route('/api/delete-file', methods=['POST'])
def delete_file():
    data = request.json or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({"error": "No filename"}), 400
    filepath = safe_download_path(filename)
    if not filepath:
        return jsonify({"error": "Invalid filename"}), 400
    if os.path.isfile(filepath):
        try:
            os.remove(filepath)
            md5_p = f"{filepath}.md5"
            if os.path.exists(md5_p):
                try:
                    os.remove(md5_p)
                except Exception:
                    pass
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"error": "File not found"}), 404

@app.route('/api/clear-all', methods=['POST'])
def clear_all():
    return jsonify({"ok": True, "cleared_count": 0})

@app.route('/api/open-folder', methods=['POST'])
def open_folder():
    return jsonify({"ok": False, "message": "Disabled for security"}), 403

@app.route('/api/status/<task_id>')
def get_status(task_id):
    task = tasks.get(task_id)
    if not task:
        return jsonify({"status": "not_found"}), 404
    return jsonify(task)

@app.route('/api/download', methods=['POST'])
def start_download():
    ip = flood_protector.get_client_ip(request)
    allowed, err_msg, status_code = flood_protector.check_download_allowed(ip)
    if not allowed:
        return jsonify({"error": err_msg}), status_code

    data = request.json or {}
    url = data.get('url', '').strip()
    fmt = data.get('format', 'mp3')
    audio_fx = data.get('audio_fx', 'none')
    start_time = data.get('start_time', '').strip()
    end_time = data.get('end_time', '').strip()

    if not url:
        return jsonify({"error": "กรุณาระบุ URL"}), 400
    if len(url) > 4096 or not is_safe_remote_url(url):
        return jsonify({"error": "URL ไม่ถูกต้อง (รองรับเฉพาะลิงก์ http/https สาธารณะ)"}), 400

    task_id = str(uuid.uuid4())
    tasks[task_id] = {
        "status": "downloading",
        "percent": 0,
        "speed": "",
        "eta": "",
        "title": "",
        "filename": "",
        "thumbnail_url": "",
        "error": "",
        "created_at": time.time(),
        "client_ip": ip,
        "lan_ip": get_lan_ip(),
        "port": int(os.environ.get('PORT', 5050))
    }

    # บันทึกงานเข้า Flood Protector เพื่อจำกัด Concurrency
    flood_protector.register_task(ip, task_id)

    t = threading.Thread(target=download_worker, args=(task_id, url, fmt, audio_fx, start_time, end_time, ip), daemon=True)
    t.start()

    return jsonify({"task_id": task_id})

def download_worker(task_id, url, fmt, audio_fx="none", start_time="", end_time="", client_ip=""):
    try:
        _do_download_work(task_id, url, fmt, audio_fx, start_time, end_time)
    finally:
        if client_ip:
            flood_protector.unregister_task(client_ip, task_id)
        if task_id in tasks:
            tasks[task_id]["finished_at"] = time.time()

def _do_download_work(task_id, url, fmt, audio_fx="none", start_time="", end_time=""):
    # ตรวจจับ DRM Platforms ทันทีเพื่อความปลอดภัยและปฏิบัติตามกฎหมายลิขสิทธิ์
    drm_domains = [
        ("primevideo.com", "Amazon Prime Video"),
        ("netflix.com", "Netflix"),
        ("disneyplus.com", "Disney+ Hotstar"),
        ("hbomax.com", "HBO Max"),
        ("max.com", "Max"),
        ("tv.apple.com", "Apple TV+"),
        ("hulu.com", "Hulu"),
        ("wetv.vip", "WeTV"),
        ("iqiyi.com", "iQIYI"),
        ("udio.com", "Udio AI")
    ]
    for d, name in drm_domains:
        if d in url.lower():
            tasks[task_id]["status"] = "error"
            tasks[task_id]["error"] = (
                f"🚫 เว็บไซต์ {name} ไม่อยู่ในขอบข่ายที่รองรับ เนื่องจากมีระบบปกป้องลิขสิทธิ์ดิจิทัล (DRM) "
                f"และเป็นบริการสตรีมมิ่งเชิงพาณิชย์แบบบอกรับสมาชิก ระบบยึดถือนโยบายความปลอดภัยและกฎหมายลิขสิทธิ์ DMCA "
                f"จึงไม่มีการถอดรหัสหรือดาวน์โหลดสื่อประเภทนี้ แนะนำให้รับชมแบบออฟไลน์ผ่านแอปพลิเคชันอย่างเป็นทางการของ {name} ครับ"
            )
            return

    # ตรวจจับ Suno AI ทันทีเพื่อไม่ให้ค้าง
    if "suno.com" in url.lower() or "suno.ai" in url.lower():
        tasks[task_id]["status"] = "error"
        tasks[task_id]["error"] = (
            "⚠️ เว็บไซต์ Suno AI (suno.com) มีการเข้ารหัสป้องกันการดึงไฟล์ภายนอก\n\n"
            "📌 สาเหตุ: ระบบเพลงของ Suno AI มีการเข้ารหัสสตรีมเสียงเฉพาะในเบราว์เซอร์ (Encrypted Web Stream) "
            "และ yt-dlp ถูกระงับไม่ให้ดึงเพลงจาก Suno ตามข้อกำหนดทางกฎหมาย (Liability Protection)\n\n"
            "💡 วิธีดาวน์โหลดเพลงนี้ลงเครื่อง (ง่ายและได้ไฟล์แท้ 100%):\n"
            "1. เปิดหน้าเพลงนี้บน Suno.com ในคอมพิวเตอร์หรือมือถือของคุณ\n"
            "2. กดปุ่มจุดสามจุด (...) หรือปุ่ม [Download] ใต้ชื่อเพลง\n"
            "3. เลือก 'Audio (MP3)' เว็บไซต์ Suno จะโหลดไฟล์เพลง MP3 ออกมาให้ทันทีครับ!"
        )
        return

    def progress_hook(d):
        status = d.get('status')
        if status == 'downloading':
            total = d.get('total_bytes') or d.get('total_bytes_estimate') or 0
            downloaded = d.get('downloaded_bytes', 0)
            speed = d.get('speed')
            eta = d.get('eta')

            pct = (downloaded / total * 100) if total > 0 else 0
            speed_str = f"{speed / 1024 / 1024:.1f} MB/s" if speed else ""
            eta_str = f"{eta}s" if eta else ""

            tasks[task_id]["percent"] = pct
            tasks[task_id]["speed"] = speed_str
            tasks[task_id]["eta"] = eta_str
            tasks[task_id]["downloaded_mb"] = f"{downloaded / 1024 / 1024:.1f} MB" if downloaded > 0 else ""
            tasks[task_id]["total_mb"] = f"{total / 1024 / 1024:.1f} MB" if total > 0 else ""
            tasks[task_id]["status"] = "downloading"
        elif status == 'finished':
            tasks[task_id]["status"] = "converting"

    try:
        ydl_opts = {
            'outtmpl': os.path.join(DOWNLOAD_DIR, '%(title).80s.%(ext)s'),
            'trim_file_name': 80,
            'progress_hooks': [progress_hook],
            'noplaylist': True,
            'windowsfilenames': True,
            'quiet': True,
            'no_warnings': True,
            'keepvideo': False,
            'socket_timeout': 25,
            'retries': 10,
            'concurrent_fragment_downloads': 8,
            'buffersize': 1024 * 1024 * 4,
            'http_chunk_size': 10485760,
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,th;q=0.8',
            },
            'extractor_retries': 5,
        }

        # Set FFmpeg location for yt-dlp
        ff_dir = get_ffmpeg_dir()
        if ff_dir:
            ydl_opts['ffmpeg_location'] = ff_dir

        # Check for time range cut
        s_sec = parse_time_str(start_time)
        e_sec = parse_time_str(end_time)
        if s_sec is not None or e_sec is not None:
            start_val = s_sec if s_sec is not None else 0
            end_val = e_sec if e_sec is not None else float('inf')
            if start_val < end_val:
                ydl_opts['download_ranges'] = yt_dlp.utils.download_range_func(None, [(start_val, end_val)])
                ydl_opts['force_keyframes_at_cuts'] = True

        postprocessors = []

        if fmt in ["mp3", "m4r"]:
            ydl_opts['format'] = 'bestaudio/best'
            ydl_opts['writethumbnail'] = True
            postprocessors.append({
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '320',
            })
            postprocessors.append({
                'key': 'FFmpegThumbnailsConvertor',
                'format': 'jpg',
            })
            postprocessors.append({
                'key': 'FFmpegMetadata',
                'add_metadata': True,
            })
            postprocessors.append({
                'key': 'EmbedThumbnail',
            })
        elif fmt == "gif":
            # ดาวน์โหลดวิดีโอเพื่อแปลงเป็น GIF
            ydl_opts['format'] = 'best[ext=mp4]/bestvideo[ext=mp4]+bestaudio/best'
            ydl_opts['merge_output_format'] = 'mp4'
        else: # mp4
            ydl_opts['format'] = 'best[ext=mp4]/bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo+bestaudio/best[ext=mp4]/best'
            ydl_opts['merge_output_format'] = 'mp4'
            postprocessors.append({
                'key': 'FFmpegMetadata',
                'add_metadata': True,
            })

        ydl_opts['postprocessors'] = postprocessors

        target_url = resolve_music_streaming_url(url)
        info = None
        try:
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(target_url, download=True)
        except Exception as first_err:
            first_msg = str(first_err).lower()
            if "pornhub" in url.lower() or "410" in first_msg or "cloudflare" in first_msg:
                cookies_worked = False
                for b in ['edge', 'chrome', 'brave', 'firefox']:
                    try:
                        ydl_opts_b = ydl_opts.copy()
                        ydl_opts_b['cookiesfrombrowser'] = (b, None, None, None)
                        with yt_dlp.YoutubeDL(ydl_opts_b) as ydl_b:
                            info = ydl_b.extract_info(target_url, download=True)
                            cookies_worked = True
                            break
                    except Exception:
                        continue
                if not cookies_worked:
                    raise first_err
            else:
                raise first_err

        if not info:
            raise Exception("Unable to extract media info")

        title = info.get('title', 'Unknown')
        tasks[task_id]["title"] = title

        # ดึงภาพปก Thumbnail ที่ชัดที่สุด
        thumb_url = info.get('thumbnail')
        if not thumb_url and info.get('thumbnails'):
            thumb_url = info['thumbnails'][-1].get('url')
        tasks[task_id]["thumbnail_url"] = thumb_url or ""

        # หาไฟล์ที่ yt-dlp สร้างขึ้นมาล่าสุด
        ext_search = "mp3" if fmt in ["mp3", "m4r"] else "mp4"
        actual_filename = f"{title}.{ext_search}"
        try:
            for f in sorted(os.listdir(DOWNLOAD_DIR), key=lambda x: safe_mtime(os.path.join(DOWNLOAD_DIR, x)), reverse=True):
                if f.endswith(f".{ext_search}"):
                    actual_filename = f
                    break
        except Exception:
            pass

        full_file_path = os.path.join(DOWNLOAD_DIR, actual_filename)
        ff_bin = get_ffmpeg_binary()

        # Smart Audio FX & Format conversions via FFmpeg
        AUDIO_FILTERS = {
            'bass_boost': 'bass=g=8:f=110:w=0.6',
            'mega_bass': 'bass=g=14:f=90:w=0.7',
            'slowed_reverb': 'atempo=0.88,aecho=0.8:0.88:60:0.4',
            '8d_audio': 'apulsator=hz=0.125:mode=sine:width=0.9',
            'vocal_boost': 'loudnorm=I=-14:TP=-1.5:LRA=11',
            'karaoke_cut': 'pan=stereo|c0=c0-c1|c1=c1-c0',
            'volume_boost': 'volume=2.0'
        }

        base_no_ext = os.path.splitext(actual_filename)[0]

        if fmt == "m4r":
            # แปลงเป็น M4R สำหรับ iPhone Ringtone
            tasks[task_id]["status"] = "converting"
            m4r_name = f"{base_no_ext}.m4r"
            m4r_path = os.path.join(DOWNLOAD_DIR, m4r_name)
            cmd = [ff_bin, '-y', '-i', full_file_path]
            if audio_fx in AUDIO_FILTERS:
                cmd.extend(['-af', AUDIO_FILTERS[audio_fx]])
            cmd.extend(['-c:a', 'aac', '-b:a', '256k', '-f', 'ipod', m4r_path])
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, creationflags=SUBPROCESS_FLAGS)
            try:
                os.remove(full_file_path)
            except Exception:
                pass
            actual_filename = m4r_name
            full_file_path = m4r_path

        elif fmt == "gif":
            # แปลงเป็น GIF คุณภาพสูงด้วย Custom Palette
            tasks[task_id]["status"] = "converting"
            gif_name = f"{base_no_ext}.gif"
            gif_path = os.path.join(DOWNLOAD_DIR, gif_name)
            cmd = [
                ff_bin, '-y', '-i', full_file_path,
                '-vf', 'fps=12,scale=480:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse',
                gif_path
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, creationflags=SUBPROCESS_FLAGS)
            try:
                os.remove(full_file_path)
            except Exception:
                pass
            actual_filename = gif_name
            full_file_path = gif_path

        elif fmt == "mp3" and audio_fx in AUDIO_FILTERS:
            # ปรับแต่งเสียงด้วย Smart Audio FX
            tasks[task_id]["status"] = "converting"
            fx_name = f"{base_no_ext}_{audio_fx}.mp3"
            fx_path = os.path.join(DOWNLOAD_DIR, fx_name)
            cmd = [
                ff_bin, '-y', '-i', full_file_path,
                '-af', AUDIO_FILTERS[audio_fx],
                '-b:a', '320k',
                fx_path
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, creationflags=SUBPROCESS_FLAGS)
            try:
                os.remove(full_file_path)
            except Exception:
                pass
            actual_filename = fx_name
            full_file_path = fx_path

        # กวาดล้างไฟล์ชั่วคราว/ไฟล์ดิบส่วนเกิน (เช่น .webm, .webp, .jpg, .part) ให้เหลือไฟล์สุดท้ายเพียงไฟล์เดียว
        if full_file_path and os.path.exists(full_file_path):
            curr_base = os.path.splitext(full_file_path)[0]
            for extra_ext in ('.webm', '.webp', '.jpg', '.png', '.part', '.ytdl', '.temp', '.m4a'):
                raw_c = f"{curr_base}{extra_ext}"
                if os.path.abspath(raw_c) != os.path.abspath(full_file_path) and os.path.exists(raw_c):
                    try:
                        os.remove(raw_c)
                    except Exception:
                        pass

        tasks[task_id]["filename"] = actual_filename

        # คำนวณและบันทึก MD5 Checksum
        file_md5 = compute_and_save_md5(full_file_path, url)
        tasks[task_id]["md5"] = file_md5 or ""
        tasks[task_id]["status"] = "finished"

    except Exception as e:
        # Fallback: ลองดาวน์โหลดลิงก์ไฟล์ตรง (Direct Media File / Web Stream)
        try:
            import urllib.request
            import urllib.parse
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'
            })
            with urllib.request.urlopen(req, timeout=30, context=updater.get_ssl_context()) as resp:
                ctype = resp.headers.get('Content-Type', '').lower()
                if 'text/html' in ctype or 'text/plain' in ctype or 'application/json' in ctype:
                    raise Exception("URL is a webpage, not a direct media stream")

                cdisp = resp.headers.get('Content-Disposition', '')
                if 'filename=' in cdisp:
                    raw_fn = cdisp.split('filename=')[1].split(';')[0].strip(' "\'')
                else:
                    path_part = urllib.parse.urlparse(url).path
                    raw_fn = os.path.basename(path_part) or f"download_{int(time.time())}"

                b_name, b_ext = os.path.splitext(raw_fn)
                safe_b_name = re.sub(r'[<>:"/\\|?*\n\r\t]', '_', b_name)[:80].strip() or "media_file"
                raw_fn = sanitize_filename(f"{safe_b_name}{b_ext}")
                
                temp_p = safe_download_path(raw_fn)
                if not temp_p:
                    raise Exception("Unsafe filename")
                total_len = int(resp.headers.get('Content-Length', 0) or 0)
                max_bytes = 2 * 1024 * 1024 * 1024  # จำกัด 2GB กันดิสก์เต็ม
                downloaded = 0
                with open(temp_p, 'wb') as out_f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        downloaded += len(chunk)
                        if downloaded > max_bytes:
                            raise Exception("File too large")
                        if total_len > 0:
                            tasks[task_id]["percent"] = (downloaded / total_len * 100)

                if fmt == "mp3" and not raw_fn.lower().endswith('.mp3'):
                    base_n = os.path.splitext(raw_fn)[0]
                    final_mp3 = os.path.join(DOWNLOAD_DIR, f"{base_n}.mp3")
                    ff_bin = get_ffmpeg_binary()
                    cmd = [ff_bin, '-y', '-i', temp_p, '-vn', '-b:a', '320k']
                    if s_sec is not None:
                        cmd.extend(['-ss', str(s_sec)])
                    if e_sec is not None:
                        cmd.extend(['-to', str(e_sec)])
                    cmd.append(final_mp3)
                    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, creationflags=SUBPROCESS_FLAGS)
                    try:
                        os.remove(temp_p)
                    except Exception:
                        pass
                    actual_fn = f"{base_n}.mp3"
                else:
                    actual_fn = raw_fn

                full_p = os.path.join(DOWNLOAD_DIR, actual_fn)
                f_md5 = compute_and_save_md5(full_p, url)
                tasks[task_id]["md5"] = f_md5 or ""
                tasks[task_id]["filename"] = actual_fn
                tasks[task_id]["title"] = actual_fn
                tasks[task_id]["status"] = "finished"
                return
        except Exception:
            pass

        raw_err = str(e)
        clean_err = re.sub(r'\x1b\[[0-9;]*m', '', raw_err)
        if 'pornhub' in url.lower() and ('410' in clean_err or 'gone' in clean_err.lower()):
            tasks[task_id]["error"] = (
                "⚠️ เว็บไซต์ PornHub บล็อกคำขอดาวน์โหลดภายนอก (HTTP Error 410: Gone)\n\n"
                "📌 สาเหตุที่ในเว็บเบราว์เซอร์ยังดูได้ แต่โปรแกรมดาวน์โหลดไม่ได้:\n"
                "1. คุณเปิดดูในเบราว์เซอร์ผ่านส่วนขยาย VPN, พร็อกซี หรือระบบ Secure DNS (เช่น Cloudflare 1.1.1.1) เฉพาะในเบราว์เซอร์\n"
                "2. ผู้ให้บริการอินเทอร์เน็ตในไทย (ISP) บล็อกเว็บ PornHub ที่ระดับเครือข่าย เมื่อโปรแกรมภายนอกเชื่อมต่อตรงๆ จึงถูกตัดการเชื่อมต่อ\n"
                "3. เว็บไซต์มีระบบตรวจจับบอต (Cloudflare/Anti-Scraping) ที่บล็อกโปรแกรมดาวน์โหลดหากไม่มีคุกกี้เซสชันที่สมบูรณ์\n\n"
                "💡 วิธีแก้ไขเพื่อให้ดาวน์โหลดได้สำเร็จ:\n"
                "• เปิดโปรแกรม VPN ทั่วทั้งเครื่องคอมพิวเตอร์ (เช่น ติดตั้ง Cloudflare WARP 1.1.1.1 ฟรี แล้วเปิดใช้งาน)\n"
                "• หรือเปิดหน้าเว็บเบราว์เซอร์ (Edge หรือ Chrome) ที่กำลังเล่นคลิปนี้ทิ้งไว้ แล้วลองกดยืนยันดาวน์โหลดอีกครั้งครับ"
            )
        elif '410' in clean_err and ('gone' in clean_err.lower() or 'http error 410' in clean_err.lower()):
            tasks[task_id]["error"] = (
                "⚠️ วิดีโอนี้ถูกลบออกจากเว็บไซต์ต้นทางแล้วอย่างถาวร (HTTP 410: Gone)\n\n"
                "📌 สาเหตุ: วิดีโอคลิปนี้ถูกเจ้าของคลิปสั่งลบ หรือถูกทางเว็บไซต์ต้นทางลบ/ระงับออกจากระบบไปแล้วอย่างถาวร จึงไม่มีไฟล์บนเซิร์ฟเวอร์ให้ดาวน์โหลดอีกต่อไป\n\n"
                "💡 คำแนะนำ: หากคุณลองเปิดลิงก์นี้ในเว็บเบราว์เซอร์ เว็บจะแจ้งเตือนว่า 'This video has been removed' หรือ 'Video Deleted'\n"
                "แนะนำให้ค้นหาคลิปอื่น หรือค้นหาชื่อเรื่องเดียวกันที่อัปโหลดโดยผู้ใช้อื่นแทนครับ"
            )
        elif '404' in clean_err and ('not found' in clean_err.lower() or 'http error 404' in clean_err.lower()):
            tasks[task_id]["error"] = (
                "⚠️ ไม่พบคลิปนี้ในระบบ (HTTP 404: Not Found)\n\n"
                "📌 สาเหตุ: ลิงก์ที่ระบุอาจตกหล่น ลิงก์ไม่ถูกต้อง หรือวิดีโอถูกลบไปแล้ว\n\n"
                "💡 คำแนะนำ: กรุณาตรวจสอบลิงก์ URL ในช่องอีกครั้งว่าคัดลอกมาครบถ้วนหรือไม่ครับ"
            )
        elif 'sign in' in clean_err.lower() and ('confirm your age' in clean_err.lower() or 'age-restricted' in clean_err.lower()):
            tasks[task_id]["error"] = (
                "⚠️ คลิปนี้ติดจำกัดอายุผู้ชม (Age-restricted / 18+)\n\n"
                "📌 สาเหตุ: เว็บไซต์ต้นทางกำหนดให้ต้องเข้าสู่ระบบบัญชีผู้ใช้เพื่อยืนยันอายุของผู้รับชมก่อน จึงไม่สามารถดึงไฟล์แบบสาธารณะได้โดยตรง\n\n"
                "💡 คำแนะนำ: แนะนำให้เปิดรับชมผ่านหน้าเว็บหรือแอปพลิเคชันอย่างเป็นทางการที่เข้าสู่ระบบไว้แล้วครับ"
            )
        elif 'this video is private' in clean_err.lower() or 'private video' in clean_err.lower():
            tasks[task_id]["error"] = (
                "⚠️ วิดีโอนี้ถูกตั้งค่าเป็น 'วิดีโอส่วนตัว' (Private Video)\n\n"
                "📌 สาเหตุ: เจ้าของคลิปได้ล็อคคลิปนี้ให้ดูได้เฉพาะผู้ที่ได้รับอนุญาตเท่านั้น ไม่เปิดเป็นสาธารณะ\n\n"
                "💡 คำแนะนำ: โปรแกรมสามารถดาวน์โหลดได้เฉพาะคลิปที่เปิดสถานะ 'สาธารณะ' (Public) เท่านั้นครับ"
            )
        elif 'primevideo' in url.lower() or 'netflix' in url.lower() or 'disneyplus' in url.lower():
            tasks[task_id]["error"] = (
                "⚠️ ลิงก์นี้มาจากบริการสตรีมมิ่งที่ติด DRM ลิขสิทธิ์ระดับสูง (Prime Video / Netflix / Disney+)\n\n"
                "📌 สาเหตุ: ภาพยนตร์และซีรีส์บนบริการเหล่านี้ มีการเข้ารหัสล็อคไฟล์แบบ Widevine DRM L1 "
                "จึงไม่สามารถดึงไฟล์หนังออกมาตรงๆ ได้\n\n"
                "💡 วิธีดาวน์โหลดเพลง/คลิปเรื่องนี้: แนะนำให้พิมพ์ชื่อเรื่องหรือเพลงประกอบใน YouTube หรือ Bilibili แล้วนำลิงก์มาวาง จะโหลด MP3 320kbps หรือ MP4 ได้ทันทีครับ!"
            )
        elif 'facebook' in url.lower() and ('login' in clean_err.lower() or 'private' in clean_err.lower() or 'unavailable' in clean_err.lower()):
            tasks[task_id]["error"] = (
                "⚠️ ไม่สามารถดาวน์โหลดคลิปนี้จาก Facebook ได้\n\n"
                "📌 สาเหตุ: คลิป Facebook นี้อาจถูกตั้งค่าความเป็นส่วนตัวไว้เป็น 'เฉพาะเพื่อน' (Private / Friends Only) หรือต้องล็อคอินบัญชีผู้ใช้เพื่อดู\n\n"
                "💡 คำแนะนำ: โปรแกรมจะสามารถดาวน์โหลดคลิปจาก Facebook ได้เฉพาะคลิปที่เป็น 'สาธารณะ' (มีไอคอนรูปโลก 🌐) เท่านั้นครับ"
            )
        elif '[DRM]' in clean_err or 'DRM protection' in clean_err:
            tasks[task_id]["error"] = (
                "⚠️ ลิงก์นี้ติดการเข้ารหัสป้องกันลิขสิทธิ์ (DRM Protection)\n\n"
                "📌 สาเหตุ: เว็บไซต์ต้นทาง (เช่น สตรีมมิ่งที่ใช้ Widevine/FairPlay DRM) มีการเข้ารหัสป้องกันการดาวน์โหลดไฟล์โดยตรง\n\n"
                "💡 คำแนะนำ: หากต้องการเพลงหรือคลิปนี้ แนะนำให้ค้นหาชื่อเรื่องจาก YouTube, TikTok หรือ SoundCloud แล้วนำลิงก์มาวางดาวน์โหลดแทนได้เลยครับ"
            )
        else:
            tasks[task_id]["error"] = clean_err


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    host = os.environ.get('HOST', '0.0.0.0')
    lan_ip = get_lan_ip()
    print("========================================================")
    print("      ⚡ กำลังเปิดเซิร์ฟเวอร์ Universal Media Downloader...")
    print("========================================================")
    print(f"กำลังเปิดหน้าเว็บในบราวเซอร์ของคุณอัตโนมัติ...")
    print(f"ที่อยู่เว็บในคอมพิวเตอร์: http://127.0.0.1:{port}")
    print(f"ที่อยู่เว็บสำหรับมือถือ (Wi-Fi): http://{lan_ip}:{port}")
    print("--------------------------------------------------------")
    print("[!] สำคัญมาก: กรุณาอย่าปิดหน้าต่างนี้ในขณะใช้งานเว็บครับ")
    print("    (หากปิดหน้าต่างนี้ หน้าเว็บจะหยุดทำงาน)")
    print("--------------------------------------------------------\n")
    print(f"Universal Media Downloader Server running at: http://{host}:{port}")

    # เปิดบราวเซอร์อัตโนมัติเฉพาะเมื่อรันบนเครื่อง Windows และไม่ได้เปิดโหมด Headless
    if os.name == 'nt' and os.environ.get('HEADLESS') != '1':
        import webbrowser
        def open_browser():
            time.sleep(1.2)
            try:
                webbrowser.open(f"http://127.0.0.1:{port}")
            except Exception:
                pass
        threading.Thread(target=open_browser, daemon=True).start()

    app.run(host=host, port=port, debug=False)
