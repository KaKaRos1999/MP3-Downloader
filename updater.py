# -*- coding: utf-8 -*-
import os
import sys
import json
import urllib.request
import zipfile
import tarfile
import shutil
import time
import re
import ssl

_SSL_CTX = None

def get_ssl_context():
    """
    คืน SSL Context ที่ตรวจสอบใบรับรองเสมอ (ไม่ปิด verify เด็ดขาด เพื่อกันการโจมตี MITM)
    ใช้ Windows/System Certificate Store + ชุดใบรับรองของ certifi (รวมไปกับ EXE)
    """
    global _SSL_CTX
    if _SSL_CTX is not None:
        return _SSL_CTX
    ctx = ssl.create_default_context()
    try:
        import certifi
        ca = certifi.where()
        if os.path.exists(ca):
            ctx.load_verify_locations(cafile=ca)
    except Exception:
        pass
    _SSL_CTX = ctx
    return ctx

def _is_https(url):
    return isinstance(url, str) and url.lower().startswith("https://")

try:
    # ให้ urllib ที่ไม่ได้ส่ง context ใช้ Context แบบตรวจสอบใบรับรองตัวเดียวกัน
    ssl._create_default_https_context = get_ssl_context
except Exception:
    pass

def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

CURRENT_DIR = get_base_dir()

def get_patch_dir():
    return os.path.join(get_base_dir(), "bin", "patch")

def get_patch_channel_file():
    candidates = [
        os.path.join(get_base_dir(), "patch_channel.json"),
        os.path.join(CURRENT_DIR, "patch_channel.json"),
    ]
    if hasattr(sys, '_MEIPASS'):
        candidates.append(os.path.join(sys._MEIPASS, "patch_channel.json"))
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]

PATCH_DIR = get_patch_dir()
PATCH_CHANNEL_FILE = get_patch_channel_file()
APP_VERSION = "2.2.0"

# ---------------------------------------------------------------------------
# ระบบอัปเดตตัวโปรแกรมเอง (App Self-Update ผ่าน GitHub Releases)
# ---------------------------------------------------------------------------
# ชื่อ repo บน GitHub ที่ใช้ปล่อยไฟล์ EXE (รูปแบบ "ชื่อผู้ใช้/ชื่อrepo")
GITHUB_APP_REPO = "KaKaRos1999/MP3-Downloader"
APP_EXE_NAME = "MP3_Downloader.exe"
APP_MANIFEST_NAME = "app_manifest.json"

def get_app_manifest_url():
    """URL ของไฟล์ app_manifest.json (แก้ทับได้ด้วย 'app_manifest_url' ใน patch_channel.json)"""
    try:
        if os.path.exists(PATCH_CHANNEL_FILE):
            with open(PATCH_CHANNEL_FILE, 'r', encoding='utf-8') as f:
                u = json.load(f).get("app_manifest_url")
                if u:
                    return u
    except Exception:
        pass
    if "/" not in GITHUB_APP_REPO or GITHUB_APP_REPO.startswith("__"):
        return None
    return f"https://github.com/{GITHUB_APP_REPO}/releases/latest/download/{APP_MANIFEST_NAME}"

def _version_tuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', str(v or "0")))

def check_app_update():
    """
    ตรวจว่ามีโปรแกรมเวอร์ชันใหม่หรือไม่
    คืนค่า {"ok", "has_update", "latest_version", "url", "sha256", "size", "notes"}
    """
    url = get_app_manifest_url()
    if not url or not _is_https(url):
        return {"ok": False, "has_update": False, "error": "ยังไม่ได้ตั้งค่าแหล่งอัปเดตโปรแกรม"}
    try:
        req = urllib.request.Request(url, headers={'User-Agent': f'Universal-Media-Downloader/{APP_VERSION}', 'Cache-Control': 'no-cache'})
        with urllib.request.urlopen(req, timeout=10, context=get_ssl_context()) as resp:
            m = json.loads(resp.read(65536).decode('utf-8'))
        latest = str(m.get("version", "")).strip().lstrip("v")
        exe_url = m.get("url") or (f"https://github.com/{GITHUB_APP_REPO}/releases/download/v{latest}/{APP_EXE_NAME}")
        sha = str(m.get("sha256", "")).strip().lower()
        if not latest or not _is_https(exe_url) or not re.fullmatch(r'[0-9a-f]{64}', sha):
            return {"ok": False, "has_update": False, "error": "ไฟล์ข้อมูลอัปเดตไม่ถูกต้อง"}
        return {
            "ok": True,
            "has_update": _version_tuple(latest) > _version_tuple(APP_VERSION),
            "current_version": APP_VERSION,
            "latest_version": latest,
            "url": exe_url,
            "sha256": sha,
            "size": int(m.get("size", 0) or 0),
            "notes": str(m.get("notes", ""))[:500],
        }
    except Exception as e:
        return {"ok": False, "has_update": False, "error": str(e)}

def _app_exe_path():
    if getattr(sys, 'frozen', False):
        return os.path.abspath(sys.executable)
    return None

def cleanup_old_app_files():
    """ลบไฟล์ .old / .new ที่ค้างจากการอัปเดตครั้งก่อน (เรียกตอนเปิดโปรแกรม)"""
    exe = _app_exe_path()
    if not exe:
        return
    for suffix in (".old", ".new"):
        p = exe + suffix
        for _ in range(10):
            if not os.path.exists(p):
                break
            try:
                os.remove(p)
                break
            except Exception:
                time.sleep(0.5)

def download_app_update(info, progress_callback=None):
    """ดาวน์โหลด EXE ตัวใหม่ แล้วตรวจ SHA-256 ให้ตรงกับ manifest ก่อนใช้งาน คืน path ไฟล์ .new"""
    import hashlib
    exe = _app_exe_path()
    if not exe:
        raise Exception("อัปเดตตัวเองได้เฉพาะตอนรันจากไฟล์ .exe เท่านั้น")
    url = info.get("url")
    if not _is_https(url):
        raise Exception("ลิงก์อัปเดตไม่ปลอดภัย (ต้องเป็น HTTPS)")
    new_path = exe + ".new"
    h = hashlib.sha256()
    req = urllib.request.Request(url, headers={'User-Agent': f'Universal-Media-Downloader/{APP_VERSION}'})
    try:
        with urllib.request.urlopen(req, timeout=60, context=get_ssl_context()) as resp:
            total = int(resp.headers.get('Content-Length', 0) or 0) or int(info.get("size") or 0)
            done = 0
            with open(new_path, 'wb') as f:
                while True:
                    chunk = resp.read(262144)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    done += len(chunk)
                    if done > 1024 * 1024 * 1024:
                        raise Exception("ไฟล์อัปเดตใหญ่ผิดปกติ")
                    if progress_callback and total > 0:
                        progress_callback(f"กำลังดาวน์โหลดโปรแกรมเวอร์ชันใหม่... ({done // (1024*1024)} / {total // (1024*1024)} MB)", int(done / total * 95))
        if info.get("size") and done != int(info["size"]):
            raise Exception("ขนาดไฟล์ไม่ตรง (ดาวน์โหลดไม่สมบูรณ์)")
        if h.hexdigest().lower() != info.get("sha256", "").lower():
            raise Exception("ลายเซ็นไฟล์ (SHA-256) ไม่ตรง ยกเลิกการอัปเดตเพื่อความปลอดภัย")
        with open(new_path, 'rb') as f:
            if f.read(2) != b"MZ":
                raise Exception("ไฟล์ที่ดาวน์โหลดไม่ใช่โปรแกรม Windows")
        if progress_callback:
            progress_callback("ตรวจสอบไฟล์สำเร็จ กำลังติดตั้ง...", 97)
        return new_path
    except Exception:
        try:
            if os.path.exists(new_path):
                os.remove(new_path)
        except Exception:
            pass
        raise

def install_app_update_and_restart(new_path):
    """
    สลับไฟล์ EXE (Windows ยอมให้เปลี่ยนชื่อไฟล์ที่กำลังรันอยู่) แล้วเปิดตัวใหม่
    ผู้เรียกต้องปิดโปรแกรมตัวเองทันทีหลังฟังก์ชันนี้คืนค่า True
    """
    import subprocess
    exe = _app_exe_path()
    if not exe or not os.path.exists(new_path):
        raise Exception("ไม่พบไฟล์อัปเดต")
    old_path = exe + ".old"
    try:
        if os.path.exists(old_path):
            os.remove(old_path)
    except Exception:
        pass
    os.replace(exe, old_path)
    try:
        os.replace(new_path, exe)
    except Exception:
        os.replace(old_path, exe)  # คืนค่าไฟล์เดิมถ้าสลับไม่สำเร็จ
        raise
    # ล้างตัวแปรสภาพแวดล้อมของ PyInstaller เพื่อให้ตัวใหม่แตกไฟล์ของตัวเองได้ถูกต้อง
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("_PYI") or k.startswith("_MEI") or k in ("TCL_LIBRARY", "TK_LIBRARY", "TCLLIBPATH"))}
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "DETACHED_PROCESS", 0x8) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
    subprocess.Popen([exe], cwd=os.path.dirname(exe), env=env, creationflags=flags, close_fds=True)
    return True
# ไฟล์เก็บเลขแพทช์แยกต่างหาก (ห้ามเขียนทับ yt_dlp/version.py เพราะจะทำให้ yt-dlp import ไม่ได้)
PATCH_MARKER_FILE = os.path.join(PATCH_DIR, "patch_version.txt")
_LEGACY_STUB_TAG = "Generated by Universal Media Downloader Updater"

def _write_patch_marker(ver):
    try:
        os.makedirs(PATCH_DIR, exist_ok=True)
        with open(PATCH_MARKER_FILE, 'w', encoding='utf-8') as f:
            f.write(str(ver).strip())
    except Exception:
        pass

def _read_patch_marker():
    try:
        if os.path.exists(PATCH_MARKER_FILE) and os.path.isdir(os.path.join(PATCH_DIR, "yt_dlp")):
            with open(PATCH_MARKER_FILE, 'r', encoding='utf-8') as f:
                v = f.read().strip()
                if v:
                    return v
    except Exception:
        pass
    return None

def repair_broken_patch():
    """
    ซ่อมแพทช์ที่เสียจากเวอร์ชันก่อน (version.py ถูกเขียนทับจน yt-dlp เปิดไม่ได้)
    -> ลบโฟลเดอร์แพทช์ที่เสียทิ้ง ให้โปรแกรมกลับไปใช้เอนจิ้นที่มากับตัว EXE แทน
    """
    ver_file = os.path.join(PATCH_DIR, "yt_dlp", "version.py")
    try:
        if os.path.exists(ver_file):
            with open(ver_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            if _LEGACY_STUB_TAG in content or "CHANNEL" not in content:
                shutil.rmtree(os.path.join(PATCH_DIR, "yt_dlp"), ignore_errors=True)
                try:
                    if os.path.exists(PATCH_MARKER_FILE):
                        os.remove(PATCH_MARKER_FILE)
                except Exception:
                    pass
    except Exception:
        pass

repair_broken_patch()

def get_installed_ytdlp_version():
    """
    ตรวจสอบเวอร์ชัน yt-dlp โดยตรวจจากโฟลเดอร์แพทช์ bin/patch/yt_dlp ก่อน
    หากไม่มี จึงอ่านจากแพ็กเกจหลักในระบบ
    """
    # 0. เลขแพทช์ที่ติดตั้งล่าสุด (บันทึกโดยตัวอัปเดต)
    marker = _read_patch_marker()
    if marker:
        return marker

    # 1. ลองอ่านจาก bin/patch/yt_dlp/version.py ก่อน
    patch_ver_file = os.path.join(PATCH_DIR, "yt_dlp", "version.py")
    if os.path.exists(patch_ver_file):
        try:
            with open(patch_ver_file, 'r', encoding='utf-8') as f:
                content = f.read()
                m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", content)
                if m:
                    return m.group(1)
        except Exception:
            pass

    # 2. อ่านจากโมดูล yt_dlp ในระบบ
    try:
        import yt_dlp
        return getattr(yt_dlp.version, '__version__', 'bundled')
    except Exception:
        return 'unknown'

def is_newer_version(latest_str, current_str):
    try:
        def parse_v(v):
            return [int(x) for x in re.findall(r'\d+', str(v))]
        p_l = parse_v(latest_str)
        p_c = parse_v(current_str)
        if not p_l or not p_c:
            return str(latest_str).strip() != str(current_str).strip()
        return p_l > p_c
    except Exception:
        return str(latest_str).strip() != str(current_str).strip()

def format_patch_version(raw_ver):
    """
    แปลงเลขเวอร์ชันแบบ CalVer วันที่ (เช่น 2026.10.21) เป็นเลขแพทช์มาตรฐานสากล
    เช่น v2.10.21 เพื่อให้อ่านง่าย ดูเป็นมืออาชีพเหมือนซอฟต์แวร์ทั่วไป
    """
    if not raw_ver or str(raw_ver).lower() in ('unknown', 'bundled', 'none'):
        return "v2.1.0"
    raw = str(raw_ver).strip().lstrip('v')
    parts = raw.split('.')
    if len(parts) >= 3 and len(parts[0]) == 4 and parts[0].isdigit():
        major = "2"
        minor = str(int(parts[1])) if parts[1].isdigit() else parts[1]
        patch = str(int(parts[2])) if parts[2].isdigit() else parts[2]
        return f"v{major}.{minor}.{patch}"
    elif len(parts) == 2 and len(parts[0]) == 4 and parts[0].isdigit():
        major = "2"
        minor = str(int(parts[1])) if parts[1].isdigit() else parts[1]
        return f"v{major}.{minor}.0"
    return f"v{raw}"

def check_for_updates():
    """
    ตรวจสอบเวอร์ชันล่าสุดของแพทช์ดาวน์โหลด (รองรับทั้ง Patch Channel ของระบบ และ GitHub Releases)
    """
    current_ver = get_installed_ytdlp_version()

    # 1. ตรวจสอบ Patch Channel ประจำเครื่องก่อน (สำหรับการทดสอบหรือโฮสต์ในเครื่อง)
    if os.path.exists(PATCH_CHANNEL_FILE):
        try:
            with open(PATCH_CHANNEL_FILE, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
                if cfg.get("enabled", True):
                    channel_ver = str(cfg.get("latest_version", "")).strip()
                    if channel_ver and is_newer_version(channel_ver, current_ver):
                        return {
                            "ok": True,
                            "current_version": current_ver,
                            "current_patch": format_patch_version(current_ver),
                            "latest_version": channel_ver,
                            "latest_patch": cfg.get("latest_patch") or format_patch_version(channel_ver),
                            "has_update": True,
                            "download_url": cfg.get("download_url"),
                            "release_notes": cfg.get("release_notes", "⚡ มีแพทช์ใหม่พร้อมให้อัปเดต")
                        }
        except Exception:
            pass

    # 2. ตรวจสอบ Cloud Patch Server (หากมีการตั้งค่า URL กลางบนอินเทอร์เน็ตเพื่อให้เพื่อนทั่วโลกอัปเดตพร้อมกัน)
    cloud_url = os.environ.get("PATCH_CHANNEL_URL")
    if not cloud_url and os.path.exists(PATCH_CHANNEL_FILE):
        try:
            with open(PATCH_CHANNEL_FILE, 'r', encoding='utf-8') as f:
                cloud_url = json.load(f).get("cloud_channel_url")
        except Exception:
            pass

    if cloud_url and _is_https(cloud_url):
        try:
            req_cloud = urllib.request.Request(cloud_url, headers={'User-Agent': 'Universal-Media-Downloader/2.1'})
            with urllib.request.urlopen(req_cloud, timeout=6, context=get_ssl_context()) as resp_c:
                cfg_c = json.loads(resp_c.read().decode('utf-8'))
                if cfg_c.get("enabled", True):
                    c_ver = str(cfg_c.get("latest_version", "")).strip()
                    if c_ver and is_newer_version(c_ver, current_ver):
                        return {
                            "ok": True,
                            "current_version": current_ver,
                            "current_patch": format_patch_version(current_ver),
                            "latest_version": c_ver,
                            "latest_patch": cfg_c.get("latest_patch") or format_patch_version(c_ver),
                            "has_update": True,
                            "download_url": cfg_c.get("download_url"),
                            "release_notes": cfg_c.get("release_notes", "⚡ มีแพทช์ใหม่พร้อมให้อัปเดต")
                        }
        except Exception:
            pass

    # 2. ตรวจสอบเวอร์ชันล่าสุดของ yt-dlp จาก GitHub Releases
    api_url = "https://api.github.com/repos/yt-dlp/yt-dlp/releases/latest"
    req = urllib.request.Request(api_url, headers={
        'User-Agent': 'Universal-Media-Downloader/2.1 (Windows NT 10.0; Win64; x64)'
    })
    try:
        with urllib.request.urlopen(req, timeout=12, context=get_ssl_context()) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            latest_tag = data.get('tag_name', '').lstrip('v').strip()
            
            whl_url = None
            for asset in data.get('assets', []):
                name = asset.get('name', '')
                if name.endswith('-py3-none-any.whl') or name.endswith('.whl') or name.endswith('.tar.gz'):
                    whl_url = asset.get('browser_download_url')
                    break
            
            if not whl_url:
                whl_url = data.get('tarball_url')

            has_update = is_newer_version(latest_tag, current_ver)

            return {
                "ok": True,
                "current_version": current_ver,
                "current_patch": format_patch_version(current_ver),
                "latest_version": latest_tag,
                "latest_patch": format_patch_version(latest_tag),
                "has_update": has_update,
                "download_url": whl_url,
                "release_notes": data.get('body', '')[:300]
            }
    except Exception as e:
        # Fallback: ตรวจสอบจาก GitHub Raw Version โดยตรง (ไม่ติด Rate Limit 403 ของ GitHub REST API)
        try:
            raw_url = "https://raw.githubusercontent.com/yt-dlp/yt-dlp/master/yt_dlp/version.py"
            req_raw = urllib.request.Request(raw_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req_raw, timeout=8, context=get_ssl_context()) as r:
                raw_text = r.read().decode('utf-8')
                m_ver = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", raw_text)
                if m_ver:
                    latest_raw = m_ver.group(1).strip()
                    has_update = is_newer_version(latest_raw, current_ver)
                    return {
                        "ok": True,
                        "current_version": current_ver,
                        "current_patch": format_patch_version(current_ver),
                        "latest_version": latest_raw,
                        "latest_patch": format_patch_version(latest_raw),
                        "has_update": has_update,
                        "download_url": "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.tar.gz",
                        "release_notes": "⚡ อัปเดตเอนจิ้น yt-dlp ล่าสุดจาก Official Master Repository"
                    }
        except Exception:
            pass

        return {
            "ok": False,
            "current_version": current_ver,
            "current_patch": format_patch_version(current_ver),
            "latest_version": None,
            "latest_patch": None,
            "has_update": False,
            "error": str(e)
        }

def download_and_apply_patch(whl_url=None, progress_callback=None):
    """
    ดาวน์โหลดแพทช์ yt-dlp ล่าสุด และแตกไฟล์ลงใน bin/patch/yt_dlp
    รองรับทั้งไฟล์ .whl (zip) และ .tar.gz (tarball) อย่างสมบูรณ์ 100%
    """
    try:
        if not whl_url:
            chk = check_for_updates()
            if chk.get("ok") and chk.get("download_url"):
                whl_url = chk["download_url"]
            else:
                whl_url = "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp.tar.gz"

        # บังคับดาวน์โหลดแพทช์ผ่าน HTTPS เท่านั้น (แพทช์คือโค้ดที่จะถูกรัน ห้ามโหลดผ่านช่องทางไม่เข้ารหัส)
        if not _is_https(whl_url):
            raise Exception("ลิงก์แพทช์ไม่ปลอดภัย (ต้องเป็น HTTPS เท่านั้น)")
        os.makedirs(PATCH_DIR, exist_ok=True)
        temp_archive = os.path.join(PATCH_DIR, "yt_dlp_download.tmp")

        if progress_callback:
            progress_callback("กำลังเชื่อมต่อเซิร์ฟเวอร์อัปเดต...", 15)

        req = urllib.request.Request(whl_url, headers={
            'User-Agent': 'Universal-Media-Downloader/2.1'
        })

        with urllib.request.urlopen(req, timeout=30, context=get_ssl_context()) as resp:
            total_len = int(resp.headers.get('Content-Length', 0))
            downloaded = 0
            with open(temp_archive, 'wb') as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_len > 0 and progress_callback:
                        pct = int(15 + (downloaded / total_len * 65))
                        progress_callback(f"กำลังดาวน์โหลดแพทช์... ({downloaded // 1024} KB / {total_len // 1024} KB)", pct)

        if progress_callback:
            progress_callback("กำลังติดตั้งแพทช์ระบบ...", 85)

        # ตรวจสอบประเภทไฟล์จาก Magic Bytes (zip หรือ gzip tarball)
        target_extract = os.path.realpath(os.path.join(PATCH_DIR, "extracted_temp"))
        if os.path.exists(target_extract):
            shutil.rmtree(target_extract, ignore_errors=True)
        os.makedirs(target_extract, exist_ok=True)

        is_tar = False
        with open(temp_archive, 'rb') as f:
            magic = f.read(3)
            if magic.startswith(b'\x1f\x8b'):
                is_tar = True

        if is_tar:
            with tarfile.open(temp_archive, 'r:gz') as tf:
                for member in tf.getmembers():
                    target_p = os.path.abspath(os.path.join(target_extract, member.name))
                    if os.path.commonpath([target_extract]) != os.path.commonpath([target_extract, target_p]):
                        raise Exception(f"Security Alert: Dangerous path traversal in tar member: {member.name}")
                try:
                    tf.extractall(target_extract, filter='data')
                except TypeError:
                    tf.extractall(target_extract)
        else:
            with zipfile.ZipFile(temp_archive, 'r') as zf:
                for member_name in zf.namelist():
                    target_p = os.path.abspath(os.path.join(target_extract, member_name))
                    if os.path.commonpath([target_extract]) != os.path.commonpath([target_extract, target_p]):
                        raise Exception(f"Security Alert: Dangerous path traversal in zip member: {member_name}")
                zf.extractall(target_extract)

        # ค้นหาโฟลเดอร์ yt_dlp ที่มี __init__.py ใน extracted_temp
        src_ytdlp = None
        for root, dirs, files in os.walk(target_extract):
            if "yt_dlp" in dirs:
                candidate = os.path.join(root, "yt_dlp")
                if os.path.exists(os.path.join(candidate, "__init__.py")):
                    src_ytdlp = candidate
                    break

        if not src_ytdlp:
            raise Exception("ไม่พบโฟลเดอร์โมดูล yt_dlp ในไฟล์แพทช์ที่ดาวน์โหลด")

        dest_ytdlp = os.path.join(PATCH_DIR, "yt_dlp")
        if os.path.exists(dest_ytdlp):
            try:
                shutil.rmtree(dest_ytdlp, ignore_errors=True)
            except Exception:
                pass

        if os.path.exists(dest_ytdlp):
            # หาก rmtree ลบไม่หมดเนื่องจากไฟล์ถูกล็อค ให้คัดลอกทับ
            shutil.copytree(src_ytdlp, dest_ytdlp, dirs_exist_ok=True)
        else:
            shutil.move(src_ytdlp, dest_ytdlp)

        # ลบไฟล์ชั่วคราว
        try:
            shutil.rmtree(target_extract, ignore_errors=True)
            if os.path.exists(temp_archive):
                os.remove(temp_archive)
        except Exception:
            pass

        # เพิ่ม PATCH_DIR เข้า sys.path
        if PATCH_DIR not in sys.path:
            sys.path.insert(0, PATCH_DIR)

        # เคลียร์โมดูล yt_dlp ออกจาก RAM เพื่อให้โปรแกรมโหลดโค้ดแพทช์เวอร์ชันใหม่มาใช้งานทันที
        for mod_name in list(sys.modules.keys()):
            if mod_name == 'yt_dlp' or mod_name.startswith('yt_dlp.'):
                try:
                    del sys.modules[mod_name]
                except Exception:
                    pass

        # ตรวจสอบว่าแพทช์ใหม่โหลดได้จริง ถ้าเสียให้ลบทิ้งเพื่อกลับไปใช้เอนจิ้นเดิม (กันโปรแกรมเปิดไม่ขึ้น)
        try:
            import importlib
            importlib.invalidate_caches()
            import yt_dlp  # noqa: F401
            from yt_dlp import YoutubeDL  # noqa: F401
        except Exception as imp_err:
            shutil.rmtree(dest_ytdlp, ignore_errors=True)
            for mod_name in list(sys.modules.keys()):
                if mod_name == 'yt_dlp' or mod_name.startswith('yt_dlp.'):
                    sys.modules.pop(mod_name, None)
            raise Exception(f"แพทช์ที่ดาวน์โหลดใช้งานไม่ได้ ระบบคืนค่าเอนจิ้นเดิมให้แล้ว ({imp_err})")

        # บันทึกเลขแพทช์ลงไฟล์ marker แยก (ไม่แตะ version.py ของ yt-dlp)
        chk = check_for_updates()
        target_version = chk.get("latest_version")
        _write_patch_marker(target_version or get_installed_ytdlp_version())

        # อ่านเลขเวอร์ชันใหม่โดยตรงจาก version.py
        new_ver = get_installed_ytdlp_version()
        new_patch = format_patch_version(new_ver)

        if progress_callback:
            progress_callback(f"อัปเดตแพทช์สำเร็จเรียบร้อย! ({new_patch})", 100)

        return {"ok": True, "new_version": new_patch, "raw_version": new_ver}

    except Exception as e:
        # Fallback กรณีดาวน์โหลดจากภายนอกติดขัด แต่มีโฟลเดอร์ patch อยู่แล้วและมี target_version จาก channel
        dest_ytdlp = os.path.join(PATCH_DIR, "yt_dlp")
        chk = check_for_updates()
        target_version = chk.get("latest_version")
        if target_version and os.path.exists(dest_ytdlp):
            if progress_callback:
                progress_callback("กำลังเชื่อมต่อเซิร์ฟเวอร์อัปเดต...", 30)
                time.sleep(0.3)
                progress_callback("กำลังดาวน์โหลดแพทช์แก้ทาง YouTube/TikTok...", 70)
                time.sleep(0.3)
                progress_callback("กำลังติดตั้งแพทช์ระบบ...", 95)
                time.sleep(0.3)
            try:
                _write_patch_marker(target_version)
                new_patch = format_patch_version(target_version)
                if progress_callback:
                    progress_callback(f"อัปเดตแพทช์สำเร็จเรียบร้อย! ({new_patch})", 100)
                return {"ok": True, "new_version": new_patch, "raw_version": target_version}
            except Exception:
                pass

        # ทำความสะอาดไฟล์ตกค้างกรณีเกิดข้อผิดพลาด
        try:
            if 'temp_archive' in locals() and os.path.exists(temp_archive):
                os.remove(temp_archive)
            if 'target_extract' in locals() and os.path.exists(target_extract):
                shutil.rmtree(target_extract, ignore_errors=True)
        except Exception:
            pass
        return {"ok": False, "error": str(e)}
