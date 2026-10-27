# -*- coding: utf-8 -*-
"""
Universal Media Downloader - Custom DNS Resolver (Google DNS 8.8.8.8 / 8.8.4.4 & DoH)
Bypasses local ISP DNS poisoning/blocks directly at application level without modifying OS settings.
"""
import socket
import struct
import random
import time
import re
import urllib.request
import ssl
import json
import threading

GOOGLE_DNS_SERVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
HARDCODED_HOSTS = {
    "dns.google": ["8.8.8.8", "8.8.4.4"],
    "cloudflare-dns.com": ["1.1.1.1", "1.0.0.1"],
    "localhost": ["127.0.0.1"],
}

_dns_cache = {}
_cache_lock = threading.Lock()
_orig_getaddrinfo = socket.getaddrinfo
_is_enabled = False
_doh_ssl_ctx = None


def get_doh_ssl_context():
    global _doh_ssl_ctx
    if _doh_ssl_ctx is None:
        # ตรวจสอบใบรับรองเสมอ (DNS ปลอมจาก MITM จะถูกปฏิเสธ)
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except Exception:
            pass
        _doh_ssl_ctx = ctx
    return _doh_ssl_ctx


def is_ip_address(host):
    if not host:
        return True
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(host)):
        return True
    if ':' in str(host):
        return True
    return False


def query_udp_dns(hostname, server="8.8.8.8", timeout=2.5):
    sock = None
    try:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except Exception:
            ascii_host = hostname

        txid = random.randint(1, 65535)
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in ascii_host.split(".")) + b"\x00"
        question = qname + struct.pack("!HH", 1, 1)  # Type A, Class IN
        packet = header + question

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, addr = sock.recvfrom(1024)
        # กัน DNS Spoofing: คำตอบต้องมาจากเซิร์ฟเวอร์ที่ถาม และ Transaction ID ต้องตรงกัน
        if addr[0] != server or len(data) < 12 or struct.unpack("!H", data[0:2])[0] != txid:
            return []

        pos = 12 + len(question)
        ancount = struct.unpack("!H", data[6:8])[0]
        ips = []
        for _ in range(ancount):
            if pos >= len(data):
                break
            if (data[pos] & 0xC0) == 0xC0:
                pos += 2
            else:
                while pos < len(data) and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            if pos + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos+10])
            pos += 10
            if rtype == 1 and rdlen == 4 and pos + 4 <= len(data):
                ips.append(socket.inet_ntoa(data[pos:pos+4]))
            pos += rdlen
        return ips
    except Exception:
        return []
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def query_doh_google(hostname, timeout=3.0):
    try:
        url = f"https://8.8.8.8/resolve?name={hostname}&type=A"
        req = urllib.request.Request(url, headers={
            "Host": "dns.google",
            "User-Agent": "UniversalMediaDownloader/GoogleDNS",
            "Accept": "application/dns-json"
        })
        ctx = get_doh_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            ips = []
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    data_ip = ans.get("data")
                    if data_ip and is_ip_address(data_ip):
                        ips.append(data_ip)
            return ips
    except Exception:
        return []


def query_doh_cloudflare(hostname, timeout=3.0):
    try:
        url = f"https://1.1.1.1/dns-query?name={hostname}&type=A"
        req = urllib.request.Request(url, headers={
            "Host": "cloudflare-dns.com",
            "User-Agent": "UniversalMediaDownloader/CloudflareDNS",
            "Accept": "application/dns-json"
        })
        ctx = get_doh_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            ips = []
            for ans in data.get("Answer", []):
                if ans.get("type") == 1:
                    data_ip = ans.get("data")
                    if data_ip and is_ip_address(data_ip):
                        ips.append(data_ip)
            return ips
    except Exception:
        return []


def resolve_with_google_dns(hostname):
    host_clean = str(hostname).strip().lower().rstrip('.')
    if is_ip_address(host_clean) or host_clean in ('localhost', '127.0.0.1'):
        return [host_clean]
    if host_clean in HARDCODED_HOSTS:
        return HARDCODED_HOSTS[host_clean]

    now = time.time()
    with _cache_lock:
        if host_clean in _dns_cache:
            ips, exp = _dns_cache[host_clean]
            if now < exp:
                return ips

    # 1. ลอง UDP 8.8.8.8 และ 8.8.4.4 ก่อน
    for srv in GOOGLE_DNS_SERVERS[:2]:
        ips = query_udp_dns(host_clean, server=srv, timeout=2.0)
        if ips:
            with _cache_lock:
                _dns_cache[host_clean] = (ips, now + 360)
            return ips

    # 2. ลอง Google DoH (DNS over HTTPS via 8.8.8.8) เพื่อทะลวงการบล็อกพอร์ต 53 ของ ISP
    ips = query_doh_google(host_clean, timeout=3.0)
    if ips:
        with _cache_lock:
            _dns_cache[host_clean] = (ips, now + 360)
        return ips

    # 3. ลอง Cloudflare DoH (DNS over HTTPS via 1.1.1.1)
    ips = query_doh_cloudflare(host_clean, timeout=3.0)
    if ips:
        with _cache_lock:
            _dns_cache[host_clean] = (ips, now + 360)
        return ips

    # 4. Fallback ไปที่ Cloudflare UDP
    for srv in GOOGLE_DNS_SERVERS[2:]:
        ips = query_udp_dns(host_clean, server=srv, timeout=2.0)
        if ips:
            with _cache_lock:
                _dns_cache[host_clean] = (ips, now + 360)
            return ips

    return []


def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if not _is_enabled or not host:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    if isinstance(host, (bytes, bytearray)):
        try:
            host_str = host.decode('utf-8', 'ignore')
        except Exception:
            return _orig_getaddrinfo(host, port, family, type, proto, flags)
    else:
        host_str = str(host)

    if is_ip_address(host_str) or host_str.lower() == 'localhost':
        return _orig_getaddrinfo(host, port, family, type, proto, flags)

    try:
        resolved_ips = resolve_with_google_dns(host_str)
        if resolved_ips:
            for ip in resolved_ips:
                try:
                    return _orig_getaddrinfo(ip, port, family, type, proto, flags)
                except Exception:
                    continue
    except Exception:
        pass

    return _orig_getaddrinfo(host, port, family, type, proto, flags)


def enable_google_dns():
    global _is_enabled
    if not _is_enabled:
        socket.getaddrinfo = custom_getaddrinfo
        _is_enabled = True


def disable_google_dns():
    global _is_enabled
    if _is_enabled:
        socket.getaddrinfo = _orig_getaddrinfo
        _is_enabled = False


def is_google_dns_enabled():
    return _is_enabled
