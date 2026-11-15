#!/usr/bin/env python3
"""RU entry tunnel from Igareck BLACK (updated daily by author).
Each hourly cycle: fetch fresh BLACK → pick working entry → Xray SOCKS local.
"""
from __future__ import annotations

import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

ENTRY_URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
]

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 11080
XRAY_BIN = os.environ.get("XRAY_BIN", "xray")
UA = "AVK-VPN-ru-entry/1.0"
LINK_RE = re.compile(r"(?:vless|ss)://[^\s<>\"']+", re.I)

_proc: subprocess.Popen | None = None
_cfg_path: str | None = None


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", errors="ignore")


def _tcp_ok(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return False
    for family, typ, proto, _, sa in infos[:2]:
        s = None
        try:
            s = socket.socket(family, typ, proto)
            s.settimeout(timeout)
            s.connect(sa)
            return True
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    return False


def parse_vless(link: str) -> dict | None:
    try:
        u = urllib.parse.urlparse(link)
        if u.scheme.lower() != "vless":
            return None
        uuid = u.username
        host = u.hostname
        port = u.port or 443
        if not uuid or not host:
            return None
        q = urllib.parse.parse_qs(u.query)
        g = lambda k, d="": (q.get(k) or [d])[0]
        security = g("security", "none")
        network = g("type", "tcp")
        stream: dict = {"network": network, "security": security}
        if security in ("tls", "reality"):
            tls: dict = {
                "serverName": g("sni") or host,
                "fingerprint": g("fp") or "chrome",
            }
            if security == "reality":
                tls["realitySettings"] = {
                    "publicKey": g("pbk"),
                    "shortId": g("sid", ""),
                    "spiderX": g("spx", ""),
                }
                if g("pqv"):
                    tls["realitySettings"]["password"] = g("pqv")
            else:
                tls["allowInsecure"] = g("allowInsecure", "0") in ("1", "true", "True")
            stream["tlsSettings" if security == "tls" else "realitySettings"] = (
                tls if security == "tls" else tls.get("realitySettings", {})
            )
            # fix structure for xray
            if security == "tls":
                stream["tlsSettings"] = {
                    "serverName": g("sni") or host,
                    "fingerprint": g("fp") or "chrome",
                    "allowInsecure": g("allowInsecure", "0") in ("1", "true", "True"),
                }
            elif security == "reality":
                stream["realitySettings"] = {
                    "serverName": g("sni") or host,
                    "fingerprint": g("fp") or "chrome",
                    "publicKey": g("pbk"),
                    "shortId": g("sid", ""),
                    "spiderX": g("spx", "") or "",
                }
        if network == "ws":
            stream["wsSettings"] = {
                "path": g("path", "/"),
                "headers": {"Host": g("host") or host},
            }
        elif network == "grpc":
            stream["grpcSettings"] = {"serviceName": g("serviceName", "")}
        elif network == "xhttp" or network == "splithttp":
            stream["network"] = "xhttp"
            stream["xhttpSettings"] = {
                "path": g("path", "/"),
                "host": g("host") or host,
                "mode": g("mode", "auto"),
            }
        user: dict = {"id": uuid, "encryption": g("encryption", "none")}
        if g("flow"):
            user["flow"] = g("flow")
        return {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(port),
                    "users": [user],
                }]
            },
            "streamSettings": stream,
        }, host, int(port)
    except Exception:
        return None


def parse_ss(link: str) -> tuple[dict, str, int] | None:
    try:
        u = urllib.parse.urlparse(link)
        if u.scheme.lower() != "ss":
            return None
        # ss://base64@host:port or ss://method:pass@host:port
        rest = link.split("://", 1)[1].split("#", 1)[0]
        if "@" not in rest:
            return None
        userinfo, hostpart = rest.rsplit("@", 1)
        hostpart = hostpart.split("/")[0].split("?")[0]
        if hostpart.startswith("["):
            m = re.match(r"\[([^\]]+)\]:(\d+)$", hostpart)
            if not m:
                return None
            host, port = m.group(1), int(m.group(2))
        else:
            host, port_s = hostpart.rsplit(":", 1)
            host, port = host.strip(), int(port_s)
        if ":" not in userinfo and not userinfo.startswith("ey"):
            # maybe base64
            try:
                pad = "=" * (-len(userinfo) % 4)
                userinfo = base64.urlsafe_b64decode(userinfo + pad).decode()
            except Exception:
                pass
        method, password = userinfo.split(":", 1)
        outbound = {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }]
            },
        }
        return outbound, host, port
    except Exception:
        return None


def link_to_outbound(link: str) -> tuple[dict, str, int] | None:
    link = link.strip()
    if link.lower().startswith("vless://"):
        r = parse_vless(link)
        if not r:
            return None
        # parse_vless returns (outbound, host, port) or broken - fix
        if isinstance(r, tuple) and len(r) == 3:
            return r
        return None
    if link.lower().startswith("ss://"):
        return parse_ss(link)
    return None


# Fix parse_vless return - I mixed return types. Rewrite cleanly below in build_config.


def build_xray_config(outbound: dict) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in",
            "port": SOCKS_PORT,
            "listen": SOCKS_HOST,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
        }],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}],
        },
    }


def collect_entry_links() -> list[str]:
    out, seen = [], set()
    for url in ENTRY_URLS:
        try:
            text = _fetch(url)
            print(f"[entry] fetched {url.split('/')[-1]} bytes={len(text)}", flush=True)
        except Exception as e:
            print(f"[entry] FAIL {url}: {e}", flush=True)
            continue
        for m in LINK_RE.findall(text):
            lk = m.strip().rstrip("),.;\"'")
            if lk not in seen:
                seen.add(lk)
                out.append(lk)
    print(f"[entry] unique_links={len(out)}", flush=True)
    return out


def stop_entry() -> None:
    global _proc, _cfg_path
    if _proc is not None:
        try:
            _proc.terminate()
            _proc.wait(timeout=3)
        except Exception:
            try:
                _proc.kill()
            except Exception:
                pass
        _proc = None
    if _cfg_path and os.path.isfile(_cfg_path):
        try:
            os.unlink(_cfg_path)
        except Exception:
            pass
        _cfg_path = None


def _http_via_socks(url: str, timeout: float = 8.0) -> int | None:
    """Return HTTP status via SOCKS5, or None."""
    try:
        import socks  # PySocks
    except ImportError:
        return None
    try:
        # use urllib with socks - via socket monkey or requests
        import urllib.request as ur
        # PySocks: create opener is hard; use raw
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname
        port = p.port or (443 if p.scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, SOCKS_HOST, SOCKS_PORT)
        s.settimeout(timeout)
        s.connect((host, port))
        if p.scheme == "https":
            import ssl
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=host)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
        s.close()
        line = data.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
        # HTTP/1.1 204 No Content
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return int(parts[1])
        return None
    except Exception:
        return None


def health_ok() -> bool:
    # Google generate_204 via entry
    code = _http_via_socks("https://www.gstatic.com/generate_204", timeout=10)
    if code == 204:
        return True
    code2 = _http_via_socks("http://connectivitycheck.gstatic.com/generate_204", timeout=8)
    return code2 == 204


def start_xray(outbound: dict) -> bool:
    global _proc, _cfg_path
    stop_entry()
    cfg = build_xray_config(outbound)
    fd, path = tempfile.mkstemp(prefix="xray-entry-", suffix=".json")
    os.close(fd)
    Path(path).write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    _cfg_path = path
    try:
        _proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"[entry] xray start fail: {e}", flush=True)
        stop_entry()
        return False
    time.sleep(0.8)
    if _proc.poll() is not None:
        print("[entry] xray exited early", flush=True)
        stop_entry()
        return False
    return True


def parse_link_outbound(link: str) -> tuple[dict, str, int] | None:
    link = link.strip()
    low = link.lower()
    if low.startswith("vless://"):
        try:
            u = urllib.parse.urlparse(link)
            uuid = u.username
            host = u.hostname
            port = u.port or 443
            if not uuid or not host:
                return None
            q = urllib.parse.parse_qs(u.query)
            g = lambda k, d="": (q.get(k) or [d])[0]
            security = g("security", "none")
            network = g("type", "tcp") or "tcp"
            stream: dict = {"network": network, "security": security or "none"}
            if security == "tls":
                stream["tlsSettings"] = {
                    "serverName": g("sni") or g("host") or host,
                    "fingerprint": g("fp") or "chrome",
                    "allowInsecure": g("allowInsecure", "0") in ("1", "true"),
                }
            elif security == "reality":
                stream["realitySettings"] = {
                    "serverName": g("sni") or host,
                    "fingerprint": g("fp") or "chrome",
                    "publicKey": g("pbk"),
                    "shortId": g("sid", ""),
                    "spiderX": g("spx", "") or "",
                }
            if network == "ws":
                stream["wsSettings"] = {
                    "path": urllib.parse.unquote(g("path", "/")),
                    "headers": {"Host": g("host") or host},
                }
            elif network in ("xhttp", "splithttp"):
                stream["network"] = "xhttp"
                stream["xhttpSettings"] = {
                    "path": urllib.parse.unquote(g("path", "/")),
                    "host": g("host") or host,
                    "mode": g("mode", "auto"),
                }
            elif network == "grpc":
                stream["grpcSettings"] = {"serviceName": g("serviceName", "")}
            user = {"id": uuid, "encryption": g("encryption", "none")}
            if g("flow"):
                user["flow"] = g("flow")
            ob = {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{"address": host, "port": int(port), "users": [user]}]
                },
                "streamSettings": stream,
            }
            return ob, host, int(port)
        except Exception:
            return None
    if low.startswith("ss://"):
        return parse_ss(link)
    return None


def acquire_entry(max_try: int = 25) -> bool:
    """Fetch daily BLACK, try entries until health_ok. Returns True if SOCKS ready."""
    links = collect_entry_links()
    # prefer TCP-reachable first
    scored: list[tuple[str, str, int, dict]] = []
    for lk in links:
        parsed = parse_link_outbound(lk)
        if not parsed:
            continue
        ob, host, port = parsed
        scored.append((lk, host, port, ob))
    print(f"[entry] parsed_ok={len(scored)}", flush=True)
    # try TCP-open hosts first
    open_first, rest = [], []
    for item in scored:
        if _tcp_ok(item[1], item[2], 1.5):
            open_first.append(item)
        else:
            rest.append(item)
    order = open_first + rest
    print(f"[entry] tcp_open={len(open_first)} try_max={max_try}", flush=True)
    for i, (lk, host, port, ob) in enumerate(order[:max_try]):
        print(f"[entry] try {i+1}/{max_try} {host}:{port}", flush=True)
        if not start_xray(ob):
            continue
        if health_ok():
            print(f"[entry] UP via {host}:{port} socks={SOCKS_HOST}:{SOCKS_PORT}", flush=True)
            return True
        print(f"[entry] health fail {host}:{port}", flush=True)
        stop_entry()
    print("[entry] no working entry — fallback direct", flush=True)
    return False


def tcp_via_socks(host: str, port: int, timeout: float = 3.0) -> int | None:
    """TCP connect host:port through SOCKS5 entry; return RTT ms or None."""
    try:
        import socks
    except ImportError:
        return None
    s = None
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, SOCKS_HOST, SOCKS_PORT)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect((host, port))
        ms = int((time.perf_counter() - t0) * 1000)
        return ms
    except Exception:
        return None
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass


def http_check(url: str, ok_codes: set[int], timeout: float = 10.0) -> bool:
    code = _http_via_socks(url, timeout=timeout)
    return code in ok_codes if code is not None else False


if __name__ == "__main__":
    ok = acquire_entry()
    print("entry", ok)
    if ok:
        print("g204", health_ok())
        stop_entry()
