#!/usr/bin/env python3
"""IMMUTABLE cycle every 2h (do not change order):
  0) tunnel pick (BLACK daily)
  1 DL → 2 parse → 3 filter
  → 4 ping Google → 5 filter
  → 6 ping Telegram → 7 filter
  → 8 ping YouTube → 9 filter
  → 10 ping Yandex → 11 filter
  → 12 pack → 13 filter → 14 live.txt
  All pings via RU tunnel. MAX_MS=1000. Cron 0 */2 * * *.
"""
from __future__ import annotations

import os
import base64
import concurrent.futures
import json
import re
import socket
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

try:
    import ru_entry
except ImportError:
    ru_entry = None  # type: ignore

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS_FILE = Path(__file__).resolve().parent / "providers.txt"
OUT_FILE = ROOT / "live.txt"

MAX_MS = 1000
CONNECT_TIMEOUT = 1.0
WORKERS = 64
UA = "AVK-VPN-live-probe/tcp-only/1.0"

LINK_RE = re.compile(
    r"(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard)://[^\s<>\"']+",
    re.IGNORECASE,
)
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

UA_DENY_RE = re.compile(
    r"("
    r"\bua\b|\bukr\b|ukraine|ukrainian|украин|україн|ки[еє]в|київ|kyiv|kiev|"
    r"одес|odesa|odessa|льв[оі]в|lviv|харьк|kharkiv|дніпр|dnipro|"
    r"/ua[_\-]|[_\-]ua[_\-]|country[=:]?ua|"
    r"\.ua\b"
    r")",
    re.IGNORECASE,
)
UA_FLAG = "🇺🇦"

DENY_PROTO_RE = re.compile(
    r"("
    r"\bnaive(proxy)?\b|naive\+|naive://"
    r"|\bmieru\b|mieru://"
    r"|\btrusttunnel\b|trust[-_]?tunnel"
    r"|\bsudoku\b|sudoku://"
    r"|\bmasque\b|masque://"
    r"|\bech\b|encrypted[-_ ]?client[-_ ]?hello"
    r"|security=ech|ech=1|ech[=:]true"
    r")",
    re.IGNORECASE,
)
DENY_SCHEMES = frozenset({
    "naive", "naive+https", "naive+http", "mieru", "trusttunnel",
    "sudoku", "masque", "h3", "quic-masque",
})

INACTIVE_RE = re.compile(
    r"("
    r"\binactive\b|\bdisabled\b|\boffline\b|\bexpired\b|\bexpire[ds]?\b|"
    r"\bdead\b|\bdown\b|\bbanned\b|\bblock(ed)?\b|\bdeprec\w*|"
    r"\bnot[-_ ]?working\b|\bunavailable\b|\bmaint(enance)?\b|"
    r"\btest[-_ ]?only\b|\bdummy\b|\bplaceholder\b|"
    r"неактив|отключ|выключ|истёк|истек|просроч|не\s*работ|недосту|"
    r"тех\.?\s*работ|заблок|устарел"
    r")",
    re.IGNORECASE,
)


def load_provider_urls() -> list[str]:
    """Providers stay in private repo; fetch providers.txt via token."""
    urls, seen = [], set()
    text = ""
    token = os.environ.get("PRIVATE_REPO_TOKEN") or os.environ.get("GH_TOKEN") or ""
    # 1) local file if present (dev)
    if PROVIDERS_FILE.is_file():
        text = PROVIDERS_FILE.read_text(encoding="utf-8", errors="ignore")
    # 2) private repo raw via API
    if not text.strip() and token:
        api = "https://api.github.com/repos/Reed3130/AVK-VPN-private/contents/scripts/live_probe/providers.txt?ref=main"
        try:
            req = urllib.request.Request(
                api,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.raw",
                    "User-Agent": UA,
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            print(f"[providers] loaded from private API bytes={len(text)}", flush=True)
        except Exception as e:
            print(f"[providers] private API fail: {e}", flush=True)
    if not text.strip():
        print("[providers] EMPTY — no providers.txt", flush=True)
        return urls
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in seen:
            seen.add(line)
            urls.append(line)
    return urls


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = resp.read()
    text = raw.decode("utf-8", errors="ignore")
    stripped = "".join(text.split())
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", stripped) and len(stripped) > 64:
        try:
            pad = "=" * (-len(stripped) % 4)
            text = base64.b64decode(stripped + pad).decode("utf-8", errors="ignore")
        except Exception:
            pass
    return text


def b64decode_pad(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def extract_host_port(link: str) -> tuple[str, int] | None:
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return None
    scheme = scheme.lower()
    rest = rest.split("#", 1)[0].strip()

    if scheme == "vmess":
        try:
            data = json.loads(b64decode_pad(rest).decode("utf-8", errors="ignore"))
            host = str(data.get("add") or data.get("host") or "").strip()
            port = int(data.get("port") or 0)
            if host and 1 <= port <= 65535:
                return host, port
        except Exception:
            return None
        return None

    if scheme in ("ss", "ssr"):
        try:
            if "@" not in rest:
                try:
                    rest = b64decode_pad(rest.split("/")[0].split("?")[0]).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    pass
            if "@" in rest:
                _, hostpart = rest.rsplit("@", 1)
                hostpart = hostpart.split("/")[0].split("?")[0]
                if hostpart.startswith("["):
                    m = re.match(r"\[([^\]]+)\]:(\d+)$", hostpart)
                    if m:
                        return m.group(1), int(m.group(2))
                if ":" in hostpart:
                    host, port_s = hostpart.rsplit(":", 1)
                    return host.strip("[]"), int(port_s)
        except Exception:
            return None
        return None

    try:
        hostpart = rest.rsplit("@", 1)[1] if "@" in rest else rest
        hostpart = unquote(hostpart.split("/")[0].split("?")[0])
        if hostpart.startswith("["):
            m = re.match(r"\[([^\]]+)\]:(\d+)$", hostpart)
            if not m:
                return None
            return m.group(1), int(m.group(2))
        if ":" not in hostpart:
            return None
        host, port_s = hostpart.rsplit(":", 1)
        return host.strip(), int(port_s)
    except Exception:
        return None


def link_remark_blob(link: str) -> str:
    parts = []
    if "#" in link:
        parts.append(unquote(link.split("#", 1)[1]))
    try:
        hp = extract_host_port(link)
        if hp:
            parts.append(hp[0])
    except Exception:
        pass
    parts.append(link)
    return " ".join(parts)



# Белый список: российские сервера — TCP с GitHub (US) бессмысленен, в live без пинга
RU_FLAG = "🇷🇺"
RU_WHITELIST_RE = re.compile(
    r"("
    r"\bru\b|\brus\b|\brussia\b|russian|"
    r"росси|рф\b|москв|moscow|petersburg|spb|новосиб|екатеринбург|"
    r"sn[iі][-_]?ru|country[=:]?ru|[/_-]ru[/_-]|\[ru\]|\(ru\)|"
    r"yandex|vk\.com|mail\.ru|ok\.ru|dzen\.ru|"
    r"\*cidr.*vk|white[-_]?list.*ru"
    r")",
    re.IGNORECASE,
)


def is_russian_server(link: str) -> bool:
    """RU white-list: не пингуем (с US runner не открываются), считаем в live после фильтров."""
    blob = link_remark_blob(link)
    if RU_FLAG in blob or RU_FLAG in link:
        return True
    if RU_WHITELIST_RE.search(blob):
        return True
    # host в .ru / .рф (кроме явно UA)
    hp = extract_host_port(link)
    if hp:
        h = hp[0].lower().strip("[]")
        if h.endswith(".ru") or h.endswith(".su") or h.endswith(".xn--p1ai"):
            return True
    return False


def is_ukraine_server(link: str) -> bool:
    blob = link_remark_blob(link)
    if UA_FLAG in blob or UA_FLAG in link:
        return True
    if UA_DENY_RE.search(blob):
        return True
    hp = extract_host_port(link)
    if hp and hp[0].lower().endswith(".ua"):
        return True
    return False


def is_inactive_or_disabled(link: str) -> bool:
    return bool(INACTIVE_RE.search(link_remark_blob(link)))


def normalize_link_core(link: str) -> str:
    return link.strip().split("#", 1)[0].strip()


def identity_keys(link: str) -> set[str]:
    keys: set[str] = set()
    core = normalize_link_core(link)
    keys.add("full:" + core)
    try:
        scheme = core.split("://", 1)[0].lower()
    except Exception:
        scheme = ""
    hp = extract_host_port(link)
    if hp:
        host, port = hp
        host_l = host.strip("[]").lower()
        keys.add(f"hp:{host_l}:{port}")
        keys.add(f"shp:{scheme}:{host_l}:{port}")
    rest = core.split("://", 1)[-1] if "://" in core else core
    rest_no_q = rest.split("?", 1)[0]
    if "@" in rest_no_q:
        user = rest_no_q.split("@", 1)[0]
        uid = user.split(":")[0]
        if uid:
            keys.add(f"uid:{uid.lower()}")
            if hp:
                keys.add(f"uidhp:{uid.lower()}@{hp[0].strip('[]').lower()}:{hp[1]}")
    if scheme == "vmess":
        try:
            data = json.loads(b64decode_pad(rest).decode("utf-8", errors="ignore"))
            vid = str(data.get("id") or "").strip().lower()
            if vid:
                keys.add(f"uid:{vid}")
            add = str(data.get("add") or data.get("host") or "").strip().lower()
            port = int(data.get("port") or 0)
            if add and port:
                keys.add(f"hp:{add}:{port}")
                if vid:
                    keys.add(f"uidhp:{vid}@{add}:{port}")
        except Exception:
            pass
    return keys


def dedupe_links(links: list[str]) -> tuple[list[str], int]:
    out: list[str] = []
    seen: set[str] = set()
    rejected = 0
    for lk in links:
        keys = identity_keys(lk)
        if keys & seen:
            rejected += 1
            continue
        seen |= keys
        out.append(lk)
    return out, rejected


def is_valid_link(link: str) -> bool:
    if not link or not isinstance(link, str):
        return False
    link = link.strip()
    if is_ukraine_server(link):
        return False
    if is_inactive_or_disabled(link):
        return False
    if DENY_PROTO_RE.search(link):
        return False
    if len(link) < 20 or len(link) > 8000:
        return False
    if any(c in link for c in (" ", "\t", "\n", "\r", "<", ">", '"')):
        return False
    if "…" in link or "..." in link:
        return False
    if link.count("://") != 1:
        return False
    if not LINK_RE.match(link):
        return False
    if link.rstrip("#").endswith(("?", "&", "=", "@", ":")):
        return False
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return False
    scheme = scheme.lower()
    if scheme in DENY_SCHEMES or scheme.startswith("naive"):
        return False
    hp = extract_host_port(link)
    if not hp:
        return False
    host, port = hp
    if not (1 <= port <= 65535):
        return False
    rest_no_frag = rest.split("#", 1)[0]
    if scheme in ("vless", "trojan", "tuic"):
        if "@" not in rest_no_frag:
            return False
        uid = rest_no_frag.split("@", 1)[0].split(":")[0]
        if scheme in ("vless", "trojan") and not UUID_RE.match(uid):
            return False
    if scheme == "vmess":
        try:
            data = json.loads(b64decode_pad(rest_no_frag).decode("utf-8", errors="ignore"))
            if not str(data.get("id") or "").strip():
                return False
            if not str(data.get("add") or data.get("host") or "").strip():
                return False
            int(data.get("port") or 0)
        except Exception:
            return False
    if scheme in ("ss", "ssr") and len(rest_no_frag) < 12:
        return False
    return True


def collect_links(text: str) -> list[str]:
    found = LINK_RE.findall(text)
    for line in text.splitlines():
        line = line.strip()
        if LINK_RE.match(line):
            found.append(line)
    out, seen = [], set()
    for x in found:
        x = x.strip().rstrip("),.;\"'")
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def tcp_ping_ms(host: str, port: int) -> int | None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except Exception:
        return None
    best = None
    for family, type_, proto, _, sockaddr in infos[:3]:
        s = None
        try:
            s = socket.socket(family, type_, proto)
            s.settimeout(CONNECT_TIMEOUT)
            t0 = time.perf_counter()
            s.connect(sockaddr)
            ms = int((time.perf_counter() - t0) * 1000)
            if best is None or ms < best:
                best = ms
        except Exception:
            pass
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
        if best is not None and best <= MAX_MS:
            break
    return best


_USE_ENTRY = False


def tcp_batch(links: list[str], stage: str) -> list[tuple[int, str]]:
    """TCP host:port ≤ MAX_MS. Via RU entry SOCKS when available."""
    candidates: list[tuple[str, str, int]] = []
    for lk in links:
        hp = extract_host_port(lk)
        if not hp:
            continue
        candidates.append((lk, hp[0], hp[1]))
    if len(candidates) > 4000:
        candidates = candidates[:4000]
    mode = "via-ru-entry" if _USE_ENTRY else "direct"
    print(f"[{stage}] probing={len(candidates)} max_ms={MAX_MS} mode={mode}", flush=True)
    out: list[tuple[int, str]] = []

    def one(item: tuple[str, str, int]):
        lk, host, port = item
        if _USE_ENTRY and ru_entry is not None:
            ms = ru_entry.tcp_via_socks(host, port, timeout=CONNECT_TIMEOUT + 1.5)
        else:
            ms = tcp_ping_ms(host, port)
        return ms, lk

    workers = 32 if _USE_ENTRY else WORKERS
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one, c) for c in candidates]
        for fut in concurrent.futures.as_completed(futs, timeout=max(180, len(candidates) // 2 + 90)):
            try:
                ms, lk = fut.result(timeout=CONNECT_TIMEOUT + 4)
            except Exception:
                continue
            if ms is None or ms > MAX_MS:
                continue
            out.append((ms, lk))
    out.sort(key=lambda x: x[0])
    print(f"[{stage}] ok={len(out)}", flush=True)
    return out


def main() -> int:
    socket.setdefaulttimeout(CONNECT_TIMEOUT + 0.5)
    """
    Каждые 2 часа:
      0) пинг и подбор живого RU-туннеля (Igareck BLACK, daily)
      1) DL → parse → filter → ping Google → filter → ping Telegram
         → filter → ping YouTube → filter → pack → filter → live.txt
      Все пинги серверов — через выбранный туннель. MAX_MS=1000.
    """
    global _USE_ENTRY
    _USE_ENTRY = False
    print("[0/tunnel] ping + pick living RU entry (BLACK daily)…", flush=True)
    if ru_entry is not None:
        try:
            _USE_ENTRY = bool(ru_entry.acquire_entry(max_try=30))
        except Exception as e:
            print(f"[0/tunnel] error: {e}", flush=True)
            _USE_ENTRY = False
    if _USE_ENTRY:
        print("[0/tunnel] UP — further pings via RU tunnel", flush=True)
    else:
        print("[0/tunnel] DOWN — fallback direct (no RU path)", flush=True)

    urls = load_provider_urls()
    all_links: list[str] = []
    seen_raw: set[str] = set()
    print(f"[1/DL] providers={len(urls)} max_ms={MAX_MS}", flush=True)

    def dl_one(url: str) -> tuple[str, list[str], str | None]:
        try:
            body = fetch(url)
            return url, collect_links(body), None
        except Exception as e:
            return url, [], str(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(12, max(1, len(urls)))) as ex:
        futs = [ex.submit(dl_one, u) for u in urls]
        for fut in concurrent.futures.as_completed(futs, timeout=180):
            try:
                url, found, err = fut.result(timeout=20)
            except Exception as e:
                print(f"[1/DL] FAIL worker: {e}", flush=True)
                continue
            if err:
                print(f"[1/DL] FAIL {url[:60]}: {err}", flush=True)
                continue
            n_new = 0
            for lk in found:
                core = normalize_link_core(lk)
                if core in seen_raw:
                    continue
                seen_raw.add(core)
                all_links.append(lk)
                n_new += 1
            print(f"[1/DL] ok {url[:60]}… +{n_new}", flush=True)

    print(f"[2/parse] raw_links={len(all_links)}", flush=True)

    valid = [lk for lk in all_links if is_valid_link(lk)]
    print(f"[3/filters] valid={len(valid)}", flush=True)

    # RU тоже пингуем (через entry). Дедуп всего пула.
    ru_n = sum(1 for lk in valid if is_russian_server(lk))
    pool, d0 = dedupe_links(valid)
    print(f"[3b] all_after_dedupe={len(pool)} ru_marked={ru_n} dups={d0}", flush=True)

    # туннель уже выбран на шаге 0
    print(f"[3c] pool={len(pool)} via_tunnel={_USE_ENTRY}", flush=True)
    STAGE_PAUSE_SEC = 3

    # 4) TCP Google
    g_items = tcp_batch(pool, "4/TCP-Google")
    pool = [lk for _, lk in g_items]
    pool, d1 = dedupe_links(pool)
    print(f"[5/filters-after-Google] n={len(pool)} dups={d1}", flush=True)
    print(f"[pause] {STAGE_PAUSE_SEC}s before Telegram", flush=True)
    time.sleep(STAGE_PAUSE_SEC)

    # 6) TCP Telegram
    t_items = tcp_batch(pool, "6/TCP-Telegram")
    pool = [lk for _, lk in t_items]
    pool, d2 = dedupe_links(pool)
    print(f"[7/filters-after-Telegram] n={len(pool)} dups={d2}", flush=True)
    print(f"[pause] {STAGE_PAUSE_SEC}s before YouTube", flush=True)
    time.sleep(STAGE_PAUSE_SEC)

    # 8) TCP YouTube
    y_items = tcp_batch(pool, "8/TCP-YouTube")
    pool = [lk for _, lk in y_items]
    pool, d3 = dedupe_links(pool)
    print(f"[9/filters-after-YouTube] n={len(pool)} dups={d3}", flush=True)
    print(f"[pause] {STAGE_PAUSE_SEC}s before Yandex", flush=True)
    time.sleep(STAGE_PAUSE_SEC)

    # 10) TCP Yandex (через туннель)
    ya_items = tcp_batch(pool, "10/TCP-Yandex")
    pool = [lk for _, lk in ya_items]
    pool, d4 = dedupe_links(pool)
    print(f"[11/filters-after-Yandex] n={len(pool)} dups={d4}", flush=True)
    o_items = ya_items

    # 12 pack → 13 filter → 14 live.txt
    links, d_all = dedupe_links(pool)
    print(f"[12/pack] packed={len(links)} dups={d_all} entry={_USE_ENTRY}", flush=True)
    links = [lk for lk in links if is_valid_link(lk)]
    links, d_f = dedupe_links(links)
    print(f"[13/filter-final] n={len(links)} dups={d_f}", flush=True)

    body = "\n".join(links)
    if body:
        body += "\n"
    OUT_FILE.write_text(body, encoding="utf-8")

    now = datetime.now(timezone.utc)
    updated_utc = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    updated_human = now.strftime("%Y-%m-%d %H:%M UTC")
    n = len(links)
    avg_ms = int(sum(ms for ms, _ in o_items) / len(o_items)) if o_items else 0

    meta = Path(__file__).resolve().parent / "live_meta.env"
    meta.write_text(
        "\n".join([
            f"LIVE_COUNT={n}",
            f"LIVE_UPDATED_UTC={updated_utc}",
            f"LIVE_UPDATED_HUMAN={updated_human}",
            f"LIVE_AVG_MS={avg_ms}",
            f"LIVE_ENTRY={1 if _USE_ENTRY else 0}",
            f"LIVE_MODE=tcp-via-ru-entry",
            "",
        ]),
        encoding="utf-8",
    )
    status = {
        "updated_utc": updated_utc,
        "updated_human": updated_human,
        "mode": "tcp-stages-ru-skip",
        "max_ms": MAX_MS,
        "live": n,
        "tcp_ok": len(pool),
        "entry": bool(_USE_ENTRY),
        "avg_ms_tcp": avg_ms,
    }
    (Path(__file__).resolve().parent / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        f"[14/done] live.txt live={n} entry={_USE_ENTRY} "
        f"avg_ms={avg_ms} updated={updated_human}",
        flush=True,
    )
    if ru_entry is not None:
        try:
            ru_entry.stop_entry()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

