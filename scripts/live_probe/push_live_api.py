#!/usr/bin/env python3
"""Commit live.txt + status.json on current public repo via Contents API."""
from __future__ import annotations

import base64
import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LIVE = ROOT / "live.txt"
STATUS = Path(__file__).resolve().parent / "status.json"
META = Path(__file__).resolve().parent / "live_meta.env"
REPO = os.environ.get("GITHUB_REPOSITORY", "Reed3130/live-vpn")


def load_meta():
    d = {"count": "0", "updated": "unknown"}
    if META.is_file():
        for line in META.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k == "LIVE_COUNT":
                    d["count"] = v.strip()
                elif k == "LIVE_UPDATED_HUMAN":
                    d["updated"] = v.strip()
    return d


def put_file(path: str, content: bytes, message: str, token: str):
    api = f"https://api.github.com/repos/{REPO}/contents/{path}"
    # get sha if exists
    sha = None
    try:
        req = urllib.request.Request(
            api,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            sha = json.load(r).get("sha")
    except Exception:
        pass
    body = {
        "message": message,
        "content": base64.b64encode(content).decode("ascii"),
        "branch": "main",
    }
    if sha:
        body["sha"] = sha
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        api,
        data=data,
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        print(path, r.status, flush=True)


def main():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        raise SystemExit("no token")
    meta = load_meta()
    msg = f"live={meta['count']} @ {meta['updated']}"
    if LIVE.is_file():
        put_file("live.txt", LIVE.read_bytes(), msg, token)
    if STATUS.is_file():
        put_file("status.json", STATUS.read_bytes(), f"status: {msg}", token)
    # simple README stats
    readme = f"""# live-vpn

Автообновляемый список рабочих VPN (TCP через RU-туннель).

- **live:** {meta['count']}
- **updated:** {meta['updated']}
- **raw:** https://raw.githubusercontent.com/Reed3130/live-vpn/main/live.txt

Цикл каждые 2 часа (публичный runner). Провайдеры в private-репозитории.
"""
    put_file("README.md", readme.encode("utf-8"), f"readme: {msg}", token)
    print("done", msg)


if __name__ == "__main__":
    main()
