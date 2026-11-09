#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CF IP Finder 0.1.2 - staged IPv4 scanner and VLESS/Xray tester.
Python 3.10+; standard library only. Windows GUI uses tkinter.
"""
from __future__ import annotations

import concurrent.futures
import contextlib
import csv
import datetime as dt
import ipaddress
import json
import http.client
import os
import queue
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Iterable

import cf_ip_tester_legacy as legacy_tester

APP_NAME = "CF IP Finder"
APP_VERSION = "0.1.2"
DEFAULT_SPEED_URL = "http://speedtest.tyo11.jp.leaseweb.net/10mb.bin"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "CF-IP-Finder" if os.name == "nt" else Path.home() / ".cf-ip-finder"

# ----------------------------- IP / VLESS parsing -----------------------------

def parse_targets(text: str, max_ips: int = 100_000) -> list[tuple[str, int]]:
    """Parse one IPv4, CIDR, or inclusive start-end range per line.
    Returns (ip, source_line), preserving line/address order and de-duplicating.
    Includes all CIDR addresses, including network/broadcast, as requested.
    """
    result: list[tuple[str, int]] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        try:
            if "-" in line:
                parts = [p.strip() for p in line.split("-")]
                if len(parts) != 2:
                    raise ValueError("范围格式应为 起始IP-结束IP")
                start, end = (ipaddress.ip_address(p) for p in parts)
                if start.version != 4 or end.version != 4:
                    raise ValueError("目前只支持 IPv4")
                if int(end) < int(start):
                    raise ValueError("结束 IP 不能小于起始 IP")
                count = int(end) - int(start) + 1
                iterator = (ipaddress.IPv4Address(n) for n in range(int(start), int(end) + 1))
            elif "/" in line:
                network = ipaddress.ip_network(line, strict=False)
                if network.version != 4:
                    raise ValueError("目前只支持 IPv4")
                count = network.num_addresses
                iterator = network
            else:
                addr = ipaddress.ip_address(line)
                if addr.version != 4:
                    raise ValueError("目前只支持 IPv4")
                count = 1
                iterator = [addr]
            if len(result) + count > max_ips:
                raise ValueError(f"目标数量超过当前安全上限 {max_ips:,}，请拆分任务")
            for addr in iterator:
                ip = str(addr)
                if ip not in seen:
                    seen.add(ip)
                    result.append((ip, line_no))
        except Exception as exc:
            raise ValueError(f"第 {line_no} 行格式错误：{line}（{exc}）") from exc
    if not result:
        raise ValueError("没有解析到有效 IPv4 地址")
    return result



def parse_shodan_targets(text: str, max_ips: int = 100_000) -> list[tuple[str, int]]:
    """Extract IPv4 addresses from pasted Shodan IP lists or CSV rows."""
    ipv4_re = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
    result: list[tuple[str, int]] = []
    seen: set[str] = set()
    for line_no, line in enumerate(text.splitlines(), 1):
        # A Shodan CSV header may contain the word ip_str but no address.
        for candidate in ipv4_re.findall(line):
            try:
                ip = str(ipaddress.IPv4Address(candidate))
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                result.append((ip, line_no))
                if len(result) > max_ips:
                    raise ValueError(f"Shodan IP 数量超过安全上限 {max_ips:,}")
    if not result:
        raise ValueError("没有从 Shodan 内容中识别到有效 IPv4 地址")
    return result


def ping_probe(ip: str, count: int = 3, timeout: float = 1.0) -> dict[str, Any]:
    """Run system ICMP ping; ICMP failure is diagnostic and never removes a candidate."""
    count = max(1, min(10, int(count)))
    timeout = max(0.2, min(10.0, float(timeout)))
    if os.name == "nt":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(max(1, int(round(timeout))),), ip]
    started = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=count * timeout + 4, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        samples = [float(x) for x in re.findall(r"(?:time|时间)[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, re.I)]
        replies = min(count, len(samples))
        loss = round((count - replies) * 100.0 / count, 1)
        return {"ping_status": "success" if replies else "timeout",
                "ping_ms": round(sum(samples) / len(samples), 2) if samples else None,
                "ping_min_ms": round(min(samples), 2) if samples else None,
                "ping_max_ms": round(max(samples), 2) if samples else None,
                "ping_loss_pct": loss, "ping_replies": replies,
                "ping_error": "" if replies else (output.strip()[-300:] or "无 ICMP 响应")}
    except FileNotFoundError:
        return {"ping_status": "unavailable", "ping_ms": None, "ping_min_ms": None,
                "ping_max_ms": None, "ping_loss_pct": 100.0, "ping_replies": 0,
                "ping_error": "系统未找到 ping 命令"}
    except Exception as exc:
        return {"ping_status": "error", "ping_ms": None, "ping_min_ms": None,
                "ping_max_ms": None, "ping_loss_pct": 100.0, "ping_replies": 0,
                "ping_error": str(exc)[:300]}


def tcping_probe(ip: str, count: int = 5, timeout: float = 1.5, port: int = 443) -> dict[str, Any]:
    """Repeat TCP connect probes and return average/min/max and success rate."""
    count = max(1, min(20, int(count)))
    timeout = max(0.2, min(15.0, float(timeout)))
    samples: list[float] = []
    errors: list[str] = []
    for _ in range(count):
        started = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                samples.append((time.perf_counter() - started) * 1000)
        except Exception as exc:
            errors.append(str(exc))
    rate = round(len(samples) * 100.0 / count, 1)
    return {"tcping_status": "success" if len(samples) == count else ("partial" if samples else "failed"),
            "tcping_ms": round(sum(samples) / len(samples), 2) if samples else None,
            "tcping_min_ms": round(min(samples), 2) if samples else None,
            "tcping_max_ms": round(max(samples), 2) if samples else None,
            "tcping_success_pct": rate, "tcping_successes": len(samples),
            "tcping_error": "; ".join(errors[:2])[:300]}

def parse_vless(uri: str) -> dict[str, Any]:
    uri = uri.strip()
    if not uri.lower().startswith("vless://"):
        raise ValueError("目前只支持 vless:// URI 模板")
    p = urllib.parse.urlsplit(uri)
    if not p.hostname or not p.username:
        raise ValueError("VLESS 链接缺少服务器地址或 UUID")
    try:
        port = p.port or 443
    except ValueError as exc:
        raise ValueError("VLESS 端口格式不正确") from exc
    q = {k: v[-1] for k, v in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()}
    network = q.get("type", "tcp").lower()
    security = q.get("security", "none").lower()
    if network not in ("ws", "grpc", "tcp", "raw", "httpupgrade", "xhttp"):
        raise ValueError(f"暂不支持传输类型：{network}（支持 ws / grpc / tcp / httpupgrade / xhttp）")
    if security not in ("tls", "reality", "none"):
        raise ValueError(f"暂不支持 security={security}")
    return {
        "original": uri, "uuid": urllib.parse.unquote(p.username), "host": p.hostname,
        "port": port, "fragment": urllib.parse.unquote(p.fragment), "query": q,
        "network": network, "security": security,
    }


def replace_vless_host(uri: str, new_host: str) -> str:
    p = urllib.parse.urlsplit(uri.strip())
    if p.scheme.lower() != "vless" or not p.hostname:
        raise ValueError("不是有效的 VLESS URI")
    # Keep userinfo, port, query, fragment untouched; correctly bracket IPv6 if ever used.
    userinfo = p.netloc.rsplit("@", 1)[0] if "@" in p.netloc else ""
    host = f"[{new_host}]" if ":" in new_host and not new_host.startswith("[") else new_host
    netloc = (userinfo + "@" if userinfo else "") + host + (f":{p.port}" if p.port else "")
    return urllib.parse.urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))


def make_xray_config(vless: dict[str, Any], target_ip: str, socks_port: int) -> dict[str, Any]:
    q = vless["query"]
    user: dict[str, Any] = {"id": vless["uuid"], "encryption": q.get("encryption", "none") or "none"}
    if q.get("flow"):
        user["flow"] = q["flow"]
    outbound: dict[str, Any] = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": target_ip, "port": vless["port"], "users": [user]}]},
        "tag": "proxy",
    }
    network = vless["network"]
    security = vless["security"]
    stream: dict[str, Any] = {"network": "raw" if network == "tcp" else network, "security": security}
    if security == "tls":
        tls: dict[str, Any] = {"serverName": q.get("sni") or vless["host"], "allowInsecure": q.get("allowInsecure", "false").lower() in ("1", "true", "yes")}
        if q.get("fp"):
            tls["fingerprint"] = q["fp"]
        if q.get("alpn"):
            tls["alpn"] = [x.strip() for x in q["alpn"].split(",") if x.strip()]
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {"serverName": q.get("sni") or vless["host"], "fingerprint": q.get("fp", "chrome"),
                   "publicKey": q.get("pbk", ""), "shortId": q.get("sid", ""), "spiderX": q.get("spx", "/")}
        if not reality["publicKey"]:
            raise ValueError("Reality 节点缺少 pbk 公钥参数")
        stream["realitySettings"] = reality
    if network == "ws":
        ws: dict[str, Any] = {"path": q.get("path", "/") or "/"}
        if q.get("host"):
            ws["headers"] = {"Host": q["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict[str, Any] = {"serviceName": q.get("serviceName", "")}
        if q.get("authority"):
            grpc["authority"] = q["authority"]
        stream["grpcSettings"] = grpc
    elif network in ("tcp", "raw") and q.get("headerType"):
        stream["tcpSettings"] = {"header": {"type": q["headerType"]}}
    outbound["streamSettings"] = stream
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }

# ----------------------------- network probes -----------------------------

def tcp_probe(ip: str, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection((ip, 443), timeout=timeout):
            return {"port_status": "open", "port_ms": round((time.perf_counter() - started) * 1000, 2), "port_error": ""}
    except socket.timeout:
        return {"port_status": "timeout", "port_ms": round((time.perf_counter() - started) * 1000, 2), "port_error": "timeout"}
    except OSError as exc:
        return {"port_status": "closed", "port_ms": round((time.perf_counter() - started) * 1000, 2), "port_error": str(exc)[:240]}


def read_http_response(sock: socket.socket, max_body: int = 8192) -> tuple[str, dict[str, str], bytes]:
    sock.settimeout(3)
    f = sock.makefile("rb")
    status_line = f.readline(4096).decode("latin-1", "replace").strip()
    headers: dict[str, str] = {}
    total = 0
    while True:
        line = f.readline(8192)
        if not line or line in (b"\r\n", b"\n"):
            break
        total += len(line)
        if total > 64 * 1024:
            break
        decoded = line.decode("latin-1", "replace").strip()
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = f.read(max_body) if max_body > 0 else b""
    return status_line, headers, body


def http_cleartext_probe(ip: str, timeout: float) -> dict[str, Any]:
    """Send plaintext HTTP to TCP/443, resembling Shodan's HTTP-on-HTTPS-port probe."""
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0 (compatible; CF-IP-Finder/0.1)\r\nConnection: close\r\n\r\n").encode("ascii")
            sock.sendall(request)
            status, headers, body = read_http_response(sock)
        text = (status + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body.decode("utf-8", "replace"))
        low = text.lower()
        code_match = re.search(r"\s(\d{3})(?:\s|$)", status)
        code = int(code_match.group(1)) if code_match else 0
        server = headers.get("server", "")
        cf_ray_raw = headers.get("cf-ray", "")
        cf_ray = "" if cf_ray_raw.strip().lower() in ("", "-", "none") else cf_ray_raw
        contains_cf = "cloudflare" in low
        cf_phrase = "the plain http request was sent to https port" in low
        score = (4 if "cloudflare" in server.lower() else 0) + (5 if cf_ray else 0) + (2 if contains_cf else 0) + (1 if cf_phrase else 0)
        # Mirror the useful core of the user's Shodan query: HTTP 400 plus Cloudflare text.
        # A real non-placeholder CF-RAY together with Cloudflare's Server header is also a candidate.
        candidate = (code == 400 and contains_cf) or (bool(cf_ray) and "cloudflare" in server.lower())
        return {"http_status": code, "http_status_line": status[:300], "http_server": server[:200],
                "cf_ray": cf_ray[:200], "cf_text_match": int(contains_cf), "cf_phrase_match": int(cf_phrase),
                "cf_score": score, "cf_candidate": int(candidate),
                "http_excerpt": body.decode("utf-8", "replace")[:500].replace("\x00", "")}
    except Exception as exc:
        return {"http_status": -1, "http_status_line": "", "http_server": "", "cf_ray": "",
                "cf_text_match": 0, "cf_phrase_match": 0, "cf_score": 0, "cf_candidate": 0,
                "http_excerpt": "", "http_error": str(exc)[:240]}


def tls_probe(ip: str, timeout: float, sni: str, host: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((ip, 443), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=sni or None) as tls:
            cert = tls.getpeercert(binary_form=True)
            tls_version = tls.version() or ""
            cipher = tls.cipher()[0] if tls.cipher() else ""
            # Probe Cloudflare trace using the same IP but the original VLESS SNI/Host.
            request_host = host or sni or ip
            req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {request_host}\r\nUser-Agent: CF-IP-Finder/0.1\r\nConnection: close\r\n\r\n").encode("ascii", "ignore")
            tls.settimeout(timeout)
            tls.sendall(req)
            status, headers, body = read_http_response(tls)
            response_text = body.decode("utf-8", "replace")
            tls_ray_raw = headers.get("cf-ray", "")
            tls_ray = "" if tls_ray_raw.strip().lower() in ("", "-", "none") else tls_ray_raw
            trace_fields = set(re.findall(r"(?m)^([a-z_]+)=", response_text))
            trace_match = ("cloudflare" in headers.get("server", "").lower() or bool(tls_ray) or
                           {"colo", "loc", "tls", "sni"}.issubset(trace_fields))
            return {"tls_status": "ok", "tls_ms": round((time.perf_counter() - started) * 1000, 2),
                    "tls_version": tls_version, "tls_cipher": cipher, "tls_cert_sha256": __import__("hashlib").sha256(cert).hexdigest() if cert else "",
                    "tls_http_status": status[:200], "tls_server": headers.get("server", "")[:200],
                    "tls_cf_ray": tls_ray[:200], "tls_trace_match": int(trace_match),
                    "tls_excerpt": response_text[:500].replace("\x00", ""),
                    **({"cf_candidate": 1} if trace_match else {})}
    except Exception as exc:
        return {"tls_status": "failed", "tls_ms": round((time.perf_counter() - started) * 1000, 2),
                "tls_version": "", "tls_cipher": "", "tls_cert_sha256": "", "tls_http_status": "",
                "tls_server": "", "tls_cf_ray": "", "tls_trace_match": 0, "tls_excerpt": "", "tls_error": str(exc)[:240]}

# ----------------------------- SOCKS5 VLESS speed test -----------------------------

# ----------------------------- BGP / ASN metadata -----------------------------

_ROUTE_CACHE: dict[str, dict[str, Any]] = {}
_ROUTE_CACHE_LOCK = threading.Lock()


def _ripestat_json(endpoint: str, resource: str, timeout: float = 10.0) -> dict[str, Any]:
    query = urllib.parse.urlencode({"resource": resource, "sourceapp": "cf-ip-finder"})
    url = f"https://stat.ripe.net/data/{endpoint}/data.json?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "CF-IP-Finder/0.1.2"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.load(resp)
    if payload.get("status") not in (None, "ok"):
        raise RuntimeError(f"RIPEstat 返回状态：{payload.get('status')}")
    return payload.get("data", {})


def route_info_probe(ip: str) -> dict[str, Any]:
    """Get current observed origin ASN/prefix from RIPE RIS; enrich holder names by prefix."""
    try:
        data = _ripestat_json("network-info", ip)
        prefix = str(data.get("prefix") or "")
        raw_asns = data.get("asns") or []
        asn_values = []
        for item in raw_asns:
            value = item.get("asn") if isinstance(item, dict) else item
            if value is not None:
                text_value = str(value)
                asn_values.append(text_value if text_value.upper().startswith("AS") else "AS" + text_value)
        orgs: list[str] = []
        if prefix:
            with _ROUTE_CACHE_LOCK:
                cached = _ROUTE_CACHE.get(prefix)
            if cached is None:
                try:
                    summary = _ripestat_json("prefix-overview", prefix)
                    holders = []
                    for item in summary.get("asns") or []:
                        if isinstance(item, dict) and item.get("holder"):
                            holders.append(str(item["holder"]))
                    cached = {"organization": "; ".join(dict.fromkeys(holders))}
                except Exception:
                    cached = {"organization": ""}
                with _ROUTE_CACHE_LOCK:
                    _ROUTE_CACHE[prefix] = cached
            if cached.get("organization"):
                orgs.append(cached["organization"])
        return {"asn_info_status": "ok", "asn": ", ".join(dict.fromkeys(asn_values)),
                "organization": "; ".join(dict.fromkeys(orgs)), "bgp_prefix": prefix,
                "route_source": "RIPEstat RIS", "route_error": ""}
    except Exception as exc:
        return {"asn_info_status": "error", "asn": "", "organization": "", "bgp_prefix": "",
                "route_source": "RIPEstat RIS", "route_error": str(exc)[:300]}


# ----------------------------- durable task store -----------------------------

CREATE_SQL = """
CREATE TABLE IF NOT EXISTS ips (
 ip TEXT PRIMARY KEY, seq INTEGER NOT NULL, source_line INTEGER NOT NULL,
 port_status TEXT, port_ms REAL, port_error TEXT, port_source TEXT,
 http_status INTEGER, http_status_line TEXT, http_server TEXT, cf_ray TEXT,
 cf_text_match INTEGER, cf_phrase_match INTEGER, cf_score INTEGER, cf_candidate INTEGER,
 http_excerpt TEXT, http_error TEXT,
 tls_status TEXT, tls_ms REAL, tls_version TEXT, tls_cipher TEXT, tls_cert_sha256 TEXT,
 tls_http_status TEXT, tls_server TEXT, tls_cf_ray TEXT, tls_trace_match INTEGER, tls_excerpt TEXT, tls_error TEXT,
 ping_status TEXT, ping_ms REAL, ping_min_ms REAL, ping_max_ms REAL, ping_loss_pct REAL, ping_replies INTEGER, ping_error TEXT,
 tcping_status TEXT, tcping_ms REAL, tcping_min_ms REAL, tcping_max_ms REAL, tcping_success_pct REAL, tcping_successes INTEGER, tcping_error TEXT,
 vless_status TEXT, speed_mbps REAL, peak_mbps REAL, download_bytes INTEGER, ttfb_ms REAL, speed_seconds REAL,
 speed_requests INTEGER, vless_error TEXT,
 asn_info_status TEXT, asn TEXT, organization TEXT, bgp_prefix TEXT, route_source TEXT, route_error TEXT,
 updated_at TEXT
);
CREATE TABLE IF NOT EXISTS stages (name TEXT PRIMARY KEY, status TEXT NOT NULL, started_at TEXT, finished_at TEXT, item_count INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def db_locked(method):
    """Serialize SQLite access shared by the UI and worker threads."""
    def wrapper(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)
    wrapper.__name__ = method.__name__
    return wrapper


class TaskStore:
    def __init__(self, folder: Path, create: bool = False):
        self.lock = threading.RLock()
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.stage_dir = folder / "stages"
        self.stage_dir.mkdir(exist_ok=True)
        self.db_path = folder / "checkpoint.db"
        self.conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(CREATE_SQL)
        self.conn.commit()
        # Safe in-place migration for tasks created by 0.1.0 / 0.1.1.
        migrations = {
            "port_source": "TEXT",
            "ping_status": "TEXT", "ping_ms": "REAL", "ping_min_ms": "REAL", "ping_max_ms": "REAL",
            "ping_loss_pct": "REAL", "ping_replies": "INTEGER", "ping_error": "TEXT",
            "tcping_status": "TEXT", "tcping_ms": "REAL", "tcping_min_ms": "REAL", "tcping_max_ms": "REAL",
            "tcping_success_pct": "REAL", "tcping_successes": "INTEGER", "tcping_error": "TEXT",
        }
        existing = {r[1] for r in self.conn.execute("PRAGMA table_info(ips)")}
        for column, kind in migrations.items():
            if column not in existing:
                self.conn.execute(f"ALTER TABLE ips ADD COLUMN {column} {kind}")
        self.conn.commit()
        self.columns = {r[1] for r in self.conn.execute("PRAGMA table_info(ips)")}
        if create:
            self.conn.execute("INSERT OR REPLACE INTO stages(name,status) VALUES('targets','completed')")
            self.conn.commit()

    @db_locked
    def close(self):
        with contextlib.suppress(Exception):
            self.conn.execute("PRAGMA wal_checkpoint(FULL)")
            self.conn.close()

    @db_locked
    def add_targets(self, targets: list[tuple[str, int]]):
        with self.conn:
            self.conn.executemany("INSERT OR IGNORE INTO ips(ip,seq,source_line) VALUES(?,?,?)",
                                  [(ip, i, line) for i, (ip, line) in enumerate(targets, 1)])
        atomic_write(self.stage_dir / "01_targets.txt", "\n".join(ip for ip, _ in targets) + "\n")

    @db_locked
    def mark_shodan_imported(self):
        """Shodan results are assumed to have already matched port:443."""
        with self.conn:
            self.conn.execute("UPDATE ips SET port_status='open',port_ms=NULL,port_source='Shodan 导入确认 443',port_error='跳过本地 443 重扫' WHERE port_status IS NULL")
        atomic_write(self.stage_dir / "02_port_scan.jsonl", "".join(json.dumps({"ip": r[0], "port_status": "open", "port_source": "Shodan 导入确认 443"}, ensure_ascii=False)+"\n" for r in self.conn.execute("SELECT ip FROM ips ORDER BY seq")))
        self.stage_start("port")
        self.stage_finish("port", self.conn.execute("SELECT COUNT(*) FROM ips").fetchone()[0])

    @db_locked
    def set_meta(self, key: str, value: str):
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))

    @db_locked
    def get_meta(self, key: str, default: str = "") -> str:
        r = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return str(r["value"]) if r else default

    @db_locked
    def stage_start(self, name: str):
        now = utc_now()
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO stages(name,status,started_at,finished_at) VALUES(?,?,?,NULL)", (name, "running", now))

    @db_locked
    def stage_finish(self, name: str, count: int):
        with self.conn:
            self.conn.execute("UPDATE stages SET status='completed',finished_at=?,item_count=? WHERE name=?", (utc_now(), count, name))
        self.write_stage_file(name)

    @db_locked
    def stage_status(self, name: str) -> str:
        row = self.conn.execute("SELECT status FROM stages WHERE name=?", (name,)).fetchone()
        return row["status"] if row else "pending"

    @db_locked
    def save_result(self, ip: str, result: dict[str, Any]):
        payload = {k: v for k, v in result.items() if k in self.columns and k != "ip"}
        payload["updated_at"] = utc_now()
        cols = list(payload)
        sql = "UPDATE ips SET " + ",".join(f"{c}=?" for c in cols) + " WHERE ip=?"
        with self.conn:
            self.conn.execute(sql, [payload[c] for c in cols] + [ip])

    @db_locked
    def pending_ips(self, stage: str, only_candidates: bool = True, limit: int | None = None) -> list[str]:
        queries = {
            "port": ("SELECT ip FROM ips WHERE port_status IS NULL ORDER BY seq", ()),
            "http": ("SELECT ip FROM ips WHERE port_status='open' AND http_status IS NULL ORDER BY seq", ()),
            "tls": ("SELECT ip FROM ips WHERE port_status='open' AND tls_status IS NULL ORDER BY seq", ()),
            "ping": ("SELECT ip FROM ips WHERE cf_candidate=1 AND ping_status IS NULL ORDER BY seq", ()),
            "tcping": ("SELECT ip FROM ips WHERE cf_candidate=1 AND tcping_status IS NULL ORDER BY seq", ()),
            "speed": ("SELECT ip FROM ips WHERE port_status='open' AND vless_status IS NULL" + (" AND cf_candidate=1" if only_candidates else "") + " ORDER BY seq", ()),
            "route": ("SELECT ip FROM ips WHERE asn_info_status IS NULL" + (" AND cf_candidate=1" if only_candidates else "") + " ORDER BY seq", ()),
        }
        if stage not in queries:
            return []
        sql, params = queries[stage]
        if stage == "route" and limit is not None and limit > 0:
            # Shodan mode queries only the fastest successful VLESS candidates.
            sql = ("SELECT ip FROM (SELECT ip,speed_mbps,ttfb_ms,seq FROM ips "
                   "WHERE cf_candidate=1 AND vless_status='success' "
                   "ORDER BY speed_mbps DESC, ttfb_ms ASC, seq ASC LIMIT ?) ranked "
                   "WHERE ip IN (SELECT ip FROM ips WHERE asn_info_status IS NULL) "
                   "ORDER BY speed_mbps DESC, ttfb_ms ASC, seq ASC")
            params = (int(limit),)
        rows = self.conn.execute(sql, params)
        return [r["ip"] for r in rows]

    @db_locked
    def all_rows(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM ips ORDER BY seq ASC"))

    @db_locked
    def counts(self) -> dict[str, int]:
        row = self.conn.execute("SELECT COUNT(*) total, SUM(CASE WHEN port_status='open' THEN 1 ELSE 0 END) opened, SUM(CASE WHEN cf_candidate=1 THEN 1 ELSE 0 END) candidates, SUM(CASE WHEN vless_status='success' THEN 1 ELSE 0 END) good, SUM(CASE WHEN ping_status IS NOT NULL THEN 1 ELSE 0 END) pinged, SUM(CASE WHEN tcping_status IS NOT NULL THEN 1 ELSE 0 END) tcpinged, SUM(CASE WHEN asn_info_status IS NOT NULL THEN 1 ELSE 0 END) asned FROM ips").fetchone()
        return {k: int(row[k] or 0) for k in ("total", "opened", "candidates", "good", "pinged", "tcpinged", "asned")}

    @db_locked
    def add_log(self, level: str, message: str):
        with self.conn:
            self.conn.execute("INSERT INTO logs(at,level,message) VALUES(?,?,?)", (utc_now(), level, message[:2000]))

    @db_locked
    def write_stage_file(self, stage: str):
        mapping = {
            "port": ("02_port_scan.jsonl", "port_status IS NOT NULL"),
            "http": ("03_cf_probe.jsonl", "http_status IS NOT NULL"),
            "tls": ("04_tls_probe.jsonl", "tls_status IS NOT NULL"),
            "ping": ("05_ping.jsonl", "ping_status IS NOT NULL"),
            "tcping": ("06_tcping.jsonl", "tcping_status IS NOT NULL"),
            "speed": ("07_vless_speed.jsonl", "vless_status IS NOT NULL"),
            "route": ("08_network_info.jsonl", "asn_info_status IS NOT NULL"),
        }
        if stage not in mapping:
            return
        filename, where = mapping[stage]
        rows = self.conn.execute(f"SELECT * FROM ips WHERE {where} ORDER BY seq")
        tmp = self.stage_dir / (filename + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.stage_dir / filename)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def atomic_write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# ----------------------------- task runner -----------------------------

class ScanRunner:
    def __init__(self, store: TaskStore, config: dict[str, Any], emit):
        self.store = store
        self.cfg = config
        self.emit = emit
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()

    def stop(self):
        self.stop_event.set()
        self.pause_event.set()

    def pause(self):
        self.pause_event.clear()

    def resume(self):
        self.pause_event.set()

    def wait_active(self):
        while not self.pause_event.wait(0.25):
            if self.stop_event.is_set():
                return False
        return not self.stop_event.is_set()

    def _run_stage(self, name: str, ips: list[str], worker, concurrency: int):
        self.store.stage_start(name)
        if not ips:
            self.emit("log", f"{name}：没有待处理记录，标记为完成（0 条）")
            self.store.stage_finish(name, 0)
            return True
        self.emit("stage", name)
        concurrency = max(1, concurrency)
        self.emit("log", f"{name}：开始处理 {len(ips)} 个 IP，并发 {concurrency}")
        completed = 0
        errors = 0
        next_index = 0
        futures: dict[concurrent.futures.Future, str] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            while next_index < len(ips) or futures:
                if self.stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    self.emit("log", f"{name}：收到停止请求，保留已提交检查点")
                    return False

                # Pause prevents new submissions. Existing requests are allowed to finish
                # and are committed before the runner waits for the user to resume.
                if self.pause_event.is_set():
                    while next_index < len(ips) and len(futures) < concurrency:
                        ip = ips[next_index]
                        next_index += 1
                        futures[pool.submit(worker, ip)] = ip

                if not futures:
                    if next_index >= len(ips):
                        break
                    self.pause_event.wait(0.2)
                    continue

                done, _ = concurrent.futures.wait(futures, timeout=0.2,
                                                   return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    ip = futures.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        errors += 1
                        result = {self._failure_field(name): "error", self._failure_error(name): str(exc)[:240]}
                    self.store.save_result(ip, result)
                    completed += 1
                    if completed % 10 == 0 or completed == len(ips):
                        self.emit("progress", (name, completed, len(ips)))
                    if completed % 100 == 0:
                        self.store.write_stage_file(name)

        if self.stop_event.is_set():
            return False
        self.store.stage_finish(name, completed)
        self.emit("log", f"{name}：完成 {completed} 个，异常 {errors}")
        return True

    @staticmethod
    def _failure_field(stage: str) -> str:
        return {"port": "port_status", "http": "http_status", "tls": "tls_status", "ping": "ping_status", "tcping": "tcping_status", "route": "asn_info_status", "speed": "vless_status"}.get(stage, "port_status")

    @staticmethod
    def _failure_error(stage: str) -> str:
        return {"port": "port_error", "http": "http_error", "tls": "tls_error", "ping": "ping_error", "tcping": "tcping_error", "route": "route_error", "speed": "vless_error"}.get(stage, "port_error")

    def run(self):
        try:
            timeout = float(self.cfg.get("timeout", 2.0))
            scan_workers = int(self.cfg.get("scan_workers", 100))
            speed_workers = int(self.cfg.get("speed_workers", 1))
            speed_timeout = float(self.cfg.get("speed_timeout", 15))
            vless_uri = self.cfg.get("vless_uri", "").strip()
            vless = parse_vless(vless_uri) if vless_uri else None
            legacy_template = legacy_tester.parse_vless_link(vless_uri) if vless_uri else None
            sni = (vless["query"].get("sni") or vless["host"]) if vless else self.cfg.get("sni", "")
            host = (vless["query"].get("host") or sni) if vless else sni
            stages = [
                ("port", lambda: self.store.pending_ips("port"), lambda ip: tcp_probe(ip, timeout), scan_workers),
                ("http", lambda: self.store.pending_ips("http"), lambda ip: http_cleartext_probe(ip, timeout), scan_workers),
                ("tls", lambda: self.store.pending_ips("tls"), lambda ip: tls_probe(ip, timeout, sni, host), max(1, scan_workers // 2)),
                ("route", lambda: self.store.pending_ips("route", only_candidates=bool(self.cfg.get("only_cf_candidates", True))), route_info_probe, 4),
            ]
            for name, get_ips, fn, concurrency in stages:
                if self.stop_event.is_set():
                    self.emit("done", "stopped")
                    return
                if not self.wait_active():
                    self.emit("done", "paused")
                    return
                # Read this stage's inputs only after the preceding stage has committed.
                ips = get_ips()
                if ips:
                    ok = self._run_stage(name, ips, fn, concurrency)
                    if not ok:
                        self.emit("done", "paused" if not self.stop_event.is_set() else "stopped")
                        return
                else:
                    self.store.stage_finish(name, 0)
            if vless_uri:
                xray_path = self.cfg.get("xray_path", "")
                if not xray_path or not Path(xray_path).is_file():
                    self.emit("log", "未找到 xray.exe：已完成 IP/CF/TLS 检测；VLESS 阶段暂未执行。请设置 Xray 路径后继续。")
                    self.emit("done", "needs_xray")
                    return
                only_cf = bool(self.cfg.get("only_cf_candidates", True))
                ips = self.store.pending_ips("speed", only_candidates=only_cf)
                if ips:
                    # Validate precisely the same config format used by CFIPTester 0.1.0
                    # before launching any candidate processes.
                    valid, detail = legacy_tester.validate_xray_config(xray_path, legacy_template, ips[0])
                    if not valid:
                        self.emit("log", "旧版 CFIPTester 测速引擎的 Xray 配置校验失败：" + detail)
                        self.emit("done", "error")
                        return
                def speed_worker(ip: str):
                    result = legacy_tester.test_one_ip(
                        ip, xray_path, legacy_template, self.cfg.get("speed_url", DEFAULT_SPEED_URL),
                        max(5, int(speed_timeout)), self.stop_event
                    )
                    # Previous tester measures the complete file from first payload byte
                    # until download completion. Its speed unit is decimal MB/s.
                    return {
                        "vless_status": "success" if result.get("ok") else "failed",
                        "speed_mbps": round(float(result["speed"]), 3) if result.get("ok") and result.get("speed") is not None else 0.0,
                        "peak_mbps": None,
                        "download_bytes": int(result.get("bytes") or 0),
                        "ttfb_ms": float(result["latency"]) if result.get("latency") is not None else None,
                        "speed_seconds": None,
                        "speed_requests": 1 if result.get("ok") else 0,
                        "vless_error": str(result.get("error") or "")[:400],
                    }
                if ips:
                    ok = self._run_stage("speed", ips, speed_worker, speed_workers)
                    if not ok:
                        self.emit("done", "paused" if not self.stop_event.is_set() else "stopped")
                        return
                else:
                    self.store.stage_finish("speed", 0)
            else:
                self.emit("log", "没有填写 VLESS 模板，已完成 443 / CF / TLS / ASN-BGP 检测；测速阶段跳过。")
            self.emit("done", "completed")
        except Exception as exc:
            self.store.add_log("ERROR", str(exc))
            self.emit("log", f"任务异常：{exc}")
            self.emit("done", "error")


class ManualStageRunner(ScanRunner):
    """Run exactly one user-selected stage; every stage is separately resumable."""
    def __init__(self, store: TaskStore, config: dict[str, Any], emit, mode: str, stage: str):
        super().__init__(store, config, emit)
        self.mode = mode
        self.stage_name = stage

    def run(self):
        stage = self.stage_name
        try:
            cfg = self.cfg
            timeout = float(cfg.get("timeout", 1.5))
            scan_workers = max(1, min(800, int(cfg.get("scan_workers", 300))))
            probe_workers = max(1, min(300, int(cfg.get("probe_workers", 100))))
            if stage == "port":
                if self.mode != "local":
                    raise ValueError("Shodan 模式已通过导入结果确认 443，不需要重复扫描")
                ips = self.store.pending_ips("port")
                worker = lambda ip: tcp_probe(ip, timeout)
                concurrency = scan_workers
            elif stage == "http":
                ips = self.store.pending_ips("http")
                sni = (cfg.get("sni") or "").strip()
                host = sni
                uri = (cfg.get("vless_uri") or "").strip()
                if uri:
                    try:
                        v = parse_vless(uri)
                        sni = v["query"].get("sni") or v["host"]
                        host = v["query"].get("host") or sni
                    except Exception:
                        pass
                def worker(ip):
                    result = http_cleartext_probe(ip, timeout)
                    # On confirmed HTTP candidates, collect TLS/trace diagnostics only.
                    # TLS data supplements the row but does not override the HTTP hit rule.
                    if result.get("cf_candidate"):
                        tls = tls_probe(ip, max(timeout, 2.0), sni, host)
                        tls.pop("cf_candidate", None)
                        result.update(tls)
                    return result
                concurrency = scan_workers
            elif stage == "ping":
                ips = self.store.pending_ips("ping")
                count = int(cfg.get("ping_count", 3))
                ping_timeout = float(cfg.get("ping_timeout", 1.0))
                worker = lambda ip: ping_probe(ip, count, ping_timeout)
                concurrency = probe_workers
            elif stage == "tcping":
                ips = self.store.pending_ips("tcping")
                count = int(cfg.get("tcping_count", 5))
                tcp_timeout = float(cfg.get("tcping_timeout", 1.5))
                worker = lambda ip: tcping_probe(ip, count, tcp_timeout)
                concurrency = probe_workers
            elif stage == "speed":
                uri = (cfg.get("vless_uri") or "").strip()
                if not uri:
                    raise ValueError("请先填写 VLESS 模板")
                xray_path = cfg.get("xray_path", "")
                if not xray_path or not Path(xray_path).is_file():
                    raise FileNotFoundError("没有找到 xray.exe，请先下载或选择 Xray-core")
                legacy_template = legacy_tester.parse_vless_link(uri)
                ips = self.store.pending_ips("speed", only_candidates=True)
                if ips:
                    valid, detail = legacy_tester.validate_xray_config(xray_path, legacy_template, ips[0])
                    if not valid:
                        raise RuntimeError("Xray 配置校验失败：" + detail)
                speed_timeout = max(5, int(cfg.get("speed_timeout", 30)))
                url = cfg.get("speed_url", DEFAULT_SPEED_URL)
                def worker(ip):
                    result = legacy_tester.test_one_ip(ip, xray_path, legacy_template, url, speed_timeout, self.stop_event)
                    return {"vless_status": "success" if result.get("ok") else "failed",
                            "speed_mbps": round(float(result["speed"]), 3) if result.get("ok") and result.get("speed") is not None else 0.0,
                            "peak_mbps": None, "download_bytes": int(result.get("bytes") or 0),
                            "ttfb_ms": float(result["latency"]) if result.get("latency") is not None else None,
                            "speed_seconds": None, "speed_requests": 1 if result.get("ok") else 0,
                            "vless_error": str(result.get("error") or "")[:400]}
                concurrency = max(1, min(8, int(cfg.get("speed_workers", 1))))
            elif stage == "route":
                limit = 0
                if self.mode == "shodan":
                    limit = max(1, min(1000, int(cfg.get("asn_limit", 30))))
                ips = self.store.pending_ips("route", only_candidates=True, limit=limit or None)
                worker = route_info_probe
                concurrency = min(8, max(1, int(cfg.get("route_workers", 4))))
            else:
                raise ValueError(f"未知步骤：{stage}")

            self.store.set_meta("active_stage", stage)
            self.store.set_meta("task_mode", self.mode)
            if stage == "port" and not ips:
                self.emit("log", "443 扫描：没有待处理 IP")
            self.emit("log", f"开始步骤：{self.stage_label(stage)}；待处理 {len(ips):,} 个 IP")
            ok = self._run_stage(stage, ips, worker, concurrency)
            if not ok:
                state = "stopped" if self.stop_event.is_set() else "paused"
            else:
                state = "completed"
                self.store.set_meta("last_completed_stage", stage)
                self.store.set_meta("active_stage", "")
            self.emit("done", (stage, state))
        except Exception as exc:
            self.store.add_log("ERROR", f"{stage}: {exc}")
            self.emit("log", f"{self.stage_label(stage)}失败：{exc}")
            self.emit("done", (stage, "error"))

    @staticmethod
    def stage_label(stage: str) -> str:
        return {"port": "扫描 443", "http": "CF 命中检测", "ping": "PING", "tcping": "TCPING", "speed": "VLESS 实际测速", "route": "ASN / BGP 查询"}.get(stage, stage)

# ----------------------------- Xray downloader / exports -----------------------------

def find_xray() -> str:
    candidates = [Path(__file__).resolve().parent / "xray.exe", APP_DIR / "xray" / "xray.exe", Path.cwd() / "xray.exe"]
    for p in candidates:
        if p.exists():
            return str(p)
    return ""


def download_xray(destination: Path, progress_cb=None) -> Path:
    api = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "CF-IP-Finder/0.1.2", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        release = json.load(resp)
    assets = release.get("assets", [])
    wanted = None
    for asset in assets:
        name = asset.get("name", "")
        if re.fullmatch(r"Xray-windows-64\.zip", name, re.I):
            wanted = asset
            break
    if not wanted:
        raise RuntimeError("GitHub 最新版未找到 Xray-windows-64.zip，请手动下载 Xray-core")
    destination.mkdir(parents=True, exist_ok=True)
    zip_path = destination / "xray_windows_64.zip"
    req = urllib.request.Request(wanted["browser_download_url"], headers={"User-Agent": "CF-IP-Finder/0.1.2"})
    with urllib.request.urlopen(req, timeout=60) as resp, zip_path.open("wb") as out:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
            done += len(chunk)
            if progress_cb:
                progress_cb(done, total)
    with zipfile.ZipFile(zip_path) as zf:
        exe_name = next((n for n in zf.namelist() if n.lower().endswith("xray.exe")), None)
        if not exe_name:
            raise RuntimeError("下载包中没有找到 xray.exe")
        target = destination / "xray.exe"
        with zf.open(exe_name) as src, target.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    with contextlib.suppress(Exception):
        zip_path.unlink()
    return target


def export_results(store: TaskStore, output_dir: Path, base_name: str, vless_uri: str = "") -> dict[str, Path]:
    rows = store.all_rows()
    rows.sort(key=lambda r: (0 if r["vless_status"] == "success" else 1,
                             -(r["speed_mbps"] or 0) if r["vless_status"] == "success" else 0,
                             r["seq"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / f"{base_name}_完整结果.csv"
    fields = ["rank", "ip", "port_status", "port_source", "port_ms", "http_status", "http_status_line", "http_server", "cf_ray", "cf_candidate", "cf_score",
              "tls_status", "tls_ms", "tls_version", "tls_cipher", "tls_server", "tls_trace_match",
              "ping_status", "ping_ms", "ping_min_ms", "ping_max_ms", "ping_loss_pct", "ping_replies", "ping_error",
              "tcping_status", "tcping_ms", "tcping_min_ms", "tcping_max_ms", "tcping_success_pct", "tcping_successes", "tcping_error",
              "vless_status", "download_speed_MB_s", "ttfb_ms", "download_bytes",
              "asn", "organization", "bgp_prefix", "route_source", "route_error", "vless_error"]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        rank = 0
        for r in rows:
            d = dict(r)
            d["download_speed_MB_s"] = d.get("speed_mbps")
            if d.get("vless_status") == "success":
                rank += 1
            d.update({"rank": rank if d.get("vless_status") == "success" else ""})
            writer.writerow(d)

    good = [r for r in rows if r["vless_status"] == "success"]
    good.sort(key=lambda r: (-(r["speed_mbps"] or 0), r["ttfb_ms"] or 999999))
    ip_path = output_dir / f"{base_name}_有效IP.txt"
    atomic_write(ip_path, "\n".join(r["ip"] for r in good) + ("\n" if good else ""))

    # Export the exact rows marked as CF candidates in the GUI, independent of VLESS success.
    cf_hits = [r for r in rows if int(r["cf_candidate"] or 0) == 1]
    cf_hits.sort(key=lambda r: (-(r["cf_score"] or 0), r["port_ms"] or 999999, r["seq"]))
    cf_path = output_dir / f"{base_name}_CF命中IP.txt"
    atomic_write(cf_path, "\n".join(r["ip"] for r in cf_hits) + ("\n" if cf_hits else ""))

    # Keep the Shodan-style HTTP 400 + Cloudflare-text subset separate for easy comparison.
    cf400 = [r for r in rows if int(r["http_status"] or 0) == 400 and int(r["cf_text_match"] or 0) == 1]
    cf400.sort(key=lambda r: (-(r["cf_score"] or 0), r["port_ms"] or 999999, r["seq"]))
    cf400_path = output_dir / f"{base_name}_CF-400命中IP.txt"
    atomic_write(cf400_path, "\n".join(r["ip"] for r in cf400) + ("\n" if cf400 else ""))

    ret = {"csv": csv_path, "ips": ip_path, "cf_candidates": cf_path, "cf_400": cf400_path}
    if vless_uri:
        vless_path = output_dir / f"{base_name}_有效VLESS.txt"
        lines = [replace_vless_host(vless_uri, r["ip"]) for r in good]
        atomic_write(vless_path, "\n".join(lines) + ("\n" if lines else ""))
        ret["vless"] = vless_path
    json_path = output_dir / f"{base_name}_完整数据.json"
    atomic_write(json_path, json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
    ret["json"] = json_path
    return ret


def export_cf_candidates(store: TaskStore, path: Path) -> int:
    rows = [r for r in store.all_rows() if int(r["cf_candidate"] or 0) == 1]
    rows.sort(key=lambda r: (-(r["cf_score"] or 0), r["port_ms"] or 999999, r["seq"]))
    atomic_write(path, "\n".join(r["ip"] for r in rows) + ("\n" if rows else ""))
    return len(rows)


def set_windows_awake(enabled: bool):
    """Prevent Windows system sleep while a scan is running; display may still turn off."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ES_CONTINUOUS = 0x80000000
        ES_SYSTEM_REQUIRED = 0x00000001
        flags = ES_CONTINUOUS | (ES_SYSTEM_REQUIRED if enabled else 0)
        ctypes.windll.kernel32.SetThreadExecutionState(flags)
    except Exception:
        pass

# ----------------------------- Tk UI -----------------------------

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except Exception:  # allows --self-test on systems without Tk
    tk = None

class App:
    STAGES = [
        ("port", "1  扫描 443", "仅本地网段模式"),
        ("http", "2  查 CF 命中", "明文 HTTP / 443，识别 CF-400、Server、CF-RAY"),
        ("ping", "3  PING", "ICMP 平均延迟、最小/最大值、丢包"),
        ("tcping", "4  TCPING", "重复连接 TCP 443，计算平均/最小/最大耗时"),
        ("speed", "5  VLESS 测速", "复用 CFIPTester 旧版完整文件测速引擎"),
        ("route", "6  查询 ASN", "Shodan 默认取测速最快前 N 名；本地模式查询全部命中项"),
    ]

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1380x960")
        self.root.minsize(1120, 780)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.events: queue.Queue = queue.Queue()
        self.runner: ManualStageRunner | None = None
        self.runner_thread: threading.Thread | None = None
        self.store: TaskStore | None = None
        self.task_folder: Path | None = None
        self.last_config: dict[str, Any] = {}
        self.current_stage = ""
        self.sort_column = "speed"
        self.sort_desc = True
        self.only_hits_var = None
        self._build_ui()
        self.xray_var.set(find_xray())
        self._load_latest_task()
        self.root.after(150, self._poll_events)

    def _build_ui(self):
        style = ttk.Style()
        with contextlib.suppress(Exception):
            style.theme_use("vista" if os.name == "nt" else "clam")
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="CF IP Finder", font=("Microsoft YaHei UI", 20, "bold")).pack(side="left")
        ttk.Label(header, text=f"v{APP_VERSION}  |  手动分阶段 · Shodan 导入 · 断点恢复 · VLESS 实测", foreground="#666").pack(side="left", padx=16, pady=(8, 0))

        mode_frame = ttk.LabelFrame(outer, text="工作模式", padding=8)
        mode_frame.pack(fill="x", pady=(10, 5))
        self.mode_var = tk.StringVar(value="local")
        ttk.Radiobutton(mode_frame, text="本地网段模式（CIDR / 起止 IP）", variable=self.mode_var, value="local", command=self._mode_changed).pack(side="left", padx=(4, 18))
        ttk.Radiobutton(mode_frame, text="Shodan 导入模式（IP 列表 / CSV）", variable=self.mode_var, value="shodan", command=self._mode_changed).pack(side="left")
        self.mode_hint_var = tk.StringVar(value="本地模式：先创建任务，再按步骤点击执行。")
        ttk.Label(mode_frame, textvariable=self.mode_hint_var, foreground="#555").pack(side="right", padx=5)

        top = ttk.Frame(outer)
        top.pack(fill="x", pady=5)
        left = ttk.LabelFrame(top, text="目标列表：每行一个网段 / 范围 / IP", padding=7)
        self.target_frame = left
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.targets_text = tk.Text(left, height=6, wrap="none", font=("Consolas", 10), undo=True)
        self.targets_text.pack(side="left", fill="both", expand=True)
        yscroll = ttk.Scrollbar(left, orient="vertical", command=self.targets_text.yview)
        yscroll.pack(side="right", fill="y")
        self.targets_text.configure(yscrollcommand=yscroll.set)
        self.targets_text.insert("1.0", "65.49.236.0/22\n")
        right = ttk.LabelFrame(top, text="VLESS 模板（测速时使用，可暂时留空）", padding=7)
        right.pack(side="left", fill="both", expand=True)
        self.vless_text = tk.Text(right, height=6, wrap="word", font=("Consolas", 9), undo=True)
        self.vless_text.pack(fill="both", expand=True)

        target_actions = ttk.Frame(outer)
        target_actions.pack(fill="x", pady=(0, 5))
        self.create_btn = ttk.Button(target_actions, text="创建任务（不自动开始）", command=self.start_new_task)
        self.create_btn.pack(side="left")
        self.import_csv_btn = ttk.Button(target_actions, text="导入 Shodan CSV", command=self.import_shodan_csv)
        self.import_csv_btn.pack(side="left", padx=6)
        ttk.Button(target_actions, text="恢复上次任务", command=self.resume_task).pack(side="left", padx=6)
        ttk.Button(target_actions, text="打开任务目录", command=self.open_task_folder).pack(side="left", padx=6)
        self.task_status_var = tk.StringVar(value="尚未创建任务")
        ttk.Label(target_actions, textvariable=self.task_status_var, foreground="#555").pack(side="right")

        settings = ttk.LabelFrame(outer, text="各阶段参数（只影响之后启动的步骤）", padding=8)
        settings.pack(fill="x", pady=5)
        self.scan_workers_var = tk.StringVar(value="300")
        self.probe_workers_var = tk.StringVar(value="100")
        self.timeout_var = tk.StringVar(value="1.5")
        self.ping_count_var = tk.StringVar(value="3")
        self.ping_timeout_var = tk.StringVar(value="1")
        self.tcping_count_var = tk.StringVar(value="5")
        self.tcping_timeout_var = tk.StringVar(value="1.5")
        self.speed_workers_var = tk.StringVar(value="1")
        self.speed_timeout_var = tk.StringVar(value="30")
        self.asn_limit_var = tk.StringVar(value="30")
        self.speed_url_var = tk.StringVar(value=DEFAULT_SPEED_URL)
        self.sni_var = tk.StringVar(value="")
        self.xray_var = tk.StringVar(value="")
        entries = [
            ("扫描并发", self.scan_workers_var, 6), ("PING/TCP 并发", self.probe_workers_var, 6),
            ("连接超时 s", self.timeout_var, 6), ("PING 次数", self.ping_count_var, 5), ("PING 超时 s", self.ping_timeout_var, 5),
            ("TCPING 次数", self.tcping_count_var, 5), ("TCPING 超时 s", self.tcping_timeout_var, 5),
            ("测速并发", self.speed_workers_var, 5), ("测速超时 s", self.speed_timeout_var, 6),
            ("Shodan ASN 前 N", self.asn_limit_var, 6),
        ]
        for i, (label, var, width) in enumerate(entries):
            row, col = divmod(i, 5)
            ttk.Label(settings, text=label).grid(row=row, column=col*2, sticky="w", padx=(5, 2), pady=3)
            ttk.Entry(settings, textvariable=var, width=width).grid(row=row, column=col*2+1, sticky="w", padx=(0, 8), pady=3)
        ttk.Label(settings, text="测速 URL").grid(row=2, column=0, sticky="w", padx=(5, 2), pady=(7, 2))
        ttk.Entry(settings, textvariable=self.speed_url_var).grid(row=2, column=1, columnspan=7, sticky="ew", pady=(7, 2))
        ttk.Label(settings, text="Xray-core").grid(row=2, column=8, sticky="e", padx=(8, 2), pady=(7, 2))
        ttk.Entry(settings, textvariable=self.xray_var).grid(row=2, column=9, columnspan=3, sticky="ew", pady=(7, 2))
        ttk.Button(settings, text="选择", command=self._browse_xray).grid(row=2, column=12, padx=3, pady=(7, 2))
        ttk.Button(settings, text="下载 Xray", command=self._download_xray).grid(row=2, column=13, padx=3, pady=(7, 2))
        for c in range(14):
            if c in (1, 3, 5, 7, 9, 11):
                settings.columnconfigure(c, weight=1)

        stages = ttk.LabelFrame(outer, text="分阶段操作：每一步单独点击，完成后再决定下一步", padding=8)
        stages.pack(fill="x", pady=5)
        self.stage_buttons: dict[str, ttk.Button] = {}
        self.stage_status_vars: dict[str, tk.StringVar] = {}
        for index, (stage, label, desc) in enumerate(self.STAGES):
            row, col = divmod(index, 3)
            cell = ttk.Frame(stages, padding=5, relief="groove")
            cell.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
            ttk.Label(cell, text=label, font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")
            ttk.Label(cell, text=desc, foreground="#666", wraplength=350).pack(anchor="w", pady=(2, 5))
            btn = ttk.Button(cell, text="执行此步骤", command=lambda st=stage: self.run_stage(st))
            btn.pack(side="left")
            self.stage_buttons[stage] = btn
            status = tk.StringVar(value="等待")
            self.stage_status_vars[stage] = status
            ttk.Label(cell, textvariable=status, foreground="#555").pack(side="left", padx=8)
            stages.columnconfigure(col, weight=1)

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(2, 4))
        self.pause_btn = ttk.Button(controls, text="暂停当前步骤", command=self.pause_task, state="disabled")
        self.pause_btn.pack(side="left")
        self.stop_btn = ttk.Button(controls, text="停止当前步骤", command=self.stop_task, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        ttk.Button(controls, text="导出全部结果", command=self.export).pack(side="left", padx=6)
        ttk.Button(controls, text="导出 CF 命中 IP", command=self.export_cf_hits).pack(side="left", padx=6)
        self.only_hits_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="仅显示 CF 命中", variable=self.only_hits_var, command=self._render_results).pack(side="left", padx=12)
        self.status_var = tk.StringVar(value="就绪：创建任务后，逐步点击各阶段按钮。")
        ttk.Label(controls, textvariable=self.status_var, foreground="#555").pack(side="right")

        progress_frame = ttk.LabelFrame(outer, text="当前步骤进度", padding=7)
        progress_frame.pack(fill="x", pady=4)
        self.stage_var = tk.StringVar(value="等待开始")
        ttk.Label(progress_frame, textvariable=self.stage_var).pack(anchor="w")
        self.progress = ttk.Progressbar(progress_frame, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=4)
        self.counts_var = tk.StringVar(value="目标 0 | 443 开放 0 | CF 命中 0 | PING 0 | TCPING 0 | VLESS 成功 0 | ASN 0")
        ttk.Label(progress_frame, textvariable=self.counts_var).pack(anchor="w")

        result_frame = ttk.LabelFrame(outer, text="结果表：点击任意表头切换升序 / 降序；缺失值始终放在最后", padding=6)
        result_frame.pack(fill="both", expand=True, pady=4)
        cols = ("ip", "port", "cf", "cfscore", "ping", "loss", "tcping", "tcpok", "speed", "ttfb", "asn", "server")
        self.column_fields = {"ip": ("ip", False), "port": ("port_ms", True), "cf": ("cf_candidate", True),
                              "cfscore": ("cf_score", True), "ping": ("ping_ms", True), "loss": ("ping_loss_pct", True), "tcping": ("tcping_ms", True),
                              "tcpok": ("tcping_success_pct", True), "speed": ("speed_mbps", True), "ttfb": ("ttfb_ms", True),
                              "asn": ("asn", False), "server": ("http_server", False)}
        self.column_labels = {"ip": "IP", "port": "443 ms", "cf": "CF 命中", "cfscore": "CF 分", "ping": "PING ms", "loss": "丢包率 %",
                              "tcping": "TCPING ms", "tcpok": "TCP 成功率 %", "speed": "VLESS MB/s", "ttfb": "TTFB ms", "asn": "ASN / 组织", "server": "Server / CF-RAY"}
        self.tree = ttk.Treeview(result_frame, columns=cols, show="headings", height=13)
        widths = {"ip": 125, "port": 75, "cf": 75, "cfscore": 65, "ping": 80, "loss": 75, "tcping": 90, "tcpok": 90, "speed": 100, "ttfb": 75, "asn": 190, "server": 220}
        for c in cols:
            self._update_heading(c)
            self.tree.column(c, width=widths[c], anchor="w" if c in ("ip", "asn", "server") else "center")
        self.tree.pack(side="left", fill="both", expand=True)
        ysb = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        ysb.pack(side="right", fill="y")
        xsb = ttk.Scrollbar(outer, orient="horizontal", command=self.tree.xview)
        xsb.pack(fill="x")
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.bind("<Double-1>", self._copy_selected_ip)

        log_frame = ttk.LabelFrame(outer, text="运行日志 / 阶段记录", padding=6)
        log_frame.pack(fill="both", expand=True, pady=(3, 0))
        self.log_text = tk.Text(log_frame, height=5, wrap="word", state="disabled", font=("Consolas", 9))
        self.log_text.pack(side="left", fill="both", expand=True)
        lsb = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        lsb.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=lsb.set)
        self._mode_changed()

    def _update_heading(self, col):
        if not hasattr(self, "tree"):
            return
        arrow = " ↑" if self.sort_column == col and not self.sort_desc else (" ↓" if self.sort_column == col and self.sort_desc else " ↕")
        self.tree.heading(col, text=self.column_labels[col] + arrow, command=lambda c=col: self._sort_by(c))

    def _sort_by(self, col):
        if self.sort_column == col:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column = col
            self.sort_desc = (col in ("cf", "speed", "tcpok"))
        for c in self.column_fields:
            self._update_heading(c)
        self._render_results()

    def _mode_changed(self):
        mode = self.mode_var.get()
        if mode == "shodan":
            self.mode_hint_var.set("Shodan 模式：导入结果视为已确认 443；不自动查 ASN。")
            self.target_frame.configure(text="Shodan IP 列表：每行一个 IP，支持粘贴 CSV / JSON")
            self.import_csv_btn.configure(state="normal")
            self.only_hits_var.set(True)
            self.targets_label = "Shodan IP 列表 / CSV"
        else:
            self.mode_hint_var.set("本地模式：输入 CIDR / 起止 IP；各步骤同样由你手动启动。")
            self.target_frame.configure(text="目标列表：每行一个 CIDR / 起止 IP / 单 IP")
            self.import_csv_btn.configure(state="disabled")
            self.only_hits_var.set(False)
            self.targets_label = "CIDR / 起止 IP / 单 IP"
        # Update the target frame label without rebuilding the input control.
        for child in self.root.winfo_children():
            pass
        self._render_results()
        self._update_stage_buttons()

    def _log(self, message: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _config_from_ui(self) -> dict[str, Any]:
        try:
            scan_workers = max(1, min(800, int(self.scan_workers_var.get())))
            probe_workers = max(1, min(300, int(self.probe_workers_var.get())))
            timeout = max(0.3, min(30.0, float(self.timeout_var.get())))
            ping_count = max(1, min(10, int(self.ping_count_var.get())))
            ping_timeout = max(0.2, min(10.0, float(self.ping_timeout_var.get())))
            tcping_count = max(1, min(20, int(self.tcping_count_var.get())))
            tcping_timeout = max(0.2, min(15.0, float(self.tcping_timeout_var.get())))
            speed_workers = max(1, min(8, int(self.speed_workers_var.get())))
            speed_timeout = max(5, min(300, int(self.speed_timeout_var.get())))
            asn_limit = max(1, min(1000, int(self.asn_limit_var.get())))
        except ValueError as exc:
            raise ValueError("并发、次数和超时必须填写有效数字") from exc
        vless_uri = self.vless_text.get("1.0", "end").strip()
        if vless_uri:
            parse_vless(vless_uri)
            legacy_tester.parse_vless_link(vless_uri)
        url = self.speed_url_var.get().strip() or DEFAULT_SPEED_URL
        p = urllib.parse.urlsplit(url)
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            raise ValueError("测速 URL 必须是有效的 http:// 或 https:// 地址")
        return {"scan_workers": scan_workers, "probe_workers": probe_workers, "timeout": timeout,
                "ping_count": ping_count, "ping_timeout": ping_timeout,
                "tcping_count": tcping_count, "tcping_timeout": tcping_timeout,
                "speed_workers": speed_workers, "speed_timeout": speed_timeout, "asn_limit": asn_limit,
                "speed_url": url, "vless_uri": vless_uri, "sni": self.sni_var.get().strip(),
                "xray_path": self.xray_var.get().strip(), "only_cf_candidates": True,
                "target_text": self.targets_text.get("1.0", "end").strip(), "mode": self.mode_var.get()}

    def import_shodan_csv(self):
        path = filedialog.askopenfilename(title="选择 Shodan 导出文件", filetypes=[("CSV / Text", "*.csv *.txt *.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
            targets = parse_shodan_targets(content)
            self.targets_text.delete("1.0", "end")
            self.targets_text.insert("1.0", "\n".join(ip for ip, _ in targets))
            self._log(f"已导入 Shodan 文件：{len(targets):,} 个唯一 IPv4，来源 {Path(path).name}")
        except Exception as exc:
            messagebox.showerror("Shodan 导入失败", str(exc))

    def start_new_task(self):
        if self.runner_thread and self.runner_thread.is_alive():
            messagebox.showwarning(APP_NAME, "当前步骤仍在运行")
            return
        try:
            mode = self.mode_var.get()
            raw = self.targets_text.get("1.0", "end")
            targets = parse_targets(raw) if mode == "local" else parse_shodan_targets(raw)
            config = self._config_from_ui()
        except Exception as exc:
            messagebox.showerror("输入检查", str(exc))
            return
        if len(targets) > 4096 and not messagebox.askyesno("批量任务提醒", f"本次共 {len(targets):,} 个 IPv4 地址。请确认这些目标属于你获准测试的范围，并且目标网络允许此类检测。\n\n继续创建任务？"):
            return
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        folder = APP_DIR / "tasks" / f"task_{mode}_{stamp}"
        self._create_task(folder, targets, config)

    def _create_task(self, folder: Path, targets, config):
        folder.mkdir(parents=True, exist_ok=True)
        atomic_write(folder / "task_config.json", json.dumps(config, ensure_ascii=False, indent=2))
        store = TaskStore(folder, create=True)
        store.add_targets(targets)
        store.set_meta("created_at", utc_now())
        store.set_meta("app_version", APP_VERSION)
        store.set_meta("task_mode", config.get("mode", "local"))
        store.add_log("INFO", f"创建任务：{len(targets)} 个目标；模式 {config.get('mode')}")
        if config.get("mode") == "shodan":
            store.mark_shodan_imported()
            store.add_log("INFO", "Shodan 导入：将端口 443 标记为已由 Shodan 确认，跳过本地 443 扫描。")
        self._set_store(store, folder, config)
        self.status_var.set("任务已创建；请点击第 2 步查 CF 命中。" if config.get("mode") == "shodan" else "任务已创建；请点击第 1 步扫描 443。")
        self.stage_var.set("任务已创建，尚未执行任何检测步骤")
        self._update_stage_buttons()

    def _set_store(self, store, folder, config):
        if self.store:
            with contextlib.suppress(Exception):
                self.store.close()
        self.store, self.task_folder, self.last_config = store, folder, config
        mode = config.get("mode") or store.get_meta("task_mode", "local")
        self.mode_var.set(mode)
        self._load_config_to_ui(config)
        if mode == "shodan":
            self.only_hits_var.set(True)
            self.sort_column, self.sort_desc = "cf", True
        else:
            self.only_hits_var.set(False)
            self.sort_column, self.sort_desc = "cf", True
        self._render_results()
        self._update_counts()
        self.task_status_var.set(folder.name)
        self._update_stage_buttons()

    def _load_latest_task(self):
        tasks_dir = APP_DIR / "tasks"
        if not tasks_dir.exists():
            return
        folders = sorted([p for p in tasks_dir.iterdir() if p.is_dir() and (p / "checkpoint.db").exists()], key=lambda p: p.stat().st_mtime, reverse=True)
        if not folders:
            return
        folder = folders[0]
        try:
            cfg_path = folder / "task_config.json"
            cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
            store = TaskStore(folder)
            cfg.setdefault("mode", store.get_meta("task_mode", "local"))
            self._set_store(store, folder, cfg)
            self._log(f"已载入上次任务：{folder.name}。每个步骤均可从 SQLite 检查点继续。")
        except Exception as exc:
            self._log(f"载入上次任务失败：{exc}")

    def _load_config_to_ui(self, cfg):
        self.targets_text.delete("1.0", "end")
        self.targets_text.insert("1.0", cfg.get("target_text", ""))
        self.vless_text.delete("1.0", "end")
        self.vless_text.insert("1.0", cfg.get("vless_uri", ""))
        self.speed_url_var.set(cfg.get("speed_url", DEFAULT_SPEED_URL))
        self.scan_workers_var.set(str(cfg.get("scan_workers", 300)))
        self.probe_workers_var.set(str(cfg.get("probe_workers", 100)))
        self.timeout_var.set(str(cfg.get("timeout", 1.5)))
        self.ping_count_var.set(str(cfg.get("ping_count", 3)))
        self.ping_timeout_var.set(str(cfg.get("ping_timeout", 1)))
        self.tcping_count_var.set(str(cfg.get("tcping_count", 5)))
        self.tcping_timeout_var.set(str(cfg.get("tcping_timeout", 1.5)))
        self.speed_workers_var.set(str(cfg.get("speed_workers", 1)))
        self.speed_timeout_var.set(str(cfg.get("speed_timeout", 30)))
        self.asn_limit_var.set(str(cfg.get("asn_limit", 30)))
        self.sni_var.set(cfg.get("sni", ""))
        self.xray_var.set(cfg.get("xray_path", find_xray()) or find_xray())
        self.mode_var.set(cfg.get("mode", "local"))
        self._mode_changed()

    def _prerequisite_message(self, stage):
        mode = self.last_config.get("mode", "local")
        order = ["port", "http", "ping", "tcping", "speed", "route"]
        if mode == "shodan":
            order = ["http", "ping", "tcping", "speed", "route"]
        if stage not in order:
            return ""
        idx = order.index(stage)
        for required in order[:idx]:
            if self.store.stage_status(required) != "completed":
                labels = {"port":"扫描 443", "http":"查 CF 命中", "ping":"PING", "tcping":"TCPING", "speed":"VLESS 测速"}
                return f"建议先完成前一步：{labels.get(required, required)}。\n\n仍要执行当前步骤吗？"
        return ""

    def run_stage(self, stage):
        if not self.store or not self.task_folder:
            messagebox.showinfo(APP_NAME, "请先创建或恢复任务")
            return
        if self.runner_thread and self.runner_thread.is_alive():
            messagebox.showwarning(APP_NAME, "当前步骤仍在运行，请先暂停或停止")
            return
        if stage == "port" and self.last_config.get("mode") == "shodan":
            messagebox.showinfo(APP_NAME, "Shodan 模式的 443 已在导入时标记，不需要重复扫描。")
            return
        warning = self._prerequisite_message(stage)
        if warning and not messagebox.askyesno("步骤顺序提醒", warning):
            return
        try:
            cfg = self._config_from_ui()
            cfg["target_text"] = self.last_config.get("target_text", "")
            cfg["mode"] = self.last_config.get("mode", self.mode_var.get())
            atomic_write(self.task_folder / "task_config.json", json.dumps(cfg, ensure_ascii=False, indent=2))
            self.last_config = cfg
        except Exception as exc:
            messagebox.showerror("参数检查", str(exc))
            return
        self._start_stage(stage)

    def _start_stage(self, stage):
        if not self.store:
            return
        self.current_stage = stage
        self.store.set_meta("active_stage", stage)
        self.runner = ManualStageRunner(self.store, self.last_config, lambda kind, data: self.events.put((kind, data)),
                                        self.last_config.get("mode", "local"), stage)
        def run_with_power_guard():
            set_windows_awake(True)
            try:
                self.runner.run()
            finally:
                set_windows_awake(False)
        self.runner_thread = threading.Thread(target=run_with_power_guard, daemon=True)
        self.runner_thread.start()
        self.pause_btn.configure(state="normal", text="暂停当前步骤")
        self.stop_btn.configure(state="normal")
        self.status_var.set(f"正在执行：{dict((k,v) for k,v,_ in self.STAGES).get(stage,stage)}")
        self.stage_var.set(f"当前步骤：{stage}")
        self._update_stage_buttons(running=stage)

    def resume_task(self):
        if self.runner_thread and self.runner_thread.is_alive():
            messagebox.showinfo(APP_NAME, "当前步骤仍在运行")
            return
        if not self.store:
            messagebox.showinfo(APP_NAME, "没有可恢复的任务")
            return
        stage = self.store.get_meta("active_stage", "")
        if not stage or stage not in dict((k, v) for k, v, _ in self.STAGES):
            # Find the first stage that still has pending data.
            mode = self.last_config.get("mode", "local")
            order = ["http", "ping", "tcping", "speed", "route"] if mode == "shodan" else ["port", "http", "ping", "tcping", "speed", "route"]
            stage = next((x for x in order if self._stage_has_pending(x)), "")
        if not stage:
            messagebox.showinfo(APP_NAME, "没有发现未完成的步骤。可以直接点击某个步骤进行补测。")
            return
        try:
            cfg = self._config_from_ui()
            cfg["mode"] = self.last_config.get("mode", "local")
            cfg["target_text"] = self.last_config.get("target_text", "")
            self.last_config = cfg
            self._start_stage(stage)
        except Exception as exc:
            messagebox.showerror("恢复任务", str(exc))

    def _stage_has_pending(self, stage):
        if not self.store:
            return False
        if stage == "port": return bool(self.store.pending_ips("port"))
        if stage == "http": return bool(self.store.pending_ips("http"))
        if stage in ("ping", "tcping", "speed"): return bool(self.store.pending_ips(stage))
        if stage == "route": return bool(self.store.pending_ips("route", only_candidates=True))
        return False

    def _update_stage_buttons(self, running=""):
        if not hasattr(self, "stage_buttons"):
            return
        mode = self.last_config.get("mode", self.mode_var.get()) if self.store else self.mode_var.get()
        for stage, label, _ in self.STAGES:
            btn = self.stage_buttons[stage]
            if stage == "port" and mode == "shodan":
                btn.configure(state="disabled", text="1  Shodan 已确认 443")
                continue
            if stage == "route":
                label = "6  查询 ASN（速度前 N）" if mode == "shodan" else "6  查询 ASN（全部命中）"
            if running == stage:
                btn.configure(state="disabled", text="执行中…")
            else:
                btn.configure(state="normal", text=label)
            if self.store:
                status = self.store.stage_status(stage)
                self.stage_status_vars[stage].set({"completed":"已完成", "running":"上次中断/运行中", "pending":"待执行"}.get(status, status))
            else:
                self.stage_status_vars[stage].set("等待")

    def pause_task(self):
        if not self.runner:
            return
        if self.runner.pause_event.is_set():
            self.runner.pause()
            self.pause_btn.configure(text="继续当前步骤")
            self.status_var.set("已请求暂停：在途 IP 完成并保存后停止派发")
        else:
            self.runner.resume()
            self.pause_btn.configure(text="暂停当前步骤")
            self.status_var.set("继续当前步骤")

    def stop_task(self):
        if self.runner:
            self.runner.stop()
            self.status_var.set("正在安全停止当前步骤…")

    def _finish_runner(self, payload):
        stage, state = payload
        self.pause_btn.configure(state="disabled", text="暂停当前步骤")
        self.stop_btn.configure(state="disabled")
        labels = {k: v for k, v, _ in self.STAGES}
        self.status_var.set(f"{labels.get(stage, stage)}：{ {'completed':'完成', 'paused':'已暂停，可继续', 'stopped':'已停止，可恢复', 'error':'失败，请查看日志'}.get(state,state)}")
        self.stage_var.set(self.status_var.get())
        if state == "completed":
            defaults = {"port": ("port", False), "http": ("cf", True), "ping": ("ping", False),
                        "tcping": ("tcping", False), "speed": ("speed", True), "route": ("speed", True)}
            self.sort_column, self.sort_desc = defaults.get(stage, (self.sort_column, self.sort_desc))
        self._update_stage_buttons()
        self._render_results()
        self._update_counts()
        self._log(self.status_var.get())

    def _update_counts(self):
        if self.store:
            c = self.store.counts()
            self.counts_var.set(f"目标 {c['total']:,} | 443 开放 {c['opened']:,} | CF 命中 {c['candidates']:,} | PING {c['pinged']:,} | TCPING {c['tcpinged']:,} | VLESS 成功 {c['good']:,} | ASN {c['asned']:,}")

    def _sort_value(self, row, col):
        field, numeric = self.column_fields[col]
        value = row[field]
        if col == "cf":
            value = int(row["cf_candidate"] or 0)
        elif col == "asn":
            value = " ".join(x for x in (row["asn"] or "", row["organization"] or "") if x)
        elif col == "server":
            value = row["http_server"] or row["cf_ray"] or row["tls_server"] or ""
        if value is None or value == "":
            return (1, 0)
        return (0, float(value) if numeric else str(value).lower())

    def _render_results(self):
        if not hasattr(self, "tree") or not self.store:
            return
        for item in self.tree.get_children():
            self.tree.delete(item)
        rows = self.store.all_rows()
        if self.only_hits_var.get():
            rows = [r for r in rows if int(r["cf_candidate"] or 0) == 1]
        present = [r for r in rows if self._sort_value(r, self.sort_column)[0] == 0]
        missing = [r for r in rows if self._sort_value(r, self.sort_column)[0] == 1]
        present.sort(key=lambda r: self._sort_value(r, self.sort_column)[1], reverse=self.sort_desc)
        rows = present + missing
        for r in rows[:10000]:
            cf = "命中" if r["cf_candidate"] else ("未命中" if r["http_status"] is not None else "待测")
            net = " ".join(x for x in (r["asn"] or "", r["organization"] or "") if x)
            server = r["http_server"] or r["cf_ray"] or r["tls_server"] or ""
            vals = (r["ip"], f"{r['port_ms']:.2f}" if r["port_ms"] is not None else (r["port_status"] or ""), cf,
                    str(r["cf_score"] or 0) if r["http_status"] is not None else "",
                    f"{r['ping_ms']:.2f}" if r["ping_ms"] is not None else (r["ping_status"] or ""),
                    f"{r['ping_loss_pct']:.1f}" if r["ping_loss_pct"] is not None else "",
                    f"{r['tcping_ms']:.2f}" if r["tcping_ms"] is not None else (r["tcping_status"] or ""),
                    f"{r['tcping_success_pct']:.1f}" if r["tcping_success_pct"] is not None else "",
                    f"{r['speed_mbps']:.3f}" if r["speed_mbps"] else (r["vless_status"] or ""),
                    f"{r['ttfb_ms']:.2f}" if r["ttfb_ms"] is not None else "", net, server)
            self.tree.insert("", "end", values=vals)
        for c in self.column_fields:
            self._update_heading(c)

    def export(self):
        if not self.store:
            messagebox.showinfo(APP_NAME, "没有任务结果可导出")
            return
        folder = filedialog.askdirectory(title="选择导出目录", initialdir=str(self.task_folder or APP_DIR))
        if not folder:
            return
        try:
            base = self.task_folder.name if self.task_folder else "cf_ip_finder"
            paths = export_results(self.store, Path(folder), base, self.last_config.get("vless_uri", ""))
            messagebox.showinfo("导出完成", "已生成：\n" + "\n".join(str(p) for p in paths.values()))
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))

    def export_cf_hits(self):
        if not self.store:
            messagebox.showinfo(APP_NAME, "当前没有任务结果")
            return
        path = filedialog.asksaveasfilename(title="导出 CF 命中 IP", initialdir=str(self.task_folder or APP_DIR),
                                            initialfile="CF命中IP.txt", defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        count = export_cf_candidates(self.store, Path(path))
        messagebox.showinfo(APP_NAME, f"已导出 {count} 个 CF 命中 IP：\n{path}")

    def open_task_folder(self):
        if not self.task_folder:
            return
        try:
            if os.name == "nt": os.startfile(self.task_folder)
            elif sys.platform == "darwin": subprocess.Popen(["open", str(self.task_folder)])
            else: subprocess.Popen(["xdg-open", str(self.task_folder)])
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def _browse_xray(self):
        path = filedialog.askopenfilename(title="选择 Xray 可执行文件", filetypes=[("Xray", "xray.exe"), ("All files", "*.*")])
        if path: self.xray_var.set(path)

    def _download_xray(self):
        self.status_var.set("正在从 Xray-core GitHub Releases 下载…")
        def worker():
            try:
                path = download_xray(APP_DIR / "xray")
                self.events.put(("xray", str(path)))
            except Exception as exc:
                self.events.put(("xray_error", str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _copy_selected_ip(self, _event=None):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0], "values")[0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.status_var.set(f"已复制 {ip}")

    def on_close(self):
        if self.runner and self.runner_thread and self.runner_thread.is_alive():
            if not messagebox.askyesno(APP_NAME, "当前步骤仍在运行。退出会中断未完成请求，但已提交记录会保留。确定退出？"):
                return
            self.runner.stop()
            self.status_var.set("正在保存检查点并退出…")
            self.pause_btn.configure(state="disabled")
            self.stop_btn.configure(state="disabled")
            self.root.after(150, self._finish_close_when_stopped)
            return
        if self.store:
            self.store.close()
        self.root.destroy()

    def _finish_close_when_stopped(self):
        if self.runner_thread and self.runner_thread.is_alive():
            self.root.after(200, self._finish_close_when_stopped)
            return
        if self.store:
            self.store.close()
        self.root.destroy()

    def _poll_events(self):
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == "log":
                    self._log(data)
                    if self.store: self.store.add_log("INFO", data)
                elif kind == "stage":
                    self.stage_var.set(f"当前步骤：{data}")
                elif kind == "progress":
                    name, done, total = data
                    self.progress.configure(value=100 * done / max(total, 1))
                    self.stage_var.set(f"{name}：{done:,} / {total:,}")
                    self._update_counts()
                    if done % 25 == 0 or done == total: self._render_results()
                elif kind == "done":
                    self._finish_runner(data)
                elif kind == "xray":
                    self.xray_var.set(data)
                    self.status_var.set("Xray-core 下载完成")
                    self._log(f"Xray-core 已安装：{data}")
                elif kind == "xray_error":
                    self.status_var.set("Xray 下载失败")
                    messagebox.showerror("Xray 下载失败", data)
        except queue.Empty:
            pass
        self.root.after(150, self._poll_events)

def self_test():
    full_range = parse_targets("65.49.236.0/22")
    assert len(full_range) == 1024 and full_range[0][0] == "65.49.236.0" and full_range[-1][0] == "65.49.239.255"
    targets = parse_targets("65.49.236.0/30\n65.49.236.2-65.49.236.4\n65.49.236.9")
    assert [x[0] for x in targets] == ["65.49.236.0", "65.49.236.1", "65.49.236.2", "65.49.236.3", "65.49.236.4", "65.49.236.9"]
    shodan = parse_shodan_targets("ip_str,port\n65.49.236.30,443\n65.49.237.84,443\n65.49.236.30,443")
    assert [x[0] for x in shodan] == ["65.49.236.30", "65.49.237.84"]
    uri = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?encryption=none&security=tls&sni=example.com&type=ws&host=cdn.example.com&path=%2Fws#test"
    v = parse_vless(uri)
    legacy_v = legacy_tester.parse_vless_link(uri)
    assert v["network"] == "ws" and v["query"]["sni"] == "example.com"
    legacy_cfg = legacy_tester.build_xray_config(legacy_v, "65.49.236.30", 10888)
    legacy_out = legacy_cfg["outbounds"][0]
    assert legacy_out["settings"]["address"] == "65.49.236.30"
    assert legacy_out["streamSettings"]["tlsSettings"]["serverName"] == "example.com"
    assert legacy_out["streamSettings"]["wsSettings"]["host"] == "cdn.example.com"
    assert legacy_out["streamSettings"]["wsSettings"]["path"] == "/ws"
    replaced = replace_vless_host(uri, "65.49.236.30")
    assert "@65.49.236.30:443" in replaced and "sni=example.com" in replaced and "host=cdn.example.com" in replaced
    with tempfile.TemporaryDirectory() as td:
        folder = Path(td) / "task"
        store = TaskStore(folder, create=True)
        store.add_targets(shodan)
        store.mark_shodan_imported()
        assert not store.pending_ips("port")
        assert store.pending_ips("http") == ["65.49.236.30", "65.49.237.84"]
        store.save_result("65.49.236.30", {"http_status":400,"cf_candidate":1,"cf_text_match":1,"cf_score":7})
        store.save_result("65.49.237.84", {"http_status":400,"cf_candidate":1,"cf_text_match":1,"cf_score":7})
        assert store.pending_ips("ping") == ["65.49.236.30", "65.49.237.84"]
        store.save_result("65.49.236.30", {"ping_status":"success","ping_ms":20.0,"ping_loss_pct":0.0})
        assert store.pending_ips("ping") == ["65.49.237.84"]
        store.save_result("65.49.236.30", {"tcping_status":"success","tcping_ms":35.0,"tcping_success_pct":100.0})
        store.save_result("65.49.236.30", {"vless_status":"success","speed_mbps":48.5})
        store.save_result("65.49.237.84", {"vless_status":"success","speed_mbps":36.2})
        assert store.pending_ips("route", limit=1) == ["65.49.236.30"]
        store.save_result("65.49.236.30", {"asn_info_status":"ok", "asn":"AS64500"})
        assert store.pending_ips("route", limit=1) == [], "Shodan ASN top-N must stay within the fastest N, not spill into lower ranks"
        out = export_results(store, Path(td) / "out", "test", uri)
        assert "65.49.236.30" in out["ips"].read_text(encoding="utf-8")
        assert "@65.49.236.30:443" in out["vless"].read_text(encoding="utf-8")
        direct_cf = Path(td) / "hits.txt"
        assert export_cf_candidates(store, direct_cf) == 2
        store.close()
        # Verify schema migration by reopening existing task and checking new fields.
        reopened = TaskStore(folder)
        assert {"ping_ms", "tcping_ms", "tcping_success_pct"}.issubset(reopened.columns)
        reopened.close()
    # Exercise a manually invoked phase and resume behavior without network access.
    with tempfile.TemporaryDirectory() as td:
        store = TaskStore(Path(td) / "task", create=True)
        store.add_targets([("198.51.100.10",1), ("198.51.100.11",1)])
        emitted=[]
        runner=ManualStageRunner(store, {"scan_workers":2,"timeout":0.5}, lambda *x: emitted.append(x), "local", "port")
        runner._run_stage("port", store.pending_ips("port"), lambda ip:{"port_status":"open","port_ms":1.0}, 2)
        assert not store.pending_ips("port")
        store.close()
    print("Self-test passed: CIDR/Shodan import, stage checkpoints, Ping/TCPing schema, ASN top-N ordering, exports, legacy VLESS template, and manual stage runner.")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return
    if tk is None:
        print("当前 Python 环境没有 tkinter。Windows 安装版通常自带 tkinter。")
        return
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
