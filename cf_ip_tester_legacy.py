# -*- coding: utf-8 -*-
"""Compatibility VLESS/Xray tester extracted from CFIPTester 0.1.0.
Uses the prior proven full-file-over-SOCKS measurement path.
"""
from __future__ import annotations
import json, os, re, socket, subprocess, tempfile, threading, time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

@dataclass
class VlessTemplate:
    uuid_value: str
    port: int
    encryption: str
    flow: str
    security: str
    method: str
    server_name: str
    fingerprint: str
    alpn: list[str]
    allow_insecure: bool
    host: str
    path: str
    service_name: str
    authority: str
    mode: str
    raw_query: dict[str, list[str]]


def qget(q: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = q.get(key)
        if values:
            return values[0]
    return default


def parse_vless_link(link: str) -> VlessTemplate:
    link = link.strip()
    if not link.lower().startswith("vless://"):
        raise ValueError("請填入完整的 vless:// 分享链接。")
    try:
        parsed = urlsplit(link)
        user_id = unquote(parsed.username or "")
        port = parsed.port or 443
        # Access .hostname to normalize bracketed IPv6; a node domain is not required here.
        _ = parsed.hostname
    except Exception as exc:
        raise ValueError(f"VLESS 链接格式无法解析：{exc}") from exc
    if not user_id:
        raise ValueError("VLESS 链接中没有 UUID / 用户 ID。")
    if not parsed.hostname:
        raise ValueError("VLESS 链接中没有服务器域名。")
    if not (1 <= port <= 65535):
        raise ValueError("VLESS 端口不在有效范围内。")

    q = parse_qs(parsed.query, keep_blank_values=True)
    method_in = qget(q, "type", "network", default="tcp").lower()
    method_map = {
        "tcp": "raw", "raw": "raw", "ws": "websocket", "websocket": "websocket",
        "grpc": "grpc", "httpupgrade": "httpupgrade", "xhttp": "xhttp",
    }
    if method_in not in method_map:
        raise ValueError(f"暂不支持传输方式：{method_in}（支持 WS / gRPC / TCP / HTTPUpgrade / XHTTP）。")
    method = method_map[method_in]
    security = qget(q, "security", default="tls").lower()
    if security == "reality":
        raise ValueError("第一版暂不支持 REALITY 节点；Cloudflare 反代常见的是 TLS + WS。请使用 TLS 节点链接。")
    if security not in ("tls", "none"):
        raise ValueError(f"暂不支持 security={security}。")

    alpn_text = qget(q, "alpn")
    alpn = [x.strip() for x in re.split(r"[,;]", alpn_text) if x.strip()] if alpn_text else []
    allow_insecure = qget(q, "allowInsecure", "allow_insecure", default="0").lower() in ("1", "true", "yes")

    return VlessTemplate(
        uuid_value=user_id,
        port=port,
        encryption=qget(q, "encryption", default="none") or "none",
        flow=qget(q, "flow"),
        security=security,
        method=method,
        server_name=qget(q, "sni", "servername", default=parsed.hostname),
        fingerprint=qget(q, "fp", "fingerprint", default="chrome"),
        alpn=alpn,
        allow_insecure=allow_insecure,
        host=qget(q, "host"),
        path=qget(q, "path", default="/"),
        service_name=qget(q, "serviceName", "servicename"),
        authority=qget(q, "authority"),
        mode=qget(q, "mode"),
        raw_query=q,
    )


def build_xray_config(template: VlessTemplate, ip: str, socks_port: int) -> dict:
    settings = {
        "address": ip,
        "port": template.port,
        "id": template.uuid_value,
        "encryption": template.encryption,
    }
    if template.flow:
        settings["flow"] = template.flow

    stream: dict = {"method": template.method, "security": template.security}
    if template.security == "tls":
        tls = {
            "serverName": template.server_name,
            "fingerprint": template.fingerprint or "chrome",
        }
        if template.alpn:
            tls["alpn"] = template.alpn
        if template.allow_insecure:
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls

    if template.method == "websocket":
        ws = {"path": template.path or "/"}
        if template.host:
            ws["host"] = template.host
        stream["wsSettings"] = ws
    elif template.method == "grpc":
        grpc = {"serviceName": template.service_name}
        if template.authority:
            grpc["authority"] = template.authority
        if template.mode:
            grpc["multiMode"] = template.mode.lower() in ("multi", "multimode", "true", "1")
        stream["grpcSettings"] = grpc
    elif template.method == "httpupgrade":
        hu = {"path": template.path or "/"}
        if template.host:
            hu["host"] = template.host
        stream["httpupgradeSettings"] = hu
    elif template.method == "xhttp":
        xh = {"path": template.path or "/"}
        if template.host:
            xh["host"] = template.host
        if template.mode:
            xh["mode"] = template.mode
        stream["xhttpSettings"] = xh

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": settings, "streamSettings": stream}],
    }



class BufferedSocket:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, n: int = 1) -> None:
        while len(self.buf) < n:
            chunk = self.sock.recv(max(65536, n - len(self.buf)))
            if not chunk:
                raise ConnectionError("服务器提前关闭连接")
            self.buf.extend(chunk)

    def read_until(self, marker: bytes, max_bytes: int = 65536) -> bytes:
        while True:
            idx = self.buf.find(marker)
            if idx >= 0:
                end = idx + len(marker)
                out = bytes(self.buf[:end])
                del self.buf[:end]
                return out
            if len(self.buf) > max_bytes:
                raise ConnectionError("HTTP 响应头过长")
            self._fill(len(self.buf) + 1)

    def read_exact(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("invalid read length")
        self._fill(n)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def take_buffer(self) -> bytes:
        out = bytes(self.buf)
        self.buf.clear()
        return out

    def read_some(self, n: int = 65536) -> bytes:
        if self.buf:
            out = bytes(self.buf[:n])
            del self.buf[:n]
            return out
        return self.sock.recv(n)


def socks5_connect(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(b"\x05\x01\x00")
    greeting = recv_exact(sock, 2)
    if greeting != b"\x05\x00":
        raise ConnectionError("本地 SOCKS5 握手失败")
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise ConnectionError("测试域名过长")
    request = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")
    sock.sendall(request)
    head = recv_exact(sock, 4)
    if head[0] != 5 or head[1] != 0:
        codes = {1: "一般 SOCKS 错误", 2: "规则禁止", 3: "网络不可达", 4: "主机不可达", 5: "连接被拒绝", 6: "TTL 超时", 7: "不支持的命令", 8: "不支持的地址类型"}
        raise ConnectionError("代理连接失败：" + codes.get(head[1], f"SOCKS 错误码 {head[1]}"))
    atyp = head[3]
    if atyp == 1:
        recv_exact(sock, 4)
    elif atyp == 3:
        ln = recv_exact(sock, 1)[0]
        recv_exact(sock, ln)
    elif atyp == 4:
        recv_exact(sock, 16)
    else:
        raise ConnectionError("SOCKS5 返回未知地址类型")
    recv_exact(sock, 2)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        part = sock.recv(length - len(chunks))
        if not part:
            raise ConnectionError("SOCKS5 连接提前关闭")
        chunks.extend(part)
    return bytes(chunks)


def download_test_via_socks(socks_port: int, test_url: str, timeout: int, stop_event: threading.Event) -> tuple[float, float, int]:
    parsed = urlsplit(test_url.strip())
    if parsed.scheme.lower() != "http":
        raise ValueError("第一版测速文件地址请使用 http:// 开头（当前指定地址符合）。")
    if not parsed.hostname:
        raise ValueError("测速文件 URL 缺少主机名。")
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    host_header = parsed.hostname if port == 80 else f"{parsed.hostname}:{port}"

    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=min(timeout, 8))
    try:
        sock.settimeout(timeout)
        socks5_connect(sock, parsed.hostname, port)
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: CF-IP-Tester/0.1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", "strict")
        t_request = time.perf_counter()
        sock.sendall(request)
        reader = BufferedSocket(sock)
        raw_headers = reader.read_until(b"\r\n\r\n")
        t_headers = time.perf_counter()
        header_text = raw_headers.decode("iso-8859-1", errors="replace")
        lines = header_text.split("\r\n")
        status_match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0] if lines else "")
        if not status_match:
            raise ConnectionError("测速服务器返回了无法识别的 HTTP 响应")
        status = int(status_match.group(1))
        if status not in (200, 206):
            raise ConnectionError(f"测速服务器 HTTP {status}")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        content_length = int(headers.get("content-length", "0") or 0)
        if content_length > 64 * 1024 * 1024:
            raise ConnectionError(f"测速文件过大：{content_length} 字节（上限 64MB）")
        transfer_encoding = headers.get("transfer-encoding", "").lower()
        first = reader.take_buffer()
        if content_length > 0:
            while not first:
                if stop_event.is_set():
                    raise InterruptedError("用户停止测试")
                first = reader.read_some(min(65536, content_length))
                if not first:
                    raise ConnectionError("测速服务器未返回文件数据")
            t_first = time.perf_counter()
            received = min(len(first), content_length)
            while received < content_length:
                if stop_event.is_set():
                    raise InterruptedError("用户停止测试")
                chunk = reader.read_some(min(65536, content_length - received))
                if not chunk:
                    raise ConnectionError(f"下载中断：只收到 {received} / {content_length} 字节")
                received += len(chunk)
        elif "chunked" in transfer_encoding:
            # Parse chunk framing and start the latency clock at the first payload byte.
            pending = bytearray(first)
            received = 0

            def read_chunk_line() -> bytes:
                while b"\r\n" not in pending:
                    if stop_event.is_set():
                        raise InterruptedError("用户停止测试")
                    more = reader.read_some(65536)
                    if not more:
                        raise ConnectionError("Chunked 下载意外结束")
                    pending.extend(more)
                line, _, remain = pending.partition(b"\r\n")
                pending[:] = remain
                return bytes(line)

            first_payload_seen = False
            while True:
                size_line = read_chunk_line()
                size = int(size_line.split(b";", 1)[0].strip(), 16)
                if size == 0:
                    if not first_payload_seen:
                        raise ConnectionError("测速服务器返回空文件")
                    break
                needed = size + 2
                while len(pending) < needed:
                    if stop_event.is_set():
                        raise InterruptedError("用户停止测试")
                    more = reader.read_some(65536)
                    if not more:
                        raise ConnectionError("Chunked 数据不完整")
                    pending.extend(more)
                if not first_payload_seen:
                    t_first = time.perf_counter()
                    first_payload_seen = True
                received += size
                del pending[:needed]
        else:
            # Fallback for servers that stream until close without Content-Length.
            while not first:
                if stop_event.is_set():
                    raise InterruptedError("用户停止测试")
                first = reader.read_some(65536)
                if not first:
                    raise ConnectionError("测速服务器未返回文件数据")
            t_first = time.perf_counter()
            received = len(first)
            while True:
                if stop_event.is_set():
                    raise InterruptedError("用户停止测试")
                chunk = reader.read_some(65536)
                if not chunk:
                    break
                received += len(chunk)
                if received > 64 * 1024 * 1024:
                    raise ConnectionError("下载超过 64MB，拒绝继续")
        t_done = time.perf_counter()
        if received < 1024 * 1024:
            raise ConnectionError(f"下载数据量异常：仅 {received} 字节")
        latency_ms = max(1, int((t_first - t_request) * 1000 + 0.5))
        download_seconds = max(0.001, t_done - t_first)
        speed_mbps = (received / 1_000_000) / download_seconds
        return latency_ms, speed_mbps, received
    finally:
        try:
            sock.close()
        except Exception:
            pass


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_port(port: int, proc: subprocess.Popen, timeout: float, stop_event: threading.Event) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stop_event.is_set():
            raise InterruptedError("用户停止测试")
        if proc.poll() is not None:
            raise RuntimeError("Xray Core 启动失败，请检查核心版本和配置。")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.12)
    raise TimeoutError("等待 Xray 本地 SOCKS 端口超时")


def test_one_ip(ip: str, xray_path: str, template: VlessTemplate, test_url: str,
                timeout: int, stop_event: threading.Event) -> dict:
    cfg_path = None
    proc = None
    socks_port = find_free_port()
    try:
        config = build_xray_config(template, ip, socks_port)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            json.dump(config, f, ensure_ascii=False, separators=(",", ":"))
            cfg_path = f.name
        creationflags = 0
        startupinfo = None
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.Popen(
            [xray_path, "run", "-c", cfg_path],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=creationflags, startupinfo=startupinfo,
        )
        wait_port(socks_port, proc, min(8, timeout), stop_event)
        latency, speed, received = download_test_via_socks(socks_port, test_url, timeout, stop_event)
        return {"ip": ip, "ok": True, "latency": latency, "speed": speed, "bytes": received, "error": ""}
    except InterruptedError as exc:
        return {"ip": ip, "ok": False, "latency": None, "speed": None, "bytes": 0, "error": str(exc), "cancelled": True}
    except Exception as exc:
        msg = str(exc).strip() or exc.__class__.__name__
        return {"ip": ip, "ok": False, "latency": None, "speed": None, "bytes": 0, "error": msg[:180]}
    finally:
        if proc is not None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass


def validate_xray_config(xray_path: str, template: VlessTemplate, sample_ip: str) -> tuple[bool, str]:
    """Ask Xray to validate generated JSON before launching a whole batch."""
    cfg_path = None
    try:
        config = build_xray_config(template, sample_ip, find_free_port())
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            json.dump(config, f, ensure_ascii=False, separators=(",", ":"))
            cfg_path = f.name
        completed = subprocess.run(
            [xray_path, "run", "-test", "-c", cfg_path],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=12,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        if completed.returncode == 0:
            return True, ""
        detail = (completed.stderr or completed.stdout or "").strip()
        return False, detail[-1400:] if detail else f"Xray 配置校验失败，退出码 {completed.returncode}"
    except subprocess.TimeoutExpired:
        return False, "Xray 配置校验超时。请确认所选文件是可运行的 Xray Core。"
    except Exception as exc:
        return False, f"无法执行 Xray 配置校验：{exc}"
    finally:
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
