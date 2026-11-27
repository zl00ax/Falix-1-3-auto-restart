import base64
import json
import os
import socket
import subprocess
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests

LOCAL_PROXY_HOST = "127.0.0.1"


def _pad_b64(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def _decode_b64(s: str) -> str:
    return base64.b64decode(_pad_b64(s)).decode("utf-8")


def _to_bool(val: Any) -> bool:
    return str(val or "").strip().lower() in ("1", "true", "yes")


def _parse_ws_path(raw_path: str) -> Tuple[str, Optional[int]]:
    path = unquote(raw_path or "/")
    if not path.startswith("/"):
        path = "/" + path
    early_data = None
    if "?ed=" in path:
        base_path, ed_part = path.split("?ed=", 1)
        try:
            early_data = int(ed_part.split("&", 1)[0])
            path = base_path or "/"
        except ValueError:
            pass
    return path, early_data


def _build_transport(
    net: str, host: str = "", path: str = "", service_name: str = ""
) -> Optional[Dict[str, Any]]:
    net = (net or "tcp").lower()
    if net in ("tcp", "raw", "none", ""):
        return None
    if net == "ws":
        clean_path, ed = _parse_ws_path(path)
        t: Dict[str, Any] = {"type": "ws", "path": clean_path}
        if host:
            t["headers"] = {"Host": host.split(",")[0].strip()}
        if ed:
            t["max_early_data"] = ed
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if net == "grpc":
        return {"type": "grpc", "service_name": unquote(service_name or path or "")}
    if net in ("h2", "http"):
        t = {"type": "http", "path": unquote(path or "/")}
        if host:
            t["host"] = [h.strip() for h in host.split(",") if h.strip()]
        return t
    if net == "httpupgrade":
        t = {"type": "httpupgrade", "path": unquote(path or "/")}
        if host:
            t["host"] = host.split(",")[0].strip()
        return t
    raise ValueError(f"sing-box 不支持的传输协议: {net}")


def parse_vless(uri: str) -> Dict[str, Any]:
    parsed = urlparse(uri)
    qs = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    server = parsed.hostname
    if not server:
        raise ValueError("VLESS 链接缺少服务器地址")
    port = parsed.port or 443
    uuid = unquote(parsed.username or "")
    if not uuid:
        raise ValueError("VLESS 链接缺少 UUID")

    outbound: Dict[str, Any] = {
        "type": "vless",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "packet_encoding": "xudp",
    }

    flow = qs.get("flow", "").strip()
    if flow:
        outbound["flow"] = flow

    security = qs.get("security", "none").lower()
    if security in ("tls", "reality"):
        sni = qs.get("sni") or qs.get("host") or server
        tls_cfg: Dict[str, Any] = {
            "enabled": True,
            "server_name": sni,
            "insecure": _to_bool(qs.get("allowInsecure") or qs.get("insecure")),
        }
        fp = qs.get("fp", "").strip()
        if fp:
            tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}
        elif security == "reality":
            tls_cfg["utls"] = {"enabled": True, "fingerprint": "chrome"}

        if security == "reality":
            pbk = qs.get("pbk", "").strip()
            if not pbk:
                raise ValueError("VLESS Reality 链接缺少 pbk (public_key)")
            tls_cfg["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": qs.get("sid", "").strip(),
            }

        alpn = qs.get("alpn", "").strip()
        if alpn:
            tls_cfg["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]

        outbound["tls"] = tls_cfg

    transport = _build_transport(
        net=qs.get("type", "tcp"),
        host=qs.get("host", ""),
        path=qs.get("path", ""),
        service_name=qs.get("serviceName", ""),
    )
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_vmess(uri: str) -> Dict[str, Any]:
    raw = uri[len("vmess://") :].split("#", 1)[0].strip()
    data = json.loads(_decode_b64(raw))
    server = data.get("add")
    if not server:
        raise ValueError("VMess 链接缺少服务器地址 (add)")
    port = int(data.get("port", 443))
    uuid = str(data.get("id", "")).strip()
    if not uuid:
        raise ValueError("VMess 链接缺少 UUID (id)")

    outbound: Dict[str, Any] = {
        "type": "vmess",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": str(data.get("scy") or "auto"),
        "alter_id": int(data.get("aid") or 0),
    }

    host = str(data.get("host") or "")
    path = str(data.get("path") or "")
    net = str(data.get("net") or "tcp").lower()
    header_type = str(data.get("type") or "none").lower()

    tls_flag = str(data.get("tls") or "").lower()
    if tls_flag in ("tls", "true", "1"):
        sni = str(data.get("sni") or "").strip() or (
            host.split(",")[0].strip() if host else server
        )
        tls_cfg: Dict[str, Any] = {
            "enabled": True,
            "server_name": sni,
            "insecure": _to_bool(data.get("insecure") or data.get("allowInsecure")),
        }
        fp = str(data.get("fp") or "").strip()
        if fp:
            tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = str(data.get("alpn") or "").strip()
        if alpn:
            tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        outbound["tls"] = tls_cfg

    if net == "tcp" and header_type == "http":
        transport = _build_transport("http", host=host, path=path)
    else:
        transport = _build_transport(net, host=host, path=path, service_name=path)
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_hysteria2(uri: str) -> Dict[str, Any]:
    normalized = uri.replace("hy2://", "hysteria2://", 1)
    parsed = urlparse(normalized)
    qs = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    server = parsed.hostname
    if not server:
        raise ValueError("Hysteria2 链接缺少服务器地址")

    port = parsed.port
    if not port and qs.get("mport"):
        first_part = qs["mport"].split(",", 1)[0].split("-", 1)[0]
        port = int(first_part)
    port = port or 443

    if parsed.password is not None:
        password = f"{unquote(parsed.username or '')}:{unquote(parsed.password)}"
    else:
        password = unquote(parsed.username or "")

    sni = qs.get("sni") or qs.get("peer") or server
    tls_cfg: Dict[str, Any] = {
        "enabled": True,
        "server_name": sni,
        "insecure": _to_bool(qs.get("insecure") or qs.get("allowInsecure")),
    }
    alpn = qs.get("alpn", "").strip()
    if alpn:
        tls_cfg["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]

    outbound: Dict[str, Any] = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": password,
        "tls": tls_cfg,
    }

    obfs_type = qs.get("obfs", "").lower()
    obfs_password = unquote(qs.get("obfs-password", ""))
    if obfs_type == "salamander" and obfs_password:
        outbound["obfs"] = {"type": "salamander", "password": obfs_password}

    if qs.get("upmbps"):
        outbound["up_mbps"] = int(qs["upmbps"])
    if qs.get("downmbps"):
        outbound["down_mbps"] = int(qs["downmbps"])

    return outbound


def parse_trojan(uri: str) -> Dict[str, Any]:
    parsed = urlparse(uri)
    qs = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
    server = parsed.hostname
    if not server:
        raise ValueError("Trojan 链接缺少服务器地址")
    port = parsed.port or 443
    password = unquote(parsed.username or "")

    outbound: Dict[str, Any] = {
        "type": "trojan",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "password": password,
    }

    security = qs.get("security", "tls").lower()
    if security != "none":
        sni = qs.get("sni") or qs.get("peer") or server
        tls_cfg: Dict[str, Any] = {
            "enabled": True,
            "server_name": sni,
            "insecure": _to_bool(qs.get("allowInsecure") or qs.get("insecure")),
        }
        fp = qs.get("fp", "").strip()
        if fp:
            tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = qs.get("alpn", "").strip()
        if alpn:
            tls_cfg["alpn"] = [a.strip() for a in unquote(alpn).split(",") if a.strip()]
        outbound["tls"] = tls_cfg

    transport = _build_transport(
        net=qs.get("type", "tcp"),
        host=qs.get("host", ""),
        path=qs.get("path", ""),
        service_name=qs.get("serviceName", ""),
    )
    if transport:
        outbound["transport"] = transport

    return outbound


def parse_ss(uri: str) -> Dict[str, Any]:
    raw = uri[len("ss://") :].split("#", 1)[0].strip()
    if "@" in raw:
        userinfo, hostport = raw.rsplit("@", 1)
        hostport = hostport.split("?", 1)[0]
        if ":" in userinfo and not userinfo.startswith("2022-"):
            decoded_user = userinfo
        else:
            try:
                decoded_user = _decode_b64(userinfo)
            except Exception:
                decoded_user = unquote(userinfo)
        method, password = decoded_user.split(":", 1)
    else:
        decoded = _decode_b64(raw)
        userinfo, hostport = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)

    parsed_hp = urlparse(f"ss://{hostport}")
    server = parsed_hp.hostname
    port = parsed_hp.port
    if not server or not port:
        raise ValueError("Shadowsocks 链接缺少地址或端口")

    return {
        "type": "shadowsocks",
        "tag": "proxy",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
    }


def build_singbox_config(proxy_uri: str, local_port: int) -> Tuple[Dict[str, Any], int]:
    proxy_uri = proxy_uri.strip()
    if proxy_uri.startswith("{"):
        custom = json.loads(proxy_uri)
        if "inbounds" in custom and "outbounds" in custom:
            inbounds = custom.get("inbounds") or []
            actual_port = (
                int(inbounds[0].get("listen_port", local_port))
                if inbounds
                else local_port
            )
            return custom, actual_port
        custom["tag"] = "proxy"
        outbound = custom
    else:
        scheme = proxy_uri.split("://", 1)[0].lower()
        if scheme == "vless":
            outbound = parse_vless(proxy_uri)
        elif scheme == "vmess":
            outbound = parse_vmess(proxy_uri)
        elif scheme in ("hy2", "hysteria2"):
            outbound = parse_hysteria2(proxy_uri)
        elif scheme == "trojan":
            outbound = parse_trojan(proxy_uri)
        elif scheme == "ss":
            outbound = parse_ss(proxy_uri)
        else:
            raise ValueError(f"不支持的代理协议: {scheme}")

    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": LOCAL_PROXY_HOST,
                "listen_port": local_port,
            }
        ],
        "outbounds": [
            outbound,
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "final": "proxy",
        },
    }
    return config, local_port


class SingBoxProxy:
    def __init__(self, proxy_uri: str, local_port: int = 10808):
        self.proxy_uri = (proxy_uri or "").strip()
        self.local_port = local_port
        self.config_path = f"/tmp/singbox_config_{local_port}.json"
        self.proc: Optional[subprocess.Popen] = None
        self.exit_ip: Optional[str] = None
        self.protocol: str = "direct"

    @property
    def local_proxy_url(self) -> str:
        return f"http://{LOCAL_PROXY_HOST}:{self.local_port}"

    def start(self) -> str:
        if not self.proxy_uri:
            print("[Proxy] 该账号未配置代理节点，使用直连模式")
            return ""

        config, actual_port = build_singbox_config(self.proxy_uri, self.local_port)
        self.local_port = actual_port
        self.config_path = f"/tmp/singbox_config_{self.local_port}.json"
        outbounds = config.get("outbounds") or []
        self.protocol = outbounds[0].get("type", "custom") if outbounds else "custom"

        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        print(f"[Proxy] 正在启动 sing-box ({self.protocol}) -> {self.local_proxy_url}")
        self.proc = subprocess.Popen(
            ["sing-box", "run", "-c", self.config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        ready = False
        for _ in range(30):
            if self.proc.poll() is not None:
                _, err = self.proc.communicate(timeout=3)
                raise RuntimeError(f"sing-box 启动失败退出:\n{err.strip()}")
            try:
                with socket.create_connection(
                    (LOCAL_PROXY_HOST, self.local_port), timeout=1
                ):
                    ready = True
                    break
            except OSError:
                time.sleep(0.5)

        if not ready:
            self.stop()
            raise RuntimeError("sing-box 本地端口监听超时")

        self.exit_ip = self._check_exit_ip()
        print(f"[Proxy] sing-box 代理连通成功，出口 IP: {self.exit_ip}")
        return self.local_proxy_url

    def _check_exit_ip(self) -> str:
        proxies = {"http": self.local_proxy_url, "https": self.local_proxy_url}
        check_urls = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://icanhazip.com",
        ]
        last_err = None
        for url in check_urls:
            try:
                resp = requests.get(url, proxies=proxies, timeout=15)
                if resp.status_code == 200 and resp.text.strip():
                    return resp.text.strip()
            except Exception as e:
                last_err = e
        raise RuntimeError(f"sing-box 代理连通性检测失败: {last_err}")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)
        if os.path.exists(self.config_path):
            try:
                os.remove(self.config_path)
            except OSError:
                pass
