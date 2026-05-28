"""
Aruba AP Syslog 受信サーバ (UDP / TCP 514)
RFC 3164 / RFC 5424 対応

接続元 AP の syslog メッセージを解析し、イベント辞書としてコールバックへ渡す。
"""
import asyncio
import re
import socket
from datetime import datetime, timezone
from typing import Awaitable, Callable

# ──────────────────────────────────────────────────────────────
# RFC パーサ
# ──────────────────────────────────────────────────────────────

# RFC 3164: <PRI>Mon DD HH:MM:SS HOSTNAME PROCESS[PID]: MSG
_RE_3164 = re.compile(
    r'^(?:<(\d+)>)?'
    r'(\w{3}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(\S+)\s+'
    r'(?:(\S+?)(?:\[(\d+)\])?:\s+)?'
    r'(.*)',
    re.S,
)

# RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG
_RE_5424 = re.compile(
    r'^<(\d+)>1\s+'
    r'(\S+)\s+'   # TIMESTAMP
    r'(\S+)\s+'   # HOSTNAME
    r'(\S+)\s+'   # APP-NAME
    r'(\S+)\s+'   # PROCID
    r'(\S+)\s+'   # MSGID
    r'(\S+)\s*'   # SD
    r'(?:\xef\xbb\xbf)?(.*)',  # optional BOM + MSG
    re.S,
)

_SEVERITY = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug']
_FACILITY = [
    'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
    'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert2', 'cron2',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
]


def _parse_priority(pri_str: str | None) -> dict:
    if not pri_str:
        return {"facility": "user", "severity": "info"}
    try:
        pri = int(pri_str)
        return {
            "facility": _FACILITY[pri >> 3] if (pri >> 3) < len(_FACILITY) else f"f{pri>>3}",
            "severity": _SEVERITY[pri & 7] if (pri & 7) < len(_SEVERITY) else "info",
        }
    except (ValueError, IndexError):
        return {"facility": "user", "severity": "info"}


def _parse_syslog_raw(raw: bytes, src_ip: str) -> dict:
    """バイト列を RFC 3164/5424 に従って解析する。"""
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        text = raw.decode("latin-1", errors="replace").strip()

    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    base = {"src_ip": src_ip, "received_at": now, "raw": text}

    m = _RE_5424.match(text)
    if m:
        ts = m.group(2) if m.group(2) != "-" else now
        return {
            **base, **_parse_priority(m.group(1)),
            "format": "rfc5424", "timestamp": ts,
            "hostname": m.group(3) if m.group(3) != "-" else src_ip,
            "process":  m.group(4) if m.group(4) != "-" else "",
            "message":  m.group(8).strip(),
        }

    m = _RE_3164.match(text)
    if m:
        return {
            **base, **_parse_priority(m.group(1)),
            "format": "rfc3164", "timestamp": m.group(2) or now,
            "hostname": m.group(3) or src_ip,
            "process":  m.group(4) or "",
            "message":  m.group(6).strip(),
        }

    return {
        **base,
        "format": "raw", "timestamp": now,
        "hostname": src_ip, "process": "",
        "severity": "info", "facility": "user",
        "message": text,
    }


# ──────────────────────────────────────────────────────────────
# Aruba イベント分類
# ──────────────────────────────────────────────────────────────

_RE_MAC    = re.compile(r'([0-9a-f]{2}(?::[0-9a-f]{2}){5})', re.I)
_RE_IP4    = re.compile(r'(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)')
_RE_SSID   = re.compile(r'(?:SSID|essid)\s*[=:\s]+["\']?([^\s"\']+)', re.I)
_RE_REASON = re.compile(r'reason[=:\s]+(\d+)', re.I)
_RE_USER   = re.compile(r'(?:user(?:name)?|admin)\s*[=:\s]+["\']?(\S+?)["\']?(?:\s|:|$)', re.I)
_RE_VLAN   = re.compile(r'vlan\s*[=:\s]+(\d+)', re.I)


def _extract_fields(msg: str) -> dict:
    out: dict = {}
    macs = _RE_MAC.findall(msg)
    if macs:
        out["mac"] = macs[0]
        if len(macs) > 1:
            out["bssid"] = macs[1]
    ips = _RE_IP4.findall(msg)
    if ips:
        out["ip"] = ips[0]
    m = _RE_SSID.search(msg)
    if m:
        out["ssid"] = m.group(1)
    m = _RE_REASON.search(msg)
    if m:
        out["reason_code"] = m.group(1)
    m = _RE_USER.search(msg)
    if m:
        out["user"] = m.group(1)
    m = _RE_VLAN.search(msg)
    if m:
        out["vlan"] = m.group(1)
    return out


# (event_type, label, category, severity, pattern)
_RULES: list[tuple[str, str, str, str, re.Pattern]] = [
    # ── クライアント接続 ─────────────────────────────────────
    ("client.associated",    "接続",       "client",   "info",
     re.compile(r'\b(?:assoc|Assoc|ASSOC)\b(?!.*?(?:fail|Fail|FAIL|deny|error))', re.I)),
    ("client.associated",    "接続",       "client",   "info",
     re.compile(r'STA\([0-9a-f:]+\).*?(?:staAssoc\b|Assoc\b)(?!.*?(?:Fail|fail))', re.I)),
    ("client.associated",    "接続",       "client",   "info",
     re.compile(r'station associated|client connected|STA connected', re.I)),

    # ── クライアント切断 ─────────────────────────────────────
    ("client.disassociated", "切断",       "client",   "info",
     re.compile(r'\b(?:disassoc|Disassoc|DISASSOC|deauth|Deauth|DEAUTH)\b', re.I)),
    ("client.disassociated", "切断",       "client",   "info",
     re.compile(r'STA\([0-9a-f:]+\).*?(?:Disassoc|Deauth)\b', re.I)),
    ("client.disassociated", "切断",       "client",   "info",
     re.compile(r'station (?:de-?associated|disconnected)|client (?:disconnected|left)', re.I)),

    # ── 認証失敗 ────────────────────────────────────────────
    ("auth.failure",         "認証失敗",   "auth",     "warning",
     re.compile(r'(?:auth.*?fail|fail.*?auth|staAuthFail|authFail|AUTH.*FAIL'
                r'|invalid.*?(?:password|key|psk)|wrong.*?(?:password|key)'
                r'|EAP.*?fail|RADIUS.*?reject)', re.I)),

    # ── 認証成功 ────────────────────────────────────────────
    ("auth.success",         "認証成功",   "auth",     "info",
     re.compile(r'(?:auth.*?(?:ok|success|OK|SUCCESS)|Authentication OK'
                r'|802\.1X.*?success|EAP.*?success|RADIUS.*?accept)', re.I)),

    # ── ローミング ──────────────────────────────────────────
    ("client.roam",          "ローミング", "client",   "info",
     re.compile(r'(?:roam|Roam|ROAM|fast.*?BSS|BSS.*?transition|FT\s)', re.I)),

    # ── DHCP ────────────────────────────────────────────────
    ("dhcp.ack",             "IP割当",     "dhcp",     "info",
     re.compile(r'DHCPACK', re.I)),
    ("dhcp.request",         "DHCP要求",   "dhcp",     "info",
     re.compile(r'DHCPREQUEST', re.I)),
    ("dhcp.offer",           "DHCPオファー","dhcp",    "info",
     re.compile(r'DHCPOFFER', re.I)),
    ("dhcp.deny",            "DHCP拒否",   "dhcp",     "warning",
     re.compile(r'DHCPNAK|DHCPDECLINE', re.I)),

    # ── AP 状態 ─────────────────────────────────────────────
    ("ap.up",                "AP起動",     "ap",       "info",
     re.compile(r'AP.*?(?:\bup\b|\bUP\b|connect|register|online|provisioned)', re.I)),
    ("ap.down",              "AP停止",     "ap",       "warning",
     re.compile(r'AP.*?(?:\bdown\b|\bDOWN\b|disconnect|deregist|offline|unreachable)', re.I)),
    ("ap.reboot",            "AP再起動",   "ap",       "warning",
     re.compile(r'(?:reboot|restart|reload).*AP|AP.*(?:reboot|restart|reload)', re.I)),

    # ── 管理者操作 ──────────────────────────────────────────
    ("admin.login",          "管理者ログイン","admin",  "info",
     re.compile(r'(?:(?:user|admin|operator)\s+\S+\s+(?:logged.in|login)|'
                r'(?:ssh|web|gui|cli|console).*?login|management.*?login)', re.I)),
    ("admin.logout",         "管理者ログアウト","admin","info",
     re.compile(r'(?:logged.out|logout|session.*?end|connection.*?closed)', re.I)),
    ("admin.config",         "設定変更",   "admin",    "info",
     re.compile(r'(?:config.*?(?:change|apply|commit|push)|'
                r'(?:provisioned|applied|deployed).*?config)', re.I)),
    ("admin.cmd",            "コマンド実行","admin",   "info",
     re.compile(r'(?:command|cmd|exec).*?(?:executed|issued|run)', re.I)),

    # ── セキュリティ ────────────────────────────────────────
    ("security.rogue",       "不正AP検知", "security", "critical",
     re.compile(r'(?:rogue|Rogue|ROGUE|unauthorized AP)', re.I)),
    ("security.ids",         "IDS検知",   "security", "critical",
     re.compile(r'(?:IDS|intrusion|attack|ATTACK|flood|deauth.*?flood)', re.I)),
    ("security.block",       "アクセス拒否","security","warning",
     re.compile(r'(?:blocked|denied|blacklist(?:ed)?|ACL deny|access.denied)', re.I)),
    ("security.scan",        "スキャン検知","security","warning",
     re.compile(r'(?:port.scan|scan.*?detect|probe.*?detect)', re.I)),
]


def classify_syslog(parsed: dict) -> dict:
    """解析済み syslog メッセージを Aruba イベントに分類する。"""
    msg      = parsed.get("message", "")
    full_raw = parsed.get("raw", "")
    hostname = parsed.get("hostname", "")
    process  = parsed.get("process", "")
    src_ip   = parsed.get("src_ip", "")

    for ev_type, label, category, severity, pat in _RULES:
        if pat.search(msg) or pat.search(process):
            fields = _extract_fields(msg)
            return {
                "event_type":  ev_type,
                "label":       label,
                "category":    category,
                "severity":    severity,
                "hostname":    hostname,
                "process":     process,
                "src_ip":      src_ip,
                "timestamp":   parsed.get("timestamp", ""),
                "received_at": parsed.get("received_at", ""),
                "facility":    parsed.get("facility", ""),
                "message":     msg,
                **fields,
            }

    # 分類不能 → raw
    return {
        "event_type":  "syslog.raw",
        "label":       "syslog",
        "category":    "raw",
        "severity":    parsed.get("severity", "info"),
        "hostname":    hostname,
        "process":     process,
        "src_ip":      src_ip,
        "timestamp":   parsed.get("timestamp", ""),
        "received_at": parsed.get("received_at", ""),
        "facility":    parsed.get("facility", ""),
        "message":     msg,
    }


# ──────────────────────────────────────────────────────────────
# 非同期 UDP / TCP サーバ
# ──────────────────────────────────────────────────────────────

EventCallback = Callable[[dict], Awaitable[None]]


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, cb: EventCallback):
        self._cb = cb

    def datagram_received(self, data: bytes, addr: tuple):
        src_ip = addr[0]
        try:
            parsed = _parse_syslog_raw(data, src_ip)
            event  = classify_syslog(parsed)
            asyncio.get_event_loop().create_task(self._cb(event))
        except Exception:
            pass

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass


async def _tcp_client_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cb: EventCallback,
):
    src_ip = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=120)
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            parsed = _parse_syslog_raw(line, src_ip)
            event  = classify_syslog(parsed)
            await cb(event)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_syslog_server(
    host: str,
    port: int,
    callback: EventCallback,
) -> list:
    """
    UDP + TCP syslog サーバを起動する。

    Returns: 起動したサーバオブジェクトのリスト（停止時に close() を呼ぶ）
    """
    loop = asyncio.get_event_loop()
    servers: list = []

    # UDP
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(callback),
            local_addr=(host, port),
            family=socket.AF_INET,
        )
        servers.append(transport)
        print(f"[syslog] UDP {host}:{port} listening", flush=True)
    except PermissionError:
        print(f"[syslog] UDP bind {host}:{port} 失敗 — 権限不足 (ポート<1024 は root 必要)", flush=True)
    except OSError as e:
        print(f"[syslog] UDP bind {host}:{port} 失敗: {e}", flush=True)

    # TCP
    try:
        tcp_srv = await asyncio.start_server(
            lambda r, w: _tcp_client_handler(r, w, callback),
            host, port,
            family=socket.AF_INET,
        )
        servers.append(tcp_srv)
        print(f"[syslog] TCP {host}:{port} listening", flush=True)
    except OSError as e:
        print(f"[syslog] TCP bind {host}:{port} 失敗: {e}", flush=True)

    return servers
