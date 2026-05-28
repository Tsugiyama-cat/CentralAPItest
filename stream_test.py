#!/usr/bin/env python3
"""
Aruba New Central — Streaming API connection test tool.

Ref: https://developer.arubanetworks.com/new-central/docs/streaming-api-getting-started
     https://developer.arubanetworks.com/new-central/docs/streaming-api-connection-management

処理フロー:
  1. HPE GreenLake SSO で OAuth2 トークン取得
  2. WSS エンドポイントへ接続 (Authorization: Bearer <token> ヘッダー)
  3. STREAM_DURATION 秒間 Protobuf メッセージを受信して結果を表示

対応ストリームタイプ (STREAM_TYPE):
  ap-monitoring      APデバイス状態・統計イベント
  audit-trail        設定変更・監査ログイベント  (デフォルト)
  geofence           ジオフェンスイベント
  location           リアルタイム位置情報
  location-analytics 位置分析データ

環境変数:
  CLIENT_ID          GreenLake OAuth2 クライアントID          (必須)
  CLIENT_SECRET      GreenLake OAuth2 クライアントシークレット  (必須)
  BASE_URL           Aruba Central API ゲートウェイ URL       (必須)
  TOKEN_URL          HPE GreenLake SSO エンドポイント          (省略可)
  STREAM_TYPE        ストリームタイプ (デフォルト: audit-trail)
  STREAM_EVENT_TYPES フィルタするevent-types カンマ区切り      (省略可)
  STREAM_DURATION    受信待機秒数 (デフォルト: 30)
"""

import asyncio
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlencode

try:
    import websockets
    from websockets.exceptions import (
        ConnectionClosed,
        InvalidHandshake,
        WebSocketException,
    )
except ImportError:
    print(
        "ERROR: websockets がインストールされていません。\n"
        "  pip install 'websockets>=12.0'",
        file=sys.stderr,
    )
    sys.exit(1)

import requests


# ── ストリームタイプ → エンドポイントパス マッピング ──────────────────────────────

STREAM_ENDPOINTS: dict[str, str] = {
    "ap-monitoring":      "/network-monitoring/v1alpha1/ap-events",
    "audit-trail":        "/network-services/v1alpha1/audit-trail-events",
    "geofence":           "/network-services/v1alpha1/geofence-events",
    "location":           "/network-services/v1alpha1/location-events",
    "location-analytics": "/network-services/v1alpha1/location-analytics-events",
}

# ストリームタイプ別デフォルト event-types (フィルタ未指定時に使用)
DEFAULT_EVENT_TYPES: dict[str, str] = {
    "ap-monitoring": (
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.device"
    ),
    "audit-trail": (
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.device-monitoring"
    ),
}


# ── ロギング ─────────────────────────────────────────────────────────────────────

def _log(level: str, msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] [{level}] {msg}", flush=True)

def info(msg):  _log("INFO ", msg)
def warn(msg):  _log("WARN ", msg)
def error(msg): _log("ERROR", msg)
def ok(msg):    _log("OK   ", msg)


# ── 認証 ─────────────────────────────────────────────────────────────────────────

def get_access_token(token_url: str, client_id: str, client_secret: str) -> str:
    """HPE GreenLake SSO から OAuth2 ベアラートークンを取得する。"""
    payload = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
    }
    info(f"トークン取得: {token_url}")
    try:
        r = requests.post(token_url, data=payload, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        raise RuntimeError(
            f"トークンエンドポイントに接続できません ({token_url})。\n"
            "TOKEN_URL とネットワーク疎通を確認してください。"
        ) from exc

    if r.status_code == 401:
        raise RuntimeError(
            "401 Unauthorized — CLIENT_ID または CLIENT_SECRET が誤っています。"
        )
    if r.status_code == 403:
        raise RuntimeError(
            "403 Forbidden — GreenLake レベルでこのホストの IP がブロックされています。\n"
            "verify_api.py を実行して REST API 疎通を先に確認してください。"
        )
    if not r.ok:
        raise RuntimeError(
            f"トークン取得失敗 HTTP {r.status_code}: {r.text[:300]}"
        )

    data  = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"レスポンスに access_token がありません: {data}")

    expires_in = data.get("expires_in", "unknown")
    info(f"トークン取得成功 (expires_in={expires_in}s)。")
    return token


# ── URL 構築 ──────────────────────────────────────────────────────────────────────

def build_ws_url(base_url: str, stream_type: str, event_types: list[str]) -> str:
    """
    WebSocket Streaming エンドポイント URL を構築する。

    例:
      base_url    = "https://jp1.api.central.arubanetworks.com"
      stream_type = "audit-trail"
      event_types = ["com.hpe.greenlake...audit-trail.device-monitoring"]
      →
      "wss://jp1.api.central.arubanetworks.com
         /network-services/v1alpha1/audit-trail-events
         ?event-types=com.hpe.greenlake...audit-trail.device-monitoring"
    """
    if stream_type not in STREAM_ENDPOINTS:
        valid = ", ".join(STREAM_ENDPOINTS)
        raise ValueError(
            f"不明な STREAM_TYPE: '{stream_type}'\n"
            f"有効な値: {valid}"
        )

    ws_base = base_url.rstrip("/")
    ws_base = ws_base.replace("https://", "wss://").replace("http://", "ws://")
    path    = STREAM_ENDPOINTS[stream_type]
    url     = f"{ws_base}{path}"

    if event_types:
        qs  = urlencode({"event-types": ",".join(event_types)})
        url = f"{url}?{qs}"

    return url


# ── Protobuf CloudEvent デコード ──────────────────────────────────────────────────

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """varint を読み込み (値, 次のpos) を返す。"""
    value, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
    return value, pos


def _parse_proto_fields(data: bytes) -> dict[int, list]:
    """
    Protobuf wire format を field_num → [value, ...] の dict に変換する。
    wire_type=2 (LEN) のみ値を保持し、それ以外はスキップ。
    """
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        tag, pos = _read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:      # VARINT
            _, pos = _read_varint(data, pos)
        elif wire_type == 1:    # I64
            pos += 8
        elif wire_type == 2:    # LEN
            length, pos = _read_varint(data, pos)
            value = data[pos : pos + length]
            pos  += length
            fields.setdefault(field_num, []).append(value)
        elif wire_type == 5:    # I32
            pos += 4
        else:
            break   # 不明なワイヤータイプ — 解析中止
    return fields


def _parse_proto_all(data: bytes) -> dict[int, list[tuple[int, object]]]:
    """
    Protobuf wire format を field_num → [(wire_type, value), ...] に変換する。
    全ワイヤータイプ (VARINT / I64 / LEN / I32) を保持する。
    """
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(data):
        if pos >= len(data):
            break
        tag, pos = _read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:          # VARINT
            val, pos = _read_varint(data, pos)
            fields.setdefault(field_num, []).append((0, val))
        elif wire_type == 1:        # I64
            val = int.from_bytes(data[pos:pos+8], "little")
            pos += 8
            fields.setdefault(field_num, []).append((1, val))
        elif wire_type == 2:        # LEN
            length, pos = _read_varint(data, pos)
            val = data[pos:pos+length]
            pos += length
            fields.setdefault(field_num, []).append((2, val))
        elif wire_type == 5:        # I32
            val = int.from_bytes(data[pos:pos+4], "little")
            pos += 4
            fields.setdefault(field_num, []).append((5, val))
        else:
            break
    return fields


def _try_str(b: bytes) -> str | None:
    """bytes を UTF-8 文字列として返す。バイナリっぽければ None。"""
    try:
        s = b.decode("utf-8")
        # 制御文字が多い場合はバイナリと判定
        if sum(1 for c in s if ord(c) < 32 and c not in "\t\n\r") > len(s) * 0.1:
            return None
        return s
    except UnicodeDecodeError:
        return None


def decode_cloudevent(data: bytes) -> dict:
    """
    CloudEvents Protobuf エンベロープを解析して dict を返す。

    Aruba New Central CloudEvent proto フィールド定義:
      1 : id              (string)
      2 : source          (string)
      3 : specversion     (string)
      4 : type            (string)
      5 : attributes      (map<string, CloudEventAttributeValue>)
      6 : binary_data     (bytes)   ← 実際のイベントペイロード
      7 : text_data       (string)
      8 : proto_data      (google.protobuf.Any)
      9 : time            (google.protobuf.Timestamp: field1=seconds, field2=nanos)
      10: datacontenttype (string)
      11: dataschema      (string)

    Ref: https://developer.arubanetworks.com/new-central/docs/streaming-api-cloudevents
    """
    result: dict = {}
    fields = _parse_proto_fields(data)

    # 文字列フィールド
    str_fields = {
        1:  "id",
        2:  "source",
        3:  "specversion",
        4:  "type",
        10: "datacontenttype",
        11: "dataschema",
    }
    for fnum, fname in str_fields.items():
        if fnum in fields:
            s = _try_str(fields[fnum][0])
            if s:
                result[fname] = s

    # time (field 9): google.protobuf.Timestamp (field1=seconds int64, field2=nanos int32)
    if 9 in fields:
        ts_fields = _parse_proto_fields(fields[9][0])
        # field 1 は varint (seconds) → wire_type=0 なので _parse_proto_fields では取れない
        # → 生バイトから varint を直接読む
        try:
            seconds, _ = _read_varint(fields[9][0], 1)   # pos=1: tag(0x08)の次
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            result["time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # attributes (field 5): map<string, CloudEventAttributeValue>
    # map entry = embedded msg: field1=key(string), field2=value(CloudEventAttributeValue)
    attrs: dict[str, str] = {}
    for entry_bytes in fields.get(5, []):
        entry_fields = _parse_proto_fields(entry_bytes)
        if 1 not in entry_fields:
            continue
        key = _try_str(entry_fields[1][0])
        if not key:
            continue
        # CloudEventAttributeValue oneof:
        #   1=ce_boolean, 2=ce_integer, 3=ce_string, 4=ce_bytes,
        #   5=ce_uri, 6=ce_uri_ref, 7=ce_timestamp
        for val_bytes in entry_fields.get(2, []):
            val_fields = _parse_proto_fields(val_bytes)
            for vfnum in (3, 5, 6, 7):      # 文字列系フィールドを優先
                if vfnum in val_fields:
                    s = _try_str(val_fields[vfnum][0])
                    if s:
                        attrs[key] = s
                        break
    if attrs:
        result["attributes"] = attrs

    # binary_data (field 6): Aruba 固有イベントの Protobuf ペイロード
    if 6 in fields:
        payload = fields[6][0]
        result["payload_raw"]   = payload
        result["payload_bytes"] = len(payload)

    # text_data (field 7)
    if 7 in fields:
        s = _try_str(fields[7][0])
        if s:
            result["text_data"] = s

    # イベントタイプ別ペイロードデコード
    ev_type = result.get("type", "")
    if "payload_raw" in result:
        payload = result["payload_raw"]
        if "audit-trail" in ev_type:
            result["payload_decoded"] = decode_audit_trail_payload(payload)
        else:
            # best-effort 文字列抽出
            strs = _extract_strings_from_proto(payload)
            if strs:
                result["payload_decoded"] = {f"field[{k}]": v for k, v in strs.items()}

    return result


# ── デバッグ用 wire format ダンプ ─────────────────────────────────────────────────

def _debug_dump_fields(data: bytes, indent: int = 0, label: str = "CloudEvent") -> None:
    """Protobuf の全フィールドを再帰的に標準出力へダンプする（デバッグ用）。"""
    prefix = "  " * indent
    print(f"{prefix}[DEBUG] {label} ({len(data)}B):")
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _read_varint(data, pos)
        except Exception:
            break
        fnum = tag >> 3
        wt   = tag & 0x7
        if wt == 0:
            val, pos = _read_varint(data, pos)
            print(f"{prefix}  field[{fnum}] VARINT = {val}")
        elif wt == 1:
            val = int.from_bytes(data[pos:pos+8], "little"); pos += 8
            print(f"{prefix}  field[{fnum}] I64    = {val}")
        elif wt == 2:
            length, pos = _read_varint(data, pos)
            val = data[pos:pos+length]; pos += length
            try:
                s = val.decode("utf-8")
                if all(ord(c) >= 32 or c in "\t\n\r" for c in s):
                    print(f"{prefix}  field[{fnum}] STRING = {repr(s[:100])}")
                    continue
            except Exception:
                pass
            print(f"{prefix}  field[{fnum}] BYTES  = <{length}B> hex={val[:24].hex()}")
            if indent < 2:
                _debug_dump_fields(val, indent + 1, f"field[{fnum}] embedded")
        elif wt == 5:
            val = int.from_bytes(data[pos:pos+4], "little"); pos += 4
            print(f"{prefix}  field[{fnum}] I32    = {val}")
        else:
            print(f"{prefix}  [unknown wire_type={wt}]"); break


# ── AuditTrail ペイロードデコーダ ─────────────────────────────────────────────────
#
# Ref: https://developer.arubanetworks.com/new-central/docs/streaming-api-event-audit-trail
#
# AuditTrail フィールド定義:
#   1:  tenant_id        (string)
#   2:  occurred_on      (int64 VARINT, epoch ms)
#   3:  action           (string)
#   4:  category         (string)
#   5:  sub_category     (string)
#   6:  destination      (string)
#   7:  destination_name (string)
#   8:  scope_info       (ScopeInfo embedded)
#   9:  ip_address       (string)
#   10: description      (string)
#   11: source           (string)
#   12: service_name     (string)
#   13: log_details      (LogDetails embedded)
#   14: additional_info  (string)

_AUDIT_TRAIL_STR_FIELDS = {
    1:  "tenant_id",
    3:  "action",
    4:  "category",
    5:  "sub_category",
    6:  "destination",
    7:  "destination_name",
    9:  "ip_address",
    10: "description",
    11: "source",
    12: "service_name",
    14: "additional_info",
}


def decode_audit_trail_payload(data: bytes) -> dict:
    """AuditTrail Protobuf ペイロードをデコードして dict を返す。"""
    result: dict = {}
    all_fields = _parse_proto_all(data)

    # 文字列フィールド (wire_type=2)
    for fnum, fname in _AUDIT_TRAIL_STR_FIELDS.items():
        entries = [v for wt, v in all_fields.get(fnum, []) if wt == 2]
        if entries:
            s = _try_str(entries[0])
            if s:
                result[fname] = s

    # occurred_on (field 2, wire_type=0 VARINT → epoch ms)
    for wt, val in all_fields.get(2, []):
        if wt == 0 and val > 0:
            try:
                dt = datetime.fromtimestamp(val / 1000, tz=timezone.utc)
                result["occurred_on"] = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{(val % 1000):03d}Z"
            except Exception:
                result["occurred_on"] = str(val)
            break

    # scope_info (field 8, embedded)
    for wt, val in all_fields.get(8, []):
        if wt == 2:
            result["scope_info"] = _decode_scope_info(val)
            break

    # log_details (field 13, embedded)
    for wt, val in all_fields.get(13, []):
        if wt == 2:
            result["log_details"] = _decode_log_details(val)
            break

    return result


def _decode_scope_info(data: bytes) -> dict:
    """
    ScopeInfo embedded message をデコードする。
    フィールド: scope_type(string), scope_ids(repeated string)
    """
    result: dict = {}
    all_fields = _parse_proto_all(data)
    for fnum, fname in [(1, "scope_type"), (2, "scope_ids")]:
        entries = [v for wt, v in all_fields.get(fnum, []) if wt == 2]
        if not entries:
            continue
        if fname == "scope_ids":
            ids = [s for s in (_try_str(v) for v in entries) if s]
            if ids:
                result[fname] = ids
        else:
            s = _try_str(entries[0])
            if s:
                result[fname] = s
    return result


def _decode_log_details(data: bytes) -> dict:
    """
    LogDetails embedded message をデコードする。
    フィールド: changed_fields(repeated ChangedField), impact_radius(ImpactRadius), changed_json(string)
    ChangedField: field_label_key(1), before_transaction(2), after_transaction(3)
    ImpactRadius:  context(1), values(repeated string, 2)
    """
    result: dict = {}
    all_fields = _parse_proto_all(data)

    # changed_fields (field 1, repeated embedded)
    changed = []
    for wt, val in all_fields.get(1, []):
        if wt != 2:
            continue
        cf: dict = {}
        cf_all = _parse_proto_all(val)
        for fnum, fname in [(1, "field_label_key"), (2, "before"), (3, "after")]:
            entries = [v for wt2, v in cf_all.get(fnum, []) if wt2 == 2]
            if entries:
                s = _try_str(entries[0])
                if s:
                    cf[fname] = s
        if cf:
            changed.append(cf)
    if changed:
        result["changed_fields"] = changed

    # impact_radius (field 2, embedded)
    for wt, val in all_fields.get(2, []):
        if wt == 2:
            ir_all = _parse_proto_all(val)
            ir: dict = {}
            ctx = [v for wt2, v in ir_all.get(1, []) if wt2 == 2]
            if ctx:
                s = _try_str(ctx[0])
                if s:
                    ir["context"] = s
            vals = [_try_str(v) for wt2, v in ir_all.get(2, []) if wt2 == 2]
            vals = [s for s in vals if s]
            if vals:
                ir["values"] = vals
            if ir:
                result["impact_radius"] = ir
            break

    # changed_json (field 3, string)
    for wt, val in all_fields.get(3, []):
        if wt == 2:
            s = _try_str(val)
            if s:
                result["changed_json"] = s[:500]
            break

    return result


def _extract_strings_from_proto(data: bytes, max_fields: int = 20) -> dict[int, str]:
    """
    Protobuf バイナリから文字列っぽい LEN フィールドをすべて取り出す。
    .proto 定義なしのベストエフォート解析。
    """
    found: dict[int, str] = {}
    fields = _parse_proto_fields(data)
    count  = 0
    for fnum, values in sorted(fields.items()):
        for v in values:
            s = _try_str(v)
            if s and len(s) >= 2:
                found[fnum] = s
                count += 1
                if count >= max_fields:
                    return found
    return found


def _format_message(raw: bytes | str, index: int) -> str:
    """受信メッセージをログ表示用文字列に変換する（簡易1行版）。"""
    if isinstance(raw, str):
        try:
            import json
            obj = json.loads(raw)
            return f"[JSON] {json.dumps(obj, ensure_ascii=False)[:200]}"
        except Exception:
            return f"[TEXT] {raw[:200]}"
    nbytes = len(raw)
    ce     = decode_cloudevent(raw)
    ev_type = ce.get("type", "")
    if ev_type:
        return f"[PROTO {nbytes}B] type={ev_type}"
    return f"[PROTO {nbytes}B] hex={raw[:16].hex()}…"


def print_cloudevent(index: int, raw: bytes | str) -> None:
    """CloudEvent の内容を詳細に表示する。"""
    print(f"\n  ┌── イベント #{index} {'─' * 44}")

    if isinstance(raw, str):
        print(f"  │  [テキストフレーム]")
        print(f"  │  {raw[:400]}")
        print(f"  └{'─' * 58}")
        return

    ce = decode_cloudevent(raw)

    # ── CloudEvent エンベロープ ──────────────────────────
    for k in ("id", "source", "specversion", "type", "time", "datacontenttype", "dataschema"):
        if k in ce:
            print(f"  │  {k:<16}: {ce[k]}")

    # attributes (subject など)
    if "attributes" in ce:
        for k, v in ce["attributes"].items():
            print(f"  │  attr.{k:<11}: {v}")

    if "text_data" in ce:
        print(f"  │  text_data      : {ce['text_data'][:200]}")

    # ── ペイロード ──────────────────────────────────────
    if "payload_bytes" in ce:
        print(f"  │  ── payload ({ce['payload_bytes']} bytes) " + "─" * 25)

        decoded = ce.get("payload_decoded", {})
        if decoded:
            # AuditTrail 既知フィールドを整形表示
            order = [
                "occurred_on", "tenant_id", "action", "category", "sub_category",
                "service_name", "source", "destination", "destination_name",
                "ip_address", "description", "additional_info",
            ]
            for k in order:
                if k in decoded:
                    print(f"  │    {k:<20}: {str(decoded[k])[:120]}")

            if "scope_info" in decoded:
                si = decoded["scope_info"]
                print(f"  │    scope_type        : {si.get('scope_type', '')}")
                if "scope_ids" in si:
                    print(f"  │    scope_ids         : {', '.join(si['scope_ids'])}")

            if "log_details" in decoded:
                ld = decoded["log_details"]
                if "changed_fields" in ld:
                    print(f"  │    changed_fields    :")
                    for cf in ld["changed_fields"]:
                        label  = cf.get("field_label_key", "?")
                        before = cf.get("before", "")
                        after  = cf.get("after", "")
                        print(f"  │      [{label}] {before!r} → {after!r}")
                if "impact_radius" in ld:
                    ir = ld["impact_radius"]
                    print(f"  │    impact_radius     : ctx={ir.get('context','')} vals={ir.get('values','')}")
                if "changed_json" in ld:
                    print(f"  │    changed_json      : {ld['changed_json'][:200]}")

            # 未知フィールド (best-effort)
            known = set(order) | {"scope_info", "log_details"}
            for k, v in decoded.items():
                if k not in known:
                    print(f"  │    {k:<20}: {str(v)[:120]}")
        else:
            payload_raw = ce.get("payload_raw", b"")
            print(f"  │    hex              : {payload_raw[:32].hex()}…")

    print(f"  └{'─' * 58}")


# ── Streaming 本体 ────────────────────────────────────────────────────────────────

async def run_streaming(
    ws_url: str,
    token: str,
    duration: int,
) -> dict:
    """
    WebSocket Streaming API へ接続してメッセージを受信する。

    認証: HTTP Upgrade リクエストの Authorization: Bearer ヘッダー
    購読: 接続後の追加メッセージ不要 (URL + ヘッダーで完結)

    戻り値 dict:
      connected   : bool  接続成功
      event_count : int   受信メッセージ数
      byte_count  : int   受信バイト合計
      samples     : list  先頭最大 5 件のフォーマット済みサンプル
      errors      : list  エラーメッセージ
    """
    result: dict = {
        "connected":   False,
        "event_count": 0,
        "byte_count":  0,
        "samples":     [],
        "errors":      [],
    }

    headers = {"Authorization": f"Bearer {token}"}

    loop     = asyncio.get_event_loop()
    deadline = loop.time() + duration
    attempt  = 0

    while loop.time() < deadline:
        attempt += 1
        remaining_total = deadline - loop.time()
        if remaining_total <= 0:
            break
        if attempt > 1:
            wait = min(5, remaining_total)
            info(f"再接続待機 {wait:.0f}s … (試行 #{attempt})")
            await asyncio.sleep(wait)
            remaining_total = deadline - loop.time()
            if remaining_total <= 0:
                break

        try:
            async with websockets.connect(
                ws_url,
                additional_headers=headers,
                open_timeout=20,
                ping_interval=None,   # Aruba Central は ping に応答しないため無効化
            ) as ws:
                result["connected"] = True
                info(f"WebSocket 接続確立 (HTTP 101 Switching Protocols){'  ← 再接続' if attempt > 1 else ''}。")
                info(f"イベント受信待機中 (残り {remaining_total:.0f}s) …")

                while True:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        info("受信タイムアウト — 正常終了。")
                        return result

                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
                    except asyncio.TimeoutError:
                        info("受信タイムアウト — 正常終了。")
                        return result
                    except ConnectionClosed as exc:
                        code   = exc.rcvd.code   if exc.rcvd else "?"
                        reason = exc.rcvd.reason if exc.rcvd else ""
                        warn(f"接続が切断されました (code={code} {reason}) — 再接続します。")
                        _hint_close_code(exc)
                        break   # 外側ループで再接続

                    result["event_count"] += 1
                    nbytes = len(raw) if isinstance(raw, (bytes, bytearray)) else len(raw.encode())
                    result["byte_count"] += nbytes

                    fmt = _format_message(raw, result["event_count"])
                    if len(result["samples"]) < 5:
                        result["samples"].append(fmt)

                    # 全イベントを詳細表示（最大10件）
                    if result["event_count"] <= 10:
                        print_cloudevent(result["event_count"], raw)

                    # 最初の1件を /tmp/ce_raw.bin に保存（デバッグ用）
                    if result["event_count"] == 1 and isinstance(raw, (bytes, bytearray)):
                        try:
                            with open("/tmp/ce_raw.bin", "wb") as _f:
                                _f.write(raw)
                            _debug_dump_fields(raw)
                        except Exception:
                            pass

        except InvalidHandshake as exc:
            msg = str(exc)
            result["errors"].append(f"WebSocket ハンドシェイク失敗: {msg}")
            _hint_handshake(msg)
            break   # ハンドシェイク失敗は再接続しない
        except OSError as exc:
            result["errors"].append(f"ネットワークエラー: {exc}")
            break
        except WebSocketException as exc:
            result["errors"].append(f"WebSocket エラー: {exc}")
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"予期しないエラー: {type(exc).__name__}: {exc}")
            break

    return result


def _hint_handshake(msg: str) -> None:
    ml = msg.lower()
    if "400" in msg:
        error("  ヒント: STREAM_EVENT_TYPES の値が無効な可能性があります。")
        error("         公式ドキュメントで有効な event-type 一覧を確認してください。")
    elif "401" in msg or "unauthorized" in ml:
        error("  ヒント: トークンが無効です。CLIENT_ID/SECRET を確認してください。")
    elif "403" in msg or "forbidden" in ml:
        error("  ヒント: IP allowlist でブロックされています。")
        error("         verify_api.py で REST API 疎通を先に確認してください。")
    elif "404" in msg or "not found" in ml:
        error("  ヒント: Streaming エンドポイントが見つかりません。")
        error("         STREAM_TYPE または BASE_URL を確認してください。")


def _hint_close_code(exc: ConnectionClosed) -> None:
    if not exc.rcvd:
        return
    code = exc.rcvd.code
    if code == 1008:
        warn("  ヒント (1008 Policy Violation): 認証エラーまたは不正なリクエストの可能性。")
    elif code == 1011:
        warn("  ヒント (1011 Internal Error): サーバー側エラー。しばらく待ってから再試行してください。")
    elif code == 4000:
        warn("  ヒント (4000): トークン有効期限切れの可能性。トークンを再取得してください。")


# ── 結果表示 ──────────────────────────────────────────────────────────────────────

def print_summary(
    result: dict,
    stream_type: str,
    ws_url: str,
    duration: int,
) -> None:
    print()
    print("=" * 64)

    if not result["connected"]:
        error("✘  WebSocket 接続失敗")
        for e in result["errors"]:
            error(f"   {e}")
        print()
        _print_troubleshoot()
        print("=" * 64)
        return

    n = result["event_count"]
    if n > 0:
        ok(f"✔  Streaming API 正常動作確認")
        info(f"   Stream  : {stream_type}")
        info(f"   URL     : {ws_url}")
        info(f"   Duration: {duration}s")
        info(f"   Messages: {n} 件受信 / {result['byte_count']} bytes")
        if result["samples"]:
            info("   Samples :")
            for s in result["samples"]:
                info(f"     {s}")
    else:
        warn("△  接続は成功しましたが、イベントを受信できませんでした。")
        warn(f"   Stream  : {stream_type}")
        warn(f"   URL     : {ws_url}")
        warn(f"   Duration: {duration}s")
        warn("   指定したトピックで現在アクティブなイベントがない場合は正常です。")
        warn("   Streaming エンドポイント自体には到達できています。")
        if result["errors"]:
            for e in result["errors"]:
                warn(f"   {e}")

    print("=" * 64)
    print()


def _print_troubleshoot() -> None:
    rows = [
        ("接続タイムアウト / OSError", "BASE_URL が誤っている / ネットワーク疎通なし"),
        ("400 Bad Request",          "STREAM_EVENT_TYPES の値が無効"),
        ("401 Unauthorized",         "CLIENT_ID / CLIENT_SECRET が誤り"),
        ("403 Forbidden",            "IP allowlist でブロック → verify_api.py で確認"),
        ("404 Not Found",            "STREAM_TYPE が対象環境でサポートされていない"),
    ]
    print("  トラブルシューティング:")
    sep = "  " + "─" * 60
    for symptom, cause in rows:
        print(sep)
        print(f"  症状 : {symptom}")
        print(f"  原因 : {cause}")
    print(sep)
    print()


# ── main ──────────────────────────────────────────────────────────────────────────

def main() -> int:
    # 必須環境変数チェック
    required = ("CLIENT_ID", "CLIENT_SECRET", "BASE_URL")
    missing  = [k for k in required if not os.environ.get(k)]
    if missing:
        error(f"必須の環境変数が未設定です: {', '.join(missing)}")
        error(".env.example を .env にコピーして値を記入してください。")
        return 1

    client_id     = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]
    base_url      = os.environ["BASE_URL"]
    token_url     = os.environ.get(
        "TOKEN_URL",
        "https://sso.common.cloud.hpe.com/as/token.oauth2",
    )
    stream_type   = os.environ.get("STREAM_TYPE", "audit-trail").strip()
    event_types_raw = os.environ.get("STREAM_EVENT_TYPES", "")

    # event-types:
    #   環境変数未設定         → ストリームタイプ別デフォルトを使用
    #   STREAM_EVENT_TYPES=""  → フィルタなし（全イベント受信）
    #   STREAM_EVENT_TYPES=a,b → 指定したタイプのみ
    if "STREAM_EVENT_TYPES" not in os.environ:
        default = DEFAULT_EVENT_TYPES.get(stream_type, "")
        event_types = [default] if default else []
    else:
        event_types = [t.strip() for t in event_types_raw.split(",") if t.strip()]

    try:
        duration = int(os.environ.get("STREAM_DURATION", "30"))
    except ValueError:
        error("STREAM_DURATION は整数（秒）で指定してください。")
        return 1

    # WebSocket URL 構築
    try:
        ws_url = build_ws_url(base_url, stream_type, event_types)
    except ValueError as exc:
        error(str(exc))
        return 1

    print()
    print("=" * 64)
    print("  Aruba New Central — Streaming API Test Tool")
    print("=" * 64)
    print()
    info(f"Stream Type : {stream_type}")
    info(f"WS URL      : {ws_url}")
    info(f"Duration    : {duration}s")
    print()

    # Step 1: トークン取得
    info("Step 1/2  HPE GreenLake SSO 認証 …")
    try:
        token = get_access_token(token_url, client_id, client_secret)
    except RuntimeError as exc:
        error(str(exc))
        return 1

    print()

    # Step 2: Streaming 接続テスト
    info("Step 2/2  Streaming API 接続テスト …")
    print()

    result = asyncio.run(run_streaming(ws_url, token, duration))

    print_summary(result, stream_type, ws_url, duration)

    return 0 if result["connected"] else 1


if __name__ == "__main__":
    sys.exit(main())
