"""
Aruba New Central Streaming API — Protobuf デコーダ集

対応ストリーム:
  audit-trail        設定変更・監査ログ
  ap-monitoring      APデバイス状態・統計
  location           リアルタイム位置情報
  location-analytics RSSI位置分析
  geofence           ジオフェンス

Ref:
  https://developer.arubanetworks.com/new-central/docs/streaming-api-cloudevents
  https://developer.arubanetworks.com/new-central/docs/streaming-api-event-audit-trail
  https://developer.arubanetworks.com/new-central/docs/streaming-api-event-ap-monitoring
  https://developer.arubanetworks.com/new-central/docs/streaming-api-event-location
  https://developer.arubanetworks.com/new-central/docs/streaming-api-event-location-analytics
  https://developer.arubanetworks.com/new-central/docs/streaming-api-event-geofence
"""

import struct
from datetime import datetime, timezone

# ──────────────────────────────────────────────────────────────
# Wire format 基本関数
# ──────────────────────────────────────────────────────────────

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    value, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        value |= (b & 0x7F) << shift; shift += 7
        if not (b & 0x80): break
    return value, pos


def _parse_proto_all(data: bytes) -> dict[int, list[tuple[int, object]]]:
    """Protobuf wire format を field_num → [(wire_type, value), ...] に変換する。"""
    fields: dict = {}
    pos = 0
    while pos < len(data):
        try:
            tag, pos = _read_varint(data, pos)
        except Exception:
            break
        fnum = tag >> 3; wt = tag & 0x7
        if wt == 0:
            v, pos = _read_varint(data, pos)
            fields.setdefault(fnum, []).append((0, v))
        elif wt == 1:
            if pos + 8 > len(data): break
            v = int.from_bytes(data[pos:pos+8], "little"); pos += 8
            fields.setdefault(fnum, []).append((1, v))
        elif wt == 2:
            ln, pos = _read_varint(data, pos)
            if pos + ln > len(data): break
            v = data[pos:pos+ln]; pos += ln
            fields.setdefault(fnum, []).append((2, v))
        elif wt == 5:
            if pos + 4 > len(data): break
            v = int.from_bytes(data[pos:pos+4], "little"); pos += 4
            fields.setdefault(fnum, []).append((5, v))
        else:
            break
    return fields


def _try_str(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
        ctrl = sum(1 for c in s if ord(c) < 32 and c not in "\t\n\r")
        if ctrl > max(1, len(s) * 0.1): return None
        return s
    except Exception:
        return None


def _i32f(v: int) -> float:
    """32bit int → IEEE 754 float。"""
    return round(struct.unpack("<f", v.to_bytes(4, "little", signed=False))[0], 4)


def _i64d(v: int) -> float:
    """64bit int → IEEE 754 double。"""
    return round(struct.unpack("<d", v.to_bytes(8, "little", signed=False))[0], 6)


# ──────────────────────────────────────────────────────────────
# Generic schema-based decoder
# ──────────────────────────────────────────────────────────────
#
# Schema format: {field_num: (name, typecode, *optional_extra)}
# typecodes:
#   "s"  UTF-8 string        (wt=2)
#   "rs" repeated strings    (wt=2, multiple occurrences)
#   "i"  unsigned varint     (wt=0)
#   "b"  bool                (wt=0, display true/false)
#   "e"  enum                (wt=0, extra=dict{int:str})
#   "f"  float32             (wt=5, IEEE 754)
#   "d"  float64             (wt=1, IEEE 754)
#   "m"  embedded message    (wt=2, extra=sub_schema)
#   "rm" repeated messages   (wt=2, extra=sub_schema)

def _decode_msg(data: bytes, schema: dict) -> dict:
    result: dict = {}
    af = _parse_proto_all(data)
    for fnum, spec in schema.items():
        name = spec[0]; tc = spec[1]
        extra = spec[2] if len(spec) > 2 else None
        entries = af.get(fnum, [])
        if tc == "s":
            for wt, v in entries:
                if wt == 2:
                    s = _try_str(v)
                    if s: result[name] = s; break
        elif tc == "rs":
            vals = [_try_str(v) for wt, v in entries if wt == 2]
            if lst := [v for v in vals if v]: result[name] = lst
        elif tc == "i":
            for wt, v in entries:
                if wt == 0: result[name] = v; break
        elif tc == "b":
            for wt, v in entries:
                if wt == 0: result[name] = bool(v); break
        elif tc == "e":
            for wt, v in entries:
                if wt == 0:
                    result[name] = extra.get(v, f"({v})") if extra else v; break
        elif tc == "f":
            for wt, v in entries:
                if wt == 5: result[name] = _i32f(v); break
        elif tc == "d":
            for wt, v in entries:
                if wt == 1: result[name] = _i64d(v); break
        elif tc == "m":
            for wt, v in entries:
                if wt == 2 and extra: result[name] = _decode_msg(v, extra); break
        elif tc == "rm":
            msgs = [_decode_msg(v, extra) for wt, v in entries if wt == 2 and extra]
            if msgs: result[name] = msgs
    return result


# ──────────────────────────────────────────────────────────────
# Enum 定義
# ──────────────────────────────────────────────────────────────

EV_OP        = {0:"UNSPECIFIED",1:"ADD",2:"UPDATE",3:"DELETE"}
AP_MODE      = {0:"UNKNOWN",1:"CAMPUS_AP",2:"REMOTE_AP",3:"MESH_PORTAL",4:"MESH_POINT",5:"SPEC_AP"}
AP_OP_MODE   = {0:"UNSPECIFIED",1:"STANDALONE",2:"CONDUCTOR",3:"MEMBER"}
AP_ROLE      = {0:"UNSPECIFIED",1:"MASTER",2:"LOCAL",3:"STANDBY"}
MESH_ROLE    = {0:"UNSPECIFIED",1:"PORTAL",2:"POINT",3:"HYBRID"}
UPLINK_TYPE  = {0:"UNSPECIFIED",1:"ETHERNET",2:"WIFI",3:"CELLULAR"}
DOWN_REASON  = {0:"UNSPECIFIED",1:"DOWN",2:"POWER",3:"REBOOT"}
RADIO_BAND   = {0:"UNSPECIFIED",1:"BAND_2G",2:"BAND_5G",3:"BAND_6G",4:"BAND_60G"}
BAND_RANGE   = {0:"UNSPECIFIED",1:"LOW",2:"MID",3:"HIGH",4:"ULTRA"}
RADIO_MODE   = {0:"UNSPECIFIED",1:"ACCESS",2:"MONITOR",3:"SPECTRUM"}
DEV_STATUS   = {0:"UNSPECIFIED",1:"UP",2:"DOWN"}
HT_TYPE      = {0:"UNSPECIFIED",1:"HT",2:"VHT",3:"HE",4:"EHT"}
PHY_TYPE     = {0:"UNSPECIFIED",1:"A",2:"B",3:"G",4:"N",5:"AC",6:"AX",7:"BE"}
RADIO_TYPE   = {0:"UNSPECIFIED",1:"LEGACY",2:"WIFI6",3:"WIFI6E",4:"WIFI7"}
PORT_TYPE    = {0:"UNSPECIFIED",1:"ETH",2:"SFP",3:"USB"}
PORT_MODE    = {0:"UNSPECIFIED",1:"ACCESS",2:"TRUNK",3:"HYBRID"}
PORT_SPEED   = {0:"UNSPECIFIED",10:"10M",100:"100M",1000:"1G",10000:"10G",100000:"100G"}
PORT_DUPLEX  = {0:"UNSPECIFIED",1:"HALF",2:"FULL"}
PORT_VLAN_M  = {0:"UNSPECIFIED",1:"ACCESS",2:"TRUNK",3:"HYBRID"}
WLAN_OP_MODE = {0:"UNSPECIFIED",1:"EMPLOYEE",2:"VOICE",3:"GUEST"}
WLAN_TYPE    = {0:"UNSPECIFIED",1:"STANDARD",2:"MESH"}
WLAN_BAND    = {0:"UNSPECIFIED",1:"BAND_2G",2:"BAND_5G",3:"BAND_DUAL",4:"BAND_6G",5:"BAND_TRIPLE"}
TUNNEL_IDX   = {0:"UNSPECIFIED",1:"PRIMARY",2:"SECONDARY"}
TUNNEL_CRYPT = {0:"UNSPECIFIED",1:"NONE",2:"AES",3:"3DES"}
TUNNEL_ST    = {0:"UNSPECIFIED",1:"UP",2:"DOWN"}
TUNNEL_TYPE  = {0:"UNSPECIFIED",1:"GRE",2:"IPSEC",3:"MPLS"}
GEO_EV_TYPE  = {0:"UNSPECIFIED",1:"ENTER",2:"EXIT"}
FW_VER       = {0:"UNSPECIFIED",1:"CLIENT_8X_RSSI",2:"CLIENT_10X_RSSI"}


# ──────────────────────────────────────────────────────────────
# AP Monitoring スキーマ
# ──────────────────────────────────────────────────────────────

_CLUSTER_INFO = {
    1: ("cluster_id","s"), 2: ("name","s"), 3: ("ip_v4","s"),
}

AP_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("device_name","s"),
    7:("model","s"), 8:("ip_v4","s"), 9:("ip_v6","s"), 10:("public_ip","s"),
    11:("uptime_sec","i"), 12:("mode","e",AP_MODE), 13:("status","b"),
    14:("operating_mode","e",AP_OP_MODE), 15:("cluster","m",_CLUSTER_INFO),
    16:("elected_role","e",AP_ROLE), 17:("mesh_mode","e",MESH_ROLE),
    18:("current_uplink","e",UPLINK_TYPE), 19:("firmware_version","s"),
    20:("zone","s"), 22:("country_code","s"),
    23:("down_reason","e",DOWN_REASON), 24:("modem_status","b"),
}

RADIO_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("radio_mac_address","s"),
    7:("channel","s"), 8:("transmit_power","i"), 9:("radio_number","i"),
    10:("band","e",RADIO_BAND), 11:("band_range","e",BAND_RANGE),
    12:("mode","e",RADIO_MODE), 13:("status","e",DEV_STATUS),
    14:("ht_type","e",HT_TYPE), 15:("phy_type","e",PHY_TYPE),
    19:("eirp","i"), 20:("primary_chan","i"), 21:("secondary_chan","i"),
    23:("spatial_stream","s"), 24:("radio_type","e",RADIO_TYPE),
}

VAP_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("radio_mac_address","s"),
    7:("bssid","s"), 8:("essid","s"),
}

PORT_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("port_index","i"),
    7:("port_name","s"), 8:("port_mac_address","s"), 9:("status","e",DEV_STATUS),
    10:("admin_state","b"), 11:("operate_state","b"), 12:("type","e",PORT_TYPE),
    13:("mode","e",PORT_MODE), 15:("duplex","e",PORT_DUPLEX),
    17:("access_vlan","i"), 18:("native_vlan","i"), 19:("allowed_vlan","s"),
    20:("is_uplink","b"),
}

WLAN_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("essid","s"),
    7:("vlan","s"), 8:("wlan_op_mode","e",WLAN_OP_MODE),
    9:("wlan_type","e",WLAN_TYPE), 10:("wlan_band","e",WLAN_BAND),
    11:("status","b"),
}

TUNNEL_INFO_SCHEMA = {
    1:("operation","e",EV_OP), 2:("timestamp","s"), 3:("tenant_id","s"),
    4:("serial_number","s"), 5:("mac_address","s"), 6:("index","e",TUNNEL_IDX),
    7:("tunnel_name","s"), 8:("crypto_type","e",TUNNEL_CRYPT),
    9:("peer_ip","s"), 10:("ip","s"), 11:("status","e",TUNNEL_ST),
    12:("active","b"), 13:("uptime_sec","i"), 14:("peer_name","s"),
}

AP_SYSTEM_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("cpu_utilization","f"),
    6:("memory_utilization","f"), 7:("power_consumption","d"),
}

RADIO_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("radio_mac_address","s"),
    6:("band","e",RADIO_BAND), 7:("band_range","e",BAND_RANGE),
    8:("tx_bytes","i"), 9:("rx_bytes","i"), 10:("noise_floor","i"),
    11:("channel_quality","i"), 12:("total_utilization","i"),
    13:("tx_utilization","i"), 14:("rx_utilization","i"),
    15:("non_wifi_interference","i"), 17:("frame_retries_pct","f"),
    19:("frame_drops_pct","f"),
}

VAP_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("radio_mac_address","s"),
    6:("bssid","s"), 7:("essid","s"), 8:("tx_bytes","i"), 9:("rx_bytes","i"),
}

PORT_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("port_mac_address","s"), 6:("port_index","i"),
    7:("duplex","e",PORT_DUPLEX), 9:("tx_bytes","i"), 10:("rx_bytes","i"),
    11:("tx_pkts","i"), 12:("rx_pkts","i"), 14:("frame_error_pct","f"),
    16:("frame_drops_pct","f"), 18:("crc_pct","f"), 20:("collision_pct","f"),
}

MODEM_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("tx_bytes","i"), 6:("rx_bytes","i"),
    7:("cellular_signal","i"), 8:("cellular_sinr","i"),
}

TUNNEL_STAT_SCHEMA = {
    1:("timestamp","s"), 2:("tenant_id","s"), 3:("serial_number","s"),
    4:("mac_address","s"), 5:("tunnel_index","e",TUNNEL_IDX),
    6:("tunnel_name","s"), 7:("tun_type","e",TUNNEL_TYPE),
    8:("tx_bytes","i"), 9:("rx_bytes","i"), 10:("tx_pkts","i"), 11:("rx_pkts","i"),
}

# event-type サフィックス → (日本語ラベル, スキーマ)
AP_TYPE_SCHEMAS: dict[str, tuple[str, dict]] = {
    "aps.state.device":               ("AP状態",       AP_INFO_SCHEMA),
    "aps.state.radio":                ("Radio状態",    RADIO_INFO_SCHEMA),
    "aps.state.virtual_access_point": ("VAP状態",      VAP_INFO_SCHEMA),
    "aps.state.port":                 ("Port状態",     PORT_INFO_SCHEMA),
    "aps.state.wlan":                 ("WLAN状態",     WLAN_INFO_SCHEMA),
    "aps.state.tunnel":               ("Tunnel状態",   TUNNEL_INFO_SCHEMA),
    "aps.stats.device":               ("APシステム統計", AP_SYSTEM_STAT_SCHEMA),
    "aps.stats.radio":                ("Radio統計",    RADIO_STAT_SCHEMA),
    "aps.stats.virtual_access_point": ("VAP統計",      VAP_STAT_SCHEMA),
    "aps.stats.port":                 ("Port統計",     PORT_STAT_SCHEMA),
    "aps.stats.modem":                ("Modem統計",    MODEM_STAT_SCHEMA),
    "aps.stats.tunnel":               ("Tunnel統計",   TUNNEL_STAT_SCHEMA),
}


# ──────────────────────────────────────────────────────────────
# Location スキーマ
# ──────────────────────────────────────────────────────────────

_ZONE_ENTRY = {
    1:("zone_id","s"), 2:("dwell_time_seconds","i"),
}

WIFI_CLIENT_LOCATION_SCHEMA = {
    1:("x","d"), 2:("y","d"), 3:("error_level","d"),
    4:("sta_eth_mac","s"), 5:("longitude","d"), 6:("latitude","d"),
    7:("site_id","s"), 8:("building_id","s"), 9:("floor_id","s"),
    10:("reporting_ap_serial","rs"),
    11:("associated","b"), 12:("assoc_bssid","s"), 13:("connected","b"),
    14:("entered_zone_info","rm",_ZONE_ENTRY),
}

ASSET_TAG_LOCATION_SCHEMA = {
    1:("x","d"), 2:("y","d"), 3:("device_id","s"), 4:("device_mac","s"),
    5:("entered_zone_info","rm",_ZONE_ENTRY),
    6:("longitude","d"), 7:("latitude","d"),
    8:("site_id","s"), 9:("building_id","s"), 10:("floor_id","s"),
    11:("battery_level","d"), 12:("name","s"), 13:("custom_id","s"),
    14:("label","rs"), 15:("notes","s"),
}

STREAM_LOCATION_SCHEMA = {
    1:("wifi_client","m",WIFI_CLIENT_LOCATION_SCHEMA),
    2:("asset_tag","m",ASSET_TAG_LOCATION_SCHEMA),
}


# ──────────────────────────────────────────────────────────────
# Location Analytics スキーマ
# ──────────────────────────────────────────────────────────────

CLIENT_RSSI_SCHEMA = {
    1:("client_mac","s"), 2:("ap_serial","s"), 3:("ap_mac","s"),
    4:("radio_mac","s"), 5:("rssi_val","i"), 6:("associated","b"),
    7:("assoc_bssid","s"), 8:("age","i"), 9:("noise_floor","i"),
    10:("ap_ip","s"), 11:("ap_name","s"),
}

RSSI_EVENT_SCHEMA = {
    1:("firmware_version","e",FW_VER),
    2:("raw_rssi","m",CLIENT_RSSI_SCHEMA),
    3:("proximity_rssi","m",CLIENT_RSSI_SCHEMA),
}


# ──────────────────────────────────────────────────────────────
# Geofence スキーマ
# ──────────────────────────────────────────────────────────────

WIFI_CLIENT_GEO_SCHEMA = {
    1:("zone_id","s"), 2:("event_type","e",GEO_EV_TYPE),
    3:("sta_eth_mac","s"), 4:("assoc_bssid","s"),
    5:("hashed_sta_eth_mac","s"), 6:("dwell_time_seconds","i"),
}

ASSET_TAG_GEO_SCHEMA = {
    1:("zone_id","s"), 2:("event_type","e",GEO_EV_TYPE),
    3:("device_id","s"), 4:("dwell_time_seconds","i"),
}

STREAM_GEOFENCE_SCHEMA = {
    1:("wifi_client_geofence","m",WIFI_CLIENT_GEO_SCHEMA),
    2:("asset_tag_geofence","m",ASSET_TAG_GEO_SCHEMA),
}


# ──────────────────────────────────────────────────────────────
# AuditTrail デコーダ
# ──────────────────────────────────────────────────────────────

_CHANGED_FIELD_SCHEMA = {
    1:("field_label_key","s"), 2:("before","s"), 3:("after","s"),
}
_IMPACT_RADIUS_SCHEMA = {
    1:("context","s"), 2:("values","rs"),
}
_SCOPE_INFO_SCHEMA = {
    1:("scope_type","s"), 2:("scope_ids","rs"),
}
_LOG_DETAILS_SCHEMA = {
    1:("changed_fields","rm",_CHANGED_FIELD_SCHEMA),
    2:("impact_radius","m",_IMPACT_RADIUS_SCHEMA),
    3:("changed_json","s"),
}

_AT_STR = {
    1:"tenant_id", 3:"action", 4:"category", 5:"sub_category",
    6:"destination", 7:"destination_name", 9:"ip_address",
    10:"description", 11:"source", 12:"service_name", 14:"additional_info",
}

def decode_audit_trail_payload(data: bytes) -> dict:
    result: dict = {}
    af = _parse_proto_all(data)
    for fnum, fname in _AT_STR.items():
        for wt, v in af.get(fnum, []):
            if wt == 2:
                s = _try_str(v)
                if s: result[fname] = s; break
    for wt, v in af.get(2, []):
        if wt == 0 and v > 0:
            try:
                dt = datetime.fromtimestamp(v / 1000, tz=timezone.utc)
                result["occurred_on"] = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{v%1000:03d}Z"
            except Exception:
                result["occurred_on"] = str(v)
            break
    for wt, v in af.get(8, []):
        if wt == 2: result["scope_info"] = _decode_msg(v, _SCOPE_INFO_SCHEMA); break
    for wt, v in af.get(13, []):
        if wt == 2: result["log_details"] = _decode_msg(v, _LOG_DETAILS_SCHEMA); break
    return result


# ──────────────────────────────────────────────────────────────
# CloudEvent エンベロープデコーダ
# ──────────────────────────────────────────────────────────────

def decode_cloudevent(data: bytes) -> dict:
    """
    CloudEvents Protobuf エンベロープを解析し、イベント種別に応じてペイロードもデコードする。

    CloudEvent フィールド:
      1:id  2:source  3:specversion  4:type
      5:attributes(map)  6:binary_data  7:text_data  8:proto_data(Any)
      9:time(Timestamp)  10:datacontenttype  11:dataschema
    """
    result: dict = {}
    af = _parse_proto_all(data)

    # 文字列フィールド
    for fnum, fname in [(1,"id"),(2,"source"),(3,"specversion"),(4,"type"),
                         (10,"datacontenttype"),(11,"dataschema")]:
        for wt, v in af.get(fnum, []):
            if wt == 2:
                s = _try_str(v)
                if s: result[fname] = s; break

    # time (field 9: Timestamp embedded — field1=seconds VARINT)
    for wt, v in af.get(9, []):
        if wt == 2:
            try:
                seconds, _ = _read_varint(v, 1)   # tag 0x08 の次
                dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
                result["time"] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass
            break

    # attributes (field 5: map<string, CloudEventAttributeValue>)
    attrs: dict = {}
    for wt, v in af.get(5, []):
        if wt != 2: continue
        ef = _parse_proto_all(v)
        key = None
        for wt2, v2 in ef.get(1, []):
            if wt2 == 2: key = _try_str(v2); break
        if not key: continue
        for wt2, v2 in ef.get(2, []):
            if wt2 != 2: continue
            vf = _parse_proto_all(v2)
            # ce_string(3), ce_uri(5), ce_uri_ref(6), ce_timestamp(7) を試みる
            for vfnum in (3, 5, 6, 7):
                for wt3, v3 in vf.get(vfnum, []):
                    if wt3 == 2:
                        s = _try_str(v3)
                        if s: attrs[key] = s; break
                if key in attrs: break
    if attrs:
        result["attributes"] = attrs

    # ペイロード抽出: field6(binary_data) → field8(proto_data.Any) → field7(text_data)
    payload_raw: bytes | None = None
    payload_src: str = "none"

    # field6: binary_data (bytes)
    for wt, v in af.get(6, []):
        if wt == 2 and v:
            payload_raw = v
            payload_src = "binary_data(f6)"
            break

    if payload_raw is None:
        # field8: proto_data (google.protobuf.Any { type_url(1), value(2) })
        for wt, v in af.get(8, []):
            if wt == 2:
                any_af = _parse_proto_all(v)
                # type_url を記録
                for wt2, v2 in any_af.get(1, []):
                    if wt2 == 2:
                        tu = _try_str(v2)
                        if tu: result["proto_type_url"] = tu
                for wt2, v2 in any_af.get(2, []):
                    if wt2 == 2 and v2:
                        payload_raw = v2
                        payload_src = "proto_data(f8)"
                        break
                break

    if payload_raw is None:
        # field7: text_data
        for wt, v in af.get(7, []):
            if wt == 2:
                s = _try_str(v)
                if s:
                    result["text_data"] = s
                    payload_src = "text_data(f7)"
                break

    # 存在する全フィールド番号を記録（デバッグ用）
    result["_fields_found"] = sorted(af.keys())
    result["_payload_src"]  = payload_src

    if payload_raw is not None:
        result["payload_bytes"]   = len(payload_raw)
        result["payload_decoded"] = decode_event_payload(payload_raw, result.get("type", ""))

    return result


def decode_event_payload(payload: bytes, ev_type: str) -> dict:
    """イベントタイプに応じてペイロードをデコードする。"""
    if "audit-trail" in ev_type:
        return decode_audit_trail_payload(payload)

    if "network-monitoring" in ev_type:
        for suffix, (label, schema) in AP_TYPE_SCHEMAS.items():
            if ev_type.endswith(suffix):
                decoded = _decode_msg(payload, schema)
                decoded["_label"] = label
                return decoded
        return {}

    if "location-analytics" in ev_type:
        return _decode_msg(payload, RSSI_EVENT_SCHEMA)

    if "geofence" in ev_type:
        return _decode_msg(payload, STREAM_GEOFENCE_SCHEMA)

    if "location" in ev_type:
        return _decode_msg(payload, STREAM_LOCATION_SCHEMA)

    return {}


# ──────────────────────────────────────────────────────────────
# 利用可能なイベントタイプ一覧（フロントエンド用）
# ──────────────────────────────────────────────────────────────

AVAILABLE_EVENT_TYPES: dict[str, list[str]] = {
    "audit-trail": [
        # ── 一般設定・運用系 ──────────────────────────────────
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.device-monitoring",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.certificate-management",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.alert-management",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.system-management",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.central-nac",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.security",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.firmware-management",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.reporting",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.troubleshooting",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.subscription",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.extension",
        # ── 設定配布・管理系 ─────────────────────────────────
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration-validation",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration-distribution",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration-import",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration-health",
        # ── ネットワークサービス系 ────────────────────────────
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.overlay-tunnel-orchestrator",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.floorplan-manager",
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.service-config-bridge",
        # ── 認証・ログイン系 (GreenLake Cloud Identity Service) ─
        "com.hpe.greenlake.network-services.v1alpha1.audit-trail.gcis",
    ],
    "ap-monitoring": [
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.device",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.radio",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.virtual_access_point",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.port",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.wlan",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.state.tunnel",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.device",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.radio",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.virtual_access_point",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.port",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.modem",
        "com.hpe.greenlake.network-monitoring.v1alpha1.aps.stats.tunnel",
    ],
    "geofence":           [],
    "location":           [],
    "location-analytics": [],
}
