#!/usr/bin/env python3
"""
受信した CloudEvent の生バイトをダンプして、フィールド構造を解析するデバッグツール。
1件受信したら /tmp/ce_raw.bin に保存して終了する。
"""
import asyncio, os, sys
from urllib.parse import urlencode
import requests, websockets

TOKEN_URL  = os.environ.get("TOKEN_URL", "https://sso.common.cloud.hpe.com/as/token.oauth2")
CLIENT_ID  = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
BASE_URL   = os.environ["BASE_URL"].rstrip("/")
WS_URL     = BASE_URL.replace("https://","wss://") + "/network-services/v1alpha1/audit-trail-events"
EVENT_TYPE = "com.hpe.greenlake.network-services.v1alpha1.audit-trail.configuration"
DUMP_PATH  = "/tmp/ce_raw.bin"

def get_token():
    r = requests.post(TOKEN_URL, data={
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def read_varint(data, pos):
    value, shift = 0, 0
    while pos < len(data):
        b = data[pos]; pos += 1
        value |= (b & 0x7F) << shift; shift += 7
        if not (b & 0x80): break
    return value, pos

def dump_fields(data: bytes, indent=0) -> None:
    """Protobuf wire format を再帰的にダンプする。"""
    prefix = "  " * indent
    pos = 0
    while pos < len(data):
        try:
            tag, pos = read_varint(data, pos)
        except Exception:
            break
        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:
            val, pos = read_varint(data, pos)
            print(f"{prefix}field[{field_num}] VARINT = {val}")
        elif wire_type == 1:
            val = int.from_bytes(data[pos:pos+8], "little")
            pos += 8
            print(f"{prefix}field[{field_num}] I64    = {val}")
        elif wire_type == 2:
            length, pos = read_varint(data, pos)
            val = data[pos:pos+length]; pos += length
            # UTF-8 か試みる
            try:
                s = val.decode("utf-8")
                printable = all(ord(c) >= 32 or c in "\t\n\r" for c in s)
            except Exception:
                s, printable = None, False
            if printable and s:
                if len(s) > 120:
                    print(f"{prefix}field[{field_num}] LEN    = {repr(s[:120])}…  ({length}B)")
                else:
                    print(f"{prefix}field[{field_num}] LEN    = {repr(s)}")
            else:
                print(f"{prefix}field[{field_num}] LEN    = <binary {length}B>  hex={val[:24].hex()}…")
                # 再帰的に embedded message として解析
                if indent < 3:
                    try:
                        print(f"{prefix}  └─ embedded:")
                        dump_fields(val, indent + 2)
                    except Exception:
                        pass
        elif wire_type == 5:
            val = int.from_bytes(data[pos:pos+4], "little")
            pos += 4
            print(f"{prefix}field[{field_num}] I32    = {val}")
        else:
            print(f"{prefix}[不明なwire_type={wire_type} @ pos={pos}]")
            break

async def main():
    token = get_token()
    qs  = urlencode({"event-types": EVENT_TYPE})
    url = f"{WS_URL}?{qs}"
    print(f"Token OK.")
    print(f"URL: {url}")
    print("★ Central で設定変更を入れてイベントを発生させてください ★\n")

    for attempt in range(1, 10):
        print(f"接続試行 #{attempt} ...")
        try:
            async with websockets.connect(
                url,
                additional_headers={"Authorization": f"Bearer {token}"},
                open_timeout=20,
                ping_interval=None,
            ) as ws:
                print("Connected. Waiting for 1 message (90s) ...")
                raw = await asyncio.wait_for(ws.recv(), timeout=90)

            print(f"\n✔ Received {len(raw)} bytes. Saving to {DUMP_PATH} ...")
            with open(DUMP_PATH, "wb") as f:
                f.write(raw)

            print("\n" + "="*60)
            print("CloudEvent wire format dump:")
            print("="*60)
            dump_fields(raw)
            return

        except TimeoutError:
            print("90s timeout — イベントなし、再接続します ...")
        except Exception as e:
            print(f"Error: {e} — 5s 後に再接続します ...")
            await asyncio.sleep(5)

asyncio.run(main())
