"""
Aruba New Central Streaming API — Web Monitor + Syslog Receiver
ブラウザからリアルタイムで Streaming API と AP Syslog を統合監視する FastAPI アプリ
"""
import asyncio
import json
import os
from contextlib import asynccontextmanager
from urllib.parse import urlencode

import requests
import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from decoders import decode_cloudevent, AVAILABLE_EVENT_TYPES
from syslog_server import start_syslog_server

# ── 設定 ──────────────────────────────────────────────────────
CLIENT_ID     = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
BASE_URL      = os.environ.get("BASE_URL", "").rstrip("/")
TOKEN_URL     = os.environ.get("TOKEN_URL",
                    "https://sso.common.cloud.hpe.com/as/token.oauth2")
SYSLOG_HOST   = os.environ.get("SYSLOG_BIND", "0.0.0.0")
SYSLOG_PORT   = int(os.environ.get("SYSLOG_PORT", "514"))

STREAM_ENDPOINTS = {
    "audit-trail":        "/network-services/v1alpha1/audit-trail-events",
    "ap-monitoring":      "/network-monitoring/v1alpha1/ap-events",
    "geofence":           "/network-services/v1alpha1/geofence-events",
    "location":           "/network-services/v1alpha1/location-events",
    "location-analytics": "/network-services/v1alpha1/location-analytics-events",
}


# ── Syslog ブロードキャスト管理 ───────────────────────────────
# 接続中の各ブラウザ WebSocket ごとに非同期キューを保持する
_syslog_queues: set[asyncio.Queue] = set()


async def _syslog_callback(event: dict) -> None:
    """syslog_server からのコールバック。全ブラウザへ配信する。"""
    global _syslog_queues
    msg  = {"type": "syslog", **event}
    text = json.dumps(msg, ensure_ascii=False, default=str)
    dead: set[asyncio.Queue] = set()
    for q in list(_syslog_queues):
        try:
            q.put_nowait(text)
        except asyncio.QueueFull:
            dead.add(q)
    _syslog_queues -= dead


# ── ライフサイクル ────────────────────────────────────────────
_syslog_servers: list = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _syslog_servers
    _syslog_servers = await start_syslog_server(SYSLOG_HOST, SYSLOG_PORT, _syslog_callback)
    yield
    for srv in _syslog_servers:
        try:
            srv.close()
            if hasattr(srv, "wait_closed"):
                await srv.wait_closed()
        except Exception:
            pass


app = FastAPI(title="Aruba Central Streaming Monitor", lifespan=lifespan)


# ── 認証 ──────────────────────────────────────────────────────
def get_access_token(client_id: str = "", client_secret: str = "") -> str:
    """アクセストークンを取得する。引数が空の場合は環境変数の値を使用。"""
    cid = client_id    or CLIENT_ID
    sec = client_secret or CLIENT_SECRET
    if not cid or not sec:
        raise ValueError("CLIENT_ID / CLIENT_SECRET が設定されていません。"
                         "画面の入力欄または .env ファイルを確認してください。")
    r = requests.post(TOKEN_URL, data={
        "grant_type":    "client_credentials",
        "client_id":     cid,
        "client_secret": sec,
    }, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


# ── HTTP ルート ───────────────────────────────────────────────
@app.get("/")
async def index():
    with open("/app/templates/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/api/event-types")
async def api_event_types():
    return JSONResponse(AVAILABLE_EVENT_TYPES)

@app.get("/api/config")
async def api_config():
    return JSONResponse({
        "base_url":              BASE_URL,
        "stream_types":          list(STREAM_ENDPOINTS.keys()),
        "syslog_port":           SYSLOG_PORT,
        # .env に認証情報が設定済みかをフラグで返す（値は返さない）
        "has_env_credentials":   bool(CLIENT_ID and CLIENT_SECRET),
        "has_env_base_url":      bool(BASE_URL),
    })


# ── WebSocket ─────────────────────────────────────────────────
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()

    # このブラウザ接続用 syslog キュー
    syslog_q: asyncio.Queue = asyncio.Queue(maxsize=300)
    _syslog_queues.add(syslog_q)

    stream_task: asyncio.Task | None = None

    async def _forward_syslog():
        """syslog キューを監視してブラウザへ転送する。"""
        while True:
            text = await syslog_q.get()
            try:
                await ws.send_text(text)
            except Exception:
                break

    syslog_task = asyncio.create_task(_forward_syslog())

    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)

            if msg.get("action") == "start":
                if stream_task and not stream_task.done():
                    stream_task.cancel()
                    try:
                        await stream_task
                    except asyncio.CancelledError:
                        pass

                stream_type  = msg.get("stream_type", "audit-trail")
                event_types  = msg.get("event_types", [])
                # UI 入力の認証情報（空なら .env フォールバック）
                gui_cid      = msg.get("client_id", "").strip()
                gui_sec      = msg.get("client_secret", "").strip()
                stream_task  = asyncio.create_task(
                    _stream_to_browser(ws, stream_type, event_types, gui_cid, gui_sec)
                )

            elif msg.get("action") == "stop":
                if stream_task and not stream_task.done():
                    stream_task.cancel()
                    try:
                        await stream_task
                    except asyncio.CancelledError:
                        pass
                await _send(ws, {
                    "type": "status", "status": "stopped",
                    "message": "ストリーム停止しました",
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await _send(ws, {"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        _syslog_queues.discard(syslog_q)
        syslog_task.cancel()
        if stream_task and not stream_task.done():
            stream_task.cancel()


# ── ユーティリティ ────────────────────────────────────────────
async def _send(ws: WebSocket, data: dict) -> None:
    try:
        await ws.send_text(json.dumps(data, ensure_ascii=False, default=str))
    except Exception:
        pass


# ── Streaming API ─────────────────────────────────────────────
async def _stream_to_browser(
    ws: WebSocket,
    stream_type: str,
    event_types: list[str],
    client_id: str = "",
    client_secret: str = "",
) -> None:
    """Aruba Central へ接続してイベントをブラウザへ転送する（再接続ループ付き）。"""
    if stream_type not in STREAM_ENDPOINTS:
        await _send(ws, {"type": "error",
                          "message": f"不明なストリームタイプ: {stream_type}"})
        return

    ws_base = BASE_URL.replace("https://", "wss://").replace("http://", "ws://")
    url = ws_base + STREAM_ENDPOINTS[stream_type]
    if event_types:
        url += "?" + urlencode({"event-types": ",".join(event_types)})

    event_count = 0
    attempt     = 0

    while True:
        attempt += 1
        try:
            # ── 認証 ──────────────────────────────────────────
            await _send(ws, {
                "type": "status", "status": "authenticating",
                "message": f"GreenLake SSO 認証中... (試行 #{attempt})",
            })
            try:
                token = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: get_access_token(client_id, client_secret)
                )
            except Exception as e:
                await _send(ws, {"type": "error", "message": f"認証失敗: {e}"})
                return

            # ── 接続 ──────────────────────────────────────────
            await _send(ws, {
                "type": "status", "status": "connecting",
                "message": "Aruba Central へ接続中...",
                "url": url,
            })

            async with websockets.connect(
                url,
                additional_headers={"Authorization": f"Bearer {token}"},
                open_timeout=20,
                ping_interval=None,
            ) as aruba_ws:
                attempt = 0
                await _send(ws, {
                    "type": "status", "status": "connected",
                    "message": "接続確立 — イベント待機中",
                    "url": url,
                })

                # ── 受信ループ ────────────────────────────────
                while True:
                    try:
                        raw = await asyncio.wait_for(
                            aruba_ws.recv(), timeout=300
                        )
                    except asyncio.TimeoutError:
                        await _send(ws, {
                            "type": "status", "status": "reconnecting",
                            "message": "タイムアウト — 再接続します",
                        })
                        break

                    if not isinstance(raw, (bytes, bytearray)):
                        continue

                    event_count += 1
                    try:
                        ce      = decode_cloudevent(bytes(raw))
                        ev_type = ce.get("type", "unknown")
                        payload = ce.get("payload_decoded", {})

                        await _send(ws, {
                            "type":            "event",
                            "index":           event_count,
                            "event_type":      ev_type,
                            "event_time":      ce.get("time", ""),
                            "event_id":        ce.get("id", ""),
                            "source":          ce.get("source", ""),
                            "subject":         ce.get("attributes", {}).get("subject", ""),
                            "payload_bytes":   ce.get("payload_bytes", len(raw)),
                            "payload":         payload,
                            "_payload_src":    ce.get("_payload_src", ""),
                            "_fields_found":   ce.get("_fields_found", []),
                            "_proto_type_url": ce.get("proto_type_url", ""),
                        })
                    except Exception as e:
                        await _send(ws, {
                            "type": "error",
                            "message": f"デコードエラー (#{event_count}): {e}",
                        })

        except asyncio.CancelledError:
            await _send(ws, {
                "type": "status", "status": "stopped",
                "message": "停止しました",
            })
            return

        except websockets.exceptions.InvalidStatus as e:
            sc   = e.response.status_code
            body = ""
            try:
                body = e.response.body.decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            _HINTS = {
                400: "無効なリクエスト (event-types パラメータ確認)",
                401: "認証エラー — トークン期限切れの可能性",
                403: "IP制限またはアクセス拒否 — 送信元IPをArubaに登録済みか確認",
                404: "エンドポイント未対応 — このstream_typeはテナントで有効化されていない可能性",
                429: "レート制限超過",
            }
            hint   = _HINTS.get(sc, "")
            detail = f" | {body}" if body else ""
            await _send(ws, {
                "type": "error",
                "message": f"HTTP {sc} {hint}{detail}",
                "status_code": sc,
            })
            return

        except websockets.exceptions.InvalidHandshake as e:
            await _send(ws, {
                "type": "error",
                "message": f"接続拒否 (握手失敗): {e}",
            })
            return

        except Exception as e:
            await _send(ws, {
                "type": "status", "status": "reconnecting",
                "message": f"切断 ({type(e).__name__}) — 5秒後に再接続",
            })

        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            await _send(ws, {
                "type": "status", "status": "stopped",
                "message": "停止しました",
            })
            return
