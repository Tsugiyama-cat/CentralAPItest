# Aruba Central Streaming Monitor

Aruba New Central の **Streaming API** と **AP Syslog** をブラウザでリアルタイム監視するツールです。  
Docker Compose で動作するため、**Docker が使える任意の PC** で同じ手順で起動できます。

---

## 機能

| 機能 | 説明 |
|---|---|
| 📡 Streaming API | 監査ログ・AP監視・位置情報・ジオフェンスをリアルタイム表示 |
| 📥 AP Syslog 受信 | UDP/TCP 514 で AP の syslog を受信・解析・表示 |
| 🔍 イベント分類 | 接続/切断・認証・DHCP・AP状態・セキュリティを自動分類 |
| 🌐 ブラウザ UI | どの PC からもアクセス可能な Web インターフェース |

---

## 取得できるログ

### Streaming API 経由
- 設定変更・操作ログ（audit-trail 全カテゴリ）
- 認証・ログインログ（`gcis`, `system-management`）
- AP 状態変化・統計（ap-monitoring）
- セキュリティイベント、ジオフェンス等

### AP Syslog 経由
- **クライアントの SSID 接続・切断**（assoc / disassoc）
- 認証成功・失敗（EAP / PSK）
- DHCP IP アドレス割当
- AP 起動・停止・再起動
- 管理者ログイン・設定変更
- 不正 AP・IDS 検知

---

## セットアップ

### 必要なもの

- Docker Desktop（Windows/Mac）または Docker Engine（Linux）
- Aruba Central の API クライアント認証情報（GreenLake Workspace で取得）

### 手順

```bash
# 1. .env ファイルを作成
cp .env.example .env

# 2. .env を編集して認証情報を入力（後述）
nano .env   # または任意のエディタで編集

# 3. Docker イメージをビルドして起動
docker compose build
docker compose up -d web

# 4. ブラウザでアクセス
# http://<このPCのIPアドレス>:8888
```

### .env の設定項目

```env
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx    # GreenLake API クライアントID
CLIENT_SECRET=your-secret-here                     # クライアントシークレット
BASE_URL=https://jp1.api.central.arubanetworks.com # リージョン別URL
TOKEN_URL=https://sso.common.cloud.hpe.com/as/token.oauth2  # 通常変更不要
```

**BASE_URL のリージョン別一覧:**

| リージョン | URL |
|---|---|
| 日本 (APAC-1) | `https://jp1.api.central.arubanetworks.com` |
| US (East) | `https://apigw-prod2.central.arubanetworks.com` |
| US (West) | `https://apigw-us-west-4.central.arubanetworks.com` |
| EU | `https://eu-apigw.central.arubanetworks.com` |

---

## AP Syslog の設定方法

Aruba Central の管理画面で AP の syslog 送信先をこのツールの PC に向けます。

1. **Aruba Central** → **Configuration** → **AP Groups** → 対象グループ
2. **System** タブ → **Syslog** セクション
3. 以下を設定：

| 設定項目 | 値 |
|---|---|
| Syslog Server | このツールの PC の IP アドレス |
| Port | 514（変更した場合はそのポート番号） |
| Protocol | UDP |
| Log Level | Informational 以上 |

4. **Save** → **Push Config** で AP に適用

---

## コマンドリファレンス

```bash
# Web モニター起動（常時稼働）
docker compose up -d web

# ログ確認
docker compose logs -f web

# 停止
docker compose down

# 再ビルド（ファイル変更後）
docker compose build && docker compose up -d web

# REST API 疎通確認（IP制限チェック）
docker compose run --rm verify

# CLI ストリーミングテスト
docker compose run --rm stream
```

---

## ポート変更方法

`.env` に追記するだけで変更できます：

```env
WEB_PORT=9999      # Web UI を 9999 番に変更
SYSLOG_PORT=5514   # syslog を 5514 番に変更（514 が使用中の場合）
```

AP の syslog 送信先ポートも同じ番号に合わせてください。

---

## Linux でポート 514 が使えない場合

Linux ホストでは `rsyslog` が 514 番を使用している場合があります：

```bash
# rsyslog が 514 を使っているか確認
sudo ss -ulnp | grep 514

# 使っている場合は .env で別ポートを指定
echo "SYSLOG_PORT=5514" >> .env
docker compose up -d web

# ファイアウォール開放（UFW の場合）
sudo ufw allow 5514/udp
sudo ufw allow 5514/tcp
```

---

## ファイル構成

```
.
├── docker-compose.yml   # Docker Compose 設定
├── Dockerfile           # コンテナ定義
├── web_stream.py        # FastAPI バックエンド（Streaming API + Syslog 統合）
├── syslog_server.py     # Syslog UDP/TCP サーバ・Aruba ログ解析
├── decoders.py          # CloudEvent Protobuf デコーダ
├── verify_api.py        # REST API 疎通確認
├── stream_test.py       # CLI ストリーミングテスト
├── templates/
│   └── index.html       # Web UI
├── requirements.txt     # Python 依存ライブラリ
├── .env.example         # 設定テンプレート（コピーして使用）
├── .env                 # 実際の認証情報（Git 除外済み）
└── README.md            # 本ドキュメント
```

---

## トラブルシューティング

| 症状 | 原因 | 対処 |
|---|---|---|
| Web UI が開かない | コンテナ起動失敗 | `docker compose logs web` でエラー確認 |
| Syslog が届かない | ファイアウォール、ポート設定ミス | AP の送信先 IP・ポートを再確認 |
| `HTTP 403` | IP制限でブロック | GreenLake の IP Allowlist にこの PC の IP を追加 |
| `HTTP 401` | 認証情報が誤り | `CLIENT_ID` / `CLIENT_SECRET` を確認 |
| `HTTP 404` | ストリームタイプ未対応 | テナントでその機能が有効か確認 |
| ペイロード未デコード | フィールド位置の違い | イベントカードの `src:` 行でデバッグ情報を確認 |

---

## ⚠️ セキュリティ注意事項

- `.env` には API 認証情報が含まれます。**Git にコミットしないでください**（`.gitignore` で除外済み）
- Web UI はポート 8888 で全ネットワークに公開されます。信頼できないネットワークでは適切にアクセス制限をかけてください
- Syslog はポート 514 で受信します。意図しないデバイスからの syslog も受信される場合があります

---

## IP制限確認ツール（元の機能）

Aruba Central の IP Allowlist にこの PC が登録されているか確認できます：

```bash
docker compose run --rm verify
```

---

## 動作概要

```
実行ホストの
パブリックIP取得  →  GreenLake SSO 認証  →  Central API 呼び出し  →  結果判定
  (ifconfig.me)      (client_credentials)     (device_inventory)
```

| HTTP ステータス | 判定 |
|---|---|
| `200 OK` | IP制限は**許可**されている（正常） |
| `403 Forbidden` | IP制限が**ブロック**している可能性が高い |
| `401 Unauthorized` | 認証情報（CLIENT_ID / SECRET）が誤っている |

---

## 前提条件

| ツール | 最低バージョン |
|---|---|
| Docker | 24.x 以上 |
| Docker Compose | v2（`docker compose` コマンド） |
| Git | 任意 |

HPE GreenLake ポータルで **API クライアント**（OAuth2 client_credentials）を  
あらかじめ発行しておいてください。

---

## セットアップ

### 1. リポジトリをクローン

```bash
git clone https://github.com/Tsugiyama-cat/CentralAPItest.git
cd CentralAPItest
```

### 2. `.env` ファイルを作成

```bash
cp .env.example .env
```

`.env` をエディタで開き、取得した認証情報を記入します。

```dotenv
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=your-secret-here
BASE_URL=https://apigw-apac1.central.arubanetworks.com
TOKEN_URL=https://sso.common.cloud.hpe.com/as/token.oauth2
```

> **BASE_URL の選択肢**
> | リージョン | URL |
> |---|---|
> | APAC-1（日本など） | `https://apigw-apac1.central.arubanetworks.com` |
> | US-1 | `https://apigw-prod2.central.arubanetworks.com` |
> | EU-1 | `https://apigw-eu.central.arubanetworks.com` |

### 3. イメージをビルド

```bash
docker compose build
```

---

## 実行

```bash
docker compose run --rm verify
```

### 出力例（許可されている場合）

```
============================================================
  Aruba New Central — IP Restriction Verification Tool
============================================================

[2026-05-20T10:00:00Z] [INFO ] Step 1/3  Resolving public IP of this host …

  ┌─────────────────────────────────────────┐
  │  Public IP : 203.0.113.42               │
  │  → Add this IP to the GreenLake allowlist│
  └─────────────────────────────────────────┘

[2026-05-20T10:00:01Z] [INFO ] Step 2/3  Authenticating with HPE GreenLake SSO …
[2026-05-20T10:00:01Z] [INFO ] Requesting OAuth2 token from: https://sso.common.cloud.hpe.com/as/token.oauth2
[2026-05-20T10:00:02Z] [INFO ] Access token obtained successfully (expires_in=7200s).
[2026-05-20T10:00:02Z] [INFO ] Step 3/3  Calling Aruba New Central API …
[2026-05-20T10:00:02Z] [INFO ] Calling Central API: GET .../platform/device_inventory/v1/devices  params={'limit': 1}

============================================================
[2026-05-20T10:00:03Z] [INFO ] ✔  HTTP 200 OK — IP restriction is NOT blocking this host.
[2026-05-20T10:00:03Z] [INFO ]    Response sample: total=42
============================================================
```

### 出力例（IPブロックされている場合）

```
[2026-05-20T10:00:03Z] [ERROR] ✘  HTTP 403 Forbidden
[2026-05-20T10:00:03Z] [ERROR]    Cause (likely): HPE GreenLake IP allowlist is BLOCKING this host.
[2026-05-20T10:00:03Z] [ERROR]    Action: Add the public IP shown above to the GreenLake allowlist,
[2026-05-20T10:00:03Z] [ERROR]            then re-run this tool to confirm.
```

---

## IPアドレスの GreenLake への登録手順

1. ツールを実行し、出力された **Public IP** をメモする。
2. HPE GreenLake ポータルへログイン。
3. **Manage → Security → IP Allowlist**（または **Workspace Settings**）を開く。
4. メモした IP アドレスを追加して保存。
5. 本ツールを再実行し、`HTTP 200 OK` になることを確認する。

---

## エラー判別チートシート

| 症状 | 原因 | 対処 |
|---|---|---|
| `403` がトークン取得時に発生 | GreenLake SSO 自体が IP ブロック | GreenLake の allowlist に IP を追加 |
| `403` が API 呼び出し時に発生 | Central API Gateway が IP ブロック | 同上 |
| `401` が発生 | `CLIENT_ID` / `CLIENT_SECRET` が誤り | GreenLake ポータルで再発行・再設定 |
| IP 取得に失敗 | 外部インターネットへの疎通なし | ネットワーク・プロキシ設定を確認 |
| `CONNECTION ERROR` | `BASE_URL` または `TOKEN_URL` が誤り | `.env` の URL を確認 |

---

## ファイル構成

```
.
├── Dockerfile          # Python 3.12-slim ベースのコンテナ定義
├── docker-compose.yml  # ワンコマンド実行のための Compose 設定
├── verify_api.py       # 検証スクリプト本体
├── requirements.txt    # Python 依存ライブラリ（requests のみ）
├── .env.example        # 環境変数テンプレート（要コピー・編集）
├── .env                # 実際の認証情報（.gitignore で除外済み）
└── README.md           # 本ドキュメント
```

---

## Git へのプッシュ手順

```bash
# 初回のみ
git init
git remote add origin https://github.com/Tsugiyama-cat/CentralAPItest.git

# コミット＆プッシュ
git add Dockerfile docker-compose.yml verify_api.py requirements.txt \
        .env.example .gitignore README.md
git commit -m "Add Aruba Central IP restriction verification tool"
git push -u origin main
```

> `.env`（実際の認証情報）は `.gitignore` により除外されます。  
> 絶対にコミットしないでください。

---

## ライセンス

MIT
