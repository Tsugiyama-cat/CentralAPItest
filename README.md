# Aruba New Central — IP Restriction Verification Tool

HPE GreenLake プラットフォームの **IPアドレス制限（allowlist）** が  
Aruba New Central REST API に対して正しく機能しているかを検証するための、  
Docker ベースの軽量ツールです。

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
