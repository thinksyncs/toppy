Toppy OSS仕様書（usage-oriented）

この文書は「いま実際に動くもの」を基準に、Toppy の仕様と使い方をまとめます。
将来の構想は TODO / bd issue に切り出し、ここでは非目標として明示します。

## 1. 概要

Toppy は Rust 製の CLI + ゲートウェイのワークスペースです。

現状のスコープ:
- ゲートウェイ（`toppy-gw`）: QUIC ping と、HTTP/3 Extended CONNECT による CONNECT-UDP（疎通確認用 echo / UDP forwarding）。
- CLI（`toppy-cli`）: 設定/環境診断（`doctor`）、トークン取得・キャッシュ（`login`）、ポリシーでガードされたローカル forwarder（`up`=TCP / `udp`=UDP）、監査ログ検証（`audit verify`）。

対象ユーザ:
- SRE / セキュリティ担当 / 開発者（Linux / macOS / Windows）

## 2. CLI仕様

### 2.1 コマンド一覧

- `toppy doctor [--json]`
  - 設定と環境の診断結果を出力します（JSON または人間向け）。
- `toppy login [--print-token]`
  - 認証トークンを取得し、必要に応じてローカルにキャッシュします。
- `toppy up --target <ip:port> --listen <ip:port> [--once]`
  - ローカルで TCP を待ち受け、指定ターゲットへ転送します。
  - 注意: 現時点の `up` は MASQUE トンネルではなく、ローカル TCP フォワードです。
- `toppy udp --target <ip:port> --listen <ip:port>`
  - ローカルで UDP を待ち受け、指定ターゲットへ CONNECT-UDP（HTTP/3 Extended CONNECT + HTTP Datagrams）で転送します。
  - `up` と同様、既存の `[policy]` allow ルールで許可/拒否します。
- `toppy audit verify [--path <file>]`
  - ローカル監査ログ（ハッシュチェーン JSONL）の整合性を検証します。

## 3. 設定仕様（config.toml）

デフォルトパス:
- `~/.config/toppy/config.toml`

上書き:
- `TOPPY_CONFIG=/path/to/config.toml`

主要キー:
- `gateway` / `port` : doctor のネットワーク検証対象
- `server_name` : TLS SNI
- `ca_cert_path` : TLS ルート CA PEM（doctor が使用）
- `mtu` : doctor が sanity チェック
- `audit_log_path` : 監査ログ出力先（未指定はデフォルト）
- `audit_signing_key` : 監査ログ署名キー（任意、HMAC）
- `audit_ship_url` : 監査ログ送信先（任意、HTTP POST）
- `audit_ship_token` : 送信時の Bearer トークン（任意）
- `audit_ship_timeout_secs` : 送信タイムアウト秒（任意、既定 3）

### 3.1 認証（クライアント側）

認証は `[auth]` セクションで選択できます（未指定の場合は従来互換の `auth_token` を利用）。

- Token（静的トークン/JWT）:
  - `auth_token = "..."` または `[auth] mode = "token"` + `token = "..."`
- OIDC device-code:
  - `[auth] mode = "oidc_device_code"` を指定し、`toppy login` でトークンを取得してキャッシュします。
- OIDC auth-code + PKCE（ブラウザログイン）:
  - `[auth] mode = "oidc_auth_code_pkce"` を指定し、`toppy login` でローカルの `redirect_uri` に戻るフローを使います。
  - `redirect_uri` は IdP に登録済みの URL である必要があります（例: `http://127.0.0.1:8080/callback`）。
- SAML（直接統合ではなく broker 経由）:
  - `[auth] mode = "saml"` を指定し、内部的には broker の OIDC device-code を利用します。

### 3.2 ポリシー（ローカル forwarder 向け）

`toppy up` / `toppy udp` はポリシー評価により許可/拒否します。
設定が無い場合は allow ルールが空になるため、すべて deny になります。

例:

```toml
[policy]
  [[policy.allow]]
  cidr = "127.0.0.1/32"
  ports = [22, 443]
```

### 3.3 レート制限（toppy up）

`toppy up` の TCP 転送は 1 コネクションあたり token-bucket を適用します。

```toml
[rate]
bytes_per_sec = 10485760
burst_bytes = 10485760
```

無効化:

```toml
[rate]
bytes_per_sec = 0
burst_bytes = 0
```

### 3.4 監査ログの署名と送信

- 署名: `audit_signing_key`（または `TOPPY_AUDIT_SIGNING_KEY`）を設定すると、各エントリに HMAC 署名が追加されます。
- 送信: `audit_ship_url`（または `TOPPY_AUDIT_SHIP_URL`）を設定すると、JSON エントリを HTTP POST で送信します（ベストエフォート）。
- 検証: `toppy audit verify --signing-key <key>` で署名付きエントリの整合性を検証できます。

## 4. doctor のチェック仕様

主なチェック ID:
- `cfg.load`
- `net.dns`
- `h3.connect`（QUIC ping + TLS/トークン検証）
- `masque.connect_udp`（CONNECT-UDP handshake）
- `masque.connect_udp.datagram`（HTTP Datagram echo）
- `tun.perm`
- `mtu.sanity`
- `policy.denied`（`TOPPY_DOCTOR_TARGET` 指定時）

テスト/CI 向けの強制フラグ（環境変数）:
- `TOPPY_DOCTOR_NET=pass|fail|skip`
- `TOPPY_DOCTOR_TUN=pass|fail|skip`
- `TOPPY_DOCTOR_TARGET=ip:port`

## 5. ゲートウェイ仕様（toppy-gw）

- `/healthz` : HTTP 200 JSON
- QUIC:
  - 非 H3: `ping` を受け取ると `pong` を返す（トークンが必要なモードあり）
  - H3: Extended CONNECT + CONNECT-UDP を受理する
    - `/.well-known/masque/udp/<host>/<port>/` : Datagram echo（doctor 用の疎通確認）
    - `/.well-known/masque/udp-forward/<host>/<port>/` : UDP forwarding（任意 UDP 宛先）

認証（ゲートウェイ側、環境変数）:
- `TOPPY_GW_TOKEN`（共有トークン）または `TOPPY_GW_JWT_SECRET`（HS256）

## 6. 非目標（現時点）

- 完全な L3 VPN / TUN ルーティングの自動設定
- CONNECT-IP の本格実装
- CONNECT-UDP の高度な機能（複数クライアントのマッピング、NAT 的振る舞い、QoS など）
- 直接 SAML 統合（当面は SAML→OIDC broker を推奨）

## 7. TODO / ゲート

TODO と進捗、ゲートの定義は `TODO.md`（および `bd`）を参照してください。
