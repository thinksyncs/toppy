Toppy OSS仕様書（usage-oriented）

この文書は、実装済みの挙動を短く確認するための usage-oriented summary です。
詳細な設計、運用、制約は `docs/manual.tex` を一次資料として参照してください。

## 1. 文書の役割

- `README.md`: 最短の導入と導線
- `spec.md`: 現在の使い方と実装範囲の要約
- `docs/manual.tex`: 詳細な運用・設計・構成の説明
- `docs/audit-ops.md`: 監査ログ運用の補足

## 2. 概要

Toppy は Rust 製の CLI と gateway のワークスペースです。

現状のスコープ:
- `toppy-gw`: QUIC ping と HTTP/3 Extended CONNECT による CONNECT-UDP
- `toppy-cli`: `doctor`, `login`, `up`, `udp`, `audit verify`, `audit ship`, `audit remote-verify`
- `toppy-core`: auth, policy, audit, doctor, rate-limit などの共通機能

対象ユーザ:
- SRE
- セキュリティ担当
- 開発者

## 3. CLI の現在仕様

- `toppy doctor [--json]`
  - 設定、疎通、TLS、CONNECT-UDP、TUN 権限などを検査します。
- `toppy login [--print-token]`
  - 認証トークンを取得し、必要に応じてローカルにキャッシュします。
- `toppy up --target <ip:port> --listen <ip:port> [--once]`
  - ローカル TCP forwarder です。
  - MASQUE トンネルではありません。
  - ポリシー評価と per-connection rate limit が適用されます。
- `toppy udp --target <ip:port> --listen <ip:port>`
  - ローカル UDP を CONNECT-UDP で転送します。
  - ポリシー評価、per-peer rate limit、peer cap、idle cleanup が適用されます。
- `toppy audit verify [--path <file>]`
  - ローカル監査ログのハッシュチェーンを検証します。
- `toppy audit ship [--path <file>] [--batch-size <n>]`
  - ローカル監査ログを remote endpoint へ batch replay します。
- `toppy audit remote-verify --url <url> [--path <file>]`
  - ローカル監査ログ全体を remote verifier に送って検証結果を受け取ります。

## 4. 設定の要点

デフォルト設定パス:
- `~/.config/toppy/config.toml`

上書き:
- `TOPPY_CONFIG=/path/to/config.toml`

主要設定:
- `gateway`, `port`, `server_name`, `ca_cert_path`, `mtu`
- `auth_token` または `[auth]`
- `[policy]`
- `[rate]`
- `audit_log_path`, `audit_signing_key`, `audit_ship_*`
- `TOPPY_AUDIT_SHIP_RETRIES`, `TOPPY_AUDIT_SHIP_BACKOFF_MS`
- `TOPPY_AUDIT_SHIP_BATCH_SIZE`
- `TOPPY_AUDIT_VERIFY_*`

認証モード:
- token または JWT
- OIDC device-code
- OIDC auth-code + PKCE
- SAML via broker

ポリシー評価:
- 宛先 CIDR
- ポート
- auth subject
- 一部の JWT claim

allow ルールが無ければ deny です。

## 5. doctor の確認範囲

代表的なチェック:
- `cfg.load`
- `net.dns`
- `h3.connect`
- `masque.connect_udp`
- `masque.connect_udp.datagram`
- `tun.perm`
- `mtu.sanity`
- `policy.denied`

Windows では `wintun.dll` の解決とアダプタ作成権限を確認します。
細かい配置規則や運用手順は manual を参照してください。

## 6. gateway の現在仕様

- `/healthz` を提供
- 非 H3 QUIC ping に応答
- H3 Extended CONNECT による CONNECT-UDP を受理
- `/.well-known/masque/udp/<host>/<port>/` で datagram echo
- `/.well-known/masque/udp-forward/<host>/<port>/` で UDP forwarding
- gateway 実装は `auth` / `connect_udp` / `routing` / `healthz` / `tls` に分割済み

gateway 側認証は共有トークンまたは HS256 JWT を想定します。

## 7. 非目標

- 完全な L3 VPN
- CONNECT-IP の本格実装
- 高度な NAT や QoS を含む UDP middlebox 機能
- 直接 SAML 統合

## 8. Backlog / Gate Tracking

進捗と残タスクは `bd` で管理します。
