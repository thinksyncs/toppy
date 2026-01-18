Toppy TODO一覧

運用ルール: 作業は必ずチェックボックスで記載し、完了時に [x] を付ける。

1. TODOリスト

開発タスクを小さなセッションに分割し、それぞれにゲート（合否条件）とテストを設けます。下記は MVP に必要な作業の一覧です。各ゲートは実装とテストの完了が条件です。

S0 - Repo Skeleton (Gate L0: hygiene)
	- [x] Split the workspace into crates: toppy-cli, toppy-gw, toppy-core, toppy-proto, and align Cargo.toml.
	- [x] Add Makefile/justfile entry points: fmt, clippy, test, dev, compose-up, compose-down, doctor.
	- [x] Run L0 gate in CI (cargo fmt --check, cargo clippy -D warnings, cargo deny check).
	- [x] Update README with quickstart outline, license (Apache-2.0 or MIT), and threat model summary.

S1 - Doctor Command v0 (Gate L1: unit tests)
	- [x] Define toppy doctor --json schema with overall: pass|warn|fail, checks[], version.
	- [x] Unit-test pure logic: config validation, policy eval, capsule/control message types.
	- [x] Keep cargo test green and enable L1 gate in CI.

S2 - Gateway Healthcheck + Compose (Gate L2: integration)
	- [x] Add /healthz endpoint and Docker HEALTHCHECK to toppy-gw.
	- [x] Boot the gateway via docker compose and wait for healthy status.
	- [x] Add doctor checks: net.dns (GW resolve) and h3.connect (HTTP/3 handshake), then run integration tests in CI.

1.1 進捗チェック（S0 -> S3）
	- [x] S0: items 1-4 complete.
	- [x] S1: items 1-3 complete.
	- [x] S2: items 1-3 complete.
	- [x] S3: 証明書検証/トークン検証を実装済み。

1.2 詳細TODO（粒度上げ）
S0 - Repo Skeleton
	- [x] Lock workspace layout (`crates/toppy-cli`, `crates/toppy-gw`, `crates/toppy-core`, `crates/toppy-proto`).
	- [x] Add Makefile/justfile entries: fmt, clippy, test, dev, compose-up, compose-down, doctor.
	- [x] Add base docker compose file.
	- [x] Add GitHub Actions: cargo fmt --check, cargo clippy -D warnings, cargo deny check.
	- [x] Add cargo deny config.
	- [x] Add README quickstart (<= 5 minutes).
	- [x] Add README license (Apache-2.0 or MIT).
	- [x] Add README threat model summary.

S1 - Doctor Command v0
	- [x] Fix doctor JSON schema: version/overall/checks.
	- [x] Implement toppy doctor --json.
	- [x] Define human-readable output format (doctor/version/check list).
	- [x] Validate config file (required fields/types/ranges).
	- [x] Stub policy eval + unit tests.
	- [x] Minimal capsule/control message types + unit tests.
	- [x] Run cargo test in CI (L1 gate).

S2 - Gateway Healthcheck + Compose
	- [x] Add /healthz to toppy-gw (HTTP 200/JSON).
	- [x] Add Dockerfile and HEALTHCHECK.
	- [x] Boot toppy-gw via docker compose.
	- [x] Document healthcheck wait steps in README.
	- [x] Add doctor net.dns check.
	- [x] Add doctor h3.connect check (temporary OK allowed).
	- [x] Add integration tests (compose up + doctor).
	- [x] Run integration tests in CI (L2 gate).

S3 - HTTP/3 接続検証
	- [x] QUIC ping RPC を実装（gateway/doctor）
	- [x] 認証はダミー（現状スキップ）
	- [x] 証明書検証とトークン検証を追加（CA PEM + 共有トークン）

S3 - HTTP/3 接続検証（Gate L2）
	- [x] CLI からゲートウェイへの最小 RPC を実装し、HTTP/3（QUIC）接続が成立するかどうかを doctor で確認できるようにする。
	- [x] 認証はこの段階ではダミートークン等で代用し、接続の成否と証明書検証に集中する。

S4 - TUN 権限検出 + MTU サニティチェック（Gate L2）
	- [x] Linux: /dev/net/tun の存在確認と open 可否を検出（permission denied は fail）。
	- [x] macOS: utun 作成可否のチェック（AF_SYSTEM + SYSPROTO_CONTROL）。
	- [x] 推奨 MTU を 1350 として sanity チェック（<1200 / >9000 は warn）。
	- [x] doctor の JSON 出力に tun.perm と mtu.sanity を追加し、Integration テストを更新する。

S5 - E2E TCP到達性（Gate L3：End-to-End）
	- [x] Linux ランナー上で toppy up を実行し、許可されたターゲットへの TCP (例：SSH ポート 22) の疎通を nc -zv などで確認する。
	- [x] 許可されていない宛先やポートへの接続が拒否されることを確認し、doctor で policy.denied の理由を返す。
	- [ ] Windows 環境用の RDP ポート (3389) でも同様の疎通チェックを行い、必要に応じクロス OS テストを段階的に追加する。

Phase 3 以降のタスク（参考）
	- [ ] CONNECT-UDP の追加：UDP アプリ（DoQ/ゲーム等）を通すための機能。CLI に toppy udp-proxy を追加するか、既存トンネル上に UDP カプセルを流すかを検討する。
	- [ ] IdP 拡充：SAML や多要素認証、FIDO2 などへ対応し、CLI での使い勝手を壊さない範囲で統合する。
	- [ ] 監査ログの改ざん耐性：署名やリモート送信先への転送による tamper proof 化を実装する。
	- [ ] Windows/Wintun 対応：Windows 環境で TUN インタフェースを扱うための Wintun への対応。
	- [ ] レート制御・帯域制御：セッションごとの最大帯域やパケットレートを制御し、濫用を抑制する機構。

2. ゲートの定義

各タスクには段階的なゲートを設定し、合格条件を CI やレビューで自動確認します。

Gate L0 - Repo hygiene
	- [x] Criteria: workspace builds, lint/format policy enforced, license/threat model documented.
	- [x] Tests: cargo fmt --check, cargo clippy -D warnings, cargo deny check.
	- [x] Evidence: CI green + README sections present.

Gate L1 - Unit tests
	- [x] Criteria: doctor JSON schema stable; core pure logic covered by unit tests.
	- [x] Tests: cargo test (unit).
	- [x] Evidence: CI green + unit test coverage for config/policy/messages.

Gate L2 - Integration
	- [x] Criteria: gateway healthcheck OK; doctor net.dns + h3.connect + tun.perm + mtu.sanity checks pass.
	- [x] Tests: docker compose up + healthcheck wait + doctor integration tests.
	- [x] Evidence: CI green with integration job.

Gate L3 - End-to-End
	- [x] Criteria: toppy up connects to allowed targets; disallowed targets are denied with reason.
	- [x] Tests: nc -zv (or equivalent) against allowed/denied targets; doctor policy.denied verified.
	- [x] Evidence: CI green with E2E job; logs captured for audit.

3. 詳細プラン（次の作業）

S3 - 証明書検証とトークン検証
	- [x] 対象コードを特定（toppy-cli doctor の h3.connect / QUIC ping と toppy-gw 側）
	- [x] CA PEM を読み込む設定項目を追加（ca_cert_path / server_name）
	- [x] クライアント側 TLS 検証を実装（CA PEM を RootCertStore に追加）
	- [x] ゲートウェイ側で共有トークン検証を実装（TOPPY_GW_TOKEN / auth_token）
	- [x] 失敗理由を summary に出力（missing ca/token, token rejected）
	- [x] 連携設定を更新（固定証明書/キー + compose + it-compose.sh）
	- [x] JWT 検証（HS256/issuer/audience/exp）

S4 - TUN 権限検出 + MTU サニティチェック
	- [x] Linux: /dev/net/tun の存在確認と open の可否を判定
	- [x] macOS: utun 作成の可否チェック（AF_SYSTEM + SYSPROTO_CONTROL）
	- [x] MTU 推奨値を 1350 に設定（<1200 / >9000 は warn）
	- [x] 異常値のしきい値に応じた warn を実装
	- [x] doctor の JSON 出力に tun.perm / mtu.sanity を追加
	- [x] Integration テストを更新（tun.perm / mtu.sanity を検証）

S5 - E2E TCP 到達性
	- [x] 対象ターゲット/ポートのテストデータを用意（許可/拒否の両方）
	- [x] toppy up を CI 環境で実行する手順を確立
	- [x] nc -zv 等で疎通確認し、結果を doctor に反映
	- [x] 拒否理由（policy.denied）を検証するテストを追加
	- [ ] Windows RDP の検証方法を整理（段階的導入）
