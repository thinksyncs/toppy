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
	- [ ] S3: 証明書検証/トークン検証が未完了。

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
	- [ ] 証明書検証とトークン検証を追加（TLS 検証とトークン検証の双方を必須化）

S3 - HTTP/3 接続検証（Gate L2）
	- [x] CLI からゲートウェイへの最小 RPC を実装し、HTTP/3（QUIC）接続が成立するかどうかを doctor で確認できるようにする。
	- [x] 認証はこの段階ではダミートークン等で代用し、接続の成否と証明書検証に集中する。

S4 - TUN 権限検出 + MTU サニティチェック（Gate L2）
	- [ ] Linux で TUN デバイスが作成可能かを検出する (/dev/net/tun の存在や CAP_NET_ADMIN 有無)。macOS の utun への対応も検討する。
	- [ ] 推奨 MTU を計算し、接続対象の MTU が極端に小さい・大きい場合に警告を出す。
	- [ ] doctor の JSON 出力に tun.perm と mtu.sanity を追加し、Integration テストを更新する。

S5 - E2E TCP到達性（Gate L3：End-to-End）
	- [ ] Linux ランナー上で toppy up を実行し、許可されたターゲットへの TCP (例：SSH ポート 22) の疎通を nc -zv などで確認する。
	- [ ] 許可されていない宛先やポートへの接続が拒否されることを確認し、doctor で policy.denied の理由を返す。
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
	- [ ] Criteria: workspace builds, lint/format policy enforced, license/threat model documented.
	- [ ] Tests: cargo fmt --check, cargo clippy -D warnings, cargo deny check.
	- [ ] Evidence: CI green + README sections present.

Gate L1 - Unit tests
	- [ ] Criteria: doctor JSON schema stable; core pure logic covered by unit tests.
	- [ ] Tests: cargo test (unit).
	- [ ] Evidence: CI green + unit test coverage for config/policy/messages.

Gate L2 - Integration
	- [ ] Criteria: gateway healthcheck OK; doctor net.dns + h3.connect checks pass.
	- [ ] Tests: docker compose up + healthcheck wait + doctor integration tests.
	- [ ] Evidence: CI green with integration job.

Gate L3 - End-to-End
	- [ ] Criteria: toppy up connects to allowed targets; disallowed targets are denied with reason.
	- [ ] Tests: nc -zv (or equivalent) against allowed/denied targets; doctor policy.denied verified.
	- [ ] Evidence: CI green with E2E job; logs captured for audit.

3. 詳細プラン（次の作業）

S3 - 証明書検証とトークン検証
	- [ ] 対象コードを特定（toppy-cli doctor の h3.connect / QUIC ping と toppy-gw 側の doctor RPC）
	- [ ] TLS 証明書検証の要件整理（CA/ピンニング/自己署名の扱いと設定項目）
	- [ ] クライアント側に検証ロジックを追加（失敗時は doctor の check を fail）
	- [ ] トークン検証の手順定義（署名方式、発行者/オーディエンス、期限）
	- [ ] ゲートウェイ側でトークン検証を実装（検証失敗は明確なエラーコード）
	- [ ] doctor の JSON 出力に理由を追加（例: cert.invalid, token.expired）
	- [ ] 結合テストを追加（有効/無効証明書、期限切れトークン）
	- [ ] CI にテストを追加して L2 ゲートを更新

S4 - TUN 権限検出 + MTU サニティチェック
	- [ ] Linux: /dev/net/tun の存在確認と open の可否（CAP_NET_ADMIN の有無を含む）
	- [ ] macOS: utun 作成の可否チェック（実装方針の決定と実装）
	- [ ] MTU 推奨値の算出ロジックを定義（プロトコルオーバーヘッドを明示）
	- [ ] 異常値のしきい値を決めて warn を返す（極端に小/大）
	- [ ] doctor の JSON 出力に tun.perm / mtu.sanity を追加
	- [ ] Integration テストを更新（OS 差分は条件付きで検証）

S5 - E2E TCP 到達性
	- [ ] 対象ターゲット/ポートのテストデータを用意（許可/拒否の両方）
	- [ ] toppy up を CI 環境で実行する手順を確立
	- [ ] nc -zv 等で疎通確認し、結果を doctor に反映
	- [ ] 拒否理由（policy.denied）を検証するテストを追加
	- [ ] Windows RDP の検証方法を整理（段階的導入）
