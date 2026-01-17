Toppy TODO一覧

運用ルール: 作業は必ずチェックボックスで記載し、完了時に [x] を付ける。

1. TODOリスト

開発タスクを小さなセッションに分割し、それぞれにゲート（合否条件）とテストを設けます。下記は MVP に必要な作業の一覧です。

S0 - リポジトリ骨格（Gate L0：体裁）
	- [x] Workspace を crates/toppy-cli, crates/toppy-gw, crates/toppy-core, crates/toppy-proto に分割し、Cargo.toml を整備する。
	- [x] Makefile や justfile を用意し、make fmt, make clippy, make test, make dev, make compose-up, make compose-down, make doctor などのエントリポイントを定義する。
	- [x] CI（GitHub Actions）で L0 ゲート（cargo fmt --check, cargo clippy -D warnings, cargo deny check）が走るようにする。
	- [x] README にクイックスタートのアウトラインを記載し、ライセンス（Apache-2.0 または MIT）と脅威モデルの概要を追加する。

S1 - doctor コマンド v0（Gate L1：単体テスト）
	- [x] toppy doctor --json の出力形式を設計し、overall: pass|warn|fail、checks[]、version 等のフィールドを固定する。
	- [x] 設定ファイルの読み込みと検証、ポリシー評価関数、カプセル／制御メッセージ型等の純粋ロジックについてユニットテストを実装する。
	- [x] cargo test が通る状態を維持し、CI で L1 ゲートを有効にする。

S2 - ゲートウェイヘルスチェック + Compose（Gate L2：結合テスト）
	- [x] toppy-gw に /healthz エンドポイントと Docker Healthcheck を追加する。
	- [x] docker compose でゲートウェイを起動し、Healthcheck が正常になることを確認する。
	- [x] toppy doctor --json に net.dns（ゲートウェイの名前解決）および h3.connect（HTTP/3 ハンドシェイク）のチェックを実装し、CI で Integration テストを実行する。

1.1 進捗チェック（S0 -> S3）
	- [x] S0: 1-4は完了。
	- [x] S1: 1-3は完了。
	- [x] S2: 1-3は完了。
	- [ ] S3: 証明書検証/トークン検証が未完了。

1.2 詳細TODO（粒度上げ）
S0 - リポジトリ骨格
	- [x] Workspace構成を確定（`crates/toppy-cli`, `crates/toppy-gw`, `crates/toppy-core`, `crates/toppy-proto`）
	- [x] Makefile/justfile を追加し、`fmt/clippy/test/dev/compose-up/compose-down/doctor` のエントリを定義
	- [x] `docker compose` 用のベースファイルを追加
	- [x] GitHub Actions を追加（`cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny check`）
	- [x] `cargo deny` の設定ファイルを追加
	- [x] README にクイックスタート（5分以内）を追記
	- [x] README にライセンス表記（Apache-2.0 または MIT）を追記
	- [x] README に脅威モデル概要を追記

S1 - doctor コマンド v0
	- [x] `doctor` の JSON 形式に `version/overall/checks` を固定
	- [x] `toppy doctor --json` オプションを実装
	- [x] `doctor` の人間向け出力フォーマットの要件を確定（doctor/version/チェック一覧）
	- [x] 設定ファイルのバリデーション（必須項目/型/範囲）
	- [x] ポリシー評価関数のスタブとユニットテスト
	- [x] カプセル/制御メッセージ型の最低限定義とユニットテスト
	- [x] `cargo test` をCIで実行（L1ゲート）

S2 - ゲートウェイヘルスチェック + Compose
	- [x] `toppy-gw` に `/healthz` を追加（HTTP 200/JSON）
	- [x] `Dockerfile` と `HEALTHCHECK` を追加
	- [x] `docker compose` で `toppy-gw` を起動
	- [x] Healthcheckの待ち合わせ手順を README に追加
	- [x] `doctor` に `net.dns` チェックを追加
	- [x] `doctor` に `h3.connect` チェックを追加（暫定OK判定も可）
	- [x] Integration テストを追加（compose起動 + doctor）
	- [x] CI で Integration テストを実行（L2ゲート）

S3 - HTTP/3 接続検証
	- [x] QUIC ping RPC を実装（gateway/doctor）
	- [x] 認証はダミー（現状スキップ）
	- [ ] 証明書検証とトークン検証を追加

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
