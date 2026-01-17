Toppy OSS仕様書およびTODO一覧

1. ソフトウェア仕様書

本ツールは Rust 製の CLI ベース接続ツールであり、HTTP/3 MASQUE（主に RFC 9484 CONNECT‑IP）を用いてリモートネットワークへの安全なアクセスを提供します。目的は技術者が自宅や検証環境・顧客環境へアクセスする際の鍵管理・経路確立・監査の面倒を吸収し、最小権限・短寿命クレデンシャル・ポリシー管理を実現することです。主要な仕様を以下にまとめます。
	•	対象ユーザ：SRE、セキュリティ担当者、開発者など。Linux/Windows/macOS から検証機や自宅 PC へ安全にアクセスしたい技術者を想定します。
	•	主要機能
	•	toppy login：OIDC デバイスコードフロー等で認証・認可を行い、短寿命トークンを取得します。完全 CLI で実行可能で、必要に応じブラウザを開くだけに留めます。
	•	toppy up/down：HTTP/3 MASQUE（CONNECT‑IP）を用いてトンネルを確立し、TUN インタフェースを作成して指定 CIDR・ポートへのルーティングを設定します。セッションは短寿命で、自動失効します。
	•	toppy ssh <target>：ポリシーで許可されたターゲットへ接続する際に短寿命 SSH 証明書を取得し、OpenSSH クライアントに渡します。長期鍵を配布しません。
	•	toppy rdp <target>：Windows ターゲットへ接続する場合、ローカルポートフォワード（例：localhost:<ランダムポート>→ターゲット 3389）を作成した後、OS 標準の RDP クライアントを起動します。
	•	toppy pf <target> --local <port> --remote <port>：任意 TCP ポートのフォワードを安全に行います。許可されたポートに限定されます。
	•	toppy target add/list：YAML/JSON でターゲットを宣言的に管理し、CIDR/ポート単位の許可ポリシーを定義します。デフォルトは deny です。
	•	toppy audit tail：誰がいつどこへ接続したかなどの監査ログを確認できます。ログはローカルおよびゲートウェイ側に記録されます。
	•	toppy doctor：環境診断コマンド。設定の妥当性、DNS 解決、HTTP/3 接続、認証トークン期限、TUN 権限、MTU 推定、ポリシー適用等をチェックし、成功・警告・失敗を JSON および人間向け出力で返します。
	•	安全設計
	•	短寿命セッション：トークンや証明書は通常 5〜30 分で失効し、漏洩時の被害範囲を限定します。
	•	最小権限ポリシー：ターゲットごとに許可された CIDR/ポートを厳格に定義し、それ以外は拒否します。通信量のレート制御フックも用意します。
	•	監査：接続開始・終了、許可・拒否の理由、宛先、転送量などを機械可読 JSONL 形式で保存し、必要に応じ改ざん耐性のあるストレージへ送信できるよう設計します。
	•	再現可能な導入：docker compose によりゲートウェイ・テスト環境を簡単に起動でき、README に 5 分以内のクイックスタートを記載します。
	•	非目標
	•	初期リリースでは完全な L3 VPN（ネットワーク丸ごとの透過共有）を目指さず、アプリケーション／ポート単位の安全な接続に集中します。
	•	OIDC 以外の IdP や多要素認証の対応は後段で検討します。
	•	CONNECT‑UDP や他トランスポートへの対応は Phase 3 以降で追加します。

2. TODOリスト

開発タスクを小さなセッションに分割し、それぞれにゲート（合否条件）とテストを設けます。下記は MVP に必要な作業の一覧です。

S0 – リポジトリ骨格（Gate L0：体裁）
	1.	Workspace を crates/toppy-cli, crates/toppy-gw, crates/toppy-core, crates/toppy-proto に分割し、Cargo.toml を整備する。
	2.	Makefile や justfile を用意し、make fmt, make clippy, make test, make dev, make compose-up, make compose-down, make doctor などのエントリポイントを定義する。
	3.	CI（GitHub Actions）で L0 ゲート（cargo fmt --check, cargo clippy -D warnings, cargo deny check）が走るようにする。
	4.	README にクイックスタートのアウトラインを記載し、ライセンス（Apache‑2.0 または MIT）と脅威モデルの概要を追加する。

S1 – doctor コマンド v0（Gate L1：単体テスト）
	1.	toppy doctor --json の出力形式を設計し、overall: pass|warn|fail、checks[]、version 等のフィールドを固定する。
	2.	設定ファイルの読み込みと検証、ポリシー評価関数、カプセル／制御メッセージ型等の純粋ロジックについてユニットテストを実装する。
	3.	cargo test が通る状態を維持し、CI で L1 ゲートを有効にする。

S2 – ゲートウェイヘルスチェック + Compose（Gate L2：結合テスト）
	1.	toppy-gw に /healthz エンドポイントと Docker Healthcheck を追加する。
	2.	docker compose でゲートウェイを起動し、Healthcheck が正常になることを確認する。
	3.	toppy doctor --json に net.dns（ゲートウェイの名前解決）および h3.connect（HTTP/3 ハンドシェイク）のチェックを実装し、CI で Integration テストを実行する。

2.1 進捗チェック（S0 -> S2）
	S0: 1は完了。2-4は未着手。
	S1: 1は完了。2-3は未着手（純粋ロジックとCIが必要）。
	S2: 未着手。

2.2 詳細TODO（粒度上げ）
S0 – リポジトリ骨格
	- [x] Workspace構成を確定（`crates/toppy-cli`, `crates/toppy-gw`, `crates/toppy-core`, `crates/toppy-proto`）
	- [ ] Makefile/justfile を追加し、`fmt/clippy/test/dev/compose-up/compose-down/doctor` のエントリを定義
	- [ ] `docker compose` 用のベースファイルを追加
	- [ ] GitHub Actions を追加（`cargo fmt --check`, `cargo clippy -D warnings`, `cargo deny check`）
	- [ ] `cargo deny` の設定ファイルを追加
	- [ ] README にクイックスタート（5分以内）を追記
	- [ ] README にライセンス表記（Apache-2.0 または MIT）を追記
	- [ ] README に脅威モデル概要を追記

S1 – doctor コマンド v0
	- [x] `doctor` の JSON 形式に `version/overall/checks` を固定
	- [x] `toppy doctor --json` オプションを実装
	- [ ] `doctor` の人間向け出力フォーマットの要件を確定（例: status並び順、色付け可否）
	- [ ] 設定ファイルのバリデーション（必須項目/型/範囲）
	- [ ] ポリシー評価関数のスタブとユニットテスト
	- [ ] カプセル/制御メッセージ型の最低限定義とユニットテスト
	- [ ] `cargo test` をCIで実行（L1ゲート）

S2 – ゲートウェイヘルスチェック + Compose
	- [ ] `toppy-gw` に `/healthz` を追加（HTTP 200/JSON）
	- [ ] `Dockerfile` と `HEALTHCHECK` を追加
	- [ ] `docker compose` で `toppy-gw` を起動
	- [ ] Healthcheckの待ち合わせ手順を README に追加
	- [ ] `doctor` に `net.dns` チェックを追加
	- [ ] `doctor` に `h3.connect` チェックを追加（暫定OK判定も可）
	- [ ] Integration テストを追加（compose起動 + doctor）
	- [ ] CI で Integration テストを実行（L2ゲート）

S3 – HTTP/3 接続検証（Gate L2）
	1.	CLI からゲートウェイへの最小 RPC を実装し、HTTP/3（QUIC）接続が成立するかどうかを doctor で確認できるようにする。
	2.	認証はこの段階ではダミートークン等で代用し、接続の成否と証明書検証に集中する。

S4 – TUN 権限検出 + MTU サニティチェック（Gate L2）
	1.	Linux で TUN デバイスが作成可能かを検出する (/dev/net/tun の存在や CAP_NET_ADMIN 有無)。macOS の utun への対応も検討する。
	2.	推奨 MTU を計算し、接続対象の MTU が極端に小さい・大きい場合に警告を出す。
	3.	doctor の JSON 出力に tun.perm と mtu.sanity を追加し、Integration テストを更新する。

S5 – E2E TCP到達性（Gate L3：End-to-End）
	1.	Linux ランナー上で toppy up を実行し、許可されたターゲットへの TCP (例：SSH ポート 22) の疎通を nc -zv などで確認する。
	2.	許可されていない宛先やポートへの接続が拒否されることを確認し、doctor で policy.denied の理由を返す。
	3.	Windows 環境用の RDP ポート (3389) でも同様の疎通チェックを行い、必要に応じクロス OS テストを段階的に追加する。

Phase 3 以降のタスク（参考）
	•	CONNECT‑UDP の追加：UDP アプリ（DoQ/ゲーム等）を通すための機能。CLI に toppy udp-proxy を追加するか、既存トンネル上に UDP カプセルを流すかを検討する。
	•	IdP 拡充：SAML や多要素認証、FIDO2 などへ対応し、CLI での使い勝手を壊さない範囲で統合する。
	•	監査ログの改ざん耐性：署名やリモート送信先への転送による tamper proof 化を実装する。
	•	Windows/Wintun 対応：Windows 環境で TUN インタフェースを扱うための Wintun への対応。
	•	レート制御・帯域制御：セッションごとの最大帯域やパケットレートを制御し、濫用を抑制する機構。

3. ゲートの定義

各タスクには段階的なゲートを設定し、合格条件を CI やレビューで自動確認します。
