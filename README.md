# Thermo-Credit Monitor (Starter)

最小構成のMVP。公開統計CSVから、**流動性温度 (TMS-LT)**、**貨幣エントロピー (S_M)**、**規制ループ散逸面積 (PLD)**、**信用エクセルギー上限 (X_C)** を計算して、`site/report.html` を自動生成する。

## 使い方（最短）
1. `data/*.csv` を自分のデータに置き換える（サンプル同梱）。
2. GitHubに新規リポジトリ作成→この一式をpush。
3. Settings → Pages → **Build and deployment = GitHub Actions** を選択。
4. Actions → **Build & Publish** の workflow を `Run workflow` で手動実行（または毎月自動）。
5. `https://<yourname>.github.io/<repo>/report.html` で月次レポートを確認。

## 指標
- **S_M** = k · M_in · H(q)（シャノンエントロピー）。
- **T_L (TMS-LT)** = (低スプレッド×薄板×高回転) を z-score 合成して 0-1 正規化。
- **PLD** ≈ Σ p_R(t-1)·ΔV_R(t)（指数忘却付きのストリーミング近似）。
- **X_C** = U − T0 · S_M（信用エクセルギー上限）。

## ディレクトリ
- `data/` 入力CSV（サンプルあり）
- `lib/`  指標計算の関数群
- `scripts/` パイプライン（前処理→指標→レポート）
- `site/` 出力（Actionsが上書き）
- `.github/workflows/` Actions定義

## 注意
- 最低限の実装であり、数式・定義はプロジェクト規約に合わせて修正すること。
- 大規模データやAPI取得は `scripts/01_build_features.py` を拡張して対応。
