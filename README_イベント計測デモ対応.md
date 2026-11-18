# CleanStep イベント計測デモ対応版

## 内容
- `app.py`：通常15分／デモ1分の切替、デモGPS模擬値のサーバー生成、実測と模擬のDB区分
- `templates/event_live.html`：デモ時は実GPSを要求せず、模擬GPS計測表示を行う画面

## 適用前の注意
このパッケージは、2026-11-18に共有された `app(20261118-004813).py` と `event_live(2).html` を基に作成しています。
現在のローカル `app.py` にそれ以降の変更がある場合は、丸ごと上書きせず、差分を確認してください。

## デモモード起動
Flaskサーバーを停止してから、PowerShellでプロジェクトフォルダに移動し、まず通常DBをコピーします。

```powershell
Copy-Item .\database.db .\database_demo.db
```

仮想環境を有効にした状態で、次を実行します。

```powershell
$env:CLEANSTEP_DATABASE_PATH = (Resolve-Path .\database_demo.db).Path
$env:CLEANSTEP_EVENT_DEMO_MODE = "1"
python -c "import app; print('使用DB:', app.DATABASE); app.init_db()"
flask run
```

デモ終了後、通常モードに戻すには次を実行します。

```powershell
Remove-Item Env:CLEANSTEP_DATABASE_PATH
Remove-Item Env:CLEANSTEP_EVENT_DEMO_MODE
flask run
```

## 動作仕様
- 通常モード：最低15分、実際のGPS・端末センサーを使用。従来の位置確認も維持。
- デモモード：最低1分、GPSボタンで模擬計測を開始／停止。実際の位置情報許可は求めない。
- デモ値はサーバー側で再計算し、`activity_history.gps_measured=0`、`gps_simulated=1` として保存。既存DBでは `init_db()` が不足列を追加します。
- デモモードは `*_demo.db` という名前の専用DBでしか起動できない。
- デモ用のポイント加算・予約完了・活動履歴はデモDB内にのみ保存される。

## 確認済み
- Python構文解析：成功
- 文字列置換・主要ロジック存在確認：成功
- Flaskの実DBを使ったE2Eテスト：この作業環境では未実施。ローカルで起動・イベント完了まで確認してください。
