# virus-check-webui
## 概要
　個人向けのVirusTotalを用いたVirusScanを行えるツールです。APIKEYは必要のためVirusTotalのアカウントを作ってください。  あくまで現在は試験的なスクリプトです。
## 目的
- VirusTotalのwebAPIをwebUIから叩く(今後他の機能も付けるかも)
- とりあえずstreamlitを触ってみたい
- 素人でも使える(目標)

## 使い方
pythonは3系を使ってください。
- 必要なライブラリのインストール
```python
pip install streamlit matplotlib pandas
```
- 起動
```python
stremlit run .\webui.py
```
-デフォルトのブラウザが立ち上がり、localhost:8501に自動的にアクセスします。
