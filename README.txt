【開発環境構築】
# Pythonのバージョン確認
python --version

# 仮想環境を作る（任意のフォルダでよい）
cd D:\gsession\SecureSend
python -m venv venv

# 仮想環境を有効化
venv\Scripts\activate

# 実行環境を確認
where python

# 必要なライブラリをインストール
pip install -r requirements.txt

# 実行
python app.py

【開発環境起動】
cd D:\gsession\SecureSend
venv\Scripts\activate
python app.py
