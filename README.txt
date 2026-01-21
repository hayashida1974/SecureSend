【環境構築】
# Pythonのバージョン確認
python --version

# 仮想環境を作る
cd D:\gsession\SecureSend
python -m venv venv

# 仮想環境を有効化
venv\Scripts\activate

# 実行環境を確認
where python

# Flaskをインストール
pip install flask

# Flask関連ライブラリをインストール
pip install Flask-Session
pip install flask-seasurf

# その他のライブラリインストール
pip install python-dotenv
pip install requests
pip install cryptography

# 実行
python app.py


【開発環境起動】
cd D:\gsession\SecureSend
venv\Scripts\activate
python app.py
