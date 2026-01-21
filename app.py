import os
import base64
from datetime import datetime, timedelta
from dotenv import load_dotenv

from flask import Flask, render_template, request, session, g
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
from flask_seasurf import SeaSurf
from cryptography.fernet import Fernet

import db
from paths import CONFIG_PATH, UPLOAD_DIR, DB_PATH
from views.filters import format_datetime, format_filesize, format_mask_email
from views.internal import internal_bp
from views.admin import admin_bp
from views.guest import guest_bp

# ------------------------
# envファイル読込
# ------------------------
load_dotenv()

# ------------------------
# Flaskアプリ作成
# ------------------------
app = Flask(__name__)

# ----------------------------
# Apache リバースプロキシ配下で動かすため、
# X-Forwarded-* ヘッダを信頼して URL/redirect を補正する
# ----------------------------
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1,
    x_prefix=1
)

# ----------------------------
# 署名用キー（Cookieの安全性に必須）
# ----------------------------
# 本番環境ではランダムな安全な文字列を環境変数から読み込む
app.secret_key = os.environ.get("SECRET_KEY") or "dev-secret-key"

# ----------------------------
# 保存ファイル暗号化
# ----------------------------
file_encryption_raw_key = os.environ.get("FILE_ENCRYPTION_KEY") or "dev-key-32bytes-should-be-secure"
file_encryption_key = file_encryption_raw_key.encode("utf-8")
if len(file_encryption_key) < 32:
    file_encryption_key = file_encryption_key.ljust(32, b"!") 
elif len(file_encryption_key) > 32:
    file_encryption_key = file_encryption_key[:32]
# Base64 URL-safeに変換してFernetキーにする
fernet_key = base64.urlsafe_b64encode(file_encryption_key)
app.fernet = Fernet(fernet_key)

# ------------------------
# 起動時処理
# ------------------------
# DB初期化
db.init_db()
# ディレクトリ作成
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ----------------------------
# セッション設定
# ----------------------------
app.config.update(
    SESSION_TYPE='filesystem',
    SESSION_FILE_DIR='/tmp/flask_session',            # 明示推奨
    SESSION_PERMANENT=True,                           # セッションを残す
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    SESSION_COOKIE_EXPIRES=False,                     # Cookieの有効期限なし
    SESSION_COOKIE_HTTPONLY=True,                     # JSからアクセス不可
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") != "development",  # HTTPS時のみ送信
    SESSION_COOKIE_SAMESITE="Lax",                    # クロスサイト送信制限
)
Session(app)

# ----------------------------
# Blueprint登録
# ----------------------------
app.register_blueprint(internal_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(guest_bp)

app.teardown_appcontext(db.close_db)

app.template_filter("datetime")(format_datetime)
app.template_filter("filesize")(format_filesize)
app.template_filter("mask_email")(format_mask_email)

# ----------------------------
# CSRF対策
# ----------------------------
csrf = SeaSurf(app)

# ------------------------
# アクセスログ取得用
# ------------------------
@app.before_request
def before_request_logging():
    g.access_log = {
        "accessed_at": datetime.now().isoformat(),
        "user_id": session.get("user_id"),
        "action": None,
        "upload_request_id": None,
        "download_request_id": None,
        "file_id": None,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get("User-Agent"),
    }

@app.after_request
def after_request_logging(response):
    log = getattr(g, "access_log", None)
    if not log:
        return response

    log["http_status"] = response.status_code
    log["result"] = "success" if response.status_code < 400 else "error"

    if log["action"] or log["result"] == "error":
        db.crud.save_access_log(log)
        del g.access_log

    return response

@app.teardown_request
def teardown_request_logging(exc):
    if exc:
        log = getattr(g, "access_log", None)
        if log:
            log["http_status"] = 500
            log["result"] = "error"
            db.crud.save_access_log(log)
            del g.access_log

# ------------------------
# 実行
# ------------------------
if __name__ == "__main__":
    app.run(debug=True)
