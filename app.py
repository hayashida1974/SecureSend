import os
import uuid
import sqlite3
import io
import math
import zipfile
from datetime import date, datetime, timedelta
from functools import wraps
import requests
import threading
import xml.etree.ElementTree as ET
import json
import configparser
import re
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    send_file,
    jsonify,
    Response,
    stream_with_context,
    g,
    flash,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session
from flask_seasurf import SeaSurf

from paths import CONFIG_PATH, UPLOAD_DIR, DB_PATH
from filters import (
    format_datetime,
    format_filesize,
    format_mask_email
)
from views.guest import guest_bp
import db

# ------------------------
# Flaskアプリ作成
# ------------------------
app = Flask(__name__)

# ------------------------
# 設定
# ------------------------
GS_WHOAMI_URL = "https://group.system-prostage.co.jp/gsession/api/user/whoami.do"

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

app.teardown_appcontext(db.close_db)
app.register_blueprint(guest_bp)

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
# ログイン画面
# ------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if authenticate_with_gs(username, password):
            session.permanent = True
            session["user_id"] = username

            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "user_id": username,
                    "action": "login OK",
                })

            return redirect(url_for("menu"))
        else:
            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "user_id": username,
                    "action": "login NG",
                })

            error = "ユーザー名またはパスワードが正しくありません"

    return render_template("login.html", error=error)

# ログイン必須デコレータ
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

# ------------------------
# GS認証
# ------------------------
def authenticate_with_gs(username, password):
    try:
        # GSからユーザ情報取得
        response = requests.get(
            GS_WHOAMI_URL,
            auth=(username, password),
            timeout=5
        )

        # ユーザ情報が取得できなければエラー
        if response.status_code != 200:
            return False
        
        # ユーザー情報から名前とメールアドレスを取得
        root = ET.fromstring(response.text)
        result = root.find("Result")
        if result is None:
            return False
        login_id = result.findtext("LoginId")
        name_sei = result.findtext("NameSei") or ""
        name_mei = result.findtext("NameMei") or ""
        name = f"{name_sei} {name_mei}".strip()
        mail = result.findtext("Mail1") or ""

        # ユーザー情報をテーブルに保存
        db.crud.save_login_user(login_id, name, mail)
        return True
    except Exception:
        return False

# ------------------------
# ログアウト
# ------------------------
@app.route("/logout", methods=["GET"])
@login_required
def logout():

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "logout",
        })

    session.clear()
    return redirect(url_for("login"))

# ------------------------
# メニュー画面
# ------------------------
@app.route("/menu", methods=["GET"])
@login_required
def menu():
    return render_template("menu.html",
        username=session["user_id"])

# ------------------------
# アップロード依頼発行画面
# ------------------------
@app.route("/generate_upload_request", methods=["GET", "POST"])
@login_required
def generate_upload_request():
    error = None

    if request.method == "POST":

        # アップロード依頼作成データ取得
        title = request.form.get("title")
        expires_at = request.form.get("expires_at")
        max_files = request.form.get("max_files")
        max_total_size = request.form.get("max_total_size")
        user_id = session["user_id"]

        # アップロード依頼テーブル挿入
        upload_request_id = db.crud.create_upload_request(
            title,
            expires_at,
            max_files,
            max_total_size,
            user_id,
        )

        # アクセスログ
        if hasattr(g, "access_log"):
            g.access_log.update({
                "action": "generate upload url",
                "upload_request_id": upload_request_id,
            })

        # アップロード依頼詳細画面に遷移
        return redirect(
            url_for("detail_upload_request",upload_id=upload_request_id)
        )

    default_expires_at = (date.today() + timedelta(days=7)).isoformat()

    return render_template(
        "upload_request_generate.html",
        default_expires_at=default_expires_at,
        error=error
    )

# ------------------------
# アップロード依頼一覧画面
# ------------------------
@app.route("/list_upload_requests", methods=["GET"])
@login_required
def list_upload_requests():

    # アップロード依頼リスト取得
    user_id = session["user_id"]
    upload_requests = db.crud.list_upload_requests(user_id)

    return render_template(
        "upload_request_list.html",
        upload_requests=upload_requests
    )

# ------------------------
# アップロード依頼詳細画面
# ------------------------
@app.route("/upload_request/<upload_id>", methods=["GET"])
@login_required
def detail_upload_request(upload_id):

    # アップロード依頼取得
    upload_request = db.crud.get_upload_request(upload_id)
    if upload_request is None:
        abort(404)

    # アップロード済ファイルリスト取得
    files = db.crud.list_files(upload_id)

    # ダウンロード依頼リスト取得
    download_requests = db.crud.list_download_requests(upload_id)

    # ログ取得
    logs = db.crud.list_access_logs(upload_request_id=upload_id)

    # テーブルがVueなのでJSONに変換
    upload_files_json = [{
        "file_id": f["file_id"],
        "original_name": f["original_name"],
        "file_size": format_filesize(f["file_size"]),
        "uploaded_at": format_datetime(f["uploaded_at"]),
        "download_url": url_for(
            "download_file",
            upload_id=upload_id,
            file_id=f["file_id"]
        ),
        "delete_url": url_for("delete_file", file_id=f["file_id"]),
    } for f in files]

    # テーブルがVueなのでJSONに変換
    download_urls_json = [{
        "id": d["id"],
        "download_token": d["download_token"],
        "expire_days" : d["expire_days"],
        "expires_at": format_datetime(d["expires_at"]),
        "max_downloads" : d["max_downloads"],
        "auth_type" : d["auth_type"],
        "auth_password" : d["auth_password"],
        "auth_email" : d["auth_email"],
        "created_at" : format_datetime(d["created_at"]),
        "delete_url": url_for("delete_download_request", download_id=d["id"]),
    } for d in download_requests]

    # テーブルがVueなのでJSONに変換
    logs_json = [{
        "id": l["id"],
        "accessed_at": format_datetime(l["accessed_at"]),
        "user_id": l["user_id"],
        "action": l["action"],
        "download_request": l["download_request"],
        "download_request_id": l["download_request_id"],
        "file": l["file"],
        "file_id": l["file_id"],
        "result": l["result"],
        "http_status": l["http_status"],
        "ip_address": l["ip_address"],
        "user_agent": l["user_agent"],
    } for l in logs]

    return render_template(
        "upload_request_detail.html",
        upload_request=upload_request,
        files_json=json.dumps(upload_files_json),
        download_urls_json=json.dumps(download_urls_json),
        logs_json=json.dumps(logs_json),
    )

# ------------------------
# アップロード依頼詳細画面（ファイルアップロード）
# ------------------------
sigleSemaphore = threading.Semaphore(1)

@app.route("/upload/<upload_id>", methods=["POST"])
@login_required
def upload_file(upload_id):

    # app.logger.info("request.files: %s", request.files)

    if "file" not in request.files:
        return "ファイルが選択されていません", 400

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request(upload_id)
    if upload_request is None:
        abort(404)

    # 有効期限チェック
    if upload_request["expires_at"]:
        expires_at = datetime.fromisoformat(upload_request["expires_at"])
        if expires_at < datetime.now():
            return "このアップロードURLは期限切れです", 403
    
    # １件ずつ処理
    with sigleSemaphore:

        # アップロード済みファイル情報取得
        uploaded_files = db.crud.list_files(upload_id)

        # 現在のファイルサイズ合計を取得
        total_size = sum(f["file_size"] for f in uploaded_files)

        # アップロードファイル数チェック
        if upload_request["max_files"] <= len(uploaded_files):
            return "最大ファイル数に達しています", 403

        # ファイルアップロード（ファイルは１件ずつしか来ないはず）
        files = request.files.getlist("file")
        for f in files:
            if f.filename == "":
                continue

            # 格納先フォルダ作成
            upload_dir = os.path.join(UPLOAD_DIR, upload_request["id"])
            os.makedirs(upload_dir, exist_ok=True)
            
            # ファイル保存
            file_id = str(uuid.uuid4())
            save_path = os.path.join(upload_dir, file_id)
            f.save(save_path)

            # アップロードしたファイルサイズ取得
            file_size = os.path.getsize(save_path)

            # アップロード可能ファイルサイズチェック
            if total_size + file_size > upload_request["max_total_size"] * 1024 * 1024:
                # ファイルを消す
                os.remove(save_path)
                return "合計ファイルサイズの上限に達しています", 403

            # ファイルテーブル挿入
            db.crud.create_file(upload_request["id"], file_id, f.filename, file_size)
            file = db.crud.get_file(file_id)

            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "action": "upload file",
                    "upload_request_id": upload_id,
                    "file_id": file_id,
                })

    return jsonify({
        "file_id": file_id,
        "original_name": f.filename,
        "file_size": format_filesize(file_size),
        "uploaded_at": format_datetime(file["uploaded_at"]),
        "download_url": url_for(
            "download_file",
            upload_id=upload_request["id"],
            file_id=file_id
        ),
        "delete_url": url_for("delete_file", file_id=file_id)
    })

# ------------------------
# アップロードURL詳細画面－ファイルダウンロード
# ------------------------
@app.route("/download/<upload_id>/<file_id>", methods=["GET"])
@login_required
def download_file(upload_id, file_id):

    # ファイル情報取得
    file_row = db.crud.get_file(file_id)

    # ファイル情報存在チェック
    if file_row is None:
        abort(404)

    # 実ファイルパス作成
    file_path = os.path.join(
        UPLOAD_DIR,
        upload_id,
        file_id
    )

    # 実ファイル存在チェック
    if not os.path.exists(file_path):
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "download file",
            "upload_request_id": upload_id,
            "file_id": file_id,
        })

    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_row["original_name"]
    )

# ------------------------
# アップロードURL詳細画面－ファイル削除
# ------------------------
@app.route("/delete_file/<file_id>", methods=["DELETE"])
@login_required
def delete_file(file_id):

    # ファイル情報取得
    file_row = db.crud.get_file(file_id)
    if file_row is None:
        abort(404)

    # ファイル削除
    upload_dir = os.path.join(UPLOAD_DIR, file_row["upload_request_id"])
    file_path = os.path.join(upload_dir, file_id)
    os.remove(file_path)

    # ファイルテーブル削除
    db.crud.delete_file(file_id)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "delete file",
            "upload_request_id": file_row["upload_request_id"],
            "file_id": file_id,
        })

    return "", 200

# ------------------------
# アップロード依頼詳細画面－ダウンロードURL発行
# ------------------------
@app.route("/generate_download_request", methods=["POST"])
@login_required
def generate_download_request():

    # パラメータ取得
    payload = request.get_json()
    upload_request_id = payload["upload_request_id"]
    expire_days = payload["expire_days"]
    max_downloads = payload["max_downloads"]
    auth_type = payload["auth_type"]
    auth_password = payload.get("auth_password")
    auth_email = payload.get("auth_email")

    app.logger.info("auth_password: %s", auth_password)

    # ダウンロードURL発行
    download_id = db.crud.create_download_request(
        upload_request_id,
        expire_days,
        max_downloads,
        auth_type,
        auth_password,
        auth_email)

    # 発行データ取得
    download_row = db.crud.get_download_request(download_id)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "generate download url",
            "upload_request_id": upload_request_id,
            "download_request_id": download_id,
        })

    return jsonify({
        "id": download_row["id"],
        "download_token": download_row["download_token"],
        "expire_days" : download_row["expire_days"],
        "expires_at": format_datetime(download_row["expires_at"]),
        "max_downloads" : download_row["max_downloads"],
        "auth_type" : download_row["auth_type"],
        "auth_password" : download_row["auth_password"],
        "auth_email" : download_row["auth_email"],
        "created_at" : format_datetime(download_row["created_at"]),
        "delete_url": url_for("delete_download_request", download_id=download_row["id"]),
    })

# ------------------------
# アップロード依頼詳細画面－ダウンロードURL削除
# ------------------------
@app.route("/delete_download_request/<download_id>", methods=["DELETE"])
@login_required
def delete_download_request(download_id):

    # ダウンロード依頼取得
    download_row = db.crud.get_download_request(download_id)
    if download_row is None:
        abort(404)

    # ダウンロード依頼削除
    db.crud.delete_download_request(download_id)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "delete download url",
            "upload_request_id": download_row["upload_request_id"],
            "download_request_id": download_id,
        })

    return "", 200

# ------------------------
# アップロード依頼詳細画面－操作ログ取得
# ------------------------
@app.route("/access_logs/<upload_id>", methods=["GET"])
@login_required
def get_access_logs(upload_id):

    # ログ取得
    logs = db.crud.list_access_logs(upload_request_id=upload_id)

    # テーブルがVueなのでJSONに変換
    logs_json = [{
        "id": l["id"],
        "accessed_at": format_datetime(l["accessed_at"]),
        "user_id": l["user_id"],
        "action": l["action"],
        "download_request": l["download_request"],
        "download_request_id": l["download_request_id"],
        "file": l["file"],
        "file_id": l["file_id"],
        "result": l["result"],
        "http_status": l["http_status"],
        "ip_address": l["ip_address"],
        "user_agent": l["user_agent"],
    } for l in logs]

    return json.dumps(logs_json)

# ------------------------
# アップロードURL詳細画面－アップロード依頼削除
# ------------------------
@app.route("/delete_upload_request/<upload_id>", methods=["DELETE"])
@login_required
def delete_upload_request(upload_id):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "delete upload url",
            "upload_request_id": upload_id,
        })

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request(upload_id)
    if upload_request is None:
        abort(404)

    # アップロード済ファイルリスト取得
    files = db.crud.list_files(upload_id)

    # ファイル削除
    for f in files:
        upload_dir = os.path.join(UPLOAD_DIR, f["upload_request_id"])
        file_path = os.path.join(upload_dir, f["file_id"])
        os.remove(file_path)
    # フォルダ削除
    os.rmdir(upload_dir)

    # アップロード依頼削除
    files = db.crud.delete_upload_request(upload_id)

    return "", 200

# ------------------------
# 操作ログ
# ------------------------
@app.route("/admin/access_logs")
@login_required
def access_logs():

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))

    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * per_page

    # 総件数
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM access_logs")
        total = cur.fetchone()[0]
        total_pages = max(1, math.ceil(total / per_page))

    # ログ取得
    logs = db.crud.list_access_logs(per_page, offset)

    return render_template(
        "access_logs.html",
        logs=logs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )

# ------------------------
# 設定画面
# ------------------------
@app.route("/admin/settings", methods=["GET", "POST"])
@login_required
def settings():

    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")

    if request.method == "POST":
        from_address = request.form.get("from_address", "").strip()

        # 最低限のバリデーション
        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", from_address):
            flash("メールアドレスの形式が正しくありません", "danger")
            return redirect(url_for("settings_mail"))

        if not config.has_section("mail"):
            config.add_section("mail")

        config.set("mail", "from_address", from_address)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            config.write(f)

        flash("設定を保存しました", "success")
        return redirect(url_for("settings"))

    from_address = config.get("mail", "from_address", fallback="")

    return render_template(
        "settings.html",
        from_address=from_address
    )

# ------------------------
# 実行
# ------------------------
if __name__ == "__main__":
    app.run(debug=True)
