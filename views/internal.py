import os
import io
import uuid
import math
import threading
import json
from datetime import datetime, date, timedelta
from functools import wraps
import xml.etree.ElementTree as ET
import requests
from cryptography.fernet import Fernet

from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    abort,
    g,
    jsonify,
    send_file,
    current_app,
)
from views.filters import format_datetime, format_filesize, format_mask_email
import db
from paths import UPLOAD_DIR, GS_WHOAMI_URL

# current_app.logger.info("request.files: %s", request.files)

# ------------------------
# 設定
# ------------------------
internal_bp = Blueprint("internal", __name__)

# ------------------------
# ルートアクセス
# ------------------------
@internal_bp.route("/")
def index():
    return redirect(url_for("internal.menu"))

# ------------------------
# ログイン必須デコレータ
# ------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("internal.login"))
        return view(*args, **kwargs)
    return wrapped

# ------------------------
# ログイン画面
# ------------------------
@internal_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if db.crud.confirm_password(username, password) or authenticate_with_gs(username, password):
            session.permanent = True
            session["user_id"] = username
            session["admin"] = db.crud.is_admin_user(username)

            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "user_id": username,
                    "action": "ログイン OK",
                })
            return redirect(url_for("internal.menu"))

        else:
            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "user_id": username,
                    "action": "ログイン NG",
                })
            error = "ユーザー名またはパスワードが正しくありません"

    return render_template("internal_login.html", error=error)

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
        
        current_app.logger.info(response.text)

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
        db.crud.save_login_user(login_id, name, mail, external='GroupSession')
        return True

    except Exception:
        return False

# ------------------------
# ログアウト
# ------------------------
@internal_bp.route("/logout", methods=["GET"])
@login_required
def logout():

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ログアウト",
        })

    session.clear()
    return redirect(url_for("internal.login"))

# ------------------------
# メニュー画面
# ------------------------
@internal_bp.route("/menu", methods=["GET"])
@login_required
def menu():
    return render_template("internal_menu.html",
        username=session["user_id"])

# ------------------------
# アップロード依頼発行画面
# ------------------------
@internal_bp.route("/generate_upload_request", methods=["GET", "POST"])
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
                "action": "ファイルボックス作成",
                "upload_request_id": upload_request_id,
            })

        # アップロード依頼詳細画面に遷移
        return redirect(
            url_for("internal.detail_upload_request",upload_id=upload_request_id)
        )

    default_expires_at = (date.today() + timedelta(days=30)).isoformat()

    return render_template(
        "upload_request_generate.html",
        default_expires_at=default_expires_at,
        error=error
    )

# ------------------------
# アップロード依頼一覧画面
# ------------------------
@internal_bp.route("/list_upload_requests", methods=["GET"])
@login_required
def list_upload_requests():

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))

    page = request.args.get("page", 1, type=int)
    offset = (page - 1) * per_page

    # アップロード依頼リスト取得
    user_id = session["user_id"]
    upload_requests, total = db.crud.list_upload_requests(per_page=per_page, offset=offset, user_id=user_id)
    total_pages = max(1, math.ceil(total / per_page))

    return render_template(
        "upload_request_list.html",
        upload_requests=upload_requests,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )

# ------------------------
# アップロード依頼詳細画面
# ------------------------
@internal_bp.route("/upload_request/<upload_id>", methods=["GET"])
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
            "internal.download_file",
            upload_id=upload_id,
            file_id=f["file_id"]
        ),
        "delete_url": url_for("internal.delete_file", file_id=f["file_id"]),
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
        "delete_url": url_for("internal.delete_download_request", download_id=d["id"]),
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

@internal_bp.route("/upload/<upload_id>", methods=["POST"])
@login_required
def upload_file(upload_id):

    if "file" not in request.files or len(request.files.getlist("file")) < 1:
        return "ファイルが選択されていません", 400

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request(upload_id)
    if upload_request is None:
        abort(404)

    # 有効期限チェック
    if upload_request["expires_at"]:
        expires_at = datetime.fromisoformat(upload_request["expires_at"]).date()
        if expires_at < date.today():
            return "このアップロードURLは期限切れです", 403
    
    # １件ずつ処理
    with sigleSemaphore:

        # ファイルアップロード（Dropzoneなので1件のみ）
        file = request.files.getlist("file")[0]

        # アップロード済みファイル情報取得
        uploaded_files = db.crud.list_files(upload_id)

        # 同一ファイル名チェック
        existing_file = next(
            (f for f in uploaded_files if f["original_name"] == file.filename),
            None
        )

        if existing_file:
            # 既存ファイルの実体パス
            old_path = os.path.join(
                UPLOAD_DIR,
                upload_request["id"],
                existing_file["file_id"]
            )

            # 実ファイル削除
            if os.path.exists(old_path):
                os.remove(old_path)

            # DBレコード削除
            db.crud.delete_file(existing_file["file_id"])

            # uploaded_files から除外（サイズ再計算のため）
            uploaded_files = [
                f for f in uploaded_files
                if f["file_id"] != existing_file["file_id"]
            ]

        # 現在のファイルサイズ合計を取得
        total_size = sum(f["file_size"] for f in uploaded_files)

        # アップロードファイル数チェック
        if upload_request["max_files"] <= len(uploaded_files):
            return "最大ファイル数に達しています", 403

        # 元ファイルサイズ（暗号化前）
        original_data = file.read()
        file_size = len(original_data)

        # アップロード可能ファイルサイズチェック
        if total_size + file_size > upload_request["max_total_size"] * 1024 * 1024:
            return "合計ファイルサイズの上限に達しています", 403

        # 格納先フォルダ作成
        upload_dir = os.path.join(UPLOAD_DIR, upload_request["id"])
        os.makedirs(upload_dir, exist_ok=True)
            
        # 暗号化してファイル保存
        file_id = str(uuid.uuid4())
        save_path = os.path.join(upload_dir, file_id)
        encrypted_data = current_app.fernet.encrypt(original_data)
        with open(save_path, "wb") as f:
            f.write(encrypted_data)

        # ファイルテーブル挿入
        db.crud.create_file(upload_request["id"], file_id, file.filename, file_size)
        file = db.crud.get_file(file_id)

        # アクセスログ
        if hasattr(g, "access_log"):
            g.access_log.update({
                "action": "ファイルアップロード",
                "upload_request_id": upload_id,
                "file_id": file_id,
            })

    return jsonify({
        "file_id": file_id,
        "original_name": file["original_name"],
        "file_size": format_filesize(file_size),
        "uploaded_at": format_datetime(file["uploaded_at"]),
        "download_url": url_for(
            "internal.download_file",
            upload_id=upload_request["id"],
            file_id=file_id
        ),
        "delete_url": url_for("internal.delete_file", file_id=file_id)
    })

# ------------------------
# アップロードURL詳細画面－ファイルダウンロード
# ------------------------
@internal_bp.route("/download/<upload_id>/<file_id>", methods=["GET"])
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
            "action": "ファイルダウンロード",
            "upload_request_id": upload_id,
            "file_id": file_id,
        })
    
    # 暗号化ファイルを読み込み
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    # 複合化
    decrypted_data = current_app.fernet.decrypt(encrypted_data)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_row["original_name"]
    )

# ------------------------
# アップロードURL詳細画面－ファイル削除
# ------------------------
@internal_bp.route("/delete_file/<file_id>", methods=["DELETE"])
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
            "action": "ファイル削除",
            "upload_request_id": file_row["upload_request_id"],
            "file_id": file_id,
        })

    return "", 200

# ------------------------
# アップロード依頼詳細画面－ダウンロードURL発行
# ------------------------
@internal_bp.route("/generate_download_request", methods=["POST"])
@login_required
def generate_download_request():

    # パラメータ取得（VueJSからの依頼なのでJSON形式）
    payload = request.get_json()
    upload_request_id = payload["upload_request_id"]
    expire_days = payload["expire_days"]
    max_downloads = payload["max_downloads"]
    auth_type = payload["auth_type"]
    auth_password = payload.get("auth_password")
    auth_email = payload.get("auth_email")

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
            "action": "ダウンロードURL作成",
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
        "delete_url": url_for("internal.delete_download_request", download_id=download_row["id"]),
    })

# ------------------------
# アップロード依頼詳細画面－ダウンロードURL削除
# ------------------------
@internal_bp.route("/delete_download_request/<download_id>", methods=["DELETE"])
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
            "action": "ダウンロードURL削除",
            "upload_request_id": download_row["upload_request_id"],
            "download_request_id": download_id,
        })

    return "", 200

# ------------------------
# アップロード依頼詳細画面－操作ログ取得
# ------------------------
@internal_bp.route("/access_logs/<upload_id>", methods=["GET"])
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
@internal_bp.route("/delete_upload_request/<upload_id>", methods=["DELETE"])
@login_required
def delete_upload_request(upload_id):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ファイルボックス削除",
            "upload_request_id": upload_id,
        })

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request(upload_id)
    if upload_request is None:
        abort(404)

    # アップロード済ファイルリスト取得
    files = db.crud.list_files(upload_id)

    # ファイル削除
    upload_dir = os.path.join(UPLOAD_DIR, upload_id)
    for f in files:
        file_path = os.path.join(upload_dir, f["file_id"])
        os.remove(file_path)

    # フォルダ削除
    if os.path.isdir(upload_dir):
        os.rmdir(upload_dir)

    # アップロード依頼削除
    files = db.crud.delete_upload_request(upload_id)

    return "", 200

# ------------------------
# アドレス帳画面
# ------------------------
@internal_bp.route("/address_book", methods=["GET"])
@login_required
def address_book():
    return render_template("internal_address_book.html",
        username=session["user_id"])
