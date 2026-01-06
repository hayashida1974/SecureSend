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
    Blueprint,
    current_app,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_session import Session

from paths import CONFIG_PATH, UPLOAD_DIR, DB_PATH
from filters import format_datetime, format_filesize, format_mask_email
import db

# ------------------------
# 設定
# ------------------------
guest_bp = Blueprint("guest", __name__)

# ------------------------
# ゲスト認証画面
# ------------------------
@guest_bp.route("/guest_auth/<token>", methods=["GET", "POST"])
def guest_auth(token):
    error = None

    # ゲスト認証情報取得
    auth = db.crud.find_guest_auth(token)
    if not auth:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": auth["upload_request_id"],
        })

    auth_type = auth["auth_type"]
    authenticated_tokens = session.get("authenticated_tokens", [])

    if request.method == "POST":
        if auth_type == "pass":
            input_password = request.form.get("password", "")
            if input_password == auth["auth_password"]:
                if token not in authenticated_tokens:
                    authenticated_tokens.append(token)                
                session.permanent = True
                session["authenticated_tokens"] = authenticated_tokens

                # アクセスログ
                if hasattr(g, "access_log"):
                    g.access_log.update({
                        "action": "auth OK",
                    })

                return redirect(url_for("guest.guest_download", token=token))
            else:
                # アクセスログ
                if hasattr(g, "access_log"):
                    g.access_log.update({
                        "action": "auth NG",
                    })

                error = "パスワードが違います"

        elif auth_type == "mail":
            # POST時にOTP入力か、最初のアクセス時にOTP送信
            if 'send_otp' in request.form:

                # アクセスログ
                if hasattr(g, "access_log"):
                    g.access_log.update({
                        "action": "otp send",
                    })

                # ワンタイムパスワード生成
                otp_code = generate_otp()
                # テーブル登録
                db.crud.create_otp(token, auth["auth_email"], otp_code)
                # メール送信
                send_otp_email(auth["auth_email"], otp_code)
                auth_type = "otp_pass"
            else:
                otpcode = request.form.get("otpcode", "")
                otp = db.crud.confirm_otp(token, otpcode)
                if otp:
                    if token not in authenticated_tokens:
                        authenticated_tokens.append(token)
                    session.permanent = True
                    session["authenticated_tokens"] = authenticated_tokens

                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "action": "auth OK",
                        })

                    return redirect(url_for("guest.guest_download", token=token))
                else:
                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "action": "auth NG",
                        })

                    auth_type = "otp_pass"
                    error = "ワンタイムパスワードが正しくありません"

    return render_template(
        "guest_auth.html",
        token=token,
        auth_type=auth_type,
        auth_email=auth["auth_email"],
        error=error
    )

import random
def generate_otp(length=6):
    return f"{random.randint(0, 10**length - 1):0{length}d}"

import smtplib
from email.message import EmailMessage
from email.headerregistry import Address
def send_otp_email(to_email, otp_code):

    # コンフィグから送信元メールアドレス取得
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")
    from_address = config.get("mail", "from_address", fallback="")

    msg = EmailMessage()
    msg["Subject"] = "ファイルダウンロード用ワンタイムパスワード"
    username, domain = from_address.split("@", 1)
    msg["From"] = Address(
        display_name="Secure Send",
        username=username,
        domain=domain,
    )
    msg["To"] = to_email
    msg.set_content(f"""
本人確認のため、以下の認証コードを認証画面で入力してください。

----------------------------------------------------------------------------------------
【認証コード】{otp_code}

【認証コードについて】
・リクエスト時間から10分間有効です。
・一度使用すると無効になります。
・無効になった場合は、認証画面から再送要求を行ってください。
----------------------------------------------------------------------------------------

■ ご注意
このメールは、ファイルダウンロード前のユーザー確認のために送信されています。
このメールにお心当たりがない場合は、お手数ですが本メールを破棄してください。

※ このメールは配信専用のアドレスから送信されています。
　本メールへの返信はできません。
    """.strip())

    with smtplib.SMTP("mail.system-prostage.co.jp", 25) as smtp:
        smtp.send_message(msg)

# ゲスト認証必須デコレータ
def guestauth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # request.args.get("token")： リクエストパラメータ
        # kwargs.get("token")：URLパスの変数
        token = kwargs.get("token")
        if not token:
            abort(400)

        # ゲスト認証情報取得
        auth = db.crud.find_guest_auth(token)
        if not auth:
            abort(404)

        # 有効期限チェック
        expires_at = auth["expires_at"]
        if expires_at:
            try:
                if auth["token_type"] == "upload":
                    # YYYY-MM-DD
                    expires_date = date.fromisoformat(expires_at)
                    if expires_date < date.today():
                        abort(403, description="このアップロードリンクは期限切れです")

                elif auth["token_type"] == "download":
                    # YYYY-MM-DDTHH:MM:SS
                    expires_dt = datetime.fromisoformat(expires_at)
                    if expires_dt < datetime.now():
                        abort(403, description="このダウンロードリンクは期限切れです")
            except ValueError:
                # expires_at が壊れている場合
                abort(403)

        # 認証方式がある場合は認証画面へリダイレクト
        auth_type = auth["auth_type"]
        if auth_type in ("pass", "mail"):
            authenticated_tokens = session.get("authenticated_tokens", [])
            if token not in authenticated_tokens:
                return redirect(url_for(
                    "guest.guest_auth",
                    auth_type=auth_type,
                    token=token
                ))
        # 認証なしならそのまま通す

        # 有効期限設定（初回アクセス時）
        if auth["token_type"] == "download":
            db.crud.update_download_expires(token)

        return view(*args, **kwargs)
    return wrapped

# ------------------------
# ゲスト向けダウンロード一覧画面
# ------------------------
@guest_bp.route("/download/<token>", methods=["GET"])
@guestauth_required
def guest_download(token):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "download list",
        })

    # ダウンロードトークンからダウンロードリクエスト情報取得
    download_request = db.crud.get_download_request_by_token(token)

    if download_request is None:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": download_request["upload_request_id"],
            "download_request_id": download_request["id"],
        })

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request(download_request["upload_request_id"])

    if upload_request is None:
        abort(404)

    # ファイルリスト取得
    files = db.crud.list_files(download_request["upload_request_id"])

    return render_template(
        "guest_download.html",
        upload_request=upload_request,
        download_request=download_request,
        files=files,
    )

# ------------------------
# ゲスト向けファイルダウンロード
# ------------------------
@guest_bp.route("/guest_download/<token>/<file_id>", methods=["GET"])
@guestauth_required
def guest_download_file(token, file_id):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "file download",
            "file_id": file_id,
        })
    
    # ダウンロードトークンからダウンロードリクエスト情報取得
    download_request = db.crud.get_download_request_by_token(token)

    if download_request is None:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": download_request["upload_request_id"],
            "download_request_id": download_request["id"],
        })

    # ファイル情報取得
    file_row = db.crud.get_file(file_id)

    # ファイル情報存在チェック
    if file_row is None:
        abort(404)

    # 実ファイルパス作成
    file_path = os.path.join(
        UPLOAD_DIR,
        download_request["upload_request_id"],
        file_id
    )

    # 実ファイル存在チェック
    if not os.path.exists(file_path):
        abort(404)

    # ダウンロード回数チェック
    current_count = db.crud.get_file_download_count(download_request["id"], file_id)
    if current_count >= download_request["max_downloads"]:
        abort(403, description="ダウンロード回数の上限に達しました")

    # ダウンロード回数更新
    db.crud.increment_file_download_count(download_request["id"], file_id)

    return send_file(
        file_path,
        as_attachment=True,
        download_name=file_row["original_name"]
    )

# ------------------------
# ゲスト向けファイル一括ダウンロード
# ------------------------
@guest_bp.route("/guest_download/<token>/zip", methods=["GET"])
@guestauth_required
def guest_download_zip(token):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ZIP download",
        })

    # ダウンロードトークンからダウンロードリクエスト情報取得
    download_request = db.crud.get_download_request_by_token(token)
    if download_request is None:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": download_request["upload_request_id"],
            "download_request_id": download_request["id"],
        })

    files = db.crud.list_files(download_request["upload_request_id"])
    if not files:
        abort(404)

    # ダウンロード回数チェック
    available_files = []
    for f in files:
        current_count = db.crud.get_file_download_count(download_request["id"], f["file_id"])
        if current_count < download_request["max_downloads"]:
            available_files.append(f)

    if not available_files:
        abort(403, description="すべてのファイルがダウンロード上限に達しました")

    # ZIPファイル作成
    def generate():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in available_files:
                # 実ファイルパス作成
                file_path = os.path.join(
                    UPLOAD_DIR,
                    download_request["upload_request_id"],
                    f["file_id"]
                )

                with open(file_path, "rb") as fp:
                    zf.writestr(f["original_name"], fp.read())

        buffer.seek(0)
        yield from buffer
    zip_name = f"download_{download_request['id']}.zip"

    # ダウンロード回数更新
    for f in available_files:
        db.crud.increment_file_download_count(download_request["id"], f["file_id"])

    return Response(
        stream_with_context(generate()),
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{zip_name}"'
        }
    )

# ------------------------
# ゲスト向けアップロード一覧画面
# ------------------------
@guest_bp.route("/upload/<token>", methods=["GET"])
@guestauth_required
def guest_upload(token):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "upload list",
        })

    # アップロードトークンからアップロードリクエスト情報取得
    upload_request = db.crud.get_upload_request_by_token(token)

    if upload_request is None:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": upload_request["id"],
        })

    # ファイルリスト取得
    files = db.crud.list_files(upload_request["id"])

    return render_template(
        "guest_upload.html",
        upload_request=upload_request,
        files=files,
    )

# ------------------------
# ゲスト向けファイルアップロード
# ------------------------
@guest_bp.route("/guest_upload/<token>", methods=["POST"])
@guestauth_required
def guest_upload_file(token):

    if "file" not in request.files:
        return "ファイルが選択されていません", 400

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "file upload",
        })

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request_by_token(token)
    if upload_request is None:
        abort(404)

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": upload_request["id"],
        })

    # 有効期限チェック
    if upload_request["expires_at"]:
        expires_at = datetime.fromisoformat(upload_request["expires_at"])
        if expires_at < datetime.now():
            return "このアップロードURLは期限切れです", 403
    
    # １件ずつ処理
    with sigleSemaphore:

        # アップロード済みファイル情報取得
        uploaded_files = db.crud.list_files(upload_request["id"])

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

            # アクセスログ
            if hasattr(g, "access_log"):
                g.access_log.update({
                    "file_id": file_id,
                })

            # ファイルテーブル挿入
            db.crud.create_file(upload_request["id"], file_id, f.filename, file_size)
            file = db.crud.get_file(file_id)

    return jsonify({
        "file_id": file_id,
        "original_name": f.filename,
        "file_size": format_filesize(file_size),
        "uploaded_at": format_datetime(file["uploaded_at"]),
    })
