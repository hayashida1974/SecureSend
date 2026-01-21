import os
import uuid
import io
import math
import zipfile
from datetime import date, datetime, timedelta
from functools import wraps
import requests
import threading
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
from views.filters import format_datetime, format_filesize, format_mask_email
import db

# ------------------------
# 設定
# ------------------------
guest_bp = Blueprint("guest", __name__)

# ------------------------
# ゲスト認証必須デコレータ
# ------------------------
def guestauth_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # request.args.get("token")： リクエストパラメータ
        # kwargs.get("token")：URLパスの変数
        token = kwargs.get("token")
        if not token:
            abort(400)

        # ゲスト認証情報取得（有効期限チェックは関数内で実施）
        auth = db.crud.find_guest_auth(token)
        if not auth:
            abort(404)

        # アクセスログ
        if hasattr(g, "access_log"):
            g.access_log.update({
                "user_id": auth["auth_email"],
            })

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
# ゲスト認証画面
# ------------------------
@guest_bp.route("/guest_auth/<token>", methods=["GET", "POST"])
def guest_auth(token):
    error = None
    mail_address = None

    # ゲスト認証方式取得（トークンにより認証方式が異なる）
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
        # パスワード認証
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
                        "action": "ゲスト認証 OK",
                    })

                return redirect(url_for("guest.guest_download", token=token))
            else:
                # アクセスログ
                if hasattr(g, "access_log"):
                    g.access_log.update({
                        "action": "ゲスト認証 NG",
                    })

                error = "パスワードが違います"

        # メール本人確認
        elif auth_type == "mail":
            # １回目：ワンタイムパスワード送信
            if 'send_otp' in request.form:

                # 登録されているメールアドレスかチェック
                auth_emails = extract_emails(auth["auth_email"])
                mail_address = request.form.get("mail_address")
                if len(auth_emails) == 1:
                    mail_address = auth_emails[0]

                if mail_address in auth_emails:
                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "user_id": mail_address,
                            "action": "ワンタイムパスワード送信",
                        })

                    # ワンタイムパスワード生成
                    otp_code = generate_otp()
                    # テーブル登録
                    db.crud.create_otp(token, mail_address, otp_code)
                    # メール送信
                    send_otp_email(mail_address, otp_code)
                    auth_type = "otp_pass"
                else:
                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "user_id": mail_address,
                            "action": "メールアドレス入力 NG",
                        })

                    error = "このメールアドレスは登録されていません"
                    auth_type = "mail"

            # ２回目：ワンタイムパスワード検証
            else:
                mail_address = request.form.get("mail_address")
                otpcode = request.form.get("otpcode", "")
                
                if db.crud.confirm_otp(token, mail_address, otpcode):
                    if token not in authenticated_tokens:
                        authenticated_tokens.append(token)
                    session.permanent = True
                    session["authenticated_tokens"] = authenticated_tokens

                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "user_id": mail_address,
                            "action": "ゲスト認証 OK",
                        })

                    return redirect(url_for("guest.guest_download", token=token))
                else:
                    # アクセスログ
                    if hasattr(g, "access_log"):
                        g.access_log.update({
                            "user_id": mail_address,
                            "action": "ゲスト認証 NG",
                        })

                    error = "ワンタイムパスワードが正しくありません"
                    auth_type = "otp_pass"

    return render_template(
        "guest_auth.html",
        token=token,
        mail_address=mail_address,
        auth_type=auth_type,
        auth_emails=extract_emails(auth["auth_email"]),
        error=error
    )

def extract_emails(text):
    # メールアドレスの正規表現パターン
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    # findallで全ての一致をリストで取得
    return re.findall(pattern, text)

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

# ------------------------
# ゲスト向けダウンロード一覧画面
# ------------------------
@guest_bp.route("/download/<token>", methods=["GET"])
@guestauth_required
def guest_download(token):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ゲストダウンロード画面表示",
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
            "action": "ゲストファイルダウンロード",
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
# ゲスト向けファイル一括ダウンロード
# ------------------------
@guest_bp.route("/guest_download/<token>/zip", methods=["GET"])
@guestauth_required
def guest_download_zip(token):

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ゲスト一括ダウンロード",
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
                    encrypted_data = fp.read()

                # 複合化
                try:
                    decrypted_data = current_app.fernet.decrypt(encrypted_data)
                except Exception as e:
                    # 複合化失敗はスキップ
                    continue

                zf.writestr(f["original_name"], decrypted_data)

        buffer.seek(0)
        yield from buffer
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"ssend_download_{timestamp}.zip"

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
            "action": "ゲストアップロード画面表示",
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

    # テーブルがVueなのでJSONに変換
    upload_files_json = [{
        "file_id": f["file_id"],
        "original_name": f["original_name"],
        "file_size": format_filesize(f["file_size"]),
        "uploaded_at": format_datetime(f["uploaded_at"]),
        "download_url": url_for(
            "internal.download_file",
            upload_id=upload_request["id"],
            file_id=f["file_id"]
        ),
        "delete_url": url_for("internal.delete_file", file_id=f["file_id"]),
    } for f in files]

    return render_template(
        "guest_upload.html",
        upload_request=upload_request,
        files_json=json.dumps(upload_files_json),
    )

# ------------------------
# ゲスト向けファイルアップロード
# ------------------------
sigleSemaphore = threading.Semaphore(1)

@guest_bp.route("/guest_upload/<token>", methods=["POST"])
@guestauth_required
def guest_upload_file(token):

    if "file" not in request.files or len(request.files.getlist("file")) < 1:
        return "ファイルが選択されていません", 400

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "action": "ゲストファイルアップロード",
        })

    # アップロード依頼情報取得
    upload_request = db.crud.get_upload_request_by_token(token)
    if upload_request is None:
        abort(404)
    upload_id = upload_request["id"]

    # アクセスログ
    if hasattr(g, "access_log"):
        g.access_log.update({
            "upload_request_id": upload_id,
        })

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
                "file_id": file_id,
            })

    return jsonify({
        "file_id": file_id,
        "original_name": file["original_name"],
        "file_size": format_filesize(file_size),
        "uploaded_at": format_datetime(file["uploaded_at"]),
    })
