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
admin_bp = Blueprint("admin", __name__)

# ------------------------
# ユーザー管理
# ------------------------
@admin_bp.route("/admin/users", methods=["GET", "POST"])
def users():

    if request.method == "POST":
        # フォームから値取得
        login_id = request.form.get("login_id")
        name = request.form.get("name")
        mail = request.form.get("mail")
        password = request.form.get("password") or None
        admin_flag = 1 if request.form.get("admin_flag") else 0
        disabled_flag = 1 if request.form.get("disabled_flag") else 0

        # ユーザー登録
        db.crud.save_login_user(
            login_id,
            name,
            mail,
            admin_flag=admin_flag,
            disabled_flag=disabled_flag,
            password=password)

        return redirect(url_for("admin.users"))

    # GET時は一覧取得
    users = db.crud.list_users()

    return render_template("admin_users.html", users=users)

# ------------------------
# ユーザー削除
# ------------------------
@admin_bp.route("/delete/<int:user_id>")
def delete_user(user_id):

    db.crud.delete_user(user_id)
    return redirect(url_for("admin.users"))

# ------------------------
# 操作ログ
# ------------------------
@admin_bp.route("/admin/access_logs")
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
        "admin_logs.html",
        logs=logs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
    )

# ------------------------
# 設定画面
# ------------------------
@admin_bp.route("/admin/settings", methods=["GET", "POST"])
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
        "admin_settings.html",
        from_address=from_address
    )
