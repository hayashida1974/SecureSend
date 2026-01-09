import sqlite3
import uuid
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from .connection import get_db

# ------------------------
# ユーザリスト取得
# ------------------------
def list_users():
    db = get_db()
    cur = db.execute("""
        SELECT * FROM users ORDER BY id
    """)
    return cur.fetchall()

# ------------------------
# ログインユーザ情報保存
# ------------------------
def save_login_user(login_id, name, mail, external='', admin_flag=0, disabled_flag=0, password=None):

    db = get_db()
    cur = db.cursor()

    # まず既存ユーザーをチェック
    cur.execute("SELECT * FROM users WHERE login_id = ?", (login_id,))
    row = cur.fetchone()

    # パスワードが設定されていればハッシュ化
    if password:
        password = generate_password_hash(password)

    if row is None:
        # 存在しなければINSERT
        cur.execute("""
            INSERT INTO users (login_id, password, name, mail, external, admin_flag, disabled_flag)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (login_id, password, name, mail, external, admin_flag, disabled_flag))
    else:
        # 存在すればUPDATE
        fields = ["name = ?", "mail = ?", "admin_flag = ?", "disabled_flag = ?"]
        params = [name, mail, admin_flag, disabled_flag]

        if password and not external:
            fields.append("password = ?")
            params.append(password)

        params.append(login_id)
        sql = f"UPDATE users SET {', '.join(fields)} WHERE login_id = ?"
        cur.execute(sql, params)

    db.commit()
    return True

# ------------------------
# ユーザパスワード検証
# ------------------------
def confirm_password(login_id, password):
    db = get_db()
    cur = db.cursor()

    # ユーザー取得
    cur.execute(
        "SELECT password FROM users WHERE external = '' AND login_id = ? and disabled_flag = 0",
        (login_id,)
    )
    row = cur.fetchone()
    if row is None:
        return False

    hashed_password = row

    # パスワード検証
    return check_password_hash(hashed_password, password)

# ------------------------
# ユーザ削除
# ------------------------
def delete_user(id):
    db = get_db()
    db.execute("""
        DELETE FROM users WHERE id = ?
    """, (
        id,
    ))
    db.commit()

# ------------------------
# アップロード依頼生成
# ------------------------
def create_upload_request(title, expires_at, max_files, max_total_size, user_id):

    upload_request_id = str(uuid.uuid4())
    upload_token = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    db = get_db()
    db.execute("""
        INSERT INTO upload_requests (
            id,
            upload_token,
            title,
            expires_at,
            max_files,
            max_total_size,
            created_by,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        upload_request_id,
        upload_token,
        title,
        expires_at,
        max_files,
        max_total_size,
        user_id,
        created_at
    ))
    db.commit()

    return upload_request_id

# ------------------------
# アップロード依頼取得
# ------------------------
def get_upload_request(id):
    db = get_db()
    cur = db.execute("""
        SELECT
            ur.*,

            -- 期限切れ判定(1=期限切れ, 0=有効）
            CASE
                WHEN ur.expires_at IS NOT NULL
                 AND date(ur.expires_at) < date('now')
                THEN 1
                ELSE 0
            END AS is_expired
        FROM upload_requests ur
        WHERE ur.id = ?    """, (
        id,
    ))
    return cur.fetchone()

# ------------------------
# アップロード依頼取得（検索Key：upload_token）
# ------------------------
def get_upload_request_by_token(token):
    db = get_db()
    cur = db.execute("""
        SELECT
            ur.*,

            -- 期限切れ判定(1=期限切れ, 0=有効）
            CASE
                WHEN ur.expires_at IS NOT NULL
                 AND date(ur.expires_at) < date('now')
                THEN 1
                ELSE 0
            END AS is_expired
        FROM upload_requests ur
        WHERE ur.upload_token = ?
    """, (
        token,
    ))
    return cur.fetchone()

# ------------------------
# アップロード依頼リスト取得（検索Key：ユーザID）
# ------------------------
def list_upload_requests(user_id):
    db = get_db()
    cur = db.execute("""
        SELECT
            ur.*,

            -- 期限切れ判定(1=期限切れ, 0=有効）
            CASE
                WHEN ur.expires_at IS NOT NULL
                 AND date(ur.expires_at) < date('now')
                THEN 1
                ELSE 0
            END AS is_expired,

            -- アップロード済ファイル数
            (
                SELECT COUNT(*)
                FROM files f
                WHERE f.upload_request_id = ur.id
            ) AS file_count,

            -- ダウンロードURL発行数
            (
                SELECT COUNT(*)
                FROM download_requests dt
                WHERE dt.upload_request_id = ur.id
            ) AS download_url_count

        FROM upload_requests ur
        WHERE ur.created_by = ?
        ORDER BY ur.created_at DESC
    """, (
        user_id,
    ))
    return cur.fetchall()

# ------------------------
# アップロード依頼削除
# ------------------------
def delete_upload_request(upload_id):
    db = get_db()
    db.execute("""
        DELETE FROM upload_requests WHERE id = ?
    """, (
        upload_id,
    ))
    db.commit()

# ------------------------
# ファイル生成
# ------------------------
def create_file(upload_request_id, file_id, original_name, file_size):

    uploaded_at = datetime.now().isoformat()

    db = get_db()
    db.execute("""
        INSERT INTO files (
            upload_request_id,
            file_id,
            original_name,
            file_size,
            uploaded_at
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        upload_request_id,
        file_id,
        original_name,
        file_size,
        uploaded_at
    ))
    db.commit()

# ------------------------
# ファイル取得
# ------------------------
def get_file(file_id):
    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM files
        WHERE file_id = ?
    """, (
        file_id,
    ))
    return cur.fetchone()

# ------------------------
# ファイルリスト取得（検索Key：upload_request_id）
# ------------------------
def list_files(upload_id):
    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM files
        WHERE upload_request_id = ?
        ORDER BY uploaded_at
    """, (
        upload_id,
    ))
    return cur.fetchall()

# ------------------------
# ファイル削除
# ------------------------
def delete_file(file_id):
    db = get_db()
    db.execute("""
        DELETE FROM files WHERE file_id = ?
    """, (
        file_id,
    ))
    db.commit()

# ------------------------
# ダウンロード依頼生成
# ------------------------
def create_download_request(upload_request_id, expire_days, max_downloads, auth_type, auth_password, auth_email):

    download_token = str(uuid.uuid4())
    created_at = datetime.now().isoformat()

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO download_requests (
            download_token,
            upload_request_id,
            expire_days,
            max_downloads,
            auth_type,
            auth_password,
            auth_email,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        download_token,
        upload_request_id,
        expire_days,
        max_downloads,
        auth_type,
        auth_password,
        auth_email,
        created_at
    ))

    inserted_id = cur.lastrowid
    db.commit()

    return inserted_id

# ------------------------
# ダウンロード依頼有効期限更新
# ------------------------
def update_download_expires(download_token):

    db = get_db()

    # expire_days を取得（まだ expires_at が未設定のものだけ）
    row = db.execute("""
        SELECT id, expire_days
        FROM download_requests
        WHERE download_token = ?
          AND expires_at IS NULL
    """, (download_token,)).fetchone()

    if row is None:
        return  # すでに設定済み or 存在しない

    expire_days = row["expire_days"]
    if expire_days is None:
        return  # 有効期限なし仕様なら何もしない

    expires_at = (datetime.now() + timedelta(days=expire_days)).isoformat()

    db.execute("""
        UPDATE download_requests
        SET expires_at = ?
        WHERE id = ?
    """, (expires_at, row["id"]))

    db.commit()

# ------------------------
# ダウンロード依頼情報取得
# ------------------------
def get_download_request(id):
    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM download_requests
        WHERE id = ?
    """, (
        id,
    ))
    return cur.fetchone()

# ------------------------
# ダウンロード依頼情報取得
# ------------------------
def get_download_request_by_token(token):
    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM download_requests
        WHERE download_token = ?
    """, (
        token,
    ))
    return cur.fetchone()

# ------------------------
# ダウンロード依頼リスト取得（検索Key：upload_request_id）
# ------------------------
def list_download_requests(upload_id):
    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM download_requests
        WHERE upload_request_id = ?
        ORDER BY created_at DESC
    """, (
        upload_id,
    ))
    return cur.fetchall()

# ------------------------
# ダウンロード依頼削除
# ------------------------
def delete_download_request(download_id):
    db = get_db()
    db.execute("""
        DELETE FROM download_requests WHERE id = ?
    """, (
        download_id,
    ))
    db.commit()

# ------------------------
# ゲスト認証情報取得
# ------------------------
def find_guest_auth(token):
    db = get_db()
    cur = db.execute("""
        SELECT
            'upload' AS token_type,
            upload_token AS token,
            expires_at,
            auth_type,
            auth_password,
            auth_email,
            id as upload_request_id
        FROM upload_requests
        WHERE upload_token = ?
          AND date(expires_at) >= date('now')

        UNION ALL

        SELECT
            'download' AS token_type,
            download_token AS token,
            expires_at,
            auth_type,
            auth_password,
            auth_email,
            upload_request_id as upload_request_id
        FROM download_requests
        WHERE download_token = ?
          AND (
                expires_at IS NULL
                OR datetime(expires_at) >= datetime('now')
              )

        LIMIT 1
    """, (token, token))

    return cur.fetchone()

# ------------------------
# ワンタイムパスワード挿入
# ------------------------
def create_otp(token, email, otp_code, expire_min = 10):

    # ワンタイムパスワードハッシュ化
    otp_code = generate_password_hash(otp_code)

    # 現在時刻
    created_at = datetime.now()
    # 有効期限をexpire_min分後に設定
    expires_at = created_at + timedelta(minutes=expire_min)

    # ISO形式に変換して保存
    created_at_str = created_at.isoformat()
    expires_at_str = expires_at.isoformat()

    db = get_db()
    db.execute("""
        INSERT INTO otps (
            token,
            email,
            otp_code,
            expires_at,
            created_at
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        token,
        email,
        otp_code,
        expires_at,
        created_at
    ))
    db.commit()

    return db.execute("SELECT last_insert_rowid()").fetchone()[0]

# ------------------------
# ワンタイムパスワード検証
# ------------------------
def confirm_otp(token, email, otp_code):

    db = get_db()
    row = db.execute("""
        SELECT id, otp_code, expires_at
        FROM otps
        WHERE token = ?
          AND email = ?
          AND verified = 0
        ORDER BY created_at DESC
        LIMIT 1
    """, (token, email)).fetchone()

    if row is None:
        return False

    if datetime.now() > datetime.fromisoformat(row["expires_at"]):
        db.execute(
            "UPDATE otps SET verified = 1 WHERE id = ?",
            (row["id"],)
        )
        db.commit()
        return False

    if not check_password_hash(row["otp_code"], otp_code):
        return False

    db.execute(
        "UPDATE otps SET verified = 1 WHERE id = ?",
        (row["id"],)
    )
    db.commit()

    return True

# ------------------------
# ダウンロード回数取得
# ------------------------
def get_file_download_count(download_request_id, file_id):
    db = get_db()
    cur = db.execute(
        """
        SELECT download_count
        FROM download_counts
        WHERE download_request_id = ?
          AND file_id = ?
        """,
        (download_request_id, file_id)
    )
    row = cur.fetchone()
    return row["download_count"] if row else 0

# ------------------------
# ダウンロード回数インクリメント
# ------------------------
def increment_file_download_count(download_request_id, file_id):

    db = get_db()
    db.execute(
        """
        INSERT INTO download_counts (
            download_request_id,
            file_id,
            download_count
        )
        VALUES (?, ?, 1)
        ON CONFLICT(download_request_id, file_id)
        DO UPDATE SET
            download_count = download_count + 1
        """,
        (download_request_id, file_id)
    )
    db.commit()

# ------------------------
# アクセスログ保存
# ------------------------
def save_access_log(log: dict):
    try:
        db = get_db()
        db.execute(
            """
            INSERT INTO access_logs (
                accessed_at,
                user_id,
                action,
                upload_request_id,
                download_request_id,
                file_id,
                result,
                http_status,
                ip_address,
                user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log.get("accessed_at"),
                log.get("user_id"),
                log.get("action"),
                log.get("upload_request_id"),
                log.get("download_request_id"),
                log.get("file_id"),
                log.get("result"),
                log.get("http_status"),
                log.get("ip_address"),
                log.get("user_agent"),
            ),
        )

        db.commit()
    except Exception:
        # ログ失敗は業務処理に影響させない
        pass

# ------------------------
# アクセスログ取得
# ------------------------
def list_access_logs(per_page=None, offset=0, upload_request_id=None):
    db = get_db()
    cur = db.cursor()

    sql = """
        SELECT
            al.*,

            (
                SELECT ur.title
                FROM upload_requests ur
                WHERE ur.id = al.upload_request_id
            ) AS upload_request,

            (
                SELECT dr.auth_type
                FROM download_requests dr
                WHERE dr.id = al.download_request_id
            ) AS download_request,

            (
                SELECT f.original_name
                FROM files f
                WHERE f.file_id = al.file_id
            ) AS file
        FROM access_logs al
    """

    params = []

    if upload_request_id:
        sql += " WHERE al.upload_request_id = ?"
        params.append(upload_request_id)

    sql += " ORDER BY al.accessed_at DESC"

    if per_page:
        sql += " LIMIT ? OFFSET ?"
        params.extend([per_page, offset])

    cur.execute(sql, params)
    return cur.fetchall()
