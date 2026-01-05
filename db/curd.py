import sqlite3
import uuid
from datetime import datetime, timedelta
from .connection import get_db

# ------------------------
# DB初期化
# ------------------------
def init_db(db_path):
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()

        # ------------------------
        # ユーザー情報
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_id TEXT UNIQUE,         -- ユーザーID
                name TEXT,                    -- 名前
                mail TEXT,                    -- メールアドレス
                update_flag INTEGER DEFAULT 1 -- 1=更新OK, 0=更新不可
            )
        """)

        # ------------------------
        # アップロード依頼
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS upload_requests (
                id TEXT PRIMARY KEY,          -- UUID
                upload_token TEXT UNIQUE,     -- URL用トークン
                created_by TEXT,              -- ユーザーID
                title TEXT,                   -- 件名
                expires_at TEXT,              -- 有効期限
                max_files INTEGER,            -- アップロードできるファイル数
                max_total_size INTEGER,       -- アップロードできる合計サイズ

                auth_type TEXT,
                auth_password TEXT,
                auth_email TEXT,

                created_at TEXT
            )
        """)

        # ------------------------
        # ダウンロード依頼
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS download_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_request_id TEXT,
                download_token TEXT UNIQUE,   -- URL用トークン
                expire_days INTEGER,          -- 有効日数
                expires_at TEXT,              -- 有効期限
                max_downloads INTEGER,        -- 最大ダウンロード回数

                auth_type TEXT,
                auth_password TEXT,
                auth_email TEXT,

                created_at TEXT,
                FOREIGN KEY(upload_request_id)
                    REFERENCES upload_requests(id)
            )
        """)

        # ------------------------
        # ファイル実体
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_request_id TEXT,
                file_id TEXT UNIQUE,          -- 保存用UUID
                original_name TEXT,
                file_size INTEGER,
                uploaded_at TEXT,
                uploaded_by_type TEXT,        -- internal / external
                FOREIGN KEY(upload_request_id)
                    REFERENCES upload_requests(id)
            )
        """)

        # ------------------------
        # ファイルダウンロード回数
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS download_counts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                download_request_id TEXT,
                file_id TEXT,
                download_count INTEGER DEFAULT 1,
                FOREIGN KEY(download_request_id)
                    REFERENCES download_requests(id)
                UNIQUE(download_request_id, file_id)
            )
        """)

        # ------------------------
        # ワンタイムパスワード
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT NOT NULL,
                email TEXT NOT NULL,
                otp_code TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                verified INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)

        # ------------------------
        # アクセスログ
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                -- いつ
                accessed_at TEXT NOT NULL,             -- ISO8601
                -- 誰が
                user_id TEXT,                          -- internal: login_id, guest: 'guest'

                -- 何に
                action TEXT,
                upload_request_id TEXT,
                download_request_id TEXT,
                file_id TEXT,

                -- 結果
                result TEXT NOT NULL,                  -- success / denied / expired / error
                http_status INTEGER,                   -- 200 / 403 / 404 / 500 など

                -- クライアント情報
                ip_address TEXT,
                user_agent TEXT
            )
        """)

        conn.commit()

# ------------------------
# ログインユーザ情報保存
# ------------------------
def save_login_user(login_id, name, mail):

    db = get_db()
    cur = db.cursor()

    # まず既存ユーザーをチェック
    cur.execute("SELECT * FROM users WHERE login_id = ?", (login_id,))
    row = cur.fetchone()

    if row is None:
        # 存在しなければINSERT
        cur.execute("""
            INSERT INTO users (login_id, name, mail, update_flag)
            VALUES (?, ?, ?, 1)
        """, (login_id, name, mail))
    else:
        if row["update_flag"] == 1:
            # update_flag が 1 の場合のみ更新
            cur.execute("""
                UPDATE users SET name = ?, mail = ? WHERE login_id = ?
            """, (name, mail, login_id))

    db.commit()
    return True

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
def get_upload_request_by_token(upload_token):
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
        upload_token,
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
# ゲスト認証情報取得
# ------------------------
def get_guest_auth(token):
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
# ワンタイムパスワード検索
# ------------------------
def confirm_otp(token, otp_code):

    db = get_db()
    cur = db.execute("""
        SELECT
            *
        FROM otps
        WHERE token = ? AND otp_code = ? AND verified = 0
    """, (
        token,
        otp_code,
    ))
    otp = cur.fetchone()
    if not otp:
        return None

    # 有効期限チェック
    expires_at = datetime.fromisoformat(otp["expires_at"])
    if datetime.now() > expires_at:
        return None

    # OTP を使用済みにする
    db.execute("""
        UPDATE otps
        SET verified = 1
        WHERE id = ?
    """, (otp["id"],))
    db.commit()

    return otp

# ------------------------
# ダウンロード回数取得
# ------------------------
def get_download_count(download_request_id, file_id):
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
def increment_download_count(download_request_id, file_id):

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
def get_access_logs(par_page=None, offset=0, upload_request_id=None):
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

    if par_page:
        sql += " LIMIT ? OFFSET ?"
        params.extend([par_page, offset])

    cur.execute(sql, params)
    return cur.fetchall()
