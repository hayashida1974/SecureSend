import sqlite3
from flask import g
from werkzeug.security import generate_password_hash
from paths import DB_PATH

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()

        # ------------------------
        # ユーザー情報
        # ------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login_id TEXT UNIQUE,          -- ユーザーID
                password TEXT,                 -- パスワード
                name TEXT,                     -- 名前
                mail TEXT,                     -- メールアドレス
                external TEXT,                 -- 外部ユーザー
                admin_flag INTEGER DEFAULT 0,  -- 1=管理者, 0=一般
                disabled_flag INTEGER DEFAULT 0 -- 1=利用不可, 0=利用可能
            )
        """)

        # ------------------------
        # ユーザー存在チェック
        # ------------------------
        cur.execute("""
            SELECT COUNT(*)
            FROM users
        """)
        admin_count = cur.fetchone()[0]

        # ------------------------
        # 初期管理者作成
        # ------------------------
        if admin_count == 0:
            admin_pass = generate_password_hash("ssend_admin")
            cur.execute("""
                INSERT INTO users (
                    login_id,
                    password,
                    name,
                    external,
                    disabled_flag,
                    admin_flag
                ) VALUES (?, ?, ?, '', 0, 1)
            """, (
                "ssend_admin",
                admin_pass,
                "システム管理者"
            ))

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
                    ON DELETE CASCADE
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
                    ON DELETE CASCADE
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
                    ON DELETE CASCADE
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

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

