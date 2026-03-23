import sqlite3
from flask import g
from werkzeug.security import generate_password_hash
from paths import DB_PATH

def init_db():

    def migration_1(conn):
        # ------------------------
        # ユーザー情報
        # ------------------------
        conn.execute("""
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
        cur = conn.execute("""
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
        conn.execute("""
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
        conn.execute("""
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
        conn.execute("""
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
        conn.execute("""
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
        conn.execute("""
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
        conn.execute("""
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
    
    def migration_2(conn):
        conn.execute("""
            ALTER TABLE access_logs ADD COLUMN box_name TEXT;
        """)
        conn.execute("""
            ALTER TABLE access_logs ADD COLUMN file_name TEXT;
        """)

    migrations = {
        1: migration_1,
        2: migration_2,
    }
    migrate_database(migrations)

def migrate_database(migrations):
    """
    migrations: dict[int, callable]
        key: バージョン番号
        value: 関数(conn) -> None
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()

        # 現在の user_version を取得
        cursor.execute("PRAGMA user_version")
        db_version = cursor.fetchone()[0]

        # バージョン順に並べて処理
        for version, migration in sorted(migrations.items()):
            if version <= db_version:
                continue

            try:
                # トランザクション開始
                conn.execute("BEGIN")

                # マイグレーション実行
                migration(conn)

                # user_version 更新
                cursor.execute(f"PRAGMA user_version = {version}")

                # コミット
                conn.commit()

            except Exception:
                conn.rollback()
                raise  # エラー時はロールバックして再スロー

    finally:
        conn.close()

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

