import os
import sqlite3
import json
import uuid
import logging
import hmac
import hashlib
import secrets
import math
import calendar
import re
import qrcode
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, flash, render_template, request, redirect, url_for, session, send_from_directory, abort, g
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
# パスワードをハッシュ化
from werkzeug.security import generate_password_hash, check_password_hash
# 画像実体検証
from PIL import Image

load_dotenv(encoding='utf-8-sig')

# YOLOv8をインポート
try:
    from ultralytics import YOLO
except ImportError:
    YOLO = None

app = Flask(__name__)


def _internal_error_response():
    return render_template(
        'error.html',
        title='内部サーバーエラー',
        message='サーバーでエラーが発生しました。時間をおいて再度お試しください。',
    ), 500


@app.errorhandler(500)
def handle_internal_server_error(error):
    original_exception = getattr(error, 'original_exception', None)
    if original_exception is not None:
        app.logger.error(
            "未処理の内部サーバーエラー",
            exc_info=(
                type(original_exception),
                original_exception,
                original_exception.__traceback__,
            ),
        )
    return _internal_error_response()


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_ENV = os.environ.get('CLEANSTEP_ENV', 'development').strip().lower()

# 画像アップロードの最大サイズを5MBに制限
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# セッションキーの安全化
SECRET_KEY_ENV = (os.environ.get('CLEANSTEP_SECRET_KEY') or '').strip()
if not SECRET_KEY_ENV and APP_ENV in {'production', 'staging'}:
    raise RuntimeError(
        "CLEANSTEP_ENVがproduction/stagingの場合は"
        "CLEANSTEP_SECRET_KEYが必須です。"
    )
app.secret_key = SECRET_KEY_ENV or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=APP_ENV in {'production', 'staging'},
    SESSION_COOKIE_SAMESITE='Lax',
    TEMPLATES_AUTO_RELOAD=True,
)

def resolve_configured_path(value, default):
    path = value or default
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return os.path.abspath(path)

DATABASE = resolve_configured_path(
    os.environ.get('CLEANSTEP_DATABASE_PATH'), 'database.db'
)
UPLOAD_FOLDER = resolve_configured_path(
    os.environ.get('CLEANSTEP_UPLOAD_FOLDER'), os.path.join('data', 'uploads')
)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db_dir = os.path.dirname(DATABASE)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

EVENT_CATEGORIES = (
    'まち・道路清掃',
    '公園・河川清掃',
    '海岸清掃',
    'リサイクル・分別',
    '環境学習・交流',
    'その他',
)

EVENT_CATEGORY_KEYWORDS = (
    ('海岸清掃', ('海岸', 'ビーチ', '海辺', '浜辺', '海岸清掃')),
    ('公園・河川清掃', ('公園', '河川', '川辺', '河川敷', '水辺')),
    ('リサイクル・分別', ('リサイクル', '分別', '資源回収', '資源ごみ')),
    ('環境学習・交流', ('ワークショップ', '環境学習', '環境教育', '講座', '交流会')),
    ('まち・道路清掃', ('道路', '街なか', 'まち清掃', 'ごみ拾い', 'ゴミ拾い', '清掃', 'クリーン', '美化')),
)


def suggest_event_category(*values):
    text = ' '.join(str(value or '') for value in values).casefold()
    for category, keywords in EVENT_CATEGORY_KEYWORDS:
        if any(keyword.casefold() in text for keyword in keywords):
            return category
    return 'その他'


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# データベース接続と自動マイグレーション

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    # 外部キー制約を強制有効化
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _create_user_notifications_table(conn):
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            event_id INTEGER,
            notification_type TEXT NOT NULL CHECK(notification_type IN (
                'reminder', 'organizer_message', 'cancellation',
                'event_added', 'reservation', 'reservation_cancelled',
                'activity_completed'
            )),
            title TEXT NOT NULL,
            message TEXT NOT NULL CHECK(length(message) <= 1000),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            read_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE SET NULL
        )
    ''')


def _notify_all_users_of_new_event(conn, event_id):
    event = conn.execute('''
        SELECT name, location, datetime
        FROM events
        WHERE id = ? AND status = 'open' AND review_status = 'approved'
    ''', (event_id,)).fetchone()
    if event is None:
        return

    conn.execute('''
        INSERT INTO user_notifications (
            user_id, event_id, notification_type, title, message
        )
        SELECT id, ?, 'event_added', ?, ?
        FROM users
        WHERE role = 'user'
    ''', (
        event_id,
        f'新しいイベント：{event["name"]}',
        f'開催日時：{event["datetime"]}\n開催場所：{event["location"]}',
    ))


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def _auth_rate_key(kind, subject=''):
    value = f"{kind}|{request.remote_addr or 'unknown'}|{subject}"
    return hmac.new(
        app.secret_key.encode('utf-8'),
        value.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def _auth_attempt_count(conn, rate_key, window_minutes=15):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).isoformat()
    return conn.execute(
        'SELECT COUNT(*) FROM auth_rate_limits WHERE rate_key = ? AND attempted_at >= ?',
        (rate_key, cutoff),
    ).fetchone()[0]


def _record_auth_attempt(conn, rate_key):
    now = datetime.now(timezone.utc)
    retention_cutoff = (now - timedelta(days=1)).isoformat()
    conn.execute(
        'DELETE FROM auth_rate_limits WHERE attempted_at < ?',
        (retention_cutoff,),
    )
    conn.execute(
        'INSERT INTO auth_rate_limits (rate_key, attempted_at) VALUES (?, ?)',
        (rate_key, now.isoformat()),
    )
    conn.commit()


def _clear_auth_attempts(conn, rate_key):
    conn.execute('DELETE FROM auth_rate_limits WHERE rate_key = ?', (rate_key,))
    conn.commit()


def get_user_organization_id(conn, user_id):
    membership = conn.execute('''
        SELECT om.organization_id
        FROM organization_members om
        JOIN organizations o ON o.id = om.organization_id
        WHERE om.user_id = ? AND om.status = 'active'
            AND o.status = 'approved'
        ORDER BY CASE om.role WHEN 'owner' THEN 0 ELSE 1 END, om.id DESC
        LIMIT 1
    ''', (user_id,)).fetchone()
    return membership['organization_id'] if membership else None


JST = timezone(timedelta(hours=9))
EVENT_MIN_DURATION_SECONDS = 15 * 60
EVENT_MAX_SESSION_DURATION_SECONDS = 12 * 60 * 60
EVENT_LOCATION_RADIUS_METERS = 200
MAX_GPS_WALK_SPEED_MPS = 3.0
MAX_DEVICE_STEPS_PER_SECOND = 4.0
MAX_STEP_STRIDE_M = 1.8
MIN_STEP_DISTANCE_RATIO = 0.5
GPS_ESTIMATED_STEP_LENGTH_M = 0.75


def parse_event_datetime(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=JST)
    return parsed.astimezone(JST)


def haversine_m(a, b):
    earth_radius_m = 6371000
    lat1, lon1 = math.radians(a['lat']), math.radians(a['lon'])
    lat2, lon2 = math.radians(b['lat']), math.radians(b['lon'])
    lat_delta = lat2 - lat1
    lon_delta = lon2 - lon1
    arc = (
        math.sin(lat_delta / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(lon_delta / 2) ** 2
    )
    return 2 * earth_radius_m * math.asin(math.sqrt(min(1, arc)))


def calculate_gps_metrics(raw_points, started_at, now):
    if not isinstance(raw_points, list) or len(raw_points) > 5000:
        raise ValueError('GPSデータの形式または件数が正しくありません。')

    started_epoch = started_at.timestamp()
    now_epoch = now.timestamp()
    accurate_points = []
    validated_points = []
    previous_timestamp = None
    for point in raw_points:
        if not isinstance(point, dict):
            raise ValueError('GPSデータの形式が正しくありません。')
        try:
            lat = float(point['lat'])
            lon = float(point['lon'])
            accuracy = float(point['accuracy'])
            timestamp = float(point['ts']) / 1000
        except (KeyError, TypeError, ValueError, OverflowError):
            raise ValueError('GPSデータの形式が正しくありません。') from None
        if not all(math.isfinite(value) for value in (lat, lon, accuracy, timestamp)):
            raise ValueError('GPSデータに不正な数値が含まれています。')
        if not (-90 <= lat <= 90 and -180 <= lon <= 180 and accuracy >= 0):
            raise ValueError('GPS座標または精度が許容範囲外です。')
        if timestamp < started_epoch - 120 or timestamp > now_epoch + 10:
            raise ValueError('GPSデータの時刻が計測時間外です。')
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise ValueError('GPSデータの時刻順が正しくありません。')
        previous_timestamp = timestamp
        validated_points.append({
            'lat': lat,
            'lon': lon,
            'accuracy': accuracy,
            'timestamp': timestamp,
        })
        if accuracy < 30:
            accurate_points.append({
                'lat': lat,
                'lon': lon,
                'timestamp': timestamp,
            })

    distance_m = sum(
        haversine_m(previous, current)
        for previous, current in zip(accurate_points, accurate_points[1:])
    )

    if len(accurate_points) < 2:
        return {
            'steps': 0, 'distance': 0.0, 'calories': 0,
            'gps_measured': False, 'validated_points': validated_points,
        }

    duration_seconds = (now - started_at).total_seconds()
    if duration_seconds <= 0 or distance_m / duration_seconds > MAX_GPS_WALK_SPEED_MPS:
        return {
            'steps': 0, 'distance': 0.0, 'calories': 0,
            'gps_measured': False, 'validated_points': validated_points,
        }
    return {
        'steps': int(distance_m / GPS_ESTIMATED_STEP_LENGTH_M),
        'distance': distance_m / 1000,
        'calories': round(3.5 * 70 * duration_seconds / 3600),
        'gps_measured': True,
        'validated_points': validated_points,
    }


def init_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with closing(conn), conn:
        # （中のテーブル作成・マイグレーション処理はそのまま）
        # 1. ユーザーテーブルの作成と不足列の追加
        user_columns = [row['name'] for row in conn.execute('PRAGMA table_info(users)').fetchall()]
        login_destination_added = False
        if 'today_points' in user_columns:
            login_destination_added = 'login_destination' not in user_columns
            app.logger.warning(
                "users.today_points は旧列として保持し、テーブル再構築による"
                "データ消失や外部キー参照の変更を避けます。"
            )

        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone():
            conn.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    password TEXT,
                    name TEXT,
                    role TEXT,
                    total_points INTEGER DEFAULT 0 CHECK(total_points >= 0),
                    login_destination TEXT NOT NULL DEFAULT 'user'
                        CHECK(login_destination IN ('user', 'organizer'))
                )
            ''')
        # 2. イベントテーブルの作成
        user_columns = [
            row['name'] for row in conn.execute('PRAGMA table_info(users)').fetchall()
        ]
        if 'login_destination' not in user_columns:
            login_destination_added = True
            conn.execute('''
                ALTER TABLE users ADD COLUMN login_destination TEXT NOT NULL
                    DEFAULT 'user'
                    CHECK(login_destination IN ('user', 'organizer'))
            ''')
        if 'onboarding_completed' not in user_columns:
            conn.execute('''
                ALTER TABLE users ADD COLUMN onboarding_completed INTEGER NOT NULL
                    DEFAULT 0 CHECK(onboarding_completed IN (0, 1))
            ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rate_key TEXT NOT NULL,
                attempted_at TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_key_time
            ON auth_rate_limits(rate_key, attempted_at)
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                location TEXT,
                datetime TEXT,
                bonus_points INTEGER,
                organizer_id INTEGER,
                capacity INTEGER NOT NULL DEFAULT 20 CHECK(capacity >= 1),
                status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'cancelled')),
                review_status TEXT NOT NULL DEFAULT 'approved'
                    CHECK(review_status IN ('pending', 'reviewing', 'changes_requested', 'approved', 'rejected')),
                review_comment TEXT,
                reviewed_by INTEGER REFERENCES users(id),
                reviewed_at TEXT,
                category TEXT NOT NULL DEFAULT 'その他',
                FOREIGN KEY (organizer_id) REFERENCES users(id)
            )
        ''')

        event_cols = [row['name'] for row in conn.execute('PRAGMA table_info(events)').fetchall()]
        if 'organizer_id' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN organizer_id INTEGER REFERENCES users(id)')
        if 'latitude' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN latitude REAL')
        if 'longitude' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN longitude REAL')
        if 'capacity' not in event_cols:
            conn.execute(
                'ALTER TABLE events ADD COLUMN capacity INTEGER NOT NULL DEFAULT 20'
            )
        if 'status' not in event_cols:
            conn.execute("ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'cancelled'))")
        if 'review_status' not in event_cols:
            conn.execute("""
                ALTER TABLE events ADD COLUMN review_status TEXT NOT NULL
                DEFAULT 'approved'
                CHECK(review_status IN ('pending', 'reviewing', 'changes_requested', 'approved', 'rejected'))
            """)
        if 'review_comment' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN review_comment TEXT')
        if 'reviewed_by' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN reviewed_by INTEGER REFERENCES users(id)')
        if 'reviewed_at' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN reviewed_at TEXT')
        if 'reward_details' not in event_cols:
            conn.execute('ALTER TABLE events ADD COLUMN reward_details TEXT')
        if 'category' not in event_cols:
            conn.execute(
                "ALTER TABLE events ADD COLUMN category TEXT NOT NULL DEFAULT 'その他'"
            )
            for event in conn.execute(
                'SELECT id, name, location, reward_details FROM events'
            ).fetchall():
                conn.execute(
                    'UPDATE events SET category = ? WHERE id = ?',
                    (
                        suggest_event_category(
                            event['name'], event['location'],
                            event['reward_details'],
                        ),
                        event['id'],
                    ),
                )
        if 'purpose_issue' not in event_cols:
            conn.execute(
                "ALTER TABLE events ADD COLUMN purpose_issue TEXT NOT NULL DEFAULT ''"
            )
        conn.execute('CREATE INDEX IF NOT EXISTS idx_events_review_status_datetime ON events(review_status, datetime)')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS event_reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'reserved'
                    CHECK(status IN ('reserved', 'cancelled', 'completed')),
                participant_role TEXT NOT NULL DEFAULT 'ごみ回収・分別',
                reserved_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                UNIQUE(user_id, event_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        ''')
        reservation_cols = [
            row['name'] for row in conn.execute('PRAGMA table_info(event_reservations)').fetchall()
        ]
        if 'participant_role' not in reservation_cols:
            conn.execute(
                "ALTER TABLE event_reservations ADD COLUMN participant_role TEXT NOT NULL DEFAULT 'ごみ回収・分別'"
            )
        conn.execute('CREATE INDEX IF NOT EXISTS idx_event_reservations_event_status ON event_reservations(event_id, status)')

        notification_table = conn.execute('''
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'user_notifications'
        ''').fetchone()
        required_notification_types = (
            'event_added', 'reservation', 'reservation_cancelled',
            'activity_completed',
        )
        if notification_table and (
            not all(
                f"'{notification_type}'" in notification_table['sql']
                for notification_type in required_notification_types
            )
            or 'ON DELETE SET NULL' not in notification_table['sql'].upper()
        ):
            conn.execute('DROP INDEX IF EXISTS idx_user_notifications_reminder_once')
            conn.execute('DROP INDEX IF EXISTS idx_user_notifications_user_unread')
            conn.execute(
                'ALTER TABLE user_notifications RENAME TO user_notifications_legacy'
            )
            _create_user_notifications_table(conn)
            conn.execute('''
                INSERT INTO user_notifications (
                    id, user_id, event_id, notification_type, title, message,
                    created_at, read_at
                )
                SELECT id, user_id, event_id, notification_type, title, message,
                       created_at, read_at
                FROM user_notifications_legacy
            ''')
            conn.execute('DROP TABLE user_notifications_legacy')
        else:
            _create_user_notifications_table(conn)
        conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_user_notifications_reminder_once
            ON user_notifications(user_id, event_id, notification_type)
            WHERE notification_type = 'reminder'
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_user_notifications_user_unread
            ON user_notifications(user_id, read_at, created_at)
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS trash_bins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL,
                lat REAL NOT NULL CHECK(lat >= -90 AND lat <= 90),
                lng REAL NOT NULL CHECK(lng >= -180 AND lng <= 180),
                waste_types TEXT NOT NULL DEFAULT 'ペットボトル・カップ・容器',
                bin_status TEXT NOT NULL DEFAULT 'active'
                    CHECK(bin_status IN ('active', 'full_reported', 'maintenance')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        bin_cols = [
            row['name']
            for row in conn.execute('PRAGMA table_info(trash_bins)').fetchall()
        ]
        if 'waste_types' not in bin_cols:
            conn.execute(
                "ALTER TABLE trash_bins ADD COLUMN waste_types TEXT NOT NULL DEFAULT 'ペットボトル・カップ・容器'"
            )
        if 'bin_status' not in bin_cols:
            conn.execute(
                "ALTER TABLE trash_bins ADD COLUMN bin_status TEXT NOT NULL DEFAULT 'active'"
            )

        conn.execute('''
            CREATE TABLE IF NOT EXISTS issue_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL CHECK(latitude IS NULL OR (latitude >= -90 AND latitude <= 90)),
                longitude REAL CHECK(longitude IS NULL OR (longitude >= -180 AND longitude <= 180)),
                trash_type TEXT NOT NULL DEFAULT 'ペットボトル・飲料容器',
                severity TEXT NOT NULL DEFAULT 'medium'
                    CHECK(severity IN ('low', 'medium', 'high')),
                description TEXT,
                image_path TEXT,
                ai_detected_count INTEGER,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK(status IN ('open', 'in_progress', 'resolved')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_issue_reports_status_created
            ON issue_reports(status, created_at DESC)
        ''')
        issue_cols = [
            row['name'] for row in conn.execute('PRAGMA table_info(issue_reports)').fetchall()
        ]
        if 'action_note' not in issue_cols:
            conn.execute(
                "ALTER TABLE issue_reports ADD COLUMN action_note TEXT NOT NULL DEFAULT ''"
            )
        if 'reviewed_by' not in issue_cols:
            conn.execute(
                'ALTER TABLE issue_reports ADD COLUMN reviewed_by INTEGER REFERENCES users(id)'
            )
        if 'reviewed_at' not in issue_cols:
            conn.execute('ALTER TABLE issue_reports ADD COLUMN reviewed_at TEXT')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS improvement_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                author_role TEXT NOT NULL DEFAULT 'user'
                    CHECK(author_role IN ('user', 'organizer', 'admin')),
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                proposal_type TEXT NOT NULL DEFAULT 'ごみ箱の増設・配置見直し',
                issue_report_id INTEGER REFERENCES issue_reports(id) ON DELETE SET NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'proposed'
                    CHECK(status IN ('proposed', 'under_review', 'adopted', 'completed')),
                support_count INTEGER NOT NULL DEFAULT 0,
                admin_comment TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS improvement_proposal_supports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proposal_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(proposal_id, user_id),
                FOREIGN KEY (proposal_id) REFERENCES improvement_proposals(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS organizer_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                organization_name TEXT NOT NULL,
                contact TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'approved', 'rejected')),
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (reviewed_by) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id INTEGER NOT NULL UNIQUE,
                name TEXT NOT NULL,
                contact TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'approved'
                    CHECK(status IN ('approved', 'suspended')),
                approved_by INTEGER,
                approved_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (application_id) REFERENCES organizer_applications(id),
                FOREIGN KEY (approved_by) REFERENCES users(id)
            )
        ''')
        application_cols = [
            row['name']
            for row in conn.execute(
                'PRAGMA table_info(organizer_applications)'
            ).fetchall()
        ]
        if 'organization_id' not in application_cols:
            conn.execute(
                'ALTER TABLE organizer_applications '
                'ADD COLUMN organization_id INTEGER REFERENCES organizations(id)'
            )

        conn.execute('''
            CREATE TABLE IF NOT EXISTS organization_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL DEFAULT 'owner'
                    CHECK(role IN ('owner', 'event_manager')),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active', 'inactive')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(organization_id, user_id),
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_organization_members_user_status
            ON organization_members(user_id, status)
        ''')

        approved_applications = conn.execute('''
            SELECT * FROM organizer_applications
            WHERE status = 'approved'
            ORDER BY id
        ''').fetchall()
        for application in approved_applications:
            conn.execute('''
                INSERT INTO organizations (
                    application_id, name, contact, purpose, approved_by,
                    approved_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(application_id) DO NOTHING
            ''', (
                application['id'], application['organization_name'],
                application['contact'], application['purpose'],
                application['reviewed_by'], application['reviewed_at'],
            ))
            organization = conn.execute('''
                SELECT id FROM organizations WHERE application_id = ?
            ''', (application['id'],)).fetchone()
            conn.execute('''
                UPDATE organizer_applications SET organization_id = ?
                WHERE id = ? AND organization_id IS NULL
            ''', (organization['id'], application['id']))
            conn.execute('''
                INSERT OR IGNORE INTO organization_members (
                    organization_id, user_id, role
                ) VALUES (?, ?, 'owner')
            ''', (organization['id'], application['user_id']))

        if login_destination_added:
            conn.execute('''
            UPDATE users
            SET login_destination = 'organizer'
            WHERE EXISTS (
                SELECT 1
                FROM organization_members om
                JOIN organizations o ON o.id = om.organization_id
                WHERE om.user_id = users.id
                  AND om.status = 'active' AND o.status = 'approved'
            )
            ''')

        event_cols = [
            row['name'] for row in conn.execute('PRAGMA table_info(events)').fetchall()
        ]
        if 'organization_id' not in event_cols:
            conn.execute(
                'ALTER TABLE events '
                'ADD COLUMN organization_id INTEGER REFERENCES organizations(id)'
            )
        conn.execute('''
            UPDATE events
            SET organization_id = (
                SELECT a.organization_id
                FROM organizer_applications a
                WHERE a.user_id = events.organizer_id
                    AND a.status = 'approved'
                    AND a.organization_id IS NOT NULL
                ORDER BY a.id DESC
                LIMIT 1
            )
            WHERE organization_id IS NULL AND organizer_id IS NOT NULL
        ''')

        conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_organizer_one_pending
            ON organizer_applications(user_id) WHERE status = 'pending'
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_organizer_application_status ON organizer_applications(status, created_at)')

        # 3. 活動履歴テーブル
        conn.execute('''
            CREATE TABLE IF NOT EXISTS activity_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_id INTEGER DEFAULT NULL,
                type TEXT, 
                title TEXT,
                trash_count INTEGER DEFAULT 0,
                ai_detected_count INTEGER DEFAULT 0,
                user_declared_count INTEGER DEFAULT 0,
                points_earned INTEGER,
                steps INTEGER DEFAULT 0,
                duration INTEGER DEFAULT 0,
                distance REAL DEFAULT 0.0,
                calories INTEGER DEFAULT 0,
                gps_measured INTEGER NOT NULL DEFAULT 0
                    CHECK(gps_measured IN (0, 1)),
                step_source TEXT NOT NULL DEFAULT 'unmeasured'
                    CHECK(step_source IN ('device', 'gps_estimated', 'unmeasured')),
                detox_duration INTEGER DEFAULT 0,
                date TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, event_id), -- イベント参加の重複完了を防止
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (event_id) REFERENCES events(id) -- 🔒 参照整合性の確保
            )
        ''')

        # イベント参加後の任意アンケート。参加記録ごとに1回答に制限する。
        conn.execute('''
            CREATE TABLE IF NOT EXISTS event_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_id INTEGER NOT NULL UNIQUE,
                user_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                satisfaction INTEGER NOT NULL CHECK(satisfaction BETWEEN 1 AND 5),
                time_fit TEXT NOT NULL
                    CHECK(time_fit IN ('short', 'just_right', 'long')),
                next_participation TEXT NOT NULL
                    CHECK(next_participation IN ('yes', 'maybe', 'no')),
                comment TEXT NOT NULL DEFAULT '' CHECK(length(comment) <= 500),
                action_status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(action_status IN ('pending', 'planned', 'addressed', 'not_planned')),
                action_note TEXT NOT NULL DEFAULT '' CHECK(length(action_note) <= 500),
                reviewed_by INTEGER REFERENCES users(id),
                reviewed_at TEXT,
                submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (activity_id) REFERENCES activity_history(id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        ''')

        feedback_cols = {
            row['name'] for row in conn.execute('PRAGMA table_info(event_feedback)')
        }
        feedback_migrations = {
            'action_status': (
                "TEXT NOT NULL DEFAULT 'pending' "
                "CHECK(action_status IN ('pending', 'planned', 'addressed', 'not_planned'))"
            ),
            'action_note': "TEXT NOT NULL DEFAULT '' CHECK(length(action_note) <= 500)",
            'reviewed_by': 'INTEGER REFERENCES users(id)',
            'reviewed_at': 'TEXT',
            'noticed_issue': "TEXT NOT NULL DEFAULT ''",
            'suspected_cause': "TEXT NOT NULL DEFAULT ''",
            'collaboration_note': "TEXT NOT NULL DEFAULT ''",
            'next_improvement': "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in feedback_migrations.items():
            if column not in feedback_cols:
                conn.execute(
                    f'ALTER TABLE event_feedback ADD COLUMN {column} {definition}'
                )

        activity_cols = {
            row['name']
            for row in conn.execute('PRAGMA table_info(activity_history)')
        }
        if 'id' not in activity_cols:
            raise RuntimeError(
                'activity_historyに主キーidがありません。データを保全するため自動移行を中断しました。'
            )
        activity_column_migrations = {
            'user_id': 'INTEGER REFERENCES users(id)',
            'event_id': 'INTEGER DEFAULT NULL REFERENCES events(id)',
            'type': 'TEXT',
            'title': 'TEXT',
            'trash_count': 'INTEGER DEFAULT 0',
            'ai_detected_count': 'INTEGER DEFAULT 0',
            'user_declared_count': 'INTEGER DEFAULT 0',
            'points_earned': 'INTEGER DEFAULT 0',
            'steps': 'INTEGER DEFAULT 0',
            'duration': 'INTEGER DEFAULT 0',
            'distance': 'REAL DEFAULT 0.0',
            'calories': 'INTEGER DEFAULT 0',
            'gps_measured': (
                'INTEGER NOT NULL DEFAULT 0 CHECK(gps_measured IN (0, 1))'
            ),
            'step_source': (
                "TEXT NOT NULL DEFAULT 'unmeasured' "
                "CHECK(step_source IN ('device', 'gps_estimated', 'unmeasured'))"
            ),
            'detox_duration': 'INTEGER DEFAULT 0',
            'date': 'TEXT',
            'trash_category': "TEXT NOT NULL DEFAULT 'ペットボトル・飲料容器'",
            'bag_size': "TEXT NOT NULL DEFAULT '手持ち・少量（1〜3個）'",
            'participant_role': "TEXT NOT NULL DEFAULT ''",
            'before_state': "TEXT NOT NULL DEFAULT ''",
            'after_state': "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in activity_column_migrations.items():
            if column not in activity_cols:
                conn.execute(
                    f'ALTER TABLE activity_history ADD COLUMN {column} {definition}'
                )
        conn.execute('''
            UPDATE activity_history
            SET date = CURRENT_TIMESTAMP
            WHERE date IS NULL
        ''')
        duplicate_event_rows = conn.execute('''
            SELECT COUNT(*) FROM (
                SELECT user_id, event_id
                FROM activity_history
                WHERE event_id IS NOT NULL
                GROUP BY user_id, event_id
                HAVING COUNT(*) > 1
            )
        ''').fetchone()[0]
        if duplicate_event_rows:
            app.logger.error(
                'activity_historyに同一ユーザー・イベントの重複記録が%d組あります。'
                'データを保持するため一意制約の移行を中断しました。',
                duplicate_event_rows,
            )
            raise RuntimeError(
                'activity_historyのイベント重複記録を確認してください。'
                '既存データは変更していません。'
            )
        has_unique_user_event_index = False
        for index in conn.execute('PRAGMA index_list(activity_history)'):
            if not index['unique']:
                continue
            indexed_columns = tuple(
                row['name']
                for row in conn.execute(
                    'SELECT name FROM pragma_index_info(?) ORDER BY seqno',
                    (index['name'],),
                )
            )
            if indexed_columns == ('user_id', 'event_id'):
                has_unique_user_event_index = True
                break
        if not has_unique_user_event_index:
            conn.execute('''
                CREATE UNIQUE INDEX idx_activity_history_user_event
                ON activity_history(user_id, event_id)
            ''')

        # 4. AI判定ログテーブル
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ai_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                activity_id INTEGER,
                detected_count INTEGER,
                confidence REAL,
                image_path TEXT,
                image_sha256 TEXT,
                is_flagged INTEGER DEFAULT 0,
                flag_reason TEXT,
                result_status TEXT NOT NULL DEFAULT 'detected'
                    CHECK(result_status IN ('detected', 'no_detection', 'failed')),
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        ai_log_cols = [row['name'] for row in conn.execute('PRAGMA table_info(ai_logs)').fetchall()]
        if 'activity_id' not in ai_log_cols:
            conn.execute('ALTER TABLE ai_logs ADD COLUMN activity_id INTEGER')
        if 'flag_reason' not in ai_log_cols:
            conn.execute('ALTER TABLE ai_logs ADD COLUMN flag_reason TEXT')
        if 'result_status' not in ai_log_cols:
            conn.execute('''
                ALTER TABLE ai_logs ADD COLUMN result_status TEXT NOT NULL
                DEFAULT 'detected'
                CHECK(result_status IN ('detected', 'no_detection', 'failed'))
            ''')
        if 'image_sha256' not in ai_log_cols:
            conn.execute('ALTER TABLE ai_logs ADD COLUMN image_sha256 TEXT')
        if 'detected_classes_json' not in ai_log_cols:
            conn.execute('ALTER TABLE ai_logs ADD COLUMN detected_classes_json TEXT')
        conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_logs_image_sha256
            ON ai_logs(image_sha256)
            WHERE image_sha256 IS NOT NULL
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_ai_logs_user ON ai_logs(user_id)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS ai_duplicate_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_ai_log_id INTEGER NOT NULL,
                image_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (original_ai_log_id) REFERENCES ai_logs(id)
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_ai_duplicate_attempts_created_at
            ON ai_duplicate_attempts(created_at)
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS activity_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL CHECK(target_type IN (
                    'ai_result', 'user_declaration',
                    'gps_distance', 'gps_steps', 'gps_calories'
                )),
                activity_id INTEGER,
                ai_log_id INTEGER,
                status TEXT NOT NULL CHECK(status IN (
                    'confirmed', 'correction_required'
                )),
                reviewer_id INTEGER NOT NULL,
                reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                review_note TEXT,
                source_fingerprint TEXT NOT NULL,
                CHECK(
                    (target_type = 'ai_result'
                        AND ai_log_id IS NOT NULL AND activity_id IS NULL)
                    OR
                    (target_type != 'ai_result'
                        AND activity_id IS NOT NULL AND ai_log_id IS NULL)
                ),
                FOREIGN KEY (activity_id) REFERENCES activity_history(id),
                FOREIGN KEY (ai_log_id) REFERENCES ai_logs(id),
                FOREIGN KEY (reviewer_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_activity_verification_ai_log
            ON activity_verifications(ai_log_id)
            WHERE target_type = 'ai_result'
        ''')
        conn.execute('''
            CREATE UNIQUE INDEX IF NOT EXISTS idx_activity_verification_activity_type
            ON activity_verifications(activity_id, target_type)
            WHERE target_type != 'ai_result'
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS activity_verification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL CHECK(target_type IN (
                    'ai_result', 'user_declaration',
                    'gps_distance', 'gps_steps', 'gps_calories'
                )),
                activity_id INTEGER,
                ai_log_id INTEGER,
                status TEXT NOT NULL CHECK(status IN (
                    'unreviewed', 'confirmed', 'correction_required'
                )),
                reviewer_id INTEGER NOT NULL,
                reviewed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                review_note TEXT,
                source_fingerprint TEXT NOT NULL,
                CHECK(
                    (target_type = 'ai_result'
                        AND ai_log_id IS NOT NULL AND activity_id IS NULL)
                    OR
                    (target_type != 'ai_result'
                        AND activity_id IS NOT NULL AND ai_log_id IS NULL)
                ),
                FOREIGN KEY (activity_id) REFERENCES activity_history(id),
                FOREIGN KEY (ai_log_id) REFERENCES ai_logs(id),
                FOREIGN KEY (reviewer_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_activity_verification_history_target
            ON activity_verification_history(target_type, activity_id, ai_log_id)
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS reward_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                item_id TEXT,
                item_name TEXT,
                cost INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        conn.execute('CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_history(user_id)')

        # 固定パスワードのサンプルアカウントは明示的に有効化した場合だけ登録する。
        if os.environ.get('CLEANSTEP_DEMO_MODE', '').lower() == 'true':
            demo_users = [
                (1, 'user@example.com', 'userpass', 'テストユーザー', 'user', 350),
                (2, 'eco@example.com', 'userpass', 'エコ太郎', 'user', 1200),
                (3, 'admin@example.com', 'adminpass', '横浜市環境団体管理者', 'admin', 0),
            ]
            for user_id, email, password, name, role, points in demo_users:
                conn.execute('''
                    INSERT OR IGNORE INTO users
                        (id, email, password, name, role, total_points,
                         login_destination)
                    VALUES (?, ?, ?, ?, ?, ?, 'user')
                ''', (user_id, email, generate_password_hash(password), name, role, points))

            # 団体画面をすぐ確認できる専用デモアカウントと承認済み団体を用意する。
            conn.execute('''
                INSERT OR IGNORE INTO users (
                    email, password, name, role, total_points, login_destination
                ) VALUES (?, ?, ?, 'user', 0, 'organizer')
            ''', (
                'organizer@example.com', generate_password_hash('organizerpass'),
                'デモ団体管理者',
            ))
            demo_organizer = conn.execute(
                'SELECT id FROM users WHERE email = ?',
                ('organizer@example.com',),
            ).fetchone()
            demo_application = conn.execute('''
                SELECT id FROM organizer_applications
                WHERE user_id = ? AND organization_name = ?
                ORDER BY id LIMIT 1
            ''', (demo_organizer['id'], 'CleanStep デモ団体')).fetchone()
            if demo_application is None:
                cursor = conn.execute('''
                    INSERT INTO organizer_applications (
                        user_id, organization_name, contact, purpose,
                        status, reviewed_by, reviewed_at
                    ) VALUES (?, ?, ?, ?, 'approved', NULL, CURRENT_TIMESTAMP)
                ''', (
                    demo_organizer['id'], 'CleanStep デモ団体',
                    'organizer@example.com', '団体画面の動作確認用デモ団体',
                ))
                demo_application_id = cursor.lastrowid
            else:
                demo_application_id = demo_application['id']

            conn.execute('''
                INSERT OR IGNORE INTO organizations (
                    application_id, name, contact, purpose,
                    status, approved_by, approved_at
                )
                SELECT id, organization_name, contact, purpose,
                       'approved', NULL, COALESCE(reviewed_at, CURRENT_TIMESTAMP)
                FROM organizer_applications WHERE id = ?
            ''', (demo_application_id,))
            demo_organization = conn.execute('''
                SELECT id FROM organizations WHERE application_id = ?
            ''', (demo_application_id,)).fetchone()
            conn.execute('''
                UPDATE organizer_applications SET organization_id = ?
                WHERE id = ? AND organization_id IS NULL
            ''', (demo_organization['id'], demo_application_id))
            conn.execute('''
                INSERT OR IGNORE INTO organization_members (
                    organization_id, user_id, role, status
                ) VALUES (?, ?, 'owner', 'active')
            ''', (demo_organization['id'], demo_organizer['id']))
            
        if conn.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0:
            conn.execute('''
                INSERT INTO events (name, location, datetime, bonus_points, category)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                'みなとみらい清掃イベント', '横浜みなとみらい公園',
                '2026-10-10 10:00', 50,
                suggest_event_category('みなとみらい清掃イベント', '横浜みなとみらい公園'),
            ))
            conn.execute('''
                INSERT INTO events (name, location, datetime, bonus_points, category)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                '湘南海岸ビーチ清掃イベント', '江の島片瀬海岸',
                '2026-10-25 09:00', 80,
                suggest_event_category('湘南海岸ビーチ清掃イベント', '江の島片瀬海岸'),
            ))
            conn.execute('''
                INSERT INTO events (name, location, datetime, bonus_points, category)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                '渋谷ハロウィン翌朝ごみゼロ運動',
                '渋谷駅 ハチ公前広場（忠犬ハチ公像前）',
                '2026-11-01 06:00', 150,
                suggest_event_category(
                    '渋谷ハロウィン翌朝ごみゼロ運動',
                    '渋谷駅 ハチ公前広場（忠犬ハチ公像前）',
                ),
            ))
        if os.environ.get('CLEANSTEP_DEMO_MODE', '').lower() == 'true':
            demo_organization = conn.execute('''
                SELECT o.id FROM organizations o
                JOIN organizer_applications a ON a.id = o.application_id
                JOIN users u ON u.id = a.user_id
                WHERE u.email = 'organizer@example.com'
            ''').fetchone()
            if demo_organization:
                conn.execute('''
                    INSERT INTO events (
                        name, location, datetime, bonus_points, organizer_id,
                        reward_details, organization_id, status, review_status,
                        category
                    )
                    SELECT ?, ?, ?, ?, u.id, ?, ?, 'open', 'approved', ?
                    FROM users u
                    WHERE u.email = 'organizer@example.com'
                      AND NOT EXISTS (
                          SELECT 1 FROM events
                          WHERE name = ? AND organization_id = ?
                      )
                ''', (
                    'デモ団体 清掃イベント', '横浜みなとみらい公園',
                    (datetime.now(JST) + timedelta(days=30)).strftime('%Y-%m-%d %H:%M'),
                    50, '参加者に地域店舗で使えるドリンク引換券を配布（先着30名）',
                    demo_organization['id'], 'まち・道路清掃',
                    'デモ団体 清掃イベント', demo_organization['id'],
                ))
        conn.execute('''
            UPDATE events SET name = 'みなとみらい清掃イベント'
            WHERE name = 'みなとみらいクリーン作戦'
                AND location = '横浜みなとみらい公園'
        ''')
        conn.execute('''
            UPDATE events SET name = '湘南海岸ビーチ清掃イベント'
            WHERE name = '湘南海岸ビーチクリーン活動'
                AND location = '江の島片瀬海岸'
        ''')
        conn.execute('''
            UPDATE events
            SET location = '渋谷駅 ハチ公前広場（忠犬ハチ公像前）'
            WHERE name = '渋谷ハロウィン翌朝ごみゼロ運動'
                AND location = '渋谷駅ハチ公前広場周辺'
        ''')
        conn.execute('''
            UPDATE events
            SET latitude = 35.659058, longitude = 139.700566
            WHERE name = '渋谷ハロウィン翌朝ごみゼロ運動'
                AND location = '渋谷駅 ハチ公前広場（忠犬ハチ公像前）'
                AND latitude IS NULL AND longitude IS NULL
        ''')
        conn.commit()
    conn.close()

@app.cli.command('init-db')
def init_db_command():
    init_db()
    app.logger.info('データベースの初期化・マイグレーションが完了しました。')

model = None

def get_model():
    global model

    if not YOLO:
        return None

    if os.environ.get('CLEANSTEP_DISABLE_AI', '').lower() == 'true':
        return None

    if model is None:
        model_path = os.environ.get('CLEANSTEP_MODEL_PATH') or 'yolov8n.pt'
        app.logger.info("YOLOモデルを読み込みます: %s", model_path)
        try:
            model = YOLO(model_path)
        except Exception:
            app.logger.exception("YOLOモデルの読み込みに失敗しました。")
            return None

    return model

# ==========================================
# 認可チェック用デコレーター
# ==========================================
def user_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if session.get('role') != 'user' or not user_id:
            return redirect(url_for('login'))
        conn = get_db()
        try:
            user = conn.execute(
                'SELECT role FROM users WHERE id = ?', (user_id,)
            ).fetchone()
        finally:
            conn.close()
        if not user or user['role'] != 'user':
            session.clear()
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper


def view_mode_required(mode):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if _detect_view_mode() != mode:
                device_name = 'スマートフォン' if mode == 'mobile' else 'PC'
                flash(f'この機能は{device_name}からご利用ください。', 'info')
                return redirect(url_for('home'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if session.get('role') != 'admin' or not user_id:
            return redirect(url_for('login'))
        conn = get_db()
        try:
            user = conn.execute(
                'SELECT role FROM users WHERE id = ?', (user_id,)
            ).fetchone()
        finally:
            conn.close()
        if not user or user['role'] != 'admin':
            session.clear()
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def organizer_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if session.get('role') != 'user' or not user_id:
            return redirect(url_for('login'))

        conn = get_db()
        try:
            user = conn.execute(
                'SELECT role FROM users WHERE id = ?', (user_id,)
            ).fetchone()
            if not user or user['role'] != 'user':
                session.clear()
                return redirect(url_for('login'))
            organization_id = get_user_organization_id(conn, user_id)
        finally:
            conn.close()

        if not organization_id:
            flash('団体機能は、審査で承認された団体メンバーのみ利用できます。', 'info')
            return redirect(url_for('organizer_apply'))
        return func(*args, **kwargs)
    return wrapper

def validate_csrf():
    expected = session.get('csrf_token')
    submitted = request.form.get('csrf_token', '')
    ok = bool(expected and hmac.compare_digest(expected, submitted))
    if not ok:
        reason = (
            'セッションCookieが届いていない/読めない' if not expected
            else 'フォームにトークンが無い' if not submitted
            else 'トークン不一致（古いページ）'
        )
        app.logger.warning(
            'CSRF失敗 %s %s: %s (cookie送信=%s, Flaskから見たhttps=%s, host=%s)',
            request.method, request.path, reason,
            'session' in request.cookies, request.is_secure, request.host,
        )
    return ok


VERIFICATION_DATA_TYPES = {
    'ai_result': 'AI画像判定',
    'user_declaration': 'ユーザー申告数',
    'gps_distance': 'GPS移動距離',
    'gps_steps': 'GPS推定歩数',
    'gps_calories': 'GPS概算カロリー',
}


def verification_fingerprint(target_type, row):
    values = dict(row)
    if target_type == 'ai_result':
        fields = (
            'id', 'activity_id', 'detected_count', 'confidence',
            'image_path', 'created_at', 'result_status', 'is_flagged',
            'flag_reason',
        )
    elif target_type == 'user_declaration':
        fields = ('id', 'type', 'title', 'user_declared_count')
    else:
        metric_field = {
            'gps_distance': 'distance',
            'gps_steps': 'steps',
            'gps_calories': 'calories',
        }[target_type]
        fields = ('id', 'type', 'gps_measured', metric_field)
    snapshot = {field: values.get(field) for field in fields}
    encoded = json.dumps(
        snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=True
    ).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def load_verification_states(conn):
    rows = conn.execute('''
        SELECT v.*, u.name AS reviewer_name
        FROM activity_verifications v
        JOIN users u ON u.id = v.reviewer_id
    ''').fetchall()
    return {
        (
            row['target_type'],
            row['ai_log_id'] if row['target_type'] == 'ai_result'
            else row['activity_id'],
        ): row
        for row in rows
    }


def get_verification_state(conn, target_type, row, current_states=None):
    if current_states is not None:
        target_id = row['id']
        current = current_states.get((target_type, target_id))
    elif target_type == 'ai_result':
        current = conn.execute('''
            SELECT status, reviewer_id, reviewed_at, review_note,
                   source_fingerprint, u.name AS reviewer_name
            FROM activity_verifications
            JOIN users u ON u.id = activity_verifications.reviewer_id
            WHERE target_type = ? AND ai_log_id = ?
        ''', (target_type, row['id'])).fetchone()
    else:
        current = conn.execute('''
            SELECT status, reviewer_id, reviewed_at, review_note,
                   source_fingerprint, u.name AS reviewer_name
            FROM activity_verifications
            JOIN users u ON u.id = activity_verifications.reviewer_id
            WHERE target_type = ? AND activity_id = ?
        ''', (target_type, row['id'])).fetchone()

    if current is None:
        return {
            'status': 'unreviewed',
            'reviewer_id': None,
            'reviewer_name': None,
            'reviewed_at': None,
            'review_note': None,
            'stale': False,
        }

    stale = current['source_fingerprint'] != verification_fingerprint(
        target_type, row
    )
    return {
        'status': 'unreviewed' if stale else current['status'],
        'reviewer_id': None if stale else current['reviewer_id'],
        'reviewer_name': None if stale else current['reviewer_name'],
        'reviewed_at': None if stale else current['reviewed_at'],
        'review_note': None if stale else current['review_note'],
        'stale': stale,
    }


@app.template_filter('jst_datetime')
def format_jst_datetime(value):
    if not value:
        return ''
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone(timedelta(hours=9))).strftime('%Y-%m-%d %H:%M')


@app.template_filter('event_datetime')
def format_event_datetime(value):
    if not value:
        return ''
    try:
        return parse_event_datetime(value).strftime('%Y-%m-%d %H:%M')
    except (TypeError, ValueError):
        return value


@app.template_filter('event_started')
def event_started(value):
    try:
        return parse_event_datetime(value) <= datetime.now(JST)
    except (TypeError, ValueError):
        return False

def _detect_view_mode():
    ua = (request.headers.get('User-Agent') or '').lower()
    if any(token in ua for token in ('mobile', 'android', 'iphone', 'ipod', 'iemobile')):
        return 'mobile'
    return 'pc'


@app.route('/view-mode/<mode>')
def switch_view_mode(mode):
    next_url = request.args.get('next') or request.referrer or url_for('home')
    if not next_url.startswith('/') or next_url.startswith('//'):
        next_url = url_for('home')
    return redirect(next_url)


@app.context_processor
def inject_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    unread_notifications = 0
    if session.get('role') == 'user' and session.get('user_id'):
        conn = get_db()
        try:
            # ここでは書き込み(_create_due_event_reminders)を呼ばず、読み取りのみにする
            unread_notifications = conn.execute('''
                SELECT COUNT(*) FROM user_notifications
                WHERE user_id = ? AND read_at IS NULL
            ''', (session['user_id'],)).fetchone()[0]
        finally:
            conn.close()
    effective_view = _detect_view_mode()
    return {
        'csrf_token': session['csrf_token'],
        'unread_notifications': unread_notifications,
        'view_mode': effective_view,
    }


def _create_due_event_reminders(conn, user_id):
    now = datetime.now(JST)
    reminder_limit = now + timedelta(hours=48)
    upcoming = conn.execute('''
        SELECT e.id, e.name, e.datetime, e.location
        FROM event_reservations r
        JOIN events e ON e.id = r.event_id
        WHERE r.user_id = ? AND r.status = 'reserved'
          AND e.status = 'open' AND e.review_status = 'approved'
    ''', (user_id,)).fetchall()
    with conn:
        for event in upcoming:
            try:
                starts_at = parse_event_datetime(event['datetime'])
            except (TypeError, ValueError):
                continue
            if now < starts_at <= reminder_limit:
                conn.execute('''
                    INSERT OR IGNORE INTO user_notifications (
                        user_id, event_id, notification_type, title, message
                    ) VALUES (?, ?, 'reminder', ?, ?)
                ''', (
                    user_id, event['id'],
                    f"まもなく開催：{event['name']}",
                    f"開催日時：{starts_at.strftime('%Y年%m月%d日 %H:%M')}\n開催場所：{event['location']}",
                ))

# ==========================================
# ログイン ＆ 新規登録処理
# ==========================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if not validate_csrf():
            abort(400, description='CSRFトークンが無効です。ページを再読み込みしてください。')
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        email_rate_key = _auth_rate_key('login-email', email)
        ip_rate_key = _auth_rate_key('login-ip')

        try:
            conn = get_db()
            try:
                if (
                    _auth_attempt_count(conn, email_rate_key) >= 10
                    or _auth_attempt_count(conn, ip_rate_key) >= 30
                ):
                    return render_template(
                        'login.html',
                        error_msg='ログイン試行が多すぎます。しばらくしてからお試しください。',
                        email=email,
                    ), 429

                matching_users = conn.execute(
                    'SELECT * FROM users WHERE lower(email) = ? ORDER BY id',
                    (email,),
                ).fetchall()
                user = next(
                    (
                        candidate for candidate in matching_users
                        if check_password_hash(candidate['password'], password)
                    ),
                    None,
                )

                if not user:
                    _record_auth_attempt(conn, email_rate_key)
                    _record_auth_attempt(conn, ip_rate_key)
                    return render_template(
                        'login.html',
                        error_msg="ログイン失敗：メールアドレスまたはパスワードが違います。",
                        email=email or '',
                    )

                _clear_auth_attempts(conn, email_rate_key)
                _clear_auth_attempts(conn, ip_rate_key)
                is_organizer = (
                    user['role'] == 'user'
                    and user['login_destination'] == 'organizer'
                    and get_user_organization_id(conn, user['id']) is not None
                )
            finally:
                conn.close()

            session.clear()
            session['csrf_token'] = secrets.token_urlsafe(32)
            session['user_id'] = user['id']
            session['email'] = user['email']
            session['role'] = user['role']
            if user['role'] == "admin":
                return redirect(url_for('admin_dashboard'))
            if is_organizer:
                return redirect(url_for('organizer_dashboard'))
            return redirect(url_for('home'))
        except Exception:
            app.logger.exception("ログイン処理中に内部エラーが発生しました。")
            return render_template(
                'login.html',
                error_msg="内部エラーが発生しました。時間をおいて再度お試しください。",
                email=email or '',
            )
            
    return render_template('login.html', error_msg=None, email='')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not validate_csrf():
            abort(400, description='CSRFトークンが無効です。ページを再読み込みしてください。')
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        account_type = (request.form.get('account_type') or 'individual').strip()
        organization_name = (request.form.get('organization_name') or '').strip()
        organization_contact = (request.form.get('organization_contact') or '').strip()
        organization_purpose = (request.form.get('organization_purpose') or '').strip()
        register_values = {
            'name': name,
            'email': email,
            'account_type': account_type,
            'organization_name': organization_name,
            'organization_contact': organization_contact,
            'organization_purpose': organization_purpose,
        }

        rate_key = _auth_rate_key('register')
        conn = get_db()
        try:
            if _auth_attempt_count(conn, rate_key) >= 5:
                abort(429, description='登録試行が多すぎます。しばらくしてからお試しください。')
            _record_auth_attempt(conn, rate_key)
        finally:
            conn.close()

        error_msg = None
        if account_type not in {'individual', 'organization'}:
            error_msg = '利用区分を選択してください。'
        elif (
            not name or len(name) > 80
            or len(email) > 254
            or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email)
            or len(password) < 8 or len(password) > 128
        ):
            error_msg = '名前は1〜80文字、メールアドレスは有効な形式、パスワードは8〜128文字で入力してください。'
        elif account_type == 'organization' and (
            not organization_name or len(organization_name) > 100
            or not organization_contact or len(organization_contact) > 200
            or not organization_purpose or len(organization_purpose) > 1000
        ):
            error_msg = '団体名、連絡先、活動内容を入力してください（団体名100文字、連絡先200文字、活動内容1000文字以内）。'
        if error_msg:
            return render_template(
                'register.html',
                error_msg=error_msg, **register_values,
            )

        conn = get_db()
        try:
            existing = conn.execute(
                'SELECT id FROM users WHERE lower(email) = ?', (email,)
            ).fetchone()
            if existing:
                return render_template(
                    'register.html', error_msg="このメールアドレスは既に登録されています。",
                    **register_values,
                )

            hashed_password = generate_password_hash(password)
            with conn:
                cursor = conn.execute(
                    'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, "user")',
                    (name, email, hashed_password),
                )
                if account_type == 'organization':
                    conn.execute('''
                        INSERT INTO organizer_applications (
                            user_id, organization_name, contact, purpose
                        ) VALUES (?, ?, ?, ?)
                    ''', (
                        cursor.lastrowid, organization_name,
                        organization_contact, organization_purpose,
                    ))
            if account_type == 'organization':
                flash('ユーザーアカウントと団体申請を受け付けました。団体機能は管理者の承認後に利用できます。', 'success')
            else:
                flash('アカウントを作成しました。ログインしてください。', 'success')
            return redirect(url_for('login'))
        except Exception:
            conn.rollback()
            app.logger.exception("新規登録処理中に内部エラーが発生しました。")
            return render_template(
                'register.html',
                error_msg="内部エラーが発生しました。時間をおいて再度お試しください。",
                **register_values,
            )
        finally:
            conn.close()

    return render_template(
        'register.html', error_msg=None, name='', email='',
        account_type='individual', organization_name='',
        organization_contact='', organization_purpose='',
    )

# ==========================================
# 一般ユーザー専用マイページ（/home - UI連動・完全修復版）
# ==========================================
def generate_user_report(conn, user_id):
    current_month = datetime.now(JST).date().replace(day=1)
    previous_month = current_month - timedelta(days=1)
    previous_month = previous_month.replace(day=1)
    following_month = (
        current_month.replace(year=current_month.year + 1, month=1)
        if current_month.month == 12
        else current_month.replace(month=current_month.month + 1)
    )
    following_previous_month = current_month

    user_stats = conn.execute('''
        SELECT
            IFNULL(SUM(trash_count), 0) AS my_total_trash,
            COUNT(CASE WHEN type = 'event' THEN 1 END) AS my_event_count
        FROM activity_history
        WHERE user_id = ?
    ''', (user_id,)).fetchone()

    my_trash = user_stats['my_total_trash']
    my_events = user_stats['my_event_count']
    monthly_trends = conn.execute('''
        SELECT
            strftime('%Y-%m', date(date, '+9 hours')) AS month,
            IFNULL(SUM(trash_count), 0) AS trash,
            COUNT(CASE WHEN type = 'event' THEN 1 END) AS events,
            IFNULL(SUM(points_earned), 0) AS points
        FROM activity_history
        WHERE user_id = ?
        GROUP BY month
        ORDER BY month DESC
        LIMIT 6
    ''', (user_id,)).fetchall()

    def month_totals(start, end):
        row = conn.execute('''
            SELECT
                COALESCE(SUM(trash_count), 0) AS trash,
                COUNT(CASE WHEN type = 'event' THEN 1 END) AS events,
                COALESCE(SUM(points_earned), 0) AS points
            FROM activity_history
            WHERE user_id = ?
                AND date(date, '+9 hours') >= ?
                AND date(date, '+9 hours') < ?
        ''', (user_id, start.isoformat(), end.isoformat())).fetchone()
        return dict(row)

    current_totals = month_totals(current_month, following_month)
    previous_totals = month_totals(previous_month, following_previous_month)
    six_month_start = (current_month - timedelta(days=1)).replace(day=1)
    for _ in range(4):
        six_month_start = (six_month_start - timedelta(days=1)).replace(day=1)
    trend_rows = conn.execute('''
        SELECT
            strftime('%Y-%m', date(date, '+9 hours')) AS month,
            COALESCE(SUM(trash_count), 0) AS trash,
            COUNT(CASE WHEN type = 'event' THEN 1 END) AS events,
            COALESCE(SUM(points_earned), 0) AS points
        FROM activity_history
        WHERE user_id = ? AND date(date, '+9 hours') >= ?
        GROUP BY month
    ''', (user_id, six_month_start.isoformat())).fetchall()
    trend_by_month = {row['month']: dict(row) for row in trend_rows}
    activity_trends = []
    trend_month = six_month_start
    for _ in range(6):
        month_key = trend_month.strftime('%Y-%m')
        activity_trends.append(trend_by_month.get(month_key, {
            'month': month_key, 'trash': 0, 'events': 0, 'points': 0,
        }))
        trend_month = (
            trend_month.replace(year=trend_month.year + 1, month=1)
            if trend_month.month == 12
            else trend_month.replace(month=trend_month.month + 1)
        )

    event_history = conn.execute('''
        SELECT a.title, e.name, e.location, e.reward_details, e.category
        FROM activity_history a
        LEFT JOIN events e ON e.id = a.event_id
        WHERE a.user_id = ? AND a.type = 'event'
    ''', (user_id,)).fetchall()
    category_counts = {}
    for event in event_history:
        category = event['category']
        if category not in EVENT_CATEGORIES:
            category = suggest_event_category(
                event['name'], event['location'],
                event['reward_details'], event['title'],
            )
        category_counts[category] = category_counts.get(category, 0) + 1
    preferred_categories = [
        {'name': name, 'count': count}
        for name, count in sorted(
            category_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ]

    trash_bin_actions = conn.execute('''
        SELECT COUNT(*) FROM activity_history
        WHERE user_id = ? AND type = 'trash_bin'
    ''', (user_id,)).fetchone()[0]

    issue_report_count = 0
    try:
        issue_report_count = conn.execute('''
            SELECT COUNT(*) FROM issue_reports WHERE user_id = ?
        ''', (user_id,)).fetchone()[0]
    except sqlite3.OperationalError:
        issue_report_count = 0

    # SQLite strftime('%w') returns 0=Sunday .. 6=Saturday
    weekday_rows = conn.execute('''
        SELECT strftime('%w', datetime(date, '+9 hours')) AS wday,
               COUNT(*) AS cnt
        FROM activity_history
        WHERE user_id = ? AND date IS NOT NULL
        GROUP BY wday
    ''', (user_id,)).fetchall()
    wday_map = {row['wday']: row['cnt'] for row in weekday_rows if row['wday'] is not None}
    weekday_order = [
        ('1', '月'), ('2', '火'), ('3', '水'), ('4', '木'),
        ('5', '金'), ('6', '土'), ('0', '日'),
    ]
    weekday_trends = [
        {'key': key, 'label': label, 'count': wday_map.get(key, 0)}
        for key, label in weekday_order
    ]
    max_weekday = max(weekday_trends, key=lambda item: item['count'])
    most_active_weekday = (
        f"{max_weekday['label']}曜日" if max_weekday['count'] > 0 else 'データ蓄積中'
    )

    recent_reflections = []
    try:
        recent_reflections = [
            dict(row) for row in conn.execute('''
                SELECT f.satisfaction, f.comment, f.noticed_issue,
                       f.suspected_cause, f.collaboration_note,
                       f.next_improvement, f.action_status, f.action_note,
                       f.submitted_at, e.name AS event_name
                FROM event_feedback f
                JOIN events e ON e.id = f.event_id
                WHERE f.user_id = ?
                ORDER BY f.submitted_at DESC, f.id DESC
                LIMIT 5
            ''', (user_id,)).fetchall()
        ]
    except sqlite3.OperationalError:
        recent_reflections = []

    proposal_count = 0
    try:
        proposal_count = conn.execute(
            'SELECT COUNT(*) FROM improvement_proposals WHERE user_id = ?',
            (user_id,),
        ).fetchone()[0]
    except sqlite3.OperationalError:
        proposal_count = 0

    verified_ai_count = 0
    try:
        verified_ai_count = conn.execute('''
            SELECT COUNT(*)
            FROM activity_verifications v
            JOIN ai_logs l ON l.id = v.ai_log_id
            WHERE l.user_id = ? AND v.target_type = 'ai_result' AND v.status = 'confirmed'
        ''', (user_id,)).fetchone()[0]
    except sqlite3.OperationalError:
        verified_ai_count = 0

    contribution_badges = []
    if trash_bin_actions >= 1:
        contribution_badges.append({
            'icon': '📸',
            'title': 'エコごみ箱サポーター',
            'desc': f'日常のごみ捨てを {trash_bin_actions} 回実践',
        })
    if my_events >= 1:
        contribution_badges.append({
            'icon': '🤝',
            'title': '地域クリーンメンバー',
            'desc': f'清掃イベントに {my_events} 回参加',
        })
    if issue_report_count >= 1:
        contribution_badges.append({
            'icon': '🚩',
            'title': '地域課題ウォッチャー',
            'desc': f'地域の課題を {issue_report_count} 件発見・共有',
        })
    if len(recent_reflections) >= 1 or proposal_count >= 1:
        contribution_badges.append({
            'icon': '💡',
            'title': '地域改善プランナー',
            'desc': '活動の振り返り・改善提案で街づくりに貢献',
        })
    if not contribution_badges:
        contribution_badges.append({
            'icon': '🌱',
            'title': 'CleanStep チャレンジャー',
            'desc': '最初の1歩（ごみ捨て・課題報告・イベント参加）を踏み出しましょう',
        })

    return {
        "my_total_trash": my_trash,
        "my_event_count": my_events,
        "my_trash_bin_action_count": trash_bin_actions,
        "my_issue_report_count": issue_report_count,
        "my_proposal_count": proposal_count,
        "verified_ai_count": verified_ai_count,
        "contribution_badges": contribution_badges,
        "weekday_trends": weekday_trends,
        "most_active_weekday": most_active_weekday,
        "recent_reflections": recent_reflections,
        "monthly_trends": [dict(month) for month in monthly_trends],
        "current_month": {
            'label': current_month.strftime('%Y年%m月'),
            **current_totals,
        },
        "previous_month": {
            'label': previous_month.strftime('%Y年%m月'),
            **previous_totals,
        },
        "activity_trends": activity_trends,
        "preferred_categories": preferred_categories,
    }


def build_recommended_activity_schedule(events, preferred_categories, now=None):
    now = now or datetime.now(JST)
    preferred_order = {
        row['name']: index
        for index, row in enumerate(preferred_categories)
    }

    def rank(event):
        return (
            preferred_order.get(event['category'], len(preferred_order)),
            event['datetime'],
        )

    start = now.date().replace(day=1)
    schedule = []
    for _ in range(3):
        end = (start + timedelta(days=32)).replace(day=1)
        month_events = [
            event for event in events
            if start <= datetime.fromisoformat(event['datetime']).date() < end
        ]
        schedule.append({
            'label': start.strftime('%Y年%m月'),
            'events': sorted(month_events, key=rank)[:2],
        })
        start = end
    return schedule


@app.route('/home')
@user_required
def home():
    user_id = session['user_id']
    try:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user is None:
            conn.close()
            return redirect(url_for('logout'))
        organizer_access = get_user_organization_id(conn, user_id) is not None

        _create_due_event_reminders(conn, user_id)

        my_report = generate_user_report(conn, user_id)

        events = conn.execute("""
            SELECT * FROM events
            WHERE status = 'open' AND review_status = 'approved'
                AND datetime >= datetime('now', '+9 hours')
                AND datetime <= datetime('now', '+9 hours', '+365 days')
            ORDER BY datetime
        """).fetchall()
        all_event_count = len(events)
        organization_application = conn.execute('''
            SELECT status FROM organizer_applications
            WHERE user_id = ? ORDER BY id DESC LIMIT 1
        ''', (user_id,)).fetchone()
        today_sum = conn.execute('''
            SELECT IFNULL(SUM(points_earned), 0) AS today_sum 
            FROM activity_history 
            WHERE user_id = ? AND date(date, '+9 hours') = date('now', '+9 hours')
        ''', (user_id,)).fetchone()['today_sum']
        
        stats = conn.execute('''
            SELECT IFNULL(SUM(trash_count), 0) as total_trash, IFNULL(SUM(points_earned), 0) as total_points_gifted 
            FROM activity_history WHERE type IN ('event', 'trash_bin')
        ''').fetchone()
        
        # 【UI連動】：ログイン中のユーザーが参加済みのイベントIDを一括抽出してセットで保持
        joined_rows = conn.execute("""
            SELECT event_id FROM activity_history
            WHERE user_id = ? AND type = 'event' AND event_id IS NOT NULL
        """, (user_id,)).fetchall()
        joined_events = set(row['event_id'] for row in joined_rows)
        reservation_rows = conn.execute("""
            SELECT event_id FROM event_reservations
            WHERE user_id = ? AND status = 'reserved'
        """, (user_id,)).fetchall()
        reserved_events = set(row['event_id'] for row in reservation_rows)
        all_reserved_event_count = conn.execute("""
            SELECT COUNT(*)
            FROM event_reservations r
            JOIN events e ON e.id = r.event_id
            WHERE r.user_id = ? AND r.status = 'reserved'
                AND e.status = 'open' AND e.review_status = 'approved'
        """, (user_id,)).fetchone()[0]
        my_reserved_events = conn.execute("""
            SELECT e.*,
                   (SELECT COUNT(*) FROM event_reservations active_r
                    WHERE active_r.event_id = e.id
                      AND active_r.status = 'reserved') AS reserved_count
            FROM event_reservations r
            JOIN events e ON e.id = r.event_id
            WHERE r.user_id = ? AND r.status = 'reserved'
                AND e.status = 'open' AND e.review_status = 'approved'
                AND e.datetime >= datetime('now', '+9 hours')
            ORDER BY e.datetime
            LIMIT 3
        """, (user_id,)).fetchall()
        next_reserved_event = my_reserved_events[0] if my_reserved_events else None
        history = conn.execute('''
            SELECT * FROM activity_history
            WHERE user_id = ?
            ORDER BY date DESC, id DESC
            LIMIT 5
        ''', (user_id,)).fetchall()
        available_events = [
            event for event in events
            if event['id'] not in joined_events
            and event['id'] not in reserved_events
        ]
        preferred_categories = my_report['preferred_categories']
        category_rank = {
            row['name']: index
            for index, row in enumerate(preferred_categories)
        }
        recommended_events = sorted(
            available_events,
            key=lambda event: (
                category_rank.get(event['category'], len(category_rank)),
                event['datetime'],
            ),
        )[:3]
        activity_schedule = build_recommended_activity_schedule(
            available_events, preferred_categories
        )
        recent_issues = []
        try:
            recent_issues = conn.execute('''
                SELECT * FROM issue_reports
                ORDER BY created_at DESC, id DESC
                LIMIT 5
            ''').fetchall()
        except sqlite3.OperationalError:
            recent_issues = []
        conn.close()

        user_dict = dict(user)
        user_dict['today_points'] = today_sum
        application_pending = (
            organization_application is not None
            and organization_application['status'] == 'pending'
        )
        organizer_status = (
            'approved'
            if organizer_access
            else ('pending' if application_pending else 'none')
        )
        
        return render_template(
            'menu.html', 
            user=user_dict, events=events[:3], event_count=all_event_count,
            stats=stats,
            organization_application_pending=application_pending,
            organizer_access=organizer_access,
            organizer_status=organizer_status,
            show_onboarding=(
                not user['onboarding_completed']
                and not session.get('onboarding_dismissed')
            ),
            reserved_events=reserved_events,
            my_reserved_events=my_reserved_events,
            next_reserved_event=next_reserved_event,
            reserved_event_count=all_reserved_event_count,
            joined_events=joined_events,
            my_report=my_report,
            history=history,
            recent_issues=recent_issues,
            recommended_events=recommended_events,
            activity_schedule=activity_schedule,
        )
    except Exception:
        app.logger.exception("マイページ表示エラー")
        return _internal_error_response()


@app.route('/guide')
@user_required
def user_guide():
    return render_template('user_guide.html')


@app.route('/onboarding/dismiss', methods=['POST'])
@user_required
def dismiss_onboarding():
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400

    action = request.form.get('action')
    if action not in {'later', 'complete', 'guide'}:
        return '操作内容が正しくありません。', 400

    if action == 'later':
        session['onboarding_dismissed'] = True
    else:
        conn = get_db()
        try:
            with conn:
                conn.execute(
                    'UPDATE users SET onboarding_completed = 1 WHERE id = ?',
                    (session['user_id'],),
                )
        finally:
            conn.close()
        session['onboarding_dismissed'] = True
        if action == 'guide':
            return redirect(url_for('user_guide'))
    return redirect(url_for('home'))


@app.route('/mypage')
@user_required
def mypage():
    user_id = session['user_id']
    conn = get_db()
    try:
        user = conn.execute(
            'SELECT id, name, email, total_points FROM users WHERE id = ?',
            (user_id,),
        ).fetchone()
        if user is None:
            return redirect(url_for('logout'))

        report = generate_user_report(conn, user_id)
        history = conn.execute('''
            SELECT *, date(date, '+9 hours') AS activity_jst_date
            FROM activity_history
            WHERE user_id = ?
            ORDER BY date DESC, id DESC
        ''', (user_id,)).fetchall()
        month_value = request.args.get('month', '')
        try:
            month = datetime.strptime(month_value, '%Y-%m').date().replace(day=1)
        except ValueError:
            month = datetime.now(JST).date().replace(day=1)
        next_month = (
            month.replace(year=month.year + 1, month=1)
            if month.month == 12 else month.replace(month=month.month + 1)
        )
        previous_month = (
            month.replace(year=month.year - 1, month=12)
            if month.month == 1 else month.replace(month=month.month - 1)
        )
        activities_by_date = {}
        for activity in history:
            activity_date = activity['activity_jst_date']
            if activity_date:
                activities_by_date.setdefault(activity_date, []).append(activity)
        weeks = calendar.Calendar(firstweekday=0).monthdatescalendar(
            month.year, month.month
        )
        return render_template(
            'mypage.html',
            user=user,
            report=report,
            history=history[:20],
            weeks=weeks,
            month=month,
            previous_month=previous_month,
            next_month=next_month,
            activities_by_date=activities_by_date,
        )
    finally:
        conn.close()

@app.route('/events')
@user_required
@view_mode_required('pc')
def all_events():
    conn = get_db()
    try:
        events = conn.execute("""
            SELECT e.*,
                   (SELECT COUNT(*) FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved') AS reserved_count
            FROM events e
            WHERE e.status = 'open' AND e.review_status = 'approved'
                AND e.datetime >= datetime('now', '+9 hours')
                AND e.datetime <= datetime('now', '+9 hours', '+365 days')
            ORDER BY e.datetime
        """).fetchall()
        reserved_events = {
            row['event_id'] for row in conn.execute("""
                SELECT event_id FROM event_reservations
                WHERE user_id = ? AND status = 'reserved'
            """, (session['user_id'],)).fetchall()
        }
        joined_events = {
            row['event_id'] for row in conn.execute("""
                SELECT event_id FROM activity_history
                WHERE user_id = ? AND type = 'event' AND event_id IS NOT NULL
            """, (session['user_id'],)).fetchall()
        }
        return render_template(
            'event_list.html',
            title='開催予定のイベント',
            events=events,
            reserved_events=reserved_events,
            joined_events=joined_events,
            is_reservation_list=False,
        )
    finally:
        conn.close()

@app.route('/my/reservations')
@user_required
@view_mode_required('pc')
def my_reservations():
    conn = get_db()
    try:
        events = conn.execute("""
            SELECT e.*,
                   (SELECT COUNT(*) FROM event_reservations active_r
                    WHERE active_r.event_id = e.id
                      AND active_r.status = 'reserved') AS reserved_count
            FROM event_reservations r
            JOIN events e ON e.id = r.event_id
            WHERE r.user_id = ? AND r.status = 'reserved'
                AND e.status = 'open' AND e.review_status = 'approved'
            ORDER BY CASE WHEN e.datetime >= datetime('now', '+9 hours') THEN 0 ELSE 1 END,
                     e.datetime
        """, (session['user_id'],)).fetchall()
        return render_template(
            'event_list.html',
            title='予約したイベント',
            events=events,
            reserved_events={event['id'] for event in events},
            joined_events=set(),
            is_reservation_list=True,
        )
    finally:
        conn.close()

@app.route('/')
def index():
    if 'role' in session:
        return redirect(url_for('admin_dashboard') if session['role'] == 'admin' else url_for('home'))
    return redirect(url_for('login'))


ISSUE_TRASH_TYPES = (
    'ペットボトル・飲料容器',
    '空き缶・ビン',
    'タバコ・吸い殻',
    'ビニール・プラスチック',
    '不法投棄・粗大ごみ',
    'ごみ箱満杯・破損',
    'その他',
)


@app.route('/map')
@user_required
def regional_map():
    conn = get_db()
    try:
        bins = [
            dict(row) for row in conn.execute('''
                SELECT b.*,
                       (SELECT COUNT(*) FROM activity_history a
                        WHERE a.type = 'trash_bin' AND a.title = b.name) AS usage_count
                FROM trash_bins b
                ORDER BY b.name
            ''').fetchall()
        ]
        events = [
            dict(row) for row in conn.execute('''
                SELECT e.id, e.name, e.location, e.latitude, e.longitude,
                       e.datetime, e.bonus_points, e.category,
                       (SELECT COUNT(*) FROM event_reservations r
                        WHERE r.event_id = e.id AND r.status = 'reserved') AS reserved_count,
                       e.capacity
                FROM events e
                WHERE e.status = 'open' AND e.review_status = 'approved'
                    AND e.datetime >= datetime('now', '+9 hours')
                ORDER BY e.datetime
            ''').fetchall()
        ]
        issues = []
        hotspot_locations = []
        try:
            issues = [
                dict(row) for row in conn.execute('''
                    SELECT i.*, u.name AS reporter_name
                    FROM issue_reports i
                    LEFT JOIN users u ON u.id = i.user_id
                    ORDER BY i.created_at DESC, i.id DESC
                    LIMIT 50
                ''').fetchall()
            ]
            hotspot_locations = [
                dict(row) for row in conn.execute('''
                    SELECT location, COUNT(*) AS report_count,
                           SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END) AS open_count,
                           GROUP_CONCAT(DISTINCT trash_type) AS trash_types
                    FROM issue_reports
                    GROUP BY location
                    ORDER BY open_count DESC, report_count DESC
                    LIMIT 5
                ''').fetchall()
            ]
        except sqlite3.OperationalError:
            issues = []
            hotspot_locations = []
        full_bins_count = sum(1 for b in bins if b.get('bin_status') == 'full_reported')
        open_issues_count = sum(1 for i in issues if i.get('status') != 'resolved')
        return render_template(
            'regional_map.html',
            bins=bins,
            events=events,
            issues=issues,
            hotspot_locations=hotspot_locations,
            full_bins_count=full_bins_count,
            open_issues_count=open_issues_count,
        )
    finally:
        conn.close()


@app.route('/issues/report', methods=['GET', 'POST'])
@user_required
def issue_report_new():
    user_id = session['user_id']
    form_values = {
        'title': '',
        'location': '',
        'latitude': '',
        'longitude': '',
        'trash_type': ISSUE_TRASH_TYPES[0],
        'severity': 'medium',
        'description': '',
    }
    error_msg = None
    if request.method == 'POST':
        if not validate_csrf():
            return 'CSRFトークンが不正です。', 400
        title = (request.form.get('title') or '').strip()
        location = (request.form.get('location') or '').strip()
        raw_lat = (request.form.get('latitude') or '').strip()
        raw_lng = (request.form.get('longitude') or '').strip()
        trash_type = (request.form.get('trash_type') or ISSUE_TRASH_TYPES[0]).strip()
        severity = (request.form.get('severity') or 'medium').strip()
        description = (request.form.get('description') or '').strip()
        form_values.update({
            'title': title,
            'location': location,
            'latitude': raw_lat,
            'longitude': raw_lng,
            'trash_type': trash_type,
            'severity': severity,
            'description': description,
        })
        if not title or len(title) > 100:
            error_msg = '課題のタイトルを1〜100文字で入力してください。'
        elif not location or len(location) > 200:
            error_msg = '発見場所（目安）を1〜200文字で入力してください。'
        elif trash_type not in ISSUE_TRASH_TYPES:
            error_msg = 'ごみの種類・課題区分を選択してください。'
        elif severity not in ('low', 'medium', 'high'):
            error_msg = '状況の深刻度を選択してください。'
        elif len(description) > 500:
            error_msg = '詳細メモは500文字以内で入力してください。'
        else:
            lat = lng = None
            if raw_lat or raw_lng:
                try:
                    lat = float(raw_lat)
                    lng = float(raw_lng)
                    if (
                        not math.isfinite(lat)
                        or not math.isfinite(lng)
                        or not (-90 <= lat <= 90)
                        or not (-180 <= lng <= 180)
                    ):
                        raise ValueError
                except ValueError:
                    error_msg = '位置情報の座標が正しくありません。'

        if not error_msg:
            image_path = None
            ai_detected = None
            file = request.files.get('issue_image')
            if file and file.filename:
                if not allowed_file(file.filename):
                    error_msg = '対応していない画像ファイル形式です。'
                else:
                    try:
                        img = Image.open(file)
                        img.verify()
                        file.seek(0)
                        ext = file.filename.rsplit('.', 1)[1].lower()
                        unique_filename = f"issue_{uuid.uuid4()}.{ext}"
                        image_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                        file.save(image_path)
                        detector = get_model()
                        if detector is not None:
                            results = detector.predict(
                                image_path, imgsz=640, conf=0.25,
                                verbose=False, max_det=20,
                            )
                            ai_detected = sum(
                                1
                                for result in results
                                for box in result.boxes
                                if int(box.cls) in (39, 41)
                            )
                    except Exception:
                        app.logger.exception('課題報告画像の検証またはAI推定エラー')

        if not error_msg:
            conn = get_db()
            try:
                with conn:
                    conn.execute('''
                        INSERT INTO issue_reports (
                            user_id, title, location, latitude, longitude,
                            trash_type, severity, description, image_path,
                            ai_detected_count, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                    ''', (
                        user_id, title, location, lat, lng,
                        trash_type, severity, description, image_path,
                        ai_detected,
                    ))
                    if trash_type == 'ごみ箱満杯・破損':
                        conn.execute('''
                            UPDATE trash_bins SET bin_status = 'full_reported'
                            WHERE name = ?
                        ''', (location,))
                    conn.execute('''
                        INSERT INTO user_notifications (
                            user_id, notification_type, title, message
                        ) VALUES (?, 'activity_completed', ?, ?)
                    ''', (
                        user_id,
                        f'地域課題を報告しました：{title}',
                        f'場所：{location}\n種類：{trash_type}\n地域マップに共有されました。',
                    ))
                flash('地域の課題報告を送信しました。地域マップに反映されました。', 'success')
                return redirect(url_for('regional_map'))
            finally:
                conn.close()

    return render_template(
        'issue_report.html',
        form=form_values,
        trash_types=ISSUE_TRASH_TYPES,
        error_msg=error_msg,
    )


PROPOSAL_TYPES = (
    'ごみ箱の増設・配置見直し',
    '重点清掃イベントの開催',
    '分別案内・啓発サインの設置',
    '巡回・再発防止対策',
)


@app.route('/proposals', methods=['GET', 'POST'])
@user_required
def improvement_proposals_board():
    user_id = session['user_id']
    error_msg = None
    form_values = {
        'title': '',
        'location': request.args.get('location', '').strip(),
        'proposal_type': PROPOSAL_TYPES[0],
        'issue_report_id': request.args.get('issue_id', '').strip(),
        'description': '',
    }
    conn = get_db()
    try:
        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400
            title = (request.form.get('title') or '').strip()
            location = (request.form.get('location') or '').strip()
            proposal_type = (request.form.get('proposal_type') or PROPOSAL_TYPES[0]).strip()
            raw_issue_id = (request.form.get('issue_report_id') or '').strip()
            description = (request.form.get('description') or '').strip()
            form_values.update({
                'title': title,
                'location': location,
                'proposal_type': proposal_type,
                'issue_report_id': raw_issue_id,
                'description': description,
            })
            if not title or len(title) > 100:
                error_msg = '提案タイトルを1〜100文字で入力してください。'
            elif not location or len(location) > 200:
                error_msg = '対象場所・エリアを1〜200文字で入力してください。'
            elif proposal_type not in PROPOSAL_TYPES:
                error_msg = '提案区分を選択してください。'
            elif not description or len(description) > 500:
                error_msg = '提案内容・根拠を1〜500文字で入力してください。'
            else:
                issue_report_id = int(raw_issue_id) if raw_issue_id.isdigit() else None
                if issue_report_id is not None:
                    exists_issue = conn.execute(
                        'SELECT 1 FROM issue_reports WHERE id = ?', (issue_report_id,)
                    ).fetchone()
                    if not exists_issue:
                        issue_report_id = None
                is_org = bool(get_user_organization_id(conn, user_id))
                author_role = 'organizer' if is_org else 'user'
                with conn:
                    conn.execute('''
                        INSERT INTO improvement_proposals (
                            user_id, author_role, title, location, proposal_type,
                            issue_report_id, description, status, support_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'proposed', 1)
                    ''', (
                        user_id, author_role, title, location, proposal_type,
                        issue_report_id, description,
                    ))
                    proposal_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
                    conn.execute('''
                        INSERT OR IGNORE INTO improvement_proposal_supports (proposal_id, user_id)
                        VALUES (?, ?)
                    ''', (proposal_id, user_id))
                flash('地域改善の提案を投稿しました。', 'success')
                return redirect(url_for('improvement_proposals_board'))

        proposals = [
            dict(row) for row in conn.execute('''
                SELECT p.*, u.name AS author_name,
                       i.title AS issue_title,
                       EXISTS (
                           SELECT 1 FROM improvement_proposal_supports s
                           WHERE s.proposal_id = p.id AND s.user_id = ?
                       ) AS supported_by_me
                FROM improvement_proposals p
                LEFT JOIN users u ON u.id = p.user_id
                LEFT JOIN issue_reports i ON i.id = p.issue_report_id
                ORDER BY p.support_count DESC, p.id DESC
                LIMIT 50
            ''', (user_id,)).fetchall()
        ]
        issues = conn.execute('''
            SELECT id, title, location, trash_type, status
            FROM issue_reports
            ORDER BY id DESC LIMIT 30
        ''').fetchall()
        location_hotspots = conn.execute('''
            SELECT location, COUNT(*) AS report_count,
                   SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END) AS open_count
            FROM issue_reports
            GROUP BY location
            ORDER BY report_count DESC, location
            LIMIT 8
        ''').fetchall()
        return render_template(
            'improvement_proposals.html',
            proposals=proposals,
            issues=issues,
            location_hotspots=location_hotspots,
            proposal_types=PROPOSAL_TYPES,
            form=form_values,
            error_msg=error_msg,
        )
    finally:
        conn.close()


@app.route('/proposals/<int:proposal_id>/support', methods=['POST'])
@user_required
def support_improvement_proposal(proposal_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    user_id = session['user_id']
    conn = get_db()
    try:
        proposal = conn.execute(
            'SELECT id FROM improvement_proposals WHERE id = ?', (proposal_id,)
        ).fetchone()
        if proposal is None:
            return '提案が見つかりません。', 404
        with conn:
            cursor = conn.execute('''
                INSERT OR IGNORE INTO improvement_proposal_supports (proposal_id, user_id)
                VALUES (?, ?)
            ''', (proposal_id, user_id))
            if cursor.rowcount == 1:
                conn.execute('''
                    UPDATE improvement_proposals
                    SET support_count = support_count + 1
                    WHERE id = ?
                ''', (proposal_id,))
                flash('改善提案に賛同（共感）しました。', 'success')
            else:
                flash('この提案にはすでに賛同済みです。', 'info')
        return redirect(url_for('improvement_proposals_board'))
    finally:
        conn.close()


def _load_regional_issue_analytics(conn):
    issues = conn.execute('''
        SELECT i.*, u.name AS reporter_name
        FROM issue_reports i
        LEFT JOIN users u ON u.id = i.user_id
        ORDER BY CASE i.status WHEN 'open' THEN 0 WHEN 'in_progress' THEN 1 ELSE 2 END,
                 i.id DESC
    ''').fetchall()
    proposals = conn.execute('''
        SELECT p.*, u.name AS author_name, i.title AS issue_title
        FROM improvement_proposals p
        LEFT JOIN users u ON u.id = p.user_id
        LEFT JOIN issue_reports i ON i.id = p.issue_report_id
        ORDER BY p.support_count DESC, p.id DESC
    ''').fetchall()
    by_trash_type = conn.execute('''
        SELECT trash_type, COUNT(*) AS count,
               COALESCE(SUM(ai_detected_count), 0) AS ai_total
        FROM issue_reports
        GROUP BY trash_type
        ORDER BY count DESC
    ''').fetchall()
    by_location = conn.execute('''
        SELECT location,
               COUNT(*) AS issue_count,
               SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved_count,
               SUM(CASE WHEN status != 'resolved' THEN 1 ELSE 0 END) AS open_count
        FROM issue_reports
        GROUP BY location
        ORDER BY issue_count DESC, location
    ''').fetchall()
    trash_category_stats = conn.execute('''
        SELECT COALESCE(NULLIF(trash_category, ''), 'ペットボトル・飲料容器') AS category,
               COUNT(*) AS record_count,
               COALESCE(SUM(ai_detected_count), 0) AS ai_total
        FROM activity_history
        WHERE type = 'trash_bin'
        GROUP BY COALESCE(NULLIF(trash_category, ''), 'ペットボトル・飲料容器')
        ORDER BY record_count DESC
    ''').fetchall()
    event_state_changes = conn.execute('''
        SELECT a.id, a.title, a.date, a.participant_role,
               a.before_state, a.after_state, e.location
        FROM activity_history a
        LEFT JOIN events e ON e.id = a.event_id
        WHERE a.type = 'event'
          AND (a.before_state != '' OR a.after_state != '' OR a.participant_role != '')
        ORDER BY a.id DESC
        LIMIT 20
    ''').fetchall()
    return {
        'issues': issues,
        'proposals': proposals,
        'by_trash_type': by_trash_type,
        'by_location': by_location,
        'trash_category_stats': trash_category_stats,
        'event_state_changes': event_state_changes,
    }


@app.route('/admin/issues')
@admin_required
def admin_issues():
    conn = get_db()
    try:
        data = _load_regional_issue_analytics(conn)
        return render_template('admin_issues.html', is_admin=True, **data)
    finally:
        conn.close()


@app.route('/organizer/issues')
@organizer_required
def organizer_issues():
    conn = get_db()
    try:
        data = _load_regional_issue_analytics(conn)
        return render_template('admin_issues.html', is_admin=False, **data)
    finally:
        conn.close()


@app.route('/admin/issues/<int:issue_id>/status', methods=['POST'])
@admin_required
def admin_issue_status_update(issue_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    new_status = (request.form.get('status') or '').strip()
    action_note = (request.form.get('action_note') or '').strip()[:500]
    if new_status not in ('open', 'in_progress', 'resolved'):
        return '不正なステータスです。', 400
    conn = get_db()
    try:
        issue = conn.execute(
            'SELECT * FROM issue_reports WHERE id = ?', (issue_id,)
        ).fetchone()
        if issue is None:
            return '課題報告が見つかりません。', 404
        status_label = {
            'open': '未対応',
            'in_progress': '対応中・現地確認中',
            'resolved': '解決済み',
        }[new_status]
        with conn:
            conn.execute('''
                UPDATE issue_reports
                SET status = ?, action_note = ?, reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (new_status, action_note, session['user_id'], issue_id))
            if new_status == 'resolved' and issue['trash_type'] == 'ごみ箱満杯・破損':
                conn.execute('''
                    UPDATE trash_bins SET bin_status = 'active'
                    WHERE name = ?
                ''', (issue['location'],))
            conn.execute('''
                INSERT INTO user_notifications (
                    user_id, notification_type, title, message
                ) VALUES (?, 'organizer_message', ?, ?)
            ''', (
                issue['user_id'],
                f'課題報告の対応状況更新：{issue["title"]}',
                f'あなたが報告した「{issue["title"]}（{issue["location"]}）」の状況が「{status_label}」に更新されました。'
                + (f'\n対応メモ：{action_note}' if action_note else ''),
            ))
        flash('課題報告の対応状況を更新しました。', 'success')
        return redirect(url_for('admin_issues'))
    finally:
        conn.close()


@app.route('/admin/proposals/<int:proposal_id>/status', methods=['POST'])
@admin_required
def admin_proposal_status_update(proposal_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    new_status = (request.form.get('status') or '').strip()
    admin_comment = (request.form.get('admin_comment') or '').strip()[:500]
    if new_status not in ('proposed', 'under_review', 'adopted', 'completed'):
        return '不正なステータスです。', 400
    conn = get_db()
    try:
        proposal = conn.execute(
            'SELECT * FROM improvement_proposals WHERE id = ?', (proposal_id,)
        ).fetchone()
        if proposal is None:
            return '改善提案が見つかりません。', 404
        with conn:
            conn.execute('''
                UPDATE improvement_proposals
                SET status = ?, admin_comment = ?
                WHERE id = ?
            ''', (new_status, admin_comment, proposal_id))
        flash('改善提案のステータスを更新しました。', 'success')
        return redirect(url_for('admin_issues'))
    finally:
        conn.close()

# ==========================================
# 現場アクション：エコごみ箱（修復・強化完了版）
# ==========================================
@app.route('/trash-bin')
@user_required
@view_mode_required('mobile')
def trash_bin():
    conn = get_db()
    try:
        bins = conn.execute('SELECT * FROM trash_bins ORDER BY name').fetchall()
    finally:
        conn.close()
    selected_bin_id = request.args.get('bin_id', type=int)
    if selected_bin_id is None and bins:
        selected_bin_id = bins[0]['id']
    return render_template(
        'trash_bin.html',
        bins=bins,
        selected_bin_id=selected_bin_id,
        trash_count='',
    )

def _trash_bin_error(
    message, status, bins=None, selected_bin_id=None, trash_count=''
):
    if bins is None:
        conn = get_db()
        try:
            bins = conn.execute('SELECT * FROM trash_bins ORDER BY name').fetchall()
        finally:
            conn.close()
    if selected_bin_id is None and bins:
        selected_bin_id = bins[0]['id']
    return render_template(
        'trash_bin.html',
        error_msg=message,
        bins=bins,
        selected_bin_id=selected_bin_id,
        trash_count=trash_count,
    ), status


def _record_ai_result(
    user_id, result_status, image_path=None, detected_count=None,
    confidence=None, activity_id=None, is_flagged=0, flag_reason=None,
):
    conn = get_db()
    try:
        with conn:
            cursor = conn.execute('''
                INSERT INTO ai_logs (
                    user_id, activity_id, detected_count, confidence,
                    image_path, is_flagged, flag_reason, result_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, activity_id, detected_count, confidence,
                image_path, is_flagged, flag_reason, result_status,
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def _record_duplicate_image_attempt(user_id, original_log_id, image_sha256):
    conn = get_db()
    try:
        with conn:
            conn.execute('''
                INSERT INTO ai_duplicate_attempts (
                    user_id, original_ai_log_id, image_sha256
                ) VALUES (?, ?, ?)
            ''', (user_id, original_log_id, image_sha256))
    finally:
        conn.close()


@app.route('/trash-bin/deposit', methods=['POST'])
@user_required
@view_mode_required('mobile')
def trash_bin_deposit():
    user_id = session['user_id']
    if not validate_csrf():
        return _trash_bin_error('送信内容を確認できませんでした。画面を再読み込みして、もう一度お試しください。', 400)

    raw_count = request.form.get('trash_count', '')
    raw_bin_id = request.form.get('bin_id', '')
    try:
        bin_id = int(raw_bin_id)
    except (TypeError, ValueError):
        return _trash_bin_error('ごみ箱の設置場所を選択してください。', 400)

    conn = get_db()
    try:
        selected_bin = conn.execute(
            'SELECT * FROM trash_bins WHERE id = ?', (bin_id,)
        ).fetchone()
        bins = conn.execute('SELECT * FROM trash_bins ORDER BY name').fetchall()
    finally:
        conn.close()
    if selected_bin is None:
        return _trash_bin_error(
            '選択したごみ箱が見つかりません。設置場所を選び直してください。',
            400,
            bins=bins,
            trash_count=raw_count,
        )
    bin_location = selected_bin['name']
    file = request.files.get('garbage_image')
    
    if not file or file.filename == '':
        return _trash_bin_error(
            '写真を撮影するか、画像を選択してください。',
            400, bins, bin_id, raw_count,
        )
    if not allowed_file(file.filename):
        return _trash_bin_error(
            '対応していないファイル形式です。画像を選択してください。',
            400, bins, bin_id, raw_count,
        )
        
    try:
        img = Image.open(file)
        img.verify()
        file.seek(0)
    except Exception:
        app.logger.exception("画像検証エラー: 不正なファイルがアップロードされました。")
        return _trash_bin_error(
            '画像ファイルが不正か、破損しています。別の写真を選んでください。',
            400, bins, bin_id, raw_count,
        )

    if not raw_count.isdigit():
        return _trash_bin_error(
            'ごみの個数を正しく選択してください。',
            400, bins, bin_id, raw_count,
        )
    user_declared = int(raw_count)
    if user_declared <= 0 or user_declared > 50:
        return _trash_bin_error(
            'ごみの個数は1〜50の範囲で選択してください。',
            400, bins, bin_id, raw_count,
        )

    image_sha256 = hashlib.sha256(file.read()).hexdigest()
    file.seek(0)
    conn = get_db()
    try:
        duplicate_log = conn.execute(
            'SELECT id FROM ai_logs WHERE image_sha256 = ?',
            (image_sha256,),
        ).fetchone()
    finally:
        conn.close()
    if duplicate_log:
        try:
            _record_duplicate_image_attempt(
                user_id, duplicate_log['id'], image_sha256
            )
        except Exception:
            app.logger.exception("重複画像の試行記録を保存できませんでした。")
            return _trash_bin_error(
                '同じ画像の登録を確認しましたが、記録を保存できませんでした。管理者にお問い合わせください。',
                500,
                bins,
                bin_id,
                raw_count,
            )
        return _trash_bin_error(
            'この画像はすでに判定・登録されています。重複登録のためポイントは付与されませんでした。',
            409,
            bins,
            bin_id,
            raw_count,
        )

    detector = get_model()
    if detector is None:
        try:
            _record_ai_result(user_id, 'failed')
        except Exception:
            app.logger.exception("AI利用不可の判定失敗ログを保存できませんでした。")
            return _trash_bin_error(
                'AI判定を開始できず、失敗記録も保存できませんでした。時間をおいて再度お試しください。',
                500,
                bins,
                bin_id,
                raw_count,
            )
        return _trash_bin_error(
            'AIモデルが利用できないため、現在ごみ判定はできません。時間をおいて再度お試しください。',
            503,
            bins,
            bin_id,
            raw_count,
        )

    # 元画像の正しい拡張子（ext）を取り出して維持
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4()}.{ext}"
    image_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    
    try:
        file.save(image_path)
        try:
            results = detector.predict(
                image_path,
                imgsz=640,
                conf=0.25,
                verbose=False,
                max_det=20,
            )
            ai_detected = 0
            conf_total = 0.0
            class_counts = {'bottle': 0, 'cup': 0}
            valid_trash_classes = [39, 41]
            for result in results:
                for box in result.boxes:
                    cls_id = int(box.cls)
                    if cls_id in valid_trash_classes:
                        ai_detected += 1
                        conf_total += float(box.conf) if hasattr(box, 'conf') else 0.8
                        if cls_id == 39:
                            class_counts['bottle'] += 1
                        elif cls_id == 41:
                            class_counts['cup'] += 1
        except Exception:
            app.logger.exception("AI画像判定に失敗しました。")
            try:
                _record_ai_result(
                    user_id,
                    'failed',
                    image_path=image_path,
                )
            except Exception:
                app.logger.exception("AI判定失敗ログを保存できませんでした。")
                if os.path.exists(image_path):
                    os.remove(image_path)
                return _trash_bin_error(
                    'AI判定に失敗し、失敗記録も保存できませんでした。別の画像で再度お試しください。',
                    500,
                    bins,
                    bin_id,
                    raw_count,
                )
            return _trash_bin_error(
                'AI判定に失敗しました。失敗記録を保存しました。別の画像で再度お試しください。',
                503,
                bins,
                bin_id,
                raw_count,
            )

        if ai_detected == 0:
            try:
                _record_ai_result(
                    user_id,
                    'no_detection',
                    image_path=image_path,
                    detected_count=0,
                )
            except Exception:
                app.logger.exception("0件のAI判定結果を保存できませんでした。")
                if os.path.exists(image_path):
                    os.remove(image_path)
                return _trash_bin_error(
                    'AI判定は完了しましたが、結果を保存できませんでした。時間をおいて再度お試しください。',
                    500,
                    bins,
                    bin_id,
                    raw_count,
                )
            return _trash_bin_error(
                'AI判定は完了しましたが、対象のごみは検出されませんでした。0件の判定結果を記録しました。ポイントは付与されていません。',
                422,
                bins,
                bin_id,
                raw_count,
            )

        is_flagged = 1 if user_declared > (ai_detected + 2) else 0
        flag_reason = (
            f'申告数がAI検出数を3個以上上回りました（申告 {user_declared} 個、検出 {ai_detected} 個）'
            if is_flagged else None
        )
        avg_conf = (conf_total / ai_detected) if ai_detected > 0 else 0.0

        # AI検出数を絶対的な獲得ポイントの基準とする（申告改ざん無効化）
        final_trash_count = ai_detected
        points_earned = final_trash_count * 5
        trash_category = (request.form.get('trash_category') or 'ペットボトル・飲料容器').strip()[:100]
        bag_size = (request.form.get('bag_size') or '手持ち・少量（1〜3個）').strip()[:100]
        detected_classes_json = json.dumps(class_counts, ensure_ascii=False)

        conn = get_db()
        try:
            with conn:
                activity_cursor = conn.execute('''
                    INSERT INTO activity_history (
                        user_id, type, title, trash_count, ai_detected_count,
                        user_declared_count, points_earned, trash_category, bag_size
                    )
                    VALUES (?, "trash_bin", ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id, bin_location, final_trash_count, ai_detected,
                    user_declared, points_earned, trash_category, bag_size,
                ))
                activity_id = activity_cursor.lastrowid
                
                conn.execute('''
                    INSERT INTO ai_logs (
                        user_id, activity_id, detected_count, confidence,
                        image_path, image_sha256, is_flagged, flag_reason,
                        result_status, detected_classes_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'detected', ?)
                ''', (
                    user_id, activity_id, ai_detected, avg_conf,
                    image_path, image_sha256, is_flagged, flag_reason,
                    detected_classes_json,
                ))
                
                conn.execute('UPDATE users SET total_points = total_points + ? WHERE id = ?', (points_earned, user_id))
                conn.execute('''
                    INSERT INTO user_notifications (
                        user_id, notification_type, title, message
                    ) VALUES (?, 'activity_completed', ?, ?)
                ''', (
                    user_id,
                    'ごみ捨て完了のお知らせ',
                    f'{bin_location}でごみを{final_trash_count}個記録しました。'
                    f'{points_earned}ポイントを獲得しました。',
                ))
            app.logger.info(
                "ごみ画像判定と活動履歴の保存が完了しました。user_id=%s activity_id=%s database=%s",
                user_id, activity_id, DATABASE
            )
        except sqlite3.IntegrityError:
            duplicate_log = conn.execute(
                'SELECT id FROM ai_logs WHERE image_sha256 = ?',
                (image_sha256,),
            ).fetchone()
            if duplicate_log:
                try:
                    _record_duplicate_image_attempt(
                        user_id, duplicate_log['id'], image_sha256
                    )
                except Exception:
                    app.logger.exception("競合した重複画像の試行記録を保存できませんでした。")
                    if os.path.exists(image_path):
                        os.remove(image_path)
                    return _trash_bin_error(
                        '重複画像を検出しましたが、その試行記録を保存できませんでした。管理者にお問い合わせください。',
                        500,
                        bins,
                        bin_id,
                        raw_count,
                    )
                if os.path.exists(image_path):
                    os.remove(image_path)
                return _trash_bin_error(
                    'この画像はすでに判定・登録されています。重複登録のためポイントは付与されませんでした。',
                    409,
                    bins,
                    bin_id,
                    raw_count,
                )
            if os.path.exists(image_path):
                os.remove(image_path)
            app.logger.exception("画像判定結果の一意制約違反が発生しました。")
            return _trash_bin_error(
                '記録を保存できませんでした。時間をおいて再度お試しください。',
                500,
                bins,
                bin_id,
                raw_count,
            )
        except Exception:
            if os.path.exists(image_path): os.remove(image_path)
            app.logger.exception("データベース保存処理で内部エラーが発生しました。")
            return _trash_bin_error(
                '記録を保存できませんでした。時間をおいて再度お試しください。',
                500,
                bins,
                bin_id,
                raw_count,
            )
        finally:
            conn.close()

    except Exception:
        if os.path.exists(image_path): os.remove(image_path)
        app.logger.exception("ゴミ預け入れ処理中に深刻なエラーが発生しました。")
        return _trash_bin_error(
            '画像を処理できませんでした。時間をおいて再度お試しください。',
            500,
            bins,
            bin_id,
            raw_count,
        )

    flash(f'画像判定が完了し、活動履歴を保存しました（+{points_earned} pt）。', 'success')
    return redirect(url_for('home'))

# ==========================================
# 現場アクション：イベント参加領域（重複防止）
# ==========================================
EVENT_PARTICIPANT_ROLES = (
    'ごみ回収・分別',
    '重点エリア清掃',
    '分別・袋管理サポート',
    '課題記録・写真撮影',
    '声かけ・安全見守り',
)


@app.route('/event/reserve/<int:event_id>', methods=['GET', 'POST'])
@user_required
@view_mode_required('pc')
def event_reserve(event_id):
    user_id = session['user_id']
    conn = get_db()
    try:
        event = conn.execute(
            'SELECT * FROM events WHERE id = ?', (event_id,)
        ).fetchone()
        if not event or event['status'] != 'open' or event['review_status'] != 'approved':
            return 'イベントが見つからないか、募集を終了しています。', 404

        try:
            event_datetime = parse_event_datetime(event['datetime'])
            now = datetime.now(JST)
            upcoming = event_datetime > now
        except (TypeError, ValueError):
            event_datetime = None
            upcoming = False
        if not upcoming:
            return '開催日時を過ぎたイベントは予約できません。', 410
        if event_datetime > now + timedelta(days=365):
            return 'イベントの予約は開催日の1年前から受け付けています。', 400

        reservation = conn.execute('''
            SELECT status, participant_role FROM event_reservations
            WHERE user_id = ? AND event_id = ?
        ''', (user_id, event_id)).fetchone()
        completed = conn.execute('''
            SELECT 1 FROM activity_history
            WHERE user_id = ? AND event_id = ? AND type = 'event'
        ''', (user_id, event_id)).fetchone() is not None
        reserved = reservation is not None and reservation['status'] == 'reserved'
        selected_role = (
            reservation['participant_role']
            if reservation is not None and reservation['participant_role']
            else EVENT_PARTICIPANT_ROLES[0]
        )
        completed = completed or (
            reservation is not None and reservation['status'] == 'completed'
        )

        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400
            if completed:
                return 'このイベントは参加完了済みです。', 409

            action = request.form.get('action', 'reserve')
            if action == 'cancel':
                if not reserved:
                    return '有効な予約がありません。', 409
                with conn:
                    reservation_cursor = conn.execute('''
                        UPDATE event_reservations SET status = 'cancelled'
                        WHERE user_id = ? AND event_id = ? AND status = 'reserved'
                    ''', (user_id, event_id))
                    if reservation_cursor.rowcount != 1:
                        return '予約状態を更新できませんでした。ページを再読み込みしてください。', 409
                    conn.execute('''
                        INSERT INTO user_notifications (
                            user_id, event_id, notification_type, title, message
                        ) VALUES (?, ?, 'reservation_cancelled', ?, ?)
                    ''', (
                        user_id, event_id,
                        f'予約をキャンセルしました：{event["name"]}',
                        f'「{event["name"]}」の予約をキャンセルしました。',
                    ))
                return redirect(url_for('home'))

            if action != 'reserve':
                return '不正な操作です。', 400
            chosen_role = (request.form.get('participant_role') or EVENT_PARTICIPANT_ROLES[0]).strip()
            if chosen_role not in EVENT_PARTICIPANT_ROLES:
                chosen_role = EVENT_PARTICIPANT_ROLES[0]
            try:
                # 予約数の確認と登録を同じ書き込みロック内で行い、定員超過を防ぐ。
                conn.execute('BEGIN IMMEDIATE')
                current_event = conn.execute('''
                    SELECT name, location, capacity, datetime, status, review_status
                    FROM events WHERE id = ?
                ''', (event_id,)).fetchone()
                if (
                    current_event is None
                    or current_event['status'] != 'open'
                    or current_event['review_status'] != 'approved'
                ):
                    conn.rollback()
                    return 'イベントが見つからないか、募集を終了しています。', 404
                try:
                    if parse_event_datetime(current_event['datetime']) <= datetime.now(JST):
                        conn.rollback()
                        return '開催日時を過ぎたイベントは予約できません。', 410
                except (TypeError, ValueError):
                    conn.rollback()
                    return '開催日時を確認できないため、予約を受け付けられません。', 409
                current_reservation = conn.execute('''
                    SELECT status FROM event_reservations
                    WHERE user_id = ? AND event_id = ?
                ''', (user_id, event_id)).fetchone()
                current_reserved = (
                    current_reservation is not None
                    and current_reservation['status'] == 'reserved'
                )
                current_completed = conn.execute('''
                    SELECT 1 FROM activity_history
                    WHERE user_id = ? AND event_id = ? AND type = 'event'
                ''', (user_id, event_id)).fetchone() is not None
                current_completed = current_completed or (
                    current_reservation is not None
                    and current_reservation['status'] == 'completed'
                )
                if current_completed:
                    conn.rollback()
                    return 'このイベントは参加完了済みです。', 409

                if not current_reserved:
                    reserved_count = conn.execute('''
                        SELECT COUNT(*) FROM event_reservations
                        WHERE event_id = ? AND status = 'reserved'
                    ''', (event_id,)).fetchone()[0]
                    if reserved_count >= current_event['capacity']:
                        conn.rollback()
                        return '定員に達しています。', 409
                    if current_reservation is None:
                        conn.execute('''
                            INSERT INTO event_reservations (user_id, event_id, participant_role)
                            VALUES (?, ?, ?)
                        ''', (user_id, event_id, chosen_role))
                    else:
                        conn.execute('''
                            UPDATE event_reservations
                            SET status = 'reserved', participant_role = ?,
                                reserved_at = CURRENT_TIMESTAMP,
                                completed_at = NULL
                            WHERE user_id = ? AND event_id = ? AND status = 'cancelled'
                        ''', (chosen_role, user_id, event_id))
                    conn.execute('''
                        INSERT INTO user_notifications (
                            user_id, event_id, notification_type, title, message
                        ) VALUES (?, ?, 'reservation', ?, ?)
                    ''', (
                        user_id, event_id,
                        f'予約完了：{current_event["name"]}',
                        f'「{current_event["name"]}」を予約しました。\n'
                        f'開催日時：{current_event["datetime"]}\n'
                        f'開催場所：{current_event["location"]}\n'
                        f'参加役割：{chosen_role}',
                    ))
                conn.commit()
            except sqlite3.IntegrityError:
                conn.rollback()
                return '予約状態を更新できませんでした。ページを再読み込みしてください。', 409
            return redirect(url_for(
                'event_reservation_complete', event_id=event_id
            ))

        reserved_count = conn.execute('''
            SELECT COUNT(*) FROM event_reservations
            WHERE event_id = ? AND status = 'reserved'
        ''', (event_id,)).fetchone()[0]
        return render_template(
            'event_reserve.html', event=event,
            reserved=reserved, completed=completed,
            reserved_count=reserved_count,
            participant_roles=EVENT_PARTICIPANT_ROLES,
            selected_role=selected_role,
        )
    finally:
        conn.close()


@app.route('/event/reservation/<int:event_id>/complete')
@user_required
@view_mode_required('pc')
def event_reservation_complete(event_id):
    user_id = session['user_id']
    conn = get_db()
    try:
        event = conn.execute('''
            SELECT e.id, e.name, e.location, e.datetime, e.status,
                   e.review_status, e.latitude, e.longitude
            FROM events e
            JOIN event_reservations r ON r.event_id = e.id
            WHERE e.id = ? AND r.user_id = ?
              AND r.status IN ('reserved', 'completed')
        ''', (event_id, user_id)).fetchone()
        if event is None:
            flash('予約状態を確認できませんでした。予約一覧をご確認ください。', 'info')
            return redirect(url_for('my_reservations'))
        return render_template('event_reservation_complete.html', event=event)
    finally:
        conn.close()


@app.route('/notifications')
@user_required
def user_notifications():
    user_id = session['user_id']
    conn = get_db()
    try:
        _create_due_event_reminders(conn, user_id)
        notifications = conn.execute('''
            SELECT n.*, e.name AS event_name,
                   CASE WHEN n.read_at IS NULL THEN 0 ELSE 1 END AS is_read
            FROM user_notifications n
            LEFT JOIN events e ON e.id = n.event_id
            WHERE n.user_id = ?
            ORDER BY n.created_at DESC, n.id DESC
            LIMIT 100
        ''', (user_id,)).fetchall()
        unread_notification_count = conn.execute('''
            SELECT COUNT(*) FROM user_notifications
            WHERE user_id = ? AND read_at IS NULL
        ''', (user_id,)).fetchone()[0]
        return render_template(
            'notifications.html',
            notifications=notifications,
            unread_notification_count=unread_notification_count,
        )
    finally:
        conn.close()


@app.route('/notifications/<int:notification_id>/read', methods=['POST'])
@user_required
def mark_notification_read(notification_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    conn = get_db()
    try:
        with conn:
            notification = conn.execute('''
                SELECT 1 FROM user_notifications
                WHERE id = ? AND user_id = ?
            ''', (notification_id, session['user_id'])).fetchone()
            if notification is None:
                return '通知が見つかりません。', 404
            conn.execute('''
                UPDATE user_notifications SET read_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ? AND read_at IS NULL
            ''', (notification_id, session['user_id']))
        return redirect(url_for('user_notifications'))
    finally:
        conn.close()


@app.route('/notifications/<int:notification_id>/open', methods=['POST'])
@user_required
def open_notification(notification_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    conn = get_db()
    try:
        event_id = None
        with conn:
            notification = conn.execute('''
                SELECT event_id FROM user_notifications
                WHERE id = ? AND user_id = ?
            ''', (notification_id, session['user_id'])).fetchone()
            if notification is None:
                return '通知が見つかりません。', 404

            conn.execute('''
                UPDATE user_notifications SET read_at = CURRENT_TIMESTAMP
                WHERE id = ? AND user_id = ? AND read_at IS NULL
            ''', (notification_id, session['user_id']))
            if notification['event_id'] is not None:
                event = conn.execute('''
                    SELECT id FROM events
                    WHERE id = ? AND status = 'open'
                      AND review_status = 'approved'
                ''', (notification['event_id'],)).fetchone()
                if event is not None:
                    event_id = event['id']

        if event_id is not None:
            return redirect(url_for('event_reserve', event_id=event_id))
        return redirect(url_for('user_notifications'))
    finally:
        conn.close()


@app.route('/notifications/read-all', methods=['POST'])
@user_required
def mark_all_notifications_read():
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    conn = get_db()
    try:
        with conn:
            conn.execute('''
                UPDATE user_notifications SET read_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND read_at IS NULL
            ''', (session['user_id'],))
        return redirect(url_for('user_notifications'))
    finally:
        conn.close()

def _render_event_live(event, started_at, error_msg=None, status=200, selected_role=None):
    return render_template(
        'event_live.html',
        event=event,
        started_at_epoch=started_at.timestamp() * 1000,
        min_duration_minutes=EVENT_MIN_DURATION_SECONDS // 60,
        location_radius_meters=EVENT_LOCATION_RADIUS_METERS,
        location_check_required=(
            event['latitude'] is not None and event['longitude'] is not None
        ),
        participant_roles=EVENT_PARTICIPANT_ROLES,
        selected_role=selected_role or EVENT_PARTICIPANT_ROLES[0],
        error_msg=error_msg,
    ), status


@app.route('/event/live/<int:event_id>')
@user_required
@view_mode_required('mobile')
def event_live(event_id):
    user_id = session['user_id']
    conn = get_db()
    try:
        event = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
        if not event or event['status'] != 'open' or event['review_status'] != 'approved':
            return "エラー：参加可能なイベントが見つかりません。", 404
        reservation = conn.execute('''
            SELECT status, participant_role FROM event_reservations
            WHERE user_id = ? AND event_id = ?
        ''', (user_id, event_id)).fetchone()
        if reservation is None or reservation['status'] == 'cancelled':
            flash('イベントの予約はPCから行ってください。', 'info')
            return redirect(url_for('home'))
        if reservation['status'] == 'completed':
            return redirect(url_for('home'))
        
        now = datetime.now(JST)
        if parse_event_datetime(event['datetime']) > now:
            flash(
                'イベント開催前のため、活動計測はまだ開始できません。開催日時をご確認ください。',
                'info',
            )
            return redirect(url_for('home'))
        
        # ★ここから修正：古いセッション時刻（12時間以上前など）は破棄して再計測にする
        started_at_key = f'event_started_at_{event_id}'
        try:
            started_at = parse_event_datetime(session.get(started_at_key))
            elapsed = (now - started_at).total_seconds()
            if elapsed < 0 or elapsed > EVENT_MAX_SESSION_DURATION_SECONDS:
                raise ValueError('Session expired')
        except (TypeError, ValueError):
            started_at = now
            session[started_at_key] = started_at.isoformat()

        return _render_event_live(
            event, started_at, selected_role=reservation['participant_role']
        )
    except Exception:
        app.logger.exception("イベントライブ画面の表示エラー")
        return _internal_error_response()
    finally:
        conn.close()

@app.route('/event/complete/<int:event_id>', methods=['POST'])
@user_required
@view_mode_required('mobile')
def event_complete(event_id):
    user_id = session['user_id']
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400

    try:
        duration_val = int(request.form.get('duration', '0'))
        detox_val = int(request.form.get('detox_duration', '0'))
    except (TypeError, ValueError, OverflowError):
        return '活動データの形式が正しくありません。', 400

    if not (
        1 <= duration_val <= 86400
        and 0 <= detox_val <= 1440
    ):
        return '活動データが許容範囲外です。', 400

    started_at = session.get(f'event_started_at_{event_id}')
    try:
        started_at = parse_event_datetime(started_at)
        now = datetime.now(JST)
        elapsed_seconds = (now - started_at).total_seconds()
    except (TypeError, ValueError):
        return 'イベント参加を開始してから完了してください。', 400
    if elapsed_seconds < 0:
        session.pop(f'event_started_at_{event_id}', None)
        return '計測開始時刻が正しくありません。計測を再開してください。', 400
    if elapsed_seconds > EVENT_MAX_SESSION_DURATION_SECONDS:
        session.pop(f'event_started_at_{event_id}', None)
        flash('計測時間の上限（12時間）を超えました。計測を再開してください。', 'error')
        return redirect(url_for('event_live', event_id=event_id))
    if elapsed_seconds < duration_val:
        return '実際に経過した時間より長い活動時間は記録できません。', 400
    gps_data = request.form.get('gps_points')
    if gps_data:
        try:
            gps_points = json.loads(gps_data)
            metrics = calculate_gps_metrics(gps_points, started_at, now)
        except (json.JSONDecodeError, ValueError) as error:
            return str(error), 400
    else:
        gps_points = []
        metrics = {
            'steps': 0, 'distance': 0.0, 'calories': 0,
            'gps_measured': False, 'validated_points': [],
        }
    steps_val = metrics['steps']
    step_source = 'gps_estimated' if metrics['gps_measured'] else 'unmeasured'
    device_steps_raw = request.form.get('device_steps', '')
    if device_steps_raw:
        try:
            device_steps = int(device_steps_raw)
        except (TypeError, ValueError, OverflowError):
            device_steps = -1
        plausible_steps = (
            0 <= device_steps <= elapsed_seconds * MAX_DEVICE_STEPS_PER_SECOND
            and (
                not metrics['gps_measured']
                or metrics['distance'] * 1000 < 100
                or device_steps >= (metrics['distance'] * 1000 / MAX_STEP_STRIDE_M * MIN_STEP_DISTANCE_RATIO)
            )
        )
        if plausible_steps:
            steps_val = device_steps
            step_source = 'device'
    distance_val = metrics['distance']
    calories_val = metrics['calories']
    gps_measured_val = int(metrics['gps_measured'])
    validated_gps_points = metrics['validated_points']

    conn = None
    try:
        conn = get_db()
        
        # 同一イベントへの二重完了・重複ポイントを完全に阻止
        exists = conn.execute('SELECT 1 FROM activity_history WHERE user_id=? AND event_id=?', (user_id, event_id)).fetchone()
        if exists:
            conn.close()
            return "エラー：このイベントにはすでに参加・完了済みです。", 409
            
        event = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
        if not event or event['status'] != 'open' or event['review_status'] != 'approved':
            conn.close()
            return "エラー：参加可能なイベントが見つかりません。", 404
        if parse_event_datetime(event['datetime']) > datetime.now(JST):
            conn.close()
            flash(
                'イベント開催前のため、活動は完了できません。開催日時をご確認ください。',
                'info',
            )
            return redirect(url_for('home'))
        reservation = conn.execute('''
            SELECT status, participant_role FROM event_reservations
            WHERE user_id = ? AND event_id = ?
        ''', (user_id, event_id)).fetchone()
        if reservation is None or reservation['status'] != 'reserved':
            conn.close()
            return '計測を完了するにはイベント予約が必要です。', 403

        if elapsed_seconds < EVENT_MIN_DURATION_SECONDS:
            conn.close()
            minimum_minutes = EVENT_MIN_DURATION_SECONDS // 60
            return _render_event_live(
                event,
                started_at,
                error_msg=f'イベント完了には最低{minimum_minutes}分間の活動計測が必要です。計測を続けてください。',
                status=400,
                selected_role=reservation['participant_role'],
            )
        verified_duration = min(int(elapsed_seconds), 86400)
        location_configured = (
            event['latitude'] is not None or event['longitude'] is not None
        )
        if location_configured:
            if event['latitude'] is None or event['longitude'] is None:
                conn.close()
                return 'イベント開催地点の設定が不完全なため、完了できません。', 409
            try:
                event_latitude = float(event['latitude'])
                event_longitude = float(event['longitude'])
            except (TypeError, ValueError, OverflowError):
                conn.close()
                return 'イベント開催地点の設定が不正なため、完了できません。', 409
            if not (
                math.isfinite(event_latitude)
                and math.isfinite(event_longitude)
                and -90 <= event_latitude <= 90
                and -180 <= event_longitude <= 180
            ):
                conn.close()
                return 'イベント開催地点の設定が不正なため、完了できません。', 409
            within_event_radius = any(
                point['accuracy'] < 30
                and now.timestamp() - 120 <= point['timestamp'] <= now.timestamp() + 10
                and haversine_m(
                    {'lat': point['lat'], 'lon': point['lon']},
                    {'lat': event_latitude, 'lon': event_longitude},
                ) <= EVENT_LOCATION_RADIUS_METERS
                for point in validated_gps_points
            )
            if not within_event_radius:
                conn.close()
                return _render_event_live(
                    event,
                    started_at,
                    error_msg=(
                        f'完了直前2分以内のイベント地点から{EVENT_LOCATION_RADIUS_METERS}m以内のGPS位置情報を確認できませんでした。'
                        '開催地点でGPS計測を再開し、位置情報が更新されてから完了してください。'
                    ),
                    status=400,
                    selected_role=reservation['participant_role'],
                )

        bonus_points = event['bonus_points']
        participant_role = (
            request.form.get('participant_role')
            or reservation['participant_role']
            or EVENT_PARTICIPANT_ROLES[0]
        ).strip()[:100]
        before_state = (request.form.get('before_state') or '').strip()[:100]
        after_state = (request.form.get('after_state') or '').strip()[:100]
        
        with conn:
            reservation_cursor = conn.execute('''
                UPDATE event_reservations
                SET status = 'completed', completed_at = CURRENT_TIMESTAMP,
                    participant_role = ?
                WHERE user_id = ? AND event_id = ? AND status = 'reserved'
            ''', (participant_role, user_id, event_id))
            if reservation_cursor.rowcount != 1:
                raise sqlite3.IntegrityError('イベント予約状態が変更されています。')

            activity_cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, event_id, type, title,
                    duration, steps, distance, calories, gps_measured,
                    step_source, detox_duration, points_earned,
                    participant_role, before_state, after_state
                )
                VALUES (?, ?, 'event', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id,
                event_id,
                f"イベント参加: {event['name']}",
                verified_duration,
                steps_val,
                distance_val,
                calories_val,
                gps_measured_val,
                step_source,
                detox_val,
                bonus_points,
                participant_role,
                before_state,
                after_state,
            ))
            
            conn.execute('UPDATE users SET total_points = total_points + ? WHERE id = ?', (bonus_points, user_id))
            conn.execute('''
                INSERT INTO user_notifications (
                    user_id, event_id, notification_type, title, message
                ) VALUES (?, ?, 'activity_completed', ?, ?)
            ''', (
                user_id, event_id,
                f'イベント参加完了：{event["name"]}',
                f'「{event["name"]}」の活動が完了しました。'
                f'{bonus_points}ポイントを獲得しました。',
            ))
            
        activity_id = activity_cursor.lastrowid
        session.pop(f'event_started_at_{event_id}', None)
        conn.close()
        return redirect(url_for('event_result', activity_id=activity_id))
    except Exception:
        app.logger.exception("イベント完了処理中に内部エラーが発生しました。")
        return _internal_error_response()
    finally:
        if conn is not None:
            conn.close()

@app.route('/event/result/<int:activity_id>')
@user_required
@view_mode_required('mobile')
def event_result(activity_id):
    conn = get_db()
    try:
        row = conn.execute('''
            SELECT a.*, e.name AS event_name, e.location AS event_location,
                   e.bonus_points AS event_bonus_points,
                   e.latitude AS event_latitude, e.longitude AS event_longitude
            FROM activity_history a
            LEFT JOIN events e ON e.id = a.event_id
            WHERE a.id = ? AND a.user_id = ? AND a.type = 'event'
        ''', (activity_id, session['user_id'])).fetchone()
        feedback = conn.execute(
            '''SELECT action_status, action_note, reviewed_at
               FROM event_feedback WHERE activity_id = ? AND user_id = ?''',
            (activity_id, session['user_id']),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return '活動結果が見つかりません。', 404

    activity = dict(row)
    duration = activity['duration'] or 0
    hours, remainder = divmod(duration, 3600)
    minutes, seconds = divmod(remainder, 60)
    activity['duration_display'] = f'{hours:02d}:{minutes:02d}:{seconds:02d}'
    event = {
        'name': activity['event_name'] or activity['title'],
        'location': activity['event_location'] or '',
        'bonus_points': activity['points_earned'] or 0,
        'latitude': activity['event_latitude'],
        'longitude': activity['event_longitude'],
    }
    return render_template(
        'event_result.html', activity=activity, event=event,
        feedback_submitted=feedback is not None,
        feedback_response=feedback,
        feedback_status_labels={
            'pending': '確認中',
            'planned': '対応予定',
            'addressed': '対応済み',
            'not_planned': '今回は対応しない',
        },
    )


@app.route('/event/survey/<int:activity_id>', methods=['GET', 'POST'])
@user_required
@view_mode_required('mobile')
def event_survey(activity_id):
    user_id = session['user_id']
    conn = get_db()
    try:
        activity = conn.execute('''
            SELECT a.id, a.event_id, e.name AS event_name
            FROM activity_history a
            JOIN events e ON e.id = a.event_id
            WHERE a.id = ? AND a.user_id = ? AND a.type = 'event'
        ''', (activity_id, user_id)).fetchone()
        if activity is None:
            return 'イベント参加記録が見つかりません。', 404

        existing = conn.execute(
            'SELECT 1 FROM event_feedback WHERE activity_id = ? AND user_id = ?',
            (activity_id, user_id),
        ).fetchone()
        if existing:
            flash('アンケートは回答済みです。ご協力ありがとうございます。', 'info')
            return redirect(url_for('event_result', activity_id=activity_id))

        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400
            try:
                satisfaction = int(request.form.get('satisfaction', ''))
            except (TypeError, ValueError):
                return '満足度を選択してください。', 400
            time_fit = request.form.get('time_fit', '')
            next_participation = request.form.get('next_participation', '')
            comment = request.form.get('comment', '').strip()
            noticed_issue = request.form.get('noticed_issue', '').strip()[:500]
            suspected_cause = request.form.get('suspected_cause', '').strip()[:500]
            collaboration_note = request.form.get('collaboration_note', '').strip()[:500]
            next_improvement = request.form.get('next_improvement', '').strip()[:500]
            if satisfaction not in range(1, 6):
                return '満足度を選択してください。', 400
            if time_fit not in {'short', 'just_right', 'long'}:
                return '活動時間について選択してください。', 400
            if next_participation not in {'yes', 'maybe', 'no'}:
                return '次回参加の意向を選択してください。', 400
            if len(comment) > 500:
                return 'コメントは500文字以内で入力してください。', 400

            try:
                with conn:
                    conn.execute('''
                        INSERT INTO event_feedback (
                            activity_id, user_id, event_id, satisfaction,
                            time_fit, next_participation, comment,
                            noticed_issue, suspected_cause,
                            collaboration_note, next_improvement
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        activity_id, user_id, activity['event_id'],
                        satisfaction, time_fit, next_participation, comment,
                        noticed_issue, suspected_cause,
                        collaboration_note, next_improvement,
                    ))
            except sqlite3.IntegrityError:
                flash('アンケートはすでに回答されています。', 'info')
                return redirect(url_for('event_result', activity_id=activity_id))

            flash('アンケートへのご協力ありがとうございます。', 'success')
            return redirect(url_for('event_result', activity_id=activity_id))

        return render_template('event_survey.html', activity=activity)
    finally:
        conn.close()

@app.route('/admin/ai/image/<path:filename>')
@admin_required
def admin_ai_image(filename):
    safe_name = os.path.basename(filename)
    if safe_name != filename or not re.fullmatch(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:png|jpg|jpeg|gif|webp)',
        safe_name,
        re.IGNORECASE,
    ):
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, safe_name)

# ==========================================
# 管理者専用スコープ（認可防衛・統計・ログ監視）
# ==========================================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db()
    try:
        stats = conn.execute('''
            SELECT
                (SELECT COUNT(*) FROM users) AS users_total,
                (SELECT COUNT(*) FROM ai_logs
                 WHERE date(created_at, '+9 hours') = date('now', '+9 hours')) AS ai_count,
                (SELECT COUNT(*) FROM ai_logs
                 WHERE is_flagged = 1 AND date(created_at, '+9 hours') = date('now', '+9 hours')) AS flags,
                (SELECT COUNT(*) FROM activity_history
                 WHERE type = 'event' AND date(date, '+9 hours') = date('now', '+9 hours')) AS events_today,
                (SELECT COUNT(*) FROM events
                 WHERE review_status IN ('pending', 'reviewing')) AS events_pending_review,
                (SELECT COUNT(*) FROM organizer_applications
                 WHERE status = 'pending') AS organizer_applications_pending,
                (SELECT COUNT(*) FROM organizations
                 WHERE status = 'approved') AS approved_organizations,
                (SELECT COUNT(*) FROM reward_history
                 WHERE item_id = 'coffee' AND date(created_at, '+9 hours') = date('now', '+9 hours')) AS local_rewards,
                (SELECT COUNT(*) FROM reward_history
                 WHERE item_id = 'shop' AND date(created_at, '+9 hours') = date('now', '+9 hours')) AS universal_rewards,
                (SELECT COUNT(*) FROM reward_history
                 WHERE item_id = 'donation' AND date(created_at, '+9 hours') = date('now', '+9 hours')) AS premium_rewards,
                (SELECT COUNT(*) FROM reward_history
                 WHERE date(created_at, '+9 hours') = date('now', '+9 hours')) AS total_rewards
        ''').fetchone()
        return render_template('admin_dashboard.html', stats=stats)
    finally:
        conn.close()


@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    conn = get_db()
    try:
        summary = conn.execute('''
            SELECT COUNT(*) AS responses,
                   ROUND(AVG(satisfaction), 1) AS average_satisfaction,
                   SUM(CASE WHEN next_participation = 'yes' THEN 1 ELSE 0 END) AS yes_count,
                   SUM(CASE WHEN next_participation = 'maybe' THEN 1 ELSE 0 END) AS maybe_count,
                   SUM(CASE WHEN next_participation = 'no' THEN 1 ELSE 0 END) AS no_count,
                   SUM(CASE WHEN trim(comment) <> '' THEN 1 ELSE 0 END) AS comment_count
            FROM event_feedback
        ''').fetchone()
        events = conn.execute('''
            SELECT e.id, e.name, e.datetime, e.location,
                   COUNT(f.id) AS responses,
                   ROUND(AVG(f.satisfaction), 1) AS average_satisfaction,
                   SUM(CASE WHEN f.next_participation = 'yes' THEN 1 ELSE 0 END) AS yes_count,
                   SUM(CASE WHEN f.next_participation = 'maybe' THEN 1 ELSE 0 END) AS maybe_count,
                   SUM(CASE WHEN f.next_participation = 'no' THEN 1 ELSE 0 END) AS no_count
            FROM events e
            JOIN event_feedback f ON f.event_id = e.id
            GROUP BY e.id
            ORDER BY MAX(f.submitted_at) DESC, e.id DESC
        ''').fetchall()
        comments = conn.execute('''
            SELECT f.comment, f.satisfaction, f.next_participation,
                   f.submitted_at, e.id AS event_id, e.name AS event_name
            FROM event_feedback f
            JOIN events e ON e.id = f.event_id
            WHERE trim(f.comment) <> ''
            ORDER BY f.submitted_at DESC, f.id DESC
            LIMIT 30
        ''').fetchall()
        return render_template(
            'admin_feedback.html', summary=summary,
            events=events, comments=comments,
        )
    finally:
        conn.close()


def _verification_item(
    conn, current_states, target_type, row, value, user_name
):
    verification = get_verification_state(
        conn, target_type, row, current_states
    )
    return {
        'target_type': target_type,
        'target_id': row['id'],
        'label': VERIFICATION_DATA_TYPES[target_type],
        'value': value,
        'user_name': user_name or 'ユーザー情報なし',
        'date': row['date'] if 'date' in row.keys() else row['created_at'],
        'stale': verification['stale'],
        'reviewer_id': verification['reviewer_id'],
        'reviewer_name': verification['reviewer_name'],
        'reviewed_at': verification['reviewed_at'],
        'review_note': verification['review_note'],
        'image_url': None,
        'status': verification['status'] if value is not None else 'unrecorded',
        'reviewable': value is not None,
    }


@app.route('/admin/activity-verifications')
@admin_required
def admin_activity_verifications():
    conn = get_db()
    try:
        current_states = load_verification_states(conn)
        items = []
        logs = conn.execute('''
            SELECT l.*, u.name AS user_name, a.title AS activity_title
            FROM ai_logs l
            LEFT JOIN users u ON u.id = l.user_id
            LEFT JOIN activity_history a ON a.id = l.activity_id
            ORDER BY l.created_at DESC, l.id DESC
        ''').fetchall()
        for log in logs:
            verification = get_verification_state(
                conn, 'ai_result', log, current_states
            )
            item = {
                'target_type': 'ai_result',
                'target_id': log['id'],
                'label': VERIFICATION_DATA_TYPES['ai_result'],
                'value': (
                    f"{log['detected_count']} 個 / 信頼度 "
                    f"{round(float(log['confidence'] or 0) * 100, 1)}%"
                    if log['result_status'] != 'failed'
                    else '判定失敗'
                ),
                'user_name': log['user_name'] or 'ユーザー情報なし',
                'date': log['created_at'],
                'status': (
                    'failed'
                    if log['result_status'] == 'failed'
                    else verification['status']
                ),
                'stale': verification['stale'],
                'reviewer_id': verification['reviewer_id'],
                'reviewer_name': verification['reviewer_name'],
                'reviewed_at': verification['reviewed_at'],
                'review_note': verification['review_note'],
                'image_url': None,
                'reviewable': log['result_status'] != 'failed',
                'result_status': log['result_status'],
                'detail_url': url_for('admin_ai_log_detail', log_id=log['id']),
                'activity_title': log['activity_title'],
            }
            image_path = log['image_path'] or ''
            image_name = os.path.basename(image_path)
            if (
                image_name
                and image_name == image_path.replace('\\', '/').rsplit('/', 1)[-1]
                and allowed_file(image_name)
            ):
                item['image_url'] = url_for(
                    'admin_ai_image', filename=image_name
                )
            items.append(item)

        declarations = conn.execute('''
            SELECT a.*, u.name AS user_name
            FROM activity_history a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.type = 'trash_bin' AND a.user_declared_count > 0
            ORDER BY a.date DESC, a.id DESC
        ''').fetchall()
        for activity in declarations:
            items.append(_verification_item(
                conn,
                current_states,
                'user_declaration',
                activity,
                f"{activity['user_declared_count']} 個",
                activity['user_name'],
            ))

        gps_activities = conn.execute('''
            SELECT a.*, u.name AS user_name
            FROM activity_history a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.type = 'event' AND a.gps_measured = 1
            ORDER BY a.date DESC, a.id DESC
        ''').fetchall()
        gps_fields = {
            'gps_distance': ('distance', lambda value: f'{value:.3f} km'),
            'gps_steps': ('steps', lambda value: f'{value} 歩'),
            'gps_calories': ('calories', lambda value: f'{value} kcal'),
        }
        for activity in gps_activities:
            for target_type, (field, format_value) in gps_fields.items():
                metric_value = activity[field]
                items.append(_verification_item(
                    conn,
                    current_states,
                    target_type,
                    activity,
                    format_value(metric_value) if metric_value is not None else None,
                    activity['user_name'],
                ))

        items.sort(key=lambda item: (item['date'] or '', item['target_id']), reverse=True)
        summary = {
            target_type: {
                'label': label,
                'total': 0,
                'unreviewed': 0,
                'confirmed': 0,
                'correction_required': 0,
                'failed': 0,
                'unrecorded': 0,
            }
            for target_type, label in VERIFICATION_DATA_TYPES.items()
        }
        for item in items:
            summary[item['target_type']]['total'] += 1
            summary[item['target_type']][item['status']] += 1
        unclassified_declarations = conn.execute('''
            SELECT COUNT(*) FROM activity_history
            WHERE type = 'trash_bin'
                AND (user_declared_count IS NULL OR user_declared_count <= 0)
        ''').fetchone()[0]
        return render_template(
            'admin_activity_verifications.html',
            items=items,
            summary=summary,
            unclassified_declarations=unclassified_declarations,
        )
    finally:
        conn.close()


@app.route(
    '/admin/activity-verifications/<target_type>/<int:target_id>',
    methods=['POST'],
)
@admin_required
def update_activity_verification(target_type, target_id):
    if target_type not in VERIFICATION_DATA_TYPES:
        abort(404)
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400

    status = request.form.get('status', '')
    review_note = request.form.get('review_note', '').strip()
    if status not in ('unreviewed', 'confirmed', 'correction_required'):
        return '不正な確認状態です。', 400
    if status == 'correction_required' and not review_note:
        return '要修正にする場合は理由を入力してください。', 400
    if len(review_note) > 1000:
        return '確認メモは1000文字以内で入力してください。', 400

    conn = get_db()
    try:
        if target_type == 'ai_result':
            target = conn.execute(
                'SELECT * FROM ai_logs WHERE id = ?', (target_id,)
            ).fetchone()
            if target is None:
                abort(404)
            if target['result_status'] == 'failed':
                return '判定に失敗したAIログは確認できません。', 409
            ai_log_id = target_id
            activity_id = None
        else:
            target = conn.execute(
                'SELECT * FROM activity_history WHERE id = ?', (target_id,)
            ).fetchone()
            if target is None:
                abort(404)
            if target_type == 'user_declaration':
                valid_target = (
                    target['type'] == 'trash_bin'
                    and target['user_declared_count'] is not None
                    and target['user_declared_count'] > 0
                )
            else:
                valid_target = (
                    target['type'] == 'event'
                    and target['gps_measured'] == 1
                    and target[{
                        'gps_distance': 'distance',
                        'gps_steps': 'steps',
                        'gps_calories': 'calories',
                    }[target_type]] is not None
                )
            if not valid_target:
                abort(404)
            ai_log_id = None
            activity_id = target_id

        fingerprint = verification_fingerprint(target_type, target)
        with conn:
            conn.execute('''
                DELETE FROM activity_verifications
                WHERE target_type = ?
                    AND ((ai_log_id = ?) OR (activity_id = ?))
            ''', (target_type, ai_log_id, activity_id))
            if status != 'unreviewed':
                conn.execute('''
                    INSERT INTO activity_verifications (
                        target_type, activity_id, ai_log_id, status,
                        reviewer_id, review_note, source_fingerprint
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    target_type, activity_id, ai_log_id, status,
                    session['user_id'], review_note or None, fingerprint,
                ))
            conn.execute('''
                INSERT INTO activity_verification_history (
                    target_type, activity_id, ai_log_id, status,
                    reviewer_id, review_note, source_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                target_type, activity_id, ai_log_id, status,
                session['user_id'], review_note or None, fingerprint,
            ))
        flash('確認状態を更新しました。', 'success')
        return redirect(
            url_for('admin_activity_verifications')
            + f'#{target_type}-{target_id}'
        )
    finally:
        conn.close()


@app.route('/admin/activity-report')
@admin_required
def admin_activity_report():
    conn = get_db()
    try:
        current_states = load_verification_states(conn)
        verification_summary = {
            target_type: {
                'label': label,
                'confirmed': 0,
                'unreviewed': 0,
                'correction_required': 0,
                'failed': 0,
                'unrecorded': 0,
            }
            for target_type, label in VERIFICATION_DATA_TYPES.items()
        }
        recent_ai_logs = conn.execute('''
            SELECT l.*
            FROM ai_logs l
            LEFT JOIN activity_history a ON a.id = l.activity_id
            WHERE date(COALESCE(a.date, l.created_at), '+9 hours')
                    >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(COALESCE(a.date, l.created_at), '+9 hours') <= date('now', '+9 hours')
        ''').fetchall()
        for log in recent_ai_logs:
            verification = get_verification_state(
                conn, 'ai_result', log, current_states
            )
            review_status = (
                'failed'
                if log['result_status'] == 'failed'
                else verification['status']
            )
            verification_summary['ai_result'][review_status] += 1

        recent_declarations = conn.execute('''
            SELECT * FROM activity_history
            WHERE type = 'trash_bin' AND user_declared_count > 0
                AND date(date, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(date, '+9 hours') <= date('now', '+9 hours')
        ''').fetchall()
        for activity in recent_declarations:
            verification = get_verification_state(
                conn, 'user_declaration', activity, current_states
            )
            verification_summary['user_declaration'][verification['status']] += 1

        recent_gps = conn.execute('''
            SELECT * FROM activity_history
            WHERE type = 'event' AND gps_measured = 1
                AND date(date, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(date, '+9 hours') <= date('now', '+9 hours')
        ''').fetchall()
        gps_fields = {
            'gps_distance': 'distance',
            'gps_steps': 'steps',
            'gps_calories': 'calories',
        }
        for activity in recent_gps:
            for target_type, field in gps_fields.items():
                if activity[field] is None:
                    verification_summary[target_type]['unrecorded'] += 1
                    continue
                verification = get_verification_state(
                    conn, target_type, activity, current_states
                )
                verification_summary[target_type][verification['status']] += 1

        unclassified_declaration_count = conn.execute('''
            SELECT COUNT(*) FROM activity_history
            WHERE type = 'trash_bin'
                AND (user_declared_count IS NULL OR user_declared_count <= 0)
                AND date(date, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(date, '+9 hours') <= date('now', '+9 hours')
        ''').fetchone()[0]
        ai_result_summary = conn.execute('''
            SELECT COUNT(*) AS result_count,
                   SUM(CASE WHEN result_status = 'detected' THEN 1 ELSE 0 END)
                       AS detected_count,
                   SUM(CASE WHEN result_status = 'no_detection' THEN 1 ELSE 0 END)
                       AS no_detection_count,
                   SUM(CASE WHEN result_status = 'failed' THEN 1 ELSE 0 END)
                       AS failed_count,
                   COALESCE(SUM(CASE
                       WHEN result_status IN ('detected', 'no_detection')
                           THEN COALESCE(detected_count, 0)
                       ELSE 0
                   END), 0) AS image_detection_total
            FROM ai_logs
            WHERE date(created_at, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(created_at, '+9 hours') <= date('now', '+9 hours')
        ''').fetchone()
        ai_result_monthly = conn.execute('''
            SELECT strftime('%Y-%m', date(created_at, '+9 hours')) AS month,
                   COUNT(*) AS result_count,
                   SUM(CASE WHEN result_status = 'detected' THEN 1 ELSE 0 END)
                       AS detected_count,
                   SUM(CASE WHEN result_status = 'no_detection' THEN 1 ELSE 0 END)
                       AS no_detection_count,
                   SUM(CASE WHEN result_status = 'failed' THEN 1 ELSE 0 END)
                       AS failed_count,
                   COALESCE(SUM(CASE
                       WHEN result_status IN ('detected', 'no_detection')
                           THEN COALESCE(detected_count, 0)
                       ELSE 0
                   END), 0) AS image_detection_total
            FROM ai_logs
            WHERE date(created_at, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(created_at, '+9 hours') <= date('now', '+9 hours')
            GROUP BY strftime('%Y-%m', date(created_at, '+9 hours'))
            ORDER BY month DESC
        ''').fetchall()
        activity_data_cte = '''
            WITH linked_ai AS (
                SELECT activity_id,
                       SUM(CASE
                           WHEN result_status IN ('detected', 'no_detection')
                               THEN COALESCE(detected_count, 0)
                           ELSE 0
                       END) AS detected_count,
                       SUM(CASE
                           WHEN result_status IN ('detected', 'no_detection')
                               THEN 1
                           ELSE 0
                       END) AS result_count,
                       SUM(CASE WHEN result_status = 'failed' THEN 1 ELSE 0 END)
                           AS failed_count
                FROM ai_logs
                WHERE activity_id IS NOT NULL
                GROUP BY activity_id
            ),
            activity_data AS (
                SELECT a.*,
                       l.activity_id AS ai_log_activity_id,
                       CASE
                           WHEN a.type = 'trash_bin' AND l.result_count > 0
                               THEN l.detected_count
                       END AS report_ai_detected_count,
                       CASE
                           WHEN a.type = 'trash_bin' THEN COALESCE(l.result_count, 0)
                           ELSE 0
                       END AS report_ai_result_count,
                       CASE
                           WHEN a.type = 'trash_bin' THEN COALESCE(l.failed_count, 0)
                           ELSE 0
                       END AS report_ai_failed_count,
                       CASE
                           WHEN a.type = 'trash_bin'
                               AND l.activity_id IS NOT NULL
                               AND a.user_declared_count > 0
                               THEN a.user_declared_count
                       END AS report_user_declared_count
                FROM activity_history a
                LEFT JOIN linked_ai l ON l.activity_id = a.id
                WHERE date(a.date, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                    AND date(a.date, '+9 hours') <= date('now', '+9 hours')
            )
        '''
        summary = conn.execute(activity_data_cte + '''
            SELECT COUNT(*) AS activity_count,
                   COUNT(DISTINCT user_id) AS active_users,
                   COALESCE(SUM(points_earned), 0) AS points_earned,
                   SUM(CASE WHEN type = 'event' THEN 1 ELSE 0 END) AS event_count,
                   SUM(CASE WHEN type = 'trash_bin' THEN 1 ELSE 0 END) AS trash_record_count,
                   COALESCE(SUM(CASE
                       WHEN report_ai_detected_count IS NOT NULL
                           THEN report_ai_detected_count
                       ELSE 0
                   END), 0) AS ai_detected_count,
                   COALESCE(SUM(report_ai_result_count), 0) AS ai_record_count,
                   COALESCE(SUM(report_ai_failed_count), 0) AS ai_failed_count,
                   SUM(CASE
                       WHEN type = 'trash_bin' AND report_ai_result_count = 0
                           THEN 1
                       ELSE 0
                   END) AS ai_unclassified_count,
                   COALESCE(SUM(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN report_user_declared_count
                       ELSE 0
                   END), 0) AS user_declared_count,
                   COUNT(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN 1
                   END) AS user_declared_record_count,
                   SUM(CASE
                       WHEN type = 'trash_bin'
                           AND report_user_declared_count IS NULL
                           THEN 1
                       ELSE 0
                   END) AS user_declared_unclassified_count
            FROM activity_data
        ''').fetchone()
        monthly = conn.execute(activity_data_cte + '''
            SELECT strftime('%Y-%m', date(date, '+9 hours')) AS month,
                   COUNT(*) AS activity_count,
                   COUNT(DISTINCT user_id) AS active_users,
                   COALESCE(SUM(points_earned), 0) AS points_earned,
                   SUM(CASE WHEN type = 'event' THEN 1 ELSE 0 END) AS event_count,
                   SUM(CASE WHEN type = 'trash_bin' THEN 1 ELSE 0 END) AS trash_record_count,
                   COALESCE(SUM(CASE
                       WHEN report_ai_detected_count IS NOT NULL
                           THEN report_ai_detected_count
                       ELSE 0
                   END), 0) AS ai_detected_count,
                   COALESCE(SUM(report_ai_result_count), 0) AS ai_record_count,
                   COALESCE(SUM(report_ai_failed_count), 0) AS ai_failed_count,
                   SUM(CASE
                       WHEN type = 'trash_bin' AND report_ai_result_count = 0
                           THEN 1
                       ELSE 0
                   END) AS ai_unclassified_count,
                   COALESCE(SUM(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN report_user_declared_count
                       ELSE 0
                   END), 0) AS user_declared_count,
                   COUNT(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN 1
                   END) AS user_declared_record_count,
                   SUM(CASE
                       WHEN type = 'trash_bin'
                           AND report_user_declared_count IS NULL
                           THEN 1
                       ELSE 0
                   END) AS user_declared_unclassified_count
            FROM activity_data
            GROUP BY strftime('%Y-%m', date(date, '+9 hours'))
            ORDER BY month DESC
        ''').fetchall()
        event_activity = conn.execute('''
            SELECT COALESCE(e.name, a.title, 'イベント名未登録') AS event_name,
                   COALESCE(e.location, '—') AS location,
                   COUNT(DISTINCT a.user_id) AS participant_count,
                   COUNT(*) AS participation_record_count,
                   COALESCE(SUM(a.points_earned), 0) AS points_earned
            FROM activity_history a
            LEFT JOIN events e ON e.id = a.event_id
            WHERE a.type = 'event'
                AND date(a.date, '+9 hours') >= date('now', '+9 hours', 'start of month', '-11 months')
                AND date(a.date, '+9 hours') <= date('now', '+9 hours')
            GROUP BY a.event_id, e.name, e.location, a.title
            ORDER BY participant_count DESC, event_name
        ''').fetchall()
        trash_locations = conn.execute(activity_data_cte + '''
            SELECT COALESCE(NULLIF(title, ''), '場所未登録') AS location,
                   COUNT(*) AS record_count,
                   COUNT(DISTINCT user_id) AS user_count,
                   COALESCE(SUM(CASE
                       WHEN report_ai_detected_count IS NOT NULL
                           THEN report_ai_detected_count
                       ELSE 0
                   END), 0) AS ai_detected_count,
                   COALESCE(SUM(report_ai_result_count), 0) AS ai_record_count,
                   COALESCE(SUM(report_ai_failed_count), 0) AS ai_failed_count,
                   SUM(CASE
                       WHEN report_ai_result_count = 0 THEN 1
                       ELSE 0
                   END) AS ai_unclassified_count,
                   COALESCE(SUM(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN report_user_declared_count
                       ELSE 0
                   END), 0) AS user_declared_count,
                   COUNT(CASE
                       WHEN report_user_declared_count IS NOT NULL
                           THEN 1
                   END) AS user_declared_record_count,
                   SUM(CASE
                       WHEN report_user_declared_count IS NULL
                           THEN 1
                       ELSE 0
                   END) AS user_declared_unclassified_count
            FROM activity_data
            WHERE type = 'trash_bin'
            GROUP BY COALESCE(NULLIF(title, ''), '場所未登録')
            ORDER BY record_count DESC, location
        ''').fetchall()
        return render_template(
            'admin_activity_report.html',
            summary=summary,
            monthly=monthly,
            event_activity=event_activity,
            trash_locations=trash_locations,
            verification_summary=verification_summary,
            unclassified_declaration_count=unclassified_declaration_count,
            ai_result_summary=ai_result_summary,
            ai_result_monthly=ai_result_monthly,
        )
    finally:
        conn.close()

@app.route('/admin')
@admin_required
def admin_index():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/rewards')
@admin_required
def admin_rewards():
    conn = get_db()
    try:
        counts = {
            row['item_id']: row['exchange_count']
            for row in conn.execute('''
                SELECT item_id, COUNT(*) AS exchange_count
                FROM reward_history GROUP BY item_id
            ''').fetchall()
        }
    finally:
        conn.close()

    local_rewards = [
        {
            'id': item_id,
            'name': REWARD_ITEMS[item_id]['name'],
            'cost': REWARD_ITEMS[item_id]['cost'],
            'description': description,
            'exchange_count': counts.get(item_id, 0),
        }
        for item_id, description in (
            ('coffee', '地域の提携カフェで利用できる特典です。'),
            ('donation', '地域の緑化活動へのポイント寄付です。'),
        )
    ]
    premium = {
        'cost': '-',
        'description': '現在、商品券区分の特典は登録されていません。',
    }
    return render_template(
        'admin_rewards.html', premium=premium,
        universal_rewards=[], local_rewards=local_rewards
    )

@app.route('/admin/ai')
@admin_required
def admin_ai_logs():
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT l.*, u.name AS user_name, u.email AS email
            FROM ai_logs l
            LEFT JOIN users u ON u.id = l.user_id
            ORDER BY l.id DESC
        ''').fetchall()
    finally:
        conn.close()
    logs = [_prepare_ai_log(row) for row in rows]
    return render_template('admin_ai_logs.html', logs=logs)

@app.route('/admin/ai/flags')
@admin_required
def admin_ai_flags():
    conn = get_db()
    try:
        rows = conn.execute('''
            SELECT l.*, u.name AS user_name, u.email AS email
            FROM ai_logs l
            LEFT JOIN users u ON u.id = l.user_id
            WHERE l.is_flagged = 1
            ORDER BY l.id DESC
        ''').fetchall()
        duplicate_attempts = conn.execute('''
            SELECT d.id, d.created_at, d.image_sha256,
                   u.name AS user_name, u.email AS email,
                   l.id AS original_log_id
            FROM ai_duplicate_attempts d
            LEFT JOIN users u ON u.id = d.user_id
            LEFT JOIN ai_logs l ON l.id = d.original_ai_log_id
            ORDER BY d.id DESC
        ''').fetchall()
    finally:
        conn.close()
    flags = [_prepare_ai_log(row) for row in rows]
    return render_template(
        'admin_ai_flags.html',
        flags=flags,
        duplicate_attempts=duplicate_attempts,
    )

def _prepare_ai_log(row):
    log = dict(row)
    image_path = log.get('image_path') or ''
    image_name = os.path.basename(image_path) if image_path else ''
    log['image_url'] = (
        url_for('admin_ai_image', filename=image_name)
        if image_name and image_name == image_path.replace('\\', '/').rsplit('/', 1)[-1]
        else ''
    )
    confidence = log.get('confidence')
    log['confidence_percent'] = (
        round(float(confidence) * 100, 1)
        if confidence is not None else None
    )
    log['result_status_label'] = {
        'detected': '検出あり',
        'no_detection': '検出0件',
        'failed': '判定失敗',
    }.get(log.get('result_status'), '結果不明')
    log['timestamp'] = log.get('created_at') or ''
    log['flagged'] = bool(log.get('is_flagged'))
    log['log_id'] = log['id']
    return log

@app.route('/admin/ai/<int:log_id>')
@admin_required
def admin_ai_log_detail(log_id):
    conn = get_db()
    try:
        row = conn.execute('''
            WITH activity_summary AS (
                SELECT user_id, COUNT(*) AS activity_count,
                       COALESCE(SUM(points_earned), 0) AS lifetime_points
                FROM activity_history
                GROUP BY user_id
            )
            SELECT l.*, u.name AS user_name, u.email AS email,
                   a.points_earned AS points,
                   a.date AS point_timestamp,
                   COALESCE(s.activity_count, 0) AS activity_count,
                   COALESCE(s.lifetime_points, 0) AS lifetime_points,
                   (SELECT COUNT(*) FROM ai_logs prior
                    WHERE prior.user_id = l.user_id AND prior.id < l.id) AS user_history_count,
                   (SELECT COUNT(*) FROM ai_logs prior
                    WHERE prior.user_id = l.user_id AND prior.id < l.id
                      AND prior.is_flagged = 1) AS prior_flag_count
            FROM ai_logs l
            LEFT JOIN users u ON u.id = l.user_id
            LEFT JOIN activity_history a ON a.id = l.activity_id
            LEFT JOIN activity_summary s ON s.user_id = l.user_id
            WHERE l.id = ?
        ''', (log_id,)).fetchone()
    finally:
        conn.close()

    if row is None:
        return 'AI判定ログが見つかりません。', 404

    log = _prepare_ai_log(row)
    return render_template('admin_ai_log_detail.html', log=log)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    try:
        users = conn.execute('''
            SELECT
                u.id,
                u.name,
                u.email,
                u.role,
                u.login_destination,
                u.total_points,
                COALESCE((SELECT SUM(points_earned) FROM activity_history WHERE user_id = u.id AND date(date, '+9 hours') = date('now', '+9 hours')), 0) AS today_points,
                COALESCE((SELECT COUNT(*) FROM activity_history WHERE user_id = u.id), 0) AS action_count,
                COALESCE((SELECT MAX(date) FROM activity_history WHERE user_id = u.id), '') AS last_active
            FROM users u
            ORDER BY u.id
        ''').fetchall()
    finally:
        conn.close()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/<int:user_id>/login-destination', methods=['POST'])
@admin_required
def admin_user_login_destination(user_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400

    destination = request.form.get('login_destination', '')
    if destination not in ('user', 'organizer'):
        return 'ログイン先の指定が正しくありません。', 400

    conn = get_db()
    try:
        user = conn.execute(
            'SELECT role FROM users WHERE id = ?', (user_id,)
        ).fetchone()
        if not user or user['role'] != 'user':
            return '対象のユーザーが見つかりません。', 404
        if destination == 'organizer' and not get_user_organization_id(conn, user_id):
            return '承認済み団体のメンバーのみ団体画面をログイン先に設定できます。', 409
        with conn:
            conn.execute(
                'UPDATE users SET login_destination = ? WHERE id = ?',
                (destination, user_id),
            )
        return redirect(url_for('admin_users'))
    finally:
        conn.close()

@app.route('/admin/bins')
@admin_required
def admin_bins():
    conn = get_db()
    try:
        bins = conn.execute('''
            SELECT b.*,
                   (SELECT COUNT(*) FROM activity_history a
                    WHERE a.type = 'trash_bin' AND a.title = b.name) AS usage_count
            FROM trash_bins b
            ORDER BY b.name
        ''').fetchall()
    finally:
        conn.close()
    return render_template('admin_bins.html', bins=bins)

def _parse_trash_bin_form():
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    waste_types = (request.form.get('waste_types') or 'ペットボトル・カップ・容器').strip()[:100]
    bin_status = (request.form.get('bin_status') or 'active').strip()
    if bin_status not in ('active', 'full_reported', 'maintenance'):
        bin_status = 'active'
    try:
        lat = float(request.form.get('lat', ''))
        lng = float(request.form.get('lng', ''))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError('地図上で設置場所を選択してください。') from exc

    if not name or not description:
        raise ValueError('設置場所名と住所・説明を入力してください。')
    if not math.isfinite(lat) or not -90 <= lat <= 90:
        raise ValueError('緯度が正しくありません。地図上で設置場所を選択してください。')
    if not math.isfinite(lng) or not -180 <= lng <= 180:
        raise ValueError('経度が正しくありません。地図上で設置場所を選択してください。')
    return {
        'name': name,
        'description': description,
        'lat': lat,
        'lng': lng,
        'waste_types': waste_types,
        'bin_status': bin_status,
    }

@app.route('/admin/bins/add', methods=['GET', 'POST'])
@admin_required
def add_bin():
    bin_data = {
        'name': '', 'description': '', 'lat': '', 'lng': '',
        'waste_types': 'ペットボトル・カップ・容器', 'bin_status': 'active',
    }
    if request.method == 'POST':
        if not validate_csrf():
            return render_template(
                'add_bin.html', bin=bin_data,
                error_msg='送信内容を確認できませんでした。画面を再読み込みしてください。',
            ), 400
        try:
            bin_data = _parse_trash_bin_form()
        except ValueError as exc:
            return render_template(
                'add_bin.html', bin={
                    'name': request.form.get('name', ''),
                    'description': request.form.get('description', ''),
                    'lat': request.form.get('lat', ''),
                    'lng': request.form.get('lng', ''),
                    'waste_types': request.form.get('waste_types', 'ペットボトル・カップ・容器'),
                    'bin_status': request.form.get('bin_status', 'active'),
                }, error_msg=str(exc),
            ), 400

        conn = get_db()
        try:
            with conn:
                conn.execute('''
                    INSERT INTO trash_bins (name, description, lat, lng, waste_types, bin_status)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    bin_data['name'], bin_data['description'],
                    bin_data['lat'], bin_data['lng'],
                    bin_data['waste_types'], bin_data['bin_status'],
                ))
        except sqlite3.IntegrityError:
            return render_template(
                'add_bin.html', bin=bin_data,
                error_msg='同じ設置場所名がすでに登録されています。',
            ), 409
        finally:
            conn.close()
        return redirect(url_for('admin_bins'))
    return render_template('add_bin.html', bin=bin_data)

@app.route('/admin/bins/<int:bin_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_bin(bin_id):
    conn = get_db()
    try:
        existing_bin = conn.execute(
            'SELECT * FROM trash_bins WHERE id = ?', (bin_id,)
        ).fetchone()
    finally:
        conn.close()
    if existing_bin is None:
        return 'ごみ箱の設置場所が見つかりません。', 404

    bin_data = dict(existing_bin)
    if request.method == 'POST':
        if not validate_csrf():
            return render_template(
                'edit_bin.html', bin=bin_data,
                error_msg='送信内容を確認できませんでした。画面を再読み込みしてください。',
            ), 400
        try:
            updates = _parse_trash_bin_form()
        except ValueError as exc:
            bin_data.update({
                'name': request.form.get('name', ''),
                'description': request.form.get('description', ''),
                'lat': request.form.get('lat', ''),
                'lng': request.form.get('lng', ''),
                'waste_types': request.form.get('waste_types', 'ペットボトル・カップ・容器'),
                'bin_status': request.form.get('bin_status', 'active'),
            })
            return render_template('edit_bin.html', bin=bin_data, error_msg=str(exc)), 400

        conn = get_db()
        try:
            with conn:
                conn.execute('''
                    UPDATE trash_bins
                    SET name = ?, description = ?, lat = ?, lng = ?,
                        waste_types = ?, bin_status = ?
                    WHERE id = ?
                ''', (
                    updates['name'], updates['description'],
                    updates['lat'], updates['lng'],
                    updates['waste_types'], updates['bin_status'],
                    bin_id,
                ))
        except sqlite3.IntegrityError:
            bin_data.update(updates)
            return render_template(
                'edit_bin.html', bin=bin_data,
                error_msg='同じ設置場所名がすでに登録されています。',
            ), 409
        finally:
            conn.close()
        return redirect(url_for('admin_bins'))
    return render_template('edit_bin.html', bin=bin_data)

@app.route('/admin/bins/<int:bin_id>/delete', methods=['POST'])
@admin_required
def delete_bin(bin_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    conn = get_db()
    try:
        with conn:
            cursor = conn.execute('DELETE FROM trash_bins WHERE id = ?', (bin_id,))
            if cursor.rowcount != 1:
                return 'ごみ箱の設置場所が見つかりません。', 404
    finally:
        conn.close()
    return redirect(url_for('admin_bins'))

# ==========================================
# アクセス範囲の整理: 管理者専用一覧
# ==========================================
@app.route('/admin/events')
@admin_required
def admin_events():
    conn = get_db()
    try:
        events = conn.execute('''
            SELECT
                e.id,
                e.name,
                e.location,
                e.latitude,
                e.longitude,
                e.datetime AS date,
                e.bonus_points,
                e.category,
                e.status,
                e.review_status,
                COALESCE(o.name, u.name) AS organizer_name,
                COUNT(DISTINCT a.user_id) AS participants,
                COUNT(DISTINCT CASE WHEN r.status = 'reserved' THEN r.user_id END) AS reservations
            FROM events e
            LEFT JOIN organizations o ON o.id = e.organization_id
            LEFT JOIN users u ON u.id = e.organizer_id
            LEFT JOIN activity_history a ON a.event_id = e.id
            LEFT JOIN event_reservations r ON r.event_id = e.id
            GROUP BY e.id, e.name, e.location, e.datetime, e.bonus_points,
                e.category, e.latitude, e.longitude, e.status, e.review_status,
                o.name, u.name
            ORDER BY e.id
        ''').fetchall()
    finally:
        conn.close()
    missing_map_count = sum(
        event['latitude'] is None or event['longitude'] is None
        for event in events
    )
    return render_template(
        'admin_events.html',
        events=events,
        missing_map_count=missing_map_count,
    )

def _prefill_event_from_issue(event_values):
    from_issue_id = request.args.get('from_issue', type=int)
    if not from_issue_id:
        return
    conn = get_db()
    try:
        issue = conn.execute(
            'SELECT * FROM issue_reports WHERE id = ?', (from_issue_id,)
        ).fetchone()
        if issue:
            event_values.update({
                'name': f"{issue['location']} 課題解決クリーンイベント",
                'location': issue['location'],
                'latitude': issue['latitude'] if issue['latitude'] is not None else '',
                'longitude': issue['longitude'] if issue['longitude'] is not None else '',
                'purpose_issue': (
                    f"地域課題報告「{issue['title']}（{issue['trash_type']}）」への対応。"
                    + (f" {issue['description']}" if issue['description'] else '')
                )[:500],
            })
    finally:
        conn.close()


@app.route('/admin/events/add', methods=['GET', 'POST'])
@admin_required
def admin_event_add():
    event_values = {'bonus_points': 50, 'category': 'auto', 'purpose_issue': ''}
    if request.method == 'GET':
        _prefill_event_from_issue(event_values)
    error_msg = None
    if request.method == 'POST':
        if not validate_csrf():
            return 'CSRFトークンが不正です。', 400
        submitted_values, error_msg = _validated_event_form()
        event_values.update(submitted_values)
        if not error_msg:
            conn = get_db()
            try:
                with conn:
                    event_cursor = conn.execute('''
                        INSERT INTO events (
                            name, location, latitude, longitude, datetime,
                            bonus_points, category, purpose_issue
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event_values['name'], event_values['location'],
                        event_values['latitude'], event_values['longitude'],
                        event_values['datetime'], event_values['bonus_points'],
                        event_values['category'], event_values.get('purpose_issue', ''),
                    ))
                    _notify_all_users_of_new_event(conn, event_cursor.lastrowid)
                return redirect(url_for('admin_events'))
            finally:
                conn.close()
    return render_template(
        'add_event.html', event=event_values, error_msg=error_msg,
        event_categories=EVENT_CATEGORIES,
    )

@app.route('/admin/events/<int:event_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_event_edit(event_id):
    conn = get_db()
    try:
        event = conn.execute(
            'SELECT * FROM events WHERE id = ?', (event_id,)
        ).fetchone()
        if not event:
            return 'イベントが見つかりません。', 404
        completed = conn.execute(
            'SELECT 1 FROM activity_history WHERE event_id = ? LIMIT 1',
            (event_id,)
        ).fetchone()
        reserved = conn.execute('''
            SELECT 1 FROM event_reservations
            WHERE event_id = ? AND status = 'reserved' LIMIT 1
        ''', (event_id,)).fetchone()
        if completed or reserved:
            return '予約または参加記録があるイベントは編集できません。', 409

        event_values = dict(event)
        error_msg = None
        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400
            submitted_values, error_msg = _validated_event_form()
            event_values.update(submitted_values)
            if not error_msg:
                with conn:
                    conn.execute('''
                        UPDATE events
                        SET name = ?, location = ?, latitude = ?, longitude = ?,
                            datetime = ?, bonus_points = ?, category = ?,
                            purpose_issue = ?
                        WHERE id = ?
                    ''', (
                        event_values['name'], event_values['location'],
                        event_values['latitude'], event_values['longitude'],
                        event_values['datetime'], event_values['bonus_points'],
                        event_values['category'], event_values.get('purpose_issue', ''),
                        event_id,
                    ))
                return redirect(url_for('admin_events'))
        return render_template(
            'edit_event.html', event=event_values, error_msg=error_msg,
            event_categories=EVENT_CATEGORIES,
        )
    finally:
        conn.close()

@app.route('/admin/events/<int:event_id>/location', methods=['GET', 'POST'])
@admin_required
def admin_event_location(event_id):
    conn = get_db()
    try:
        event = conn.execute(
            'SELECT id, name, location, latitude, longitude FROM events WHERE id = ?',
            (event_id,),
        ).fetchone()
        if not event:
            return 'イベントが見つかりません。', 404

        event_values = dict(event)
        error_msg = None
        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400

            raw_latitude = request.form.get('latitude', '').strip()
            raw_longitude = request.form.get('longitude', '').strip()
            event_values.update({
                'latitude': raw_latitude,
                'longitude': raw_longitude,
            })
            try:
                latitude = float(raw_latitude)
                longitude = float(raw_longitude)
                if (
                    not math.isfinite(latitude)
                    or not -90 <= latitude <= 90
                    or not math.isfinite(longitude)
                    or not -180 <= longitude <= 180
                ):
                    raise ValueError
            except ValueError:
                error_msg = '地図上で有効な開催地点を選択してください。'
            else:
                with conn:
                    conn.execute(
                        'UPDATE events SET latitude = ?, longitude = ? WHERE id = ?',
                        (latitude, longitude, event_id),
                    )
                return redirect(url_for('admin_events'))

        return render_template(
            'admin_event_location.html',
            event=event_values,
            error_msg=error_msg,
        )
    finally:
        conn.close()

@app.route('/admin/events/review')
@admin_required
def admin_event_reviews():
    conn = get_db()
    try:
        events = conn.execute('''
            SELECT e.*, o.name AS organization_name,
                   u.name AS organizer_name,
                   (SELECT COUNT(*) FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved') AS reservations
            FROM events e
            LEFT JOIN organizations o ON o.id = e.organization_id
            LEFT JOIN users u ON u.id = e.organizer_id
            WHERE e.review_status IN ('pending', 'reviewing')
            ORDER BY e.datetime, e.id
        ''').fetchall()
        return render_template('admin_event_reviews.html', events=events)
    finally:
        conn.close()

@app.route('/admin/events/<int:event_id>/review', methods=['POST'])
@admin_required
def review_event(event_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400

    decision = request.form.get('decision', '')
    review_comment = request.form.get('review_comment', '').strip()
    if decision not in ('reviewing', 'approved', 'changes_requested', 'rejected'):
        return '不正な審査結果です。', 400
    if decision in ('changes_requested', 'rejected') and not review_comment:
        return '修正依頼・却下の理由を入力してください。', 400
    if len(review_comment) > 1000:
        return '審査コメントは1000文字以内で入力してください。', 400

    conn = get_db()
    try:
        with conn:
            self_review = conn.execute('''
                SELECT 1
                FROM events e
                WHERE e.id = ?
                  AND (
                    e.organizer_id = ?
                    OR EXISTS (
                        SELECT 1 FROM organization_members m
                        WHERE m.organization_id = e.organization_id
                          AND m.user_id = ? AND m.status = 'active'
                    )
                  )
            ''', (event_id, session['user_id'], session['user_id'])).fetchone()
            if self_review:
                return '主催団体の担当者は自団体のイベントを審査できません。', 403
            cursor = conn.execute('''
                UPDATE events
                SET review_status = ?, review_comment = ?, reviewed_by = ?,
                    reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ? AND review_status IN ('pending', 'reviewing')
            ''', (
                decision, review_comment or None, session['user_id'], event_id,
            ))
            if cursor.rowcount != 1:
                return '審査対象が見つからないか、すでに審査済みです。', 409
            if decision == 'approved':
                _notify_all_users_of_new_event(conn, event_id)
        return redirect(url_for('admin_event_reviews'))
    finally:
        conn.close()

@app.route('/organizer/apply', methods=['GET', 'POST'])
@user_required
def organizer_apply():
    user_id = session['user_id']
    conn = get_db()
    try:
        application = conn.execute('''
            SELECT * FROM organizer_applications
            WHERE user_id = ? ORDER BY id DESC LIMIT 1
        ''', (user_id,)).fetchone()
        if application is None:
            flash('団体利用の申請は、今後アカウント登録時に受け付けます。', 'info')
            return redirect(url_for('home'))
        if application['status'] == 'approved':
            return redirect(url_for('organizer_dashboard'))
        if application['status'] == 'rejected':
            flash('団体申請は承認されませんでした。登録方法について管理者にお問い合わせください。', 'info')
            return redirect(url_for('home'))
        if request.method == 'POST':
            return '申請を受け付けています。審査結果をお待ちください。', 409
        return render_template('organizer_apply.html', application=application)
    finally:
        conn.close()

@app.route('/admin/organizer-applications')
@admin_required
def admin_organizer_applications():
    conn = get_db()
    try:
        applications = conn.execute('''
            SELECT a.*, u.name AS applicant_name, u.email AS applicant_email
            FROM organizer_applications a
            JOIN users u ON u.id = a.user_id
            ORDER BY CASE a.status WHEN 'pending' THEN 0 ELSE 1 END, a.created_at DESC
        ''').fetchall()
        return render_template(
            'admin_organizer_applications.html', applications=applications
        )
    finally:
        conn.close()

@app.route('/admin/organizer-applications/<int:application_id>/review', methods=['POST'])
@admin_required
def review_organizer_application(application_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    decision = request.form.get('decision')
    if decision not in ('approved', 'rejected'):
        return '不正な審査結果です。', 400

    conn = get_db()
    try:
        with conn:
            application = conn.execute('''
                SELECT * FROM organizer_applications
                WHERE id = ? AND status = 'pending'
            ''', (application_id,)).fetchone()
            if not application:
                return '申請が見つからないか、すでに審査済みです。', 409

            cursor = conn.execute('''
                UPDATE organizer_applications
                SET status = ?, reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ? AND status = 'pending'
            ''', (decision, session.get('user_id'), application_id))
            if cursor.rowcount == 0:
                return '申請が見つからないか、すでに審査済みです。', 409

            if decision == 'approved':
                conn.execute('''
                    INSERT INTO organizations (
                        application_id, name, contact, purpose,
                        approved_by, approved_at
                    ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    application['id'], application['organization_name'],
                    application['contact'], application['purpose'],
                    session.get('user_id'),
                ))
                organization_id = conn.execute(
                    'SELECT last_insert_rowid()'
                ).fetchone()[0]
                conn.execute('''
                    UPDATE organizer_applications SET organization_id = ?
                    WHERE id = ?
                ''', (organization_id, application['id']))
                conn.execute('''
                    INSERT INTO organization_members (
                        organization_id, user_id, role
                    ) VALUES (?, ?, 'owner')
                ''', (organization_id, application['user_id']))
                conn.execute('''
                    UPDATE users SET login_destination = 'organizer'
                    WHERE id = ? AND role = 'user'
                ''', (application['user_id'],))

        return redirect(url_for('admin_organizer_applications'))
    finally:
        conn.close()

def _validated_event_form(require_reward_details=False):
    name = request.form.get('name', '').strip()
    location = request.form.get('location', '').strip()
    event_datetime = request.form.get('datetime', '').strip()
    raw_bonus = request.form.get('bonus_points', '').strip()
    raw_capacity = request.form.get('capacity', '').strip()
    reward_details = request.form.get('reward_details', '').strip()
    raw_latitude = request.form.get('latitude', '').strip()
    raw_longitude = request.form.get('longitude', '').strip()
    category_input = request.form.get('category', 'auto').strip()
    purpose_issue = request.form.get('purpose_issue', '').strip()[:500]
    submitted_values = {
        'name': name,
        'location': location,
        'latitude': raw_latitude,
        'longitude': raw_longitude,
        'datetime': event_datetime,
        'bonus_points': raw_bonus,
        'capacity': raw_capacity,
        'reward_details': reward_details,
        'category': category_input,
        'purpose_issue': purpose_issue,
    }
    if not name or len(name) > 100:
        submitted_values['name'] = ''
        return submitted_values, 'イベント名を1〜100文字で入力してください。'
    if not location or len(location) > 200:
        submitted_values['location'] = ''
        return submitted_values, '開催場所を1〜200文字で入力してください。'
    try:
        parsed_datetime = datetime.fromisoformat(event_datetime)
    except (TypeError, ValueError):
        submitted_values['datetime'] = ''
        return submitted_values, '開催日時を正しく入力してください。'
    try:
        bonus_points = int(raw_bonus)
    except ValueError:
        submitted_values['bonus_points'] = ''
        return submitted_values, 'ボーナスポイントを整数で入力してください。'
    if raw_capacity:
        try:
            capacity = int(raw_capacity)
        except ValueError:
            submitted_values['capacity'] = ''
            return submitted_values, '定員を整数で入力してください。'
    else:
        capacity = 20
    latitude = longitude = None
    if bool(raw_latitude) != bool(raw_longitude):
        submitted_values['latitude' if raw_latitude else 'longitude'] = ''
        return submitted_values, '緯度と経度は両方入力するか、両方空欄にしてください。'
    if raw_latitude and raw_longitude:
        try:
            latitude = float(raw_latitude)
        except ValueError:
            submitted_values['latitude'] = ''
            return submitted_values, '緯度・経度は数値で入力してください。'
        try:
            longitude = float(raw_longitude)
        except ValueError:
            submitted_values['longitude'] = ''
            return submitted_values, '緯度・経度は数値で入力してください。'
        if not math.isfinite(latitude) or not -90 <= latitude <= 90:
            submitted_values['latitude'] = ''
            return submitted_values, '地図上で有効な緯度を選択してください。'
        if not math.isfinite(longitude) or not -180 <= longitude <= 180:
            submitted_values['longitude'] = ''
            return submitted_values, '地図上で有効な開催地点を選択してください。'
    if parsed_datetime.tzinfo is not None:
        submitted_values['datetime'] = ''
        return submitted_values, '開催日時は端末の現地日時で入力してください。'
    parsed_event_datetime = parsed_datetime.replace(tzinfo=JST)
    if parsed_event_datetime <= datetime.now(JST):
        submitted_values['datetime'] = ''
        return submitted_values, '開催日時は未来の日時を指定してください。'
    if bonus_points < 0 or bonus_points > 1000:
        submitted_values['bonus_points'] = ''
        return submitted_values, 'ボーナスポイントは0〜1000の範囲で指定してください。'
    if capacity < 1 or capacity > 10000:
        submitted_values['capacity'] = ''
        return submitted_values, '定員は1〜10000人の範囲で入力してください。'
    if require_reward_details and not reward_details:
        return submitted_values, '参加者向け特典を入力してください。特典がない場合は「なし」と入力してください。'
    if len(reward_details) > 500:
        submitted_values['reward_details'] = ''
        return submitted_values, '参加者向け特典は500文字以内で入力してください。'
    if category_input != 'auto' and category_input not in EVENT_CATEGORIES:
        submitted_values['category'] = 'auto'
        return submitted_values, 'イベントのジャンルを選択してください。'
    category = (
        suggest_event_category(name, location, reward_details)
        if category_input == 'auto' else category_input
    )
    return {
        'name': name,
        'location': location,
        'latitude': latitude,
        'longitude': longitude,
        'datetime': parsed_datetime.strftime('%Y-%m-%d %H:%M'),
        'bonus_points': bonus_points,
        'capacity': capacity,
        'reward_details': reward_details,
        'category': category,
        'purpose_issue': purpose_issue,
    }, None

@app.route('/organizer/events')
@organizer_required
def organizer_events():
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        events = conn.execute('''
            SELECT e.*, COUNT(DISTINCT a.user_id) AS participants,
                   (SELECT COUNT(*) FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved') AS reservations,
                   (SELECT COALESCE(SUM(a_points.points_earned), 0)
                    FROM activity_history a_points
                    WHERE a_points.event_id = e.id AND a_points.type = 'event') AS points_earned
            FROM events e
            LEFT JOIN activity_history a ON a.event_id = e.id
            WHERE e.organization_id = ?
            GROUP BY e.id
            ORDER BY e.datetime DESC
        ''', (organization_id,)).fetchall()
        summary = {
            'event_count': len(events),
            'participant_records': sum(event['participants'] for event in events),
            'active_reservations': sum(event['reservations'] for event in events),
            'points_earned': sum(event['points_earned'] for event in events),
        }
        month_value = request.args.get('month', '')
        try:
            month = datetime.strptime(month_value, '%Y-%m').date().replace(day=1)
        except ValueError:
            month = datetime.now(JST).date().replace(day=1)
        next_month = (
            month.replace(year=month.year + 1, month=1)
            if month.month == 12 else month.replace(month=month.month + 1)
        )
        previous_month = (
            month.replace(year=month.year - 1, month=12)
            if month.month == 1 else month.replace(month=month.month - 1)
        )
        events_by_date = {}
        for event in events:
            event_date = event['datetime'][:10]
            events_by_date.setdefault(event_date, []).append(event)
        weeks = calendar.Calendar(firstweekday=0).monthdatescalendar(
            month.year, month.month
        )
        return render_template(
            'organizer_events.html',
            events=events,
            summary=summary,
            weeks=weeks,
            events_by_date=events_by_date,
            month=month,
            previous_month=previous_month,
            next_month=next_month,
        )
    finally:
        conn.close()

@app.route('/organizer')
@organizer_required
def organizer_dashboard():
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        event_count = conn.execute(
            'SELECT COUNT(*) FROM events WHERE organization_id = ?',
            (organization_id,),
        ).fetchone()[0]
        editable_event_count = conn.execute('''
            SELECT COUNT(*)
            FROM events e
            WHERE e.organization_id = ?
                AND e.status = 'open'
                AND e.review_status IN ('pending', 'changes_requested', 'approved')
                AND NOT EXISTS (
                    SELECT 1 FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved'
                )
                AND NOT EXISTS (
                    SELECT 1 FROM activity_history a
                    WHERE a.event_id = e.id
                )
        ''', (organization_id,)).fetchone()[0]
        active_reservations = conn.execute('''
            SELECT COUNT(*)
            FROM event_reservations r
            JOIN events e ON e.id = r.event_id
            WHERE e.organization_id = ? AND r.status = 'reserved'
        ''', (organization_id,)).fetchone()[0]
        participant_count = conn.execute('''
            SELECT COUNT(*)
            FROM activity_history a
            JOIN events e ON e.id = a.event_id
            WHERE e.organization_id = ? AND a.type = 'event'
        ''', (organization_id,)).fetchone()[0]
        pending_feedback_count = conn.execute('''
            SELECT COUNT(*)
            FROM event_feedback f
            JOIN events e ON e.id = f.event_id
            WHERE e.organization_id = ? AND f.action_status = 'pending'
        ''', (organization_id,)).fetchone()[0]
        recent_feedback = conn.execute('''
            SELECT f.event_id, f.comment, f.satisfaction, f.submitted_at,
                   e.name AS event_name
            FROM event_feedback f
            JOIN events e ON e.id = f.event_id
            WHERE e.organization_id = ? AND f.action_status = 'pending'
            ORDER BY f.submitted_at DESC, f.id DESC
            LIMIT 5
        ''', (organization_id,)).fetchall()
        return render_template(
            'organizer_dashboard.html',
            event_count=event_count,
            editable_event_count=editable_event_count,
            active_reservations=active_reservations,
            participant_count=participant_count,
            pending_feedback_count=pending_feedback_count,
            recent_feedback=recent_feedback,
        )
    finally:
        conn.close()

@app.route('/organizer/events/edit')
@organizer_required
def organizer_event_edit_list():
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        events = conn.execute('''
            SELECT e.*,
                   (SELECT COUNT(*) FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved') AS reservations,
                   (SELECT COUNT(*) FROM activity_history a
                    WHERE a.event_id = e.id) AS participants
            FROM events e
            WHERE e.organization_id = ?
                AND e.status = 'open'
                AND e.review_status IN ('pending', 'changes_requested', 'approved')
                AND NOT EXISTS (
                    SELECT 1 FROM event_reservations r
                    WHERE r.event_id = e.id AND r.status = 'reserved'
                )
                AND NOT EXISTS (
                    SELECT 1 FROM activity_history a
                    WHERE a.event_id = e.id
                )
            ORDER BY e.datetime DESC, e.id DESC
        ''', (organization_id,)).fetchall()
        return render_template('organizer_event_edit_list.html', events=events)
    finally:
        conn.close()

@app.route('/organizer/events/<int:event_id>/participants')
@organizer_required
def organizer_event_participants(event_id):
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        event = conn.execute('''
            SELECT * FROM events WHERE id = ? AND organization_id = ?
        ''', (event_id, organization_id)).fetchone()
        if not event:
            return 'イベントが見つかりません。', 404
        participants = conn.execute('''
            SELECT CASE WHEN a.id IS NOT NULL THEN 'completed'
                        ELSE r.status END AS status,
                   r.reserved_at,
                   COALESCE(r.completed_at, a.date) AS completed_at,
                   u.name, u.email, a.points_earned
            FROM (
                SELECT user_id FROM event_reservations WHERE event_id = ?
                UNION
                SELECT user_id FROM activity_history WHERE event_id = ?
            ) attendee
            JOIN users u ON u.id = attendee.user_id
            LEFT JOIN event_reservations r
                ON r.user_id = attendee.user_id AND r.event_id = ?
            LEFT JOIN activity_history a
                ON a.user_id = attendee.user_id AND a.event_id = ?
            ORDER BY CASE status
                WHEN 'reserved' THEN 0 WHEN 'completed' THEN 1 ELSE 2 END,
                r.reserved_at
        ''', (event_id, event_id, event_id, event_id)).fetchall()
        feedback_summary = conn.execute('''
            SELECT COUNT(*) AS responses,
                   ROUND(AVG(satisfaction), 1) AS average_satisfaction,
                   SUM(CASE WHEN next_participation = 'yes' THEN 1 ELSE 0 END) AS yes_count,
                   SUM(CASE WHEN next_participation = 'maybe' THEN 1 ELSE 0 END) AS maybe_count,
                   SUM(CASE WHEN next_participation = 'no' THEN 1 ELSE 0 END) AS no_count,
                   SUM(CASE WHEN trim(comment) <> '' THEN 1 ELSE 0 END) AS comment_count,
                   SUM(CASE WHEN trim(comment) <> '' AND action_status = 'addressed'
                            THEN 1 ELSE 0 END) AS addressed_comments
            FROM event_feedback WHERE event_id = ?
        ''', (event_id,)).fetchone()
        completed_count = conn.execute('''
            SELECT COUNT(*) FROM activity_history
            WHERE event_id = ? AND type = 'event'
        ''', (event_id,)).fetchone()[0]
        response_rate = (
            round(feedback_summary['responses'] * 100 / completed_count, 1)
            if completed_count else 0
        )
        reflection_rate = (
            round(feedback_summary['addressed_comments'] * 100 / feedback_summary['comment_count'], 1)
            if feedback_summary['comment_count'] else 0
        )
        feedback_comments = conn.execute('''
            SELECT id, comment, action_status, action_note, reviewed_at
            FROM event_feedback
            WHERE event_id = ? AND trim(comment) <> ''
            ORDER BY submitted_at DESC
        ''', (event_id,)).fetchall()
        return render_template(
            'organizer_event_participants.html',
            event=event,
            participants=participants,
            feedback_summary=feedback_summary,
            completed_count=completed_count,
            response_rate=response_rate,
            reflection_rate=reflection_rate,
            feedback_comments=feedback_comments,
        )
    finally:
        conn.close()

@app.route('/organizer/events/<int:event_id>/message', methods=['POST'])
@organizer_required
def organizer_event_message(event_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    message = (request.form.get('message') or '').strip()
    if not message or len(message) > 1000:
        flash('メッセージを1〜1000文字で入力してください。', 'error')
        return redirect(url_for('organizer_event_participants', event_id=event_id))

    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        event = conn.execute('''
            SELECT id, name, status FROM events
            WHERE id = ? AND organization_id = ?
        ''', (event_id, organization_id)).fetchone()
        if event is None:
            return 'イベントが見つかりません。', 404
        if event['status'] != 'open':
            return '中止済みのイベントにはメッセージを送れません。', 409
        with conn:
            cursor = conn.execute('''
                INSERT INTO user_notifications (
                    user_id, event_id, notification_type, title, message
                )
                SELECT r.user_id, ?, 'organizer_message', ?, ?
                FROM event_reservations r
                WHERE r.event_id = ? AND r.status = 'reserved'
            ''', (
                event_id, f'主催者からのお知らせ：{event["name"]}', message,
                event_id,
            ))
        if cursor.rowcount:
            flash(f'{cursor.rowcount}人の予約者にお知らせを送りました。', 'success')
        else:
            flash('現在お知らせを受け取る予約者はいません。', 'info')
        return redirect(url_for('organizer_event_participants', event_id=event_id))
    finally:
        conn.close()


@app.route('/organizer/events/<int:event_id>/feedback/<int:feedback_id>', methods=['POST'])
@organizer_required
def organizer_event_feedback_update(event_id, feedback_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    action_status = request.form.get('action_status', '')
    action_note = request.form.get('action_note', '').strip()
    allowed_statuses = {'pending', 'planned', 'addressed', 'not_planned'}
    if action_status not in allowed_statuses:
        return '対応状況の値が正しくありません。', 400
    if len(action_note) > 500:
        return '対応メモは500文字以内で入力してください。', 400

    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        event = conn.execute(
            'SELECT 1 FROM events WHERE id = ? AND organization_id = ?',
            (event_id, organization_id),
        ).fetchone()
        if not event:
            return 'イベントが見つかりません。', 404
        cursor = conn.execute('''
            UPDATE event_feedback
            SET action_status = ?, action_note = ?, reviewed_by = ?,
                reviewed_at = CURRENT_TIMESTAMP
            WHERE id = ? AND event_id = ?
        ''', (action_status, action_note, session['user_id'], feedback_id, event_id))
        if cursor.rowcount != 1:
            return 'アンケート回答が見つかりません。', 404
        conn.commit()
        flash('アンケートへの対応状況を保存しました。', 'success')
        return redirect(url_for('organizer_event_participants', event_id=event_id))
    finally:
        conn.close()


@app.route('/organizer/events/new', methods=['GET', 'POST'])
@organizer_required
def organizer_event_new():
    error_msg = None
    event_values = {'category': 'auto', 'purpose_issue': ''}
    if request.method == 'GET':
        _prefill_event_from_issue(event_values)
    if request.method == 'POST':
        if not validate_csrf():
            return 'CSRFトークンが不正です。', 400
        submitted_values, error_msg = _validated_event_form(
            require_reward_details=True
        )
        event_values.update(submitted_values)
        if not error_msg:
            conn = get_db()
            try:
                organization_id = get_user_organization_id(
                    conn, session['user_id']
                )
                if not organization_id:
                    flash('団体機能は、審査で承認された団体メンバーのみ利用できます。', 'info')
                    return redirect(url_for('home'))
                with conn:
                    conn.execute('''
                        INSERT INTO events (
                            name, location, latitude, longitude, datetime,
                            bonus_points, capacity, reward_details, review_status,
                            organizer_id, organization_id, category, purpose_issue
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                    ''', (
                        event_values['name'], event_values['location'],
                        event_values['latitude'], event_values['longitude'],
                        event_values['datetime'], event_values['bonus_points'],
                        event_values['capacity'],
                        event_values['reward_details'],
                        session['user_id'], organization_id,
                        event_values['category'],
                        event_values.get('purpose_issue', ''),
                    ))
                return redirect(url_for('organizer_events'))
            finally:
                conn.close()
    return render_template(
        'organizer_event_form.html', event=event_values, error_msg=error_msg,
        event_categories=EVENT_CATEGORIES,
    )

@app.route('/organizer/events/<int:event_id>/edit', methods=['GET', 'POST'])
@organizer_required
def organizer_event_edit(event_id):
    user_id = session['user_id']
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, user_id)
        event = conn.execute('''
            SELECT * FROM events WHERE id = ? AND organization_id = ?
        ''', (event_id, organization_id)).fetchone()
        if not event:
            return 'イベントが見つかりません。', 404
        if event['status'] != 'open':
            return '中止済みのイベントは編集できません。', 409
        if event['review_status'] in ('reviewing', 'rejected'):
            return '審査中または却下済みのイベントは編集できません。', 409
        completed = conn.execute(
            'SELECT 1 FROM activity_history WHERE event_id = ? LIMIT 1', (event_id,)
        ).fetchone()
        reserved = conn.execute('''
            SELECT 1 FROM event_reservations
            WHERE event_id = ? AND status = 'reserved' LIMIT 1
        ''', (event_id,)).fetchone()
        if completed or reserved:
            return '予約または参加記録があるイベントは編集できません。', 409

        error_msg = None
        event_values = dict(event)
        if request.method == 'POST':
            if not validate_csrf():
                return 'CSRFトークンが不正です。', 400
            submitted_values, error_msg = _validated_event_form(
                require_reward_details=True
            )
            event_values.update(submitted_values)
            if not error_msg:
                with conn:
                    conn.execute('''
                        UPDATE events
                        SET name = ?, location = ?, latitude = ?, longitude = ?,
                            datetime = ?, bonus_points = ?, capacity = ?,
                            reward_details = ?, category = ?, purpose_issue = ?,
                            review_status = 'pending', review_comment = NULL,
                            reviewed_by = NULL, reviewed_at = NULL
                        WHERE id = ? AND organization_id = ? AND status = 'open'
                    ''', (
                        event_values['name'], event_values['location'],
                        event_values['latitude'], event_values['longitude'],
                        event_values['datetime'], event_values['bonus_points'],
                        event_values['capacity'],
                        event_values['reward_details'],
                        event_values['category'],
                        event_values.get('purpose_issue', ''),
                        event_id, organization_id,
                    ))
                return redirect(url_for('organizer_events'))
        return render_template(
            'organizer_event_form.html', event=event_values,
            event_id=event_id, error_msg=error_msg,
            event_categories=EVENT_CATEGORIES,
        )
    finally:
        conn.close()

@app.route('/organizer/events/<int:event_id>/cancel', methods=['POST'])
@organizer_required
def organizer_event_cancel(event_id):
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    conn = get_db()
    try:
        organization_id = get_user_organization_id(conn, session['user_id'])
        with conn:
            event = conn.execute('''
                SELECT name FROM events
                WHERE id = ? AND organization_id = ? AND status = 'open'
            ''', (event_id, organization_id)).fetchone()
            if event is None:
                return 'イベントが見つからないか、すでに中止されています。', 404
            conn.execute('''
                INSERT INTO user_notifications (
                    user_id, event_id, notification_type, title, message
                )
                SELECT user_id, event_id, 'cancellation', ?, ?
                FROM event_reservations
                WHERE event_id = ? AND status = 'reserved'
            ''', (
                f'イベント中止のお知らせ：{event["name"]}',
                f'主催者の都合により「{event["name"]}」は中止になりました。',
                event_id,
            ))
            cursor = conn.execute('''
                UPDATE events SET status = 'cancelled'
                WHERE id = ? AND organization_id = ? AND status = 'open'
            ''', (event_id, organization_id))
            if cursor.rowcount:
                conn.execute('''
                    UPDATE event_reservations SET status = 'cancelled'
                    WHERE event_id = ? AND status = 'reserved'
                ''', (event_id,))
        if cursor.rowcount == 0:
            return 'イベントが見つからないか、すでに中止されています。', 404
        return redirect(url_for('organizer_events'))
    finally:
        conn.close()

# ==========================================
# ログアウト処理
# ==========================================
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        if not validate_csrf():
            return 'CSRFトークンが不正です。', 400
        session.clear()
        return redirect(url_for('login'))
    return render_template('logout_confirm.html')

# バックエンド側に価格の絶対基準となるマスターデータを固定定義（改ざん完全無効化）
REWARD_ITEMS = {
    "coffee": {
        "name": "地元カフェ コーヒー券",
        "cost": 100,
        "category": "local",
        "description": "地域の提携カフェとのクーポン連携を想定した特典です。現在はポイント消費と交換履歴の記録のみで、クーポン発券・利用確認は行われません。",
    },
    "shop": {
        "name": "地域共通 お買い物券",
        "cost": 300,
        "category": "local",
        "description": "地域店舗とのクーポン連携を想定した特典です。現在はポイント消費と交換履歴の記録のみで、商品券発券・利用確認は行われません。",
    },
    "donation": {
        "name": "自治体 緑化活動への寄付",
        "cost": 100,
        "category": "donation",
        "description": "地域の緑化活動への寄付を想定した特典です。現在はポイント消費と交換履歴の記録のみで、寄付金の送金は行われません。",
    },
    "pay_demo": {
        "name": "えらべるPay（実証デモ）",
        "cost": 300,
        "category": "digital_demo",
        "description": "デジタル特典連携の操作デモです。実際の発券・決済や、えらべるPayとの連携は行われません。デモ交換ではポイントが消費され、履歴に記録されます。",
    },
}


def _exchange_page_context(conn, user_id, error_msg=None):
    user = conn.execute(
        'SELECT id, total_points FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    if user is None:
        return None

    exchanged_items = {
        row['item_id']
        for row in conn.execute(
            'SELECT DISTINCT item_id FROM reward_history WHERE user_id = ?',
            (user_id,),
        ).fetchall()
    }
    history = conn.execute('''
        SELECT item_name, cost, created_at
        FROM reward_history
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 5
    ''', (user_id,)).fetchall()
    rewards = [
        {'id': item_id, **item}
        for item_id, item in REWARD_ITEMS.items()
    ]
    return {
        'user': user,
        'rewards': rewards,
        'exchanged_items': exchanged_items,
        'history': history,
        'error_msg': error_msg,
    }


@app.route('/exchange')
@user_required
def exchange_page():
    conn = get_db()
    try:
        context = _exchange_page_context(conn, session['user_id'])
        if context is None:
            return redirect(url_for('logout'))
        success_msg = None
        if session.pop('exchange_success', False):
            success_msg = session.pop(
                'exchange_message',
                '特典交換が完了しました。交換した特典は地域の提携先でご利用ください。',
            )
        return render_template('exchange.html', **context, success_msg=success_msg)
    finally:
        conn.close()

@app.route('/exchange/confirm', methods=['POST'])
@user_required
def exchange_confirm():
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    item_id = request.form.get('item_id', '')
    if item_id not in REWARD_ITEMS:
        return '不正なリクエストです。', 400

    conn = get_db()
    try:
        context = _exchange_page_context(conn, session['user_id'])
        if context is None:
            return redirect(url_for('logout'))
        item = {'id': item_id, **REWARD_ITEMS[item_id]}
        if item_id in context['exchanged_items']:
            context['error_msg'] = 'この特典はすでに交換済みです。'
            return render_template('exchange.html', **context), 409
        if context['user']['total_points'] < item['cost']:
            context['error_msg'] = 'ポイントが不足しています。'
            return render_template('exchange.html', **context), 400
        return render_template(
            'exchange_confirm.html',
            item=item,
            current_points=context['user']['total_points'],
            remaining_points=context['user']['total_points'] - item['cost'],
        )
    finally:
        conn.close()

@app.route('/exchange/item', methods=['POST'])
@user_required # 一般ユーザー専用の認可ガード
def exchange_item():
    if not validate_csrf():
        return 'CSRFトークンが不正です。', 400
    user_id = session['user_id']
    item_id = request.form.get('item_id') # フロントからはIDだけを受け取る
    
    # 登録外の不正なIDが送られてきたら即座に遮断
    if item_id not in REWARD_ITEMS:
        return "不正なリクエストです。", 400
        
    item = REWARD_ITEMS[item_id]
    item_name = item["name"]
    item_cost = item["cost"]
    
    conn = get_db()
    try:
        with conn:
            conn.execute('BEGIN IMMEDIATE')
            context = _exchange_page_context(conn, user_id)
            if context is None:
                return redirect(url_for('logout'))

            if item_id in context['exchanged_items']:
                context['error_msg'] = "この特典はすでに交換済みです。"
                return render_template('exchange.html', **context), 409

            if context['user']['total_points'] < item_cost:
                context['error_msg'] = "ポイントが不足しています。"
                return render_template('exchange.html', **context), 400

            # 1. 残高が足りている場合のみ減算を実行
            cursor = conn.execute(
                'UPDATE users SET total_points = total_points - ? WHERE id = ? AND total_points >= ?',
                (item_cost, user_id, item_cost)
            )
            if cursor.rowcount == 0:
                raise sqlite3.IntegrityError("同時アクセスによりポイント残高が変動しました。")
            # 2. 監査用の交換履歴テーブルへ厳密に挿入
            conn.execute('''
                INSERT INTO reward_history (user_id, item_id, item_name, cost) 
                VALUES (?, ?, ?, ?)
            ''', (user_id, item_id, item_name, item_cost))
            
        session['exchange_success'] = True
        if item["category"] == "digital_demo":
            session['exchange_message'] = (
                f'【実証デモ】{item_name} のデモ交換を記録しました。'
                '実際のギフト発券・決済や外部サービスとの連携は行われません。'
            )
        elif item["category"] == "local":
            session['exchange_message'] = (
                f'【連携デモ】{item_name} の交換を記録しました。'
                'このデモでは実際のクーポン発券・利用確認は行われません。'
            )
        else:
            session['exchange_message'] = (
                f'【連携デモ】{item_name} の交換を記録しました。'
                'このデモでは実際の寄付金送金は行われません。'
            )
        return redirect(url_for('exchange_page'))
    except sqlite3.IntegrityError:
        app.logger.warning("特典交換で同時アクセスまたは残高整合性エラーを検知し、ロールバックしました。")
        return "競合が発生したため交換を取り消しました。しばらくしてから再度お試しください。", 409
    except Exception:
        app.logger.exception("特典交換中にエラーが発生しました。")
        return _internal_error_response()
    finally:
        conn.close()


# ==========================================
# アプリケーション起動
# ==========================================
if __name__ == '__main__':
    init_db()
    debug_mode = os.environ.get("CLEANSTEP_DEBUG", "false").lower() == "true"
    # スマホからアクセスできるよう、デバッグ時も 0.0.0.0 で待ち受ける
    host = os.environ.get('CLEANSTEP_HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5005'))

    # PCのローカルIPを自動取得してターミナルにQRコードを表示
    import socket
    try:
        import qrcode
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        mobile_url = f"http://{local_ip}:{port}"
        print("\n" + "=" * 45)
        print(f"📱 スマホ接続用URL: {mobile_url}")
        print("（PCとスマホを同じWi-Fiに繋いで読み取ってください）")
        print("=" * 45)
        qr = qrcode.QRCode(border=4)
        qr.add_data(mobile_url)
        qr.make(fit=True)
        # 端末の文字列ではなく、ANSI背景色でQRの白黒マスを描く。
        # 1モジュールを2文字幅にして、一般的な端末フォントでも正方形に近づける。
        try:
            from colorama import just_fix_windows_console
            just_fix_windows_console()
        except ImportError:
            pass
        esc = '\x1b['
        for row in qr.get_matrix():
            line = ''.join(f"{esc}{40 if dark else 47}m  " for dark in row)
            print(line + f"{esc}0m")

        # 発表用にターミナル表示を主とし、画像ファイルも予備として残す。
        qr_path = os.path.join(app.static_folder, 'phone_access_qr.png')
        qr.make_image(fill_color='black', back_color='white').save(qr_path)
        print(f"予備のQR画像: {qr_path}")
    except Exception as e:
        print(f"QRコード生成スキップ: {e}")
        print("QRコードを利用するには、アプリの仮想環境で `python -m pip install qrcode` を実行してください。")

    app.run(host=host, debug=debug_mode, port=port)