import os
import json
import re
import hashlib
import sqlite3
import shutil
import tempfile
import threading
import unittest
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
import sys
from unittest.mock import patch

from PIL import Image
from werkzeug.security import generate_password_hash


_database_dir = tempfile.TemporaryDirectory()
_database_path = Path(_database_dir.name) / "legacy.db"
_previous_database_path = os.environ.get("CLEANSTEP_DATABASE_PATH")
_previous_disable_ai = os.environ.get("CLEANSTEP_DISABLE_AI")
_previous_demo_mode = os.environ.get("CLEANSTEP_DEMO_MODE")
os.environ["CLEANSTEP_DATABASE_PATH"] = str(_database_path)
os.environ["CLEANSTEP_DISABLE_AI"] = "true"
os.environ["CLEANSTEP_DEMO_MODE"] = "false"

with sqlite3.connect(_database_path) as legacy_db:
    legacy_db.executescript('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            name TEXT,
            role TEXT,
            total_points INTEGER DEFAULT 0 CHECK(total_points >= 0)
        );
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            location TEXT,
            datetime TEXT,
            bonus_points INTEGER,
            organizer_id INTEGER,
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open', 'cancelled')),
            FOREIGN KEY (organizer_id) REFERENCES users(id)
        );
        CREATE TABLE organizer_applications (
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
        );
        CREATE TABLE activity_history (
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
            detox_duration INTEGER DEFAULT 0,
            date TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, event_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        );
    ''')
    legacy_db.executemany(
        '''INSERT INTO users (id, email, password, name, role, total_points)
           VALUES (?, ?, ?, ?, ?, ?)''',
        [
            (1, "owner@example.test", generate_password_hash("ownerpass"),
             "Owner", "user", 350),
            (2, "admin@example.test", generate_password_hash("adminpass"),
             "Admin", "admin", 0),
            (3, "applicant@example.test", generate_password_hash("userpass"),
             "Applicant", "user", 20),
            (4, "manager@example.test", generate_password_hash("userpass"),
             "Manager", "user", 0),
            (5, "outsider@example.test", generate_password_hash("userpass"),
             "Outsider", "user", 0),
        ],
    )
    legacy_db.execute('''
        INSERT INTO organizer_applications (
            id, user_id, organization_name, contact, purpose, status,
            reviewed_by, reviewed_at
        ) VALUES (1, 1, 'Legacy Organization', 'contact@example.test',
                  'Legacy application', 'approved', 2, '2026-10-01 10:00:00')
    ''')
    legacy_db.execute('''
        INSERT INTO events (
            id, name, location, datetime, bonus_points, organizer_id, status
        ) VALUES (1, 'Legacy Event', 'Central Park', '2035-01-01 10:00',
                  50, 1, 'open')
    ''')
    legacy_db.execute('''
        INSERT INTO activity_history (
            id, user_id, event_id, type, title, points_earned
        ) VALUES (1, 1, NULL, 'trash_bin', 'Legacy activity', 10)
    ''')
legacy_db.close()

import app as cleanstep
cleanstep.init_db()

if _previous_database_path is None:
    os.environ.pop("CLEANSTEP_DATABASE_PATH", None)
else:
    os.environ["CLEANSTEP_DATABASE_PATH"] = _previous_database_path
if _previous_disable_ai is None:
    os.environ.pop("CLEANSTEP_DISABLE_AI", None)
else:
    os.environ["CLEANSTEP_DISABLE_AI"] = _previous_disable_ai
if _previous_demo_mode is None:
    os.environ.pop("CLEANSTEP_DEMO_MODE", None)
else:
    os.environ["CLEANSTEP_DEMO_MODE"] = _previous_demo_mode


@contextmanager
def database_connection():
    conn = cleanstep.get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class OrganizationModelTests(unittest.TestCase):
    PC_USER_AGENT = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
    )
    MOBILE_USER_AGENT = (
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile'
    )

    @classmethod
    def setUpClass(cls):
        cleanstep.app.config.update(TESTING=True)
        # init_db() が作成した初期DBを全テスト共通の読み取り元として保持する。
        # 各テストはこのDBの独立コピーを使い、固定IDのデータや変更が他テストへ漏れないようにする。
        cls._baseline_database = cleanstep.DATABASE

    def setUp(self):
        self._original_database = cleanstep.DATABASE
        self._test_database_dir = tempfile.TemporaryDirectory(prefix='cleanstep-test-')
        self._test_database_path = Path(self._test_database_dir.name) / 'test.db'

        # SQLite backup APIで整合性を保った状態のDBコピーを作る。
        with sqlite3.connect(self._baseline_database) as source_conn:
            with sqlite3.connect(self._test_database_path) as target_conn:
                source_conn.backup(target_conn)

        cleanstep.DATABASE = str(self._test_database_path)
        self.client = cleanstep.app.test_client()

    def tearDown(self):
        # テスト内で一時的にDATABASEを差し替えた場合も必ず元へ戻す。
        cleanstep.DATABASE = self._original_database
        self._test_database_dir.cleanup()

    def _csrf_token(self, path='/login'):
        self.client.get(path)
        with self.client.session_transaction() as user_session:
            return user_session['csrf_token']

    def _use_mobile_user_agent(self, client=None):
        (client or self.client).environ_base['HTTP_USER_AGENT'] = (
            self.MOBILE_USER_AGENT
        )

    def _use_pc_user_agent(self, client=None):
        (client or self.client).environ_base['HTTP_USER_AGENT'] = (
            self.PC_USER_AGENT
        )

    def test_user_report_aggregates_only_the_requested_user(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        current_month = datetime.now(cleanstep.JST).date().replace(day=5)
        previous_month = (
            current_month.replace(day=1) - timedelta(days=1)
        ).replace(day=5)
        current_activity_date = current_month.strftime('%Y-%m-%d 12:00:00')
        conn.execute('''
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                name TEXT,
                location TEXT,
                reward_details TEXT,
                category TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE activity_history (
                user_id INTEGER,
                event_id INTEGER,
                type TEXT,
                title TEXT,
                trash_count INTEGER,
                points_earned INTEGER,
                points_status TEXT DEFAULT 'awarded',
                points_pending INTEGER DEFAULT 0,
                date TEXT
            )
        ''')
        conn.execute('''
            INSERT INTO events (id, name, location, category)
            VALUES (1, '公園清掃', '中央公園', '公園・河川清掃')
        ''')
        conn.executemany('''
            INSERT INTO activity_history
                (user_id, event_id, type, title, trash_count, points_earned, date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', [
            (1, None, "trash_bin", "ごみ箱", 2, 5, current_activity_date),
            (1, 1, "event", "公園清掃", 0, 50, current_activity_date),
            (2, None, "trash_bin", "ごみ箱", 100, 1000, current_activity_date),
        ])

        report = cleanstep.generate_user_report(conn, 1)

        self.assertEqual(report["my_total_trash"], 2)
        self.assertEqual(report["my_event_count"], 1)
        self.assertEqual(report["monthly_trends"], [{
            "month": current_month.strftime('%Y-%m'),
            "trash": 2,
            "events": 1,
            "points": 55,
        }])
        self.assertEqual(report["current_month"]["trash"], 2)
        self.assertEqual(report["current_month"]["events"], 1)
        self.assertEqual(report["previous_month"]["points"], 0)
        self.assertEqual(report["previous_month"]["label"], previous_month.strftime('%Y年%m月'))
        self.assertEqual(report["preferred_categories"], [{
            'name': '公園・河川清掃', 'count': 1,
        }])
        self.assertEqual(report["activity_trends"][-1]["month"], current_month.strftime('%Y-%m'))
        conn.close()

    def test_user_report_tracks_reflection_behavior_indicators_by_month(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        current_month = datetime.now(cleanstep.JST).date().replace(day=5)
        previous_month = (
            current_month.replace(day=1) - timedelta(days=1)
        ).replace(day=5)
        conn.executescript('''
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                name TEXT,
                location TEXT,
                reward_details TEXT,
                category TEXT
            );
            CREATE TABLE activity_history (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                event_id INTEGER,
                type TEXT,
                title TEXT,
                trash_count INTEGER DEFAULT 0,
                points_earned INTEGER DEFAULT 0,
                points_status TEXT NOT NULL DEFAULT 'awarded',
                points_pending INTEGER NOT NULL DEFAULT 0,
                date TEXT
            );
            CREATE TABLE event_feedback (
                id INTEGER PRIMARY KEY,
                activity_id INTEGER,
                user_id INTEGER,
                event_id INTEGER,
                satisfaction INTEGER,
                comment TEXT,
                noticed_issue TEXT,
                suspected_cause TEXT,
                collaboration_note TEXT,
                next_improvement TEXT,
                action_status TEXT,
                action_note TEXT,
                submitted_at TEXT
            );
        ''')
        conn.executemany('''
            INSERT INTO events (id, name, location, category)
            VALUES (?, ?, '中央公園', '公園・河川清掃')
        ''', [(1, '先月の清掃'), (2, '今月の清掃')])
        conn.executemany('''
            INSERT INTO activity_history (
                id, user_id, event_id, type, title, date
            ) VALUES (?, 1, ?, 'event', ?, ?)
        ''', [
            (1, 1, '先月の清掃', previous_month.isoformat()),
            (2, 2, '今月の清掃', current_month.isoformat()),
        ])
        conn.executemany('''
            INSERT INTO event_feedback (
                id, activity_id, user_id, event_id, satisfaction, comment,
                noticed_issue, suspected_cause, collaboration_note,
                next_improvement, action_status, action_note, submitted_at
            ) VALUES (?, ?, ?, ?, 5, '', ?, ?, ?, ?, 'pending', '',
                      ? || ' 12:00:00')
        ''', [
            (1, 1, 1, 1, 'ごみの散乱', '通行量が多い', '', '', previous_month.isoformat()),
            (2, 2, 1, 2, '吸い殻', '', '分別を案内した', '表示を増やす', current_month.isoformat()),
            (3, 3, 2, 2, '別ユーザーの記録', '他ユーザーの原因', '', '', current_month.isoformat()),
        ])

        report = cleanstep.generate_user_report(conn, 1)

        previous_trend, current_trend = report['reflection_behavior_trends'][-2:]
        self.assertEqual(previous_trend['month'], previous_month.strftime('%Y-%m'))
        self.assertEqual(previous_trend['responses'], 1)
        self.assertEqual(previous_trend['issue_noticing'], 1)
        self.assertEqual(previous_trend['cause_analysis'], 1)
        self.assertEqual(previous_trend['collaboration'], 0)
        self.assertEqual(previous_trend['next_improvement'], 0)
        self.assertEqual(current_trend['month'], current_month.strftime('%Y-%m'))
        self.assertEqual(current_trend['responses'], 1)
        self.assertEqual(current_trend['issue_noticing'], 1)
        self.assertEqual(current_trend['cause_analysis'], 0)
        self.assertEqual(current_trend['collaboration'], 1)
        self.assertEqual(current_trend['next_improvement'], 1)
        conn.close()

    def test_event_category_suggestions_use_event_details(self):
        self.assertEqual(
            cleanstep.suggest_event_category('海岸ごみ拾い', '中央公園'),
            '海岸清掃',
        )
        self.assertEqual(
            cleanstep.suggest_event_category('川辺の清掃', '多摩川河川敷'),
            '公園・河川清掃',
        )
        self.assertEqual(
            cleanstep.suggest_event_category('環境ワークショップ', '市民館'),
            '環境学習・交流',
        )
        self.assertEqual(
            cleanstep.suggest_event_category('地域活動', '市民館'),
            'その他',
        )

    def test_activity_schedule_uses_real_upcoming_events_and_category_preferences(self):
        events = [
            {'id': 1, 'category': '海岸清掃', 'datetime': '2026-11-20 09:00', 'name': '海岸清掃'},
            {'id': 2, 'category': '公園・河川清掃', 'datetime': '2026-11-05 09:00', 'name': '公園清掃'},
            {'id': 3, 'category': '海岸清掃', 'datetime': '2027-01-10 09:00', 'name': '海岸活動'},
        ]
        schedule = cleanstep.build_recommended_activity_schedule(
            events,
            [{'name': '海岸清掃', 'count': 2}],
            datetime(2026, 10, 29, tzinfo=cleanstep.JST),
        )

        self.assertEqual(
            [month['label'] for month in schedule],
            ['2026年10月', '2026年11月', '2026年12月'],
        )
        self.assertEqual(schedule[1]['events'][0]['id'], 1)
        self.assertEqual(schedule[2]['events'], [])

    def test_home_renders_desktop_activity_feedback(self):
        self._login_as(1)

        response = self.client.get('/home')

        self.assertEqual(response.status_code, 200)
        self.assertIn('活動フィードバック'.encode(), response.data)
        self.assertIn('おすすめの活動スケジュール'.encode(), response.data)

    def test_exchange_demo_deducts_points_and_records_no_real_issuance(self):
        user_id = 991
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO users (id, email, password, name, role, total_points)
                VALUES (?, ?, '', 'Demo Tester', 'user', 1000)
            ''', (user_id, f'demo-{user_id}@example.test'))

        self._login_as(user_id)
        try:
            response = self.client.get("/exchange")
            self.assertEqual(response.status_code, 200)
            page = response.get_data(as_text=True)
            self.assertIn("えらべるPay（実証デモ）", page)
            self.assertIn("実際のギフト発券・決済・外部サービス連携は行われません", page)

            response = self.client.post(
                "/exchange/item",
                data={"csrf_token": "test-csrf-token", "item_id": "pay_demo"},
            )
            self.assertEqual(response.status_code, 302)
            response = self.client.get("/exchange")
            page = response.get_data(as_text=True)
            self.assertIn("実際のギフト発券・決済や外部サービスとの連携は行われません", page)
            self.assertIn("えらべるPay（実証デモ）", page)
            self.assertIn("✓ 交換済み", page)

            with database_connection() as conn:
                user = conn.execute(
                    'SELECT total_points FROM users WHERE id = ?', (user_id,)
                ).fetchone()
                exchange = conn.execute('''
                    SELECT item_id, cost FROM reward_history
                    WHERE user_id = ?
                ''', (user_id,)).fetchone()
            self.assertEqual(user["total_points"], 700)
            self.assertEqual(exchange["item_id"], "pay_demo")
            self.assertEqual(exchange["cost"], 300)

            response = self.client.post(
                "/exchange/item",
                data={"csrf_token": "test-csrf-token", "item_id": "pay_demo"},
            )
            self.assertEqual(response.status_code, 409)
            with database_connection() as conn:
                user = conn.execute(
                    'SELECT total_points FROM users WHERE id = ?', (user_id,)
                ).fetchone()
            self.assertEqual(user["total_points"], 700)
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM reward_history WHERE user_id = ?', (user_id,))
                conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

    def _login_as(self, user_id, role="user"):
        with self.client.session_transaction() as user_session:
            user_session["user_id"] = user_id
            user_session["role"] = role
            user_session["csrf_token"] = "test-csrf-token"

    def test_legacy_activity_migration_preserves_existing_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            legacy_path = Path(temp_dir) / 'legacy-migration.db'
            shutil.copy2(cleanstep.DATABASE, legacy_path)
            with sqlite3.connect(legacy_path) as legacy_db:
                legacy_db.execute('PRAGMA foreign_keys = OFF')
                legacy_db.execute('DELETE FROM activity_verification_history')
                legacy_db.execute('DELETE FROM activity_verifications')
                legacy_db.execute('DELETE FROM ai_duplicate_attempts')
                legacy_db.execute('DELETE FROM ai_logs')
                legacy_db.execute('DROP TABLE activity_history')
                legacy_db.execute('''
                    CREATE TABLE activity_history (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        type TEXT,
                        title TEXT,
                        trash_count INTEGER,
                        ai_detected_count INTEGER,
                        user_declared_count INTEGER,
                        points_earned INTEGER,
                        steps INTEGER,
                        duration INTEGER,
                        distance REAL,
                        calories INTEGER,
                        detox_duration INTEGER,
                        date TEXT
                    )
                ''')
                legacy_db.execute('''
                    INSERT INTO activity_history (
                        id, user_id, type, title, trash_count,
                        ai_detected_count, user_declared_count, points_earned,
                        steps, duration, distance, calories, detox_duration, date
                    ) VALUES (
                        78001, 1, 'event', 'Legacy GPS activity', 12,
                        8, 9, 40, 1200, 900, 1.25, 55, 10,
                        '2026-10-20 12:00:00'
                    )
                ''')
                legacy_db.execute('''
                    INSERT INTO activity_verifications (
                        target_type, activity_id, status, reviewer_id,
                        source_fingerprint
                    ) VALUES (
                        'user_declaration', 78001, 'confirmed', 2, 'legacy-fingerprint'
                    )
                ''')
                legacy_db.execute('''
                    INSERT INTO activity_verification_history (
                        target_type, activity_id, status, reviewer_id,
                        source_fingerprint
                    ) VALUES (
                        'user_declaration', 78001, 'confirmed', 2, 'legacy-fingerprint'
                    )
                ''')
            legacy_db.close()

            previous_database = cleanstep.DATABASE
            cleanstep.DATABASE = str(legacy_path)
            try:
                cleanstep.init_db()
                conn = cleanstep.get_db()
                try:
                    activity = conn.execute('''
                        SELECT * FROM activity_history WHERE id = 78001
                    ''').fetchone()
                    count_and_points = conn.execute('''
                        SELECT COUNT(*) AS count, SUM(points_earned) AS points
                        FROM activity_history
                    ''').fetchone()
                    unique_event_index = conn.execute('''
                        SELECT 1 FROM pragma_index_list('activity_history')
                        WHERE name = 'idx_activity_history_user_event'
                            AND "unique" = 1
                    ''').fetchone()
                    foreign_key_issues = conn.execute(
                        'PRAGMA foreign_key_check'
                    ).fetchall()
                    verification_count = conn.execute('''
                        SELECT COUNT(*) FROM activity_verifications
                        WHERE activity_id = 78001
                    ''').fetchone()[0]
                    verification_history_count = conn.execute('''
                        SELECT COUNT(*) FROM activity_verification_history
                        WHERE activity_id = 78001
                    ''').fetchone()[0]
                finally:
                    conn.close()
                self.assertEqual(activity['event_id'], None)
                self.assertEqual(activity['ai_detected_count'], 8)
                self.assertEqual(activity['user_declared_count'], 9)
                self.assertEqual(activity['steps'], 1200)
                self.assertEqual(activity['duration'], 900)
                self.assertEqual(activity['distance'], 1.25)
                self.assertEqual(activity['calories'], 55)
                self.assertEqual(activity['detox_duration'], 10)
                self.assertEqual(activity['gps_measured'], 0)
                self.assertEqual(activity['points_earned'], 40)
                self.assertEqual(activity['points_status'], 'awarded')
                self.assertEqual(activity['points_pending'], 0)
                self.assertEqual(count_and_points['count'], 1)
                self.assertEqual(count_and_points['points'], 40)
                self.assertIsNotNone(unique_event_index)
                self.assertEqual(verification_count, 1)
                self.assertEqual(verification_history_count, 1)
                self.assertEqual(foreign_key_issues, [])
            finally:
                cleanstep.DATABASE = previous_database

    def test_legacy_users_column_migration_preserves_foreign_key_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            legacy_path = Path(temp_dir) / 'legacy-users.db'
            shutil.copy2(cleanstep.DATABASE, legacy_path)
            with sqlite3.connect(legacy_path) as legacy_db:
                legacy_db.execute('ALTER TABLE users DROP COLUMN login_destination')
                legacy_db.execute('ALTER TABLE users ADD COLUMN today_points INTEGER DEFAULT 0')
                legacy_db.execute('''
                    CREATE TABLE legacy_user_reference (
                        user_id INTEGER REFERENCES users(id)
                    )
                ''')
                legacy_db.execute(
                    'INSERT INTO legacy_user_reference (user_id) VALUES (1)'
                )
                original_user_count = legacy_db.execute(
                    'SELECT COUNT(*) FROM users'
                ).fetchone()[0]
            legacy_db.close()

            previous_database = cleanstep.DATABASE
            cleanstep.DATABASE = str(legacy_path)
            try:
                cleanstep.init_db()
            finally:
                cleanstep.DATABASE = previous_database

            with sqlite3.connect(legacy_path) as migrated_db:
                migrated_db.execute('PRAGMA foreign_keys = ON')
                reference_target = migrated_db.execute(
                    'PRAGMA foreign_key_list(legacy_user_reference)'
                ).fetchone()[2]
                user_count = migrated_db.execute(
                    'SELECT COUNT(*) FROM users'
                ).fetchone()[0]
                legacy_column_exists = migrated_db.execute(
                    "SELECT 1 FROM pragma_table_info('users') WHERE name = 'today_points'"
                ).fetchone()
                old_table_exists = migrated_db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users_old'"
                ).fetchone()
                foreign_key_violations = migrated_db.execute(
                    'PRAGMA foreign_key_check'
                ).fetchall()
            migrated_db.close()

            self.assertEqual(reference_target, 'users')
            self.assertEqual(user_count, original_user_count)
            self.assertIsNotNone(legacy_column_exists)
            self.assertIsNone(old_table_exists)
            self.assertEqual(foreign_key_violations, [])

    def test_activity_migration_without_primary_key_stops_without_data_loss(self):
        temp_dir = tempfile.TemporaryDirectory()
        legacy_path = Path(temp_dir.name) / 'legacy-without-id.db'
        try:
            shutil.copy2(cleanstep.DATABASE, legacy_path)
            with sqlite3.connect(legacy_path) as legacy_db:
                legacy_db.execute('PRAGMA foreign_keys = OFF')
                legacy_db.execute('DELETE FROM activity_verification_history')
                legacy_db.execute('DELETE FROM activity_verifications')
                legacy_db.execute('DELETE FROM ai_duplicate_attempts')
                legacy_db.execute('DELETE FROM ai_logs')
                legacy_db.execute('DROP TABLE activity_history')
                legacy_db.execute('''
                    CREATE TABLE activity_history (
                        user_id INTEGER,
                        type TEXT,
                        title TEXT,
                        points_earned INTEGER
                    )
                ''')
                legacy_db.execute('''
                    INSERT INTO activity_history
                    VALUES (1, 'event', 'Activity without primary key', 25)
                ''')
            legacy_db.close()

            previous_database = cleanstep.DATABASE
            cleanstep.DATABASE = str(legacy_path)
            try:
                with self.assertRaisesRegex(RuntimeError, '主キーidがありません'):
                    cleanstep.init_db()
            finally:
                cleanstep.DATABASE = previous_database

            with sqlite3.connect(legacy_path) as legacy_db:
                row = legacy_db.execute('''
                    SELECT user_id, type, title, points_earned
                    FROM activity_history
                ''').fetchone()
                columns = {
                    item[1] for item in legacy_db.execute(
                        'PRAGMA table_info(activity_history)'
                    )
                }
            legacy_db.close()
            self.assertEqual(
                row, (1, 'event', 'Activity without primary key', 25)
            )
            self.assertEqual(
                columns, {'user_id', 'type', 'title', 'points_earned'}
            )
        finally:
            temp_dir.cleanup()

    def test_notification_schema_migration_preserves_rows_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            legacy_path = Path(temp_dir) / 'legacy-notifications.db'
            shutil.copy2(cleanstep.DATABASE, legacy_path)
            with sqlite3.connect(legacy_path) as legacy_db:
                legacy_db.execute('PRAGMA foreign_keys = OFF')
                legacy_db.execute('DROP TABLE user_notifications')
                legacy_db.execute('''
                    CREATE TABLE user_notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        event_id INTEGER,
                        notification_type TEXT NOT NULL
                            CHECK(notification_type IN (
                                'reminder', 'organizer_message', 'cancellation'
                            )),
                        title TEXT NOT NULL,
                        message TEXT NOT NULL CHECK(length(message) <= 1000),
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        read_at TEXT,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (event_id) REFERENCES events(id)
                    )
                ''')
                legacy_db.execute('''
                    INSERT INTO user_notifications (
                        id, user_id, event_id, notification_type, title, message,
                        created_at, read_at
                    ) VALUES (
                        78001, 1, 1, 'organizer_message', 'Legacy notice',
                        'Preserve this notification', '2026-10-20 12:00:00',
                        '2026-10-20 12:05:00'
                    )
                ''')
            legacy_db.close()

            previous_database = cleanstep.DATABASE
            cleanstep.DATABASE = str(legacy_path)
            try:
                cleanstep.init_db()
                cleanstep.init_db()
                with database_connection() as conn:
                    notice = conn.execute('''
                        SELECT id, user_id, event_id, notification_type, title,
                               message, created_at, read_at
                        FROM user_notifications WHERE id = 78001
                    ''').fetchone()
                    conn.executemany('''
                        INSERT INTO user_notifications (
                            user_id, event_id, notification_type, title, message
                        ) VALUES (1, 1, ?, ?, ?)
                    ''', [
                        (
                            notification_type,
                            f'Migration test: {notification_type}',
                            'New notification type is accepted',
                        )
                        for notification_type in (
                            'event_added', 'reservation',
                            'reservation_cancelled', 'activity_completed',
                        )
                    ])
                    foreign_key_issues = conn.execute(
                        'PRAGMA foreign_key_check'
                    ).fetchall()
                    migrated_count = conn.execute(
                        'SELECT COUNT(*) FROM user_notifications'
                    ).fetchone()[0]

                self.assertEqual(
                    tuple(notice),
                    (
                        78001, 1, 1, 'organizer_message', 'Legacy notice',
                        'Preserve this notification', '2026-10-20 12:00:00',
                        '2026-10-20 12:05:00',
                    ),
                )
                self.assertEqual(migrated_count, 5)
                self.assertEqual(foreign_key_issues, [])
            finally:
                cleanstep.DATABASE = previous_database

    def test_duplicate_successful_image_remains_pending_until_review(self):
        bin_name = 'Duplicate Image Test Bin'
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()['id']
            before_user = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()
            before_other_user = conn.execute(
                'SELECT total_points FROM users WHERE id = 3'
            ).fetchone()

        class DetectedBox:
            cls = 39
            conf = 0.9

        class DetectionResult:
            boxes = [DetectedBox(), DetectedBox()]

        class DetectionModel:
            def predict(self, *args, **kwargs):
                return [DetectionResult()]

        def image_upload():
            image = BytesIO()
            Image.new('RGB', (2, 2), color='white').save(image, format='PNG')
            image.seek(0)
            return image

        log_id = None
        activity_id = None
        self._login_as(1)
        self._use_mobile_user_agent()
        with tempfile.TemporaryDirectory() as upload_dir:
            try:
                with patch.object(cleanstep, 'UPLOAD_FOLDER', upload_dir):
                    with patch.object(
                        cleanstep, 'get_model', return_value=DetectionModel()
                    ):
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '2',
                                'bag_size': '大袋（45L相当）',
                                'garbage_image': (image_upload(), 'same.png'),
                            },
                            content_type='multipart/form-data',
                        )
                        self.assertEqual(response.status_code, 302)
                        self._login_as(3)
                        self._use_mobile_user_agent()
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '2',
                                'garbage_image': (image_upload(), 'reused.png'),
                            },
                            content_type='multipart/form-data',
                        )
                    self.assertEqual(response.status_code, 409)
                    self.assertIn('ポイントは付与されませんでした', response.get_data(as_text=True))

                    with database_connection() as conn:
                        original = conn.execute('''
                            SELECT id, activity_id, detected_count, image_sha256
                            FROM ai_logs WHERE user_id = 1
                            ORDER BY id DESC LIMIT 1
                        ''').fetchone()
                        log_id = original['id']
                        activity_id = original['activity_id']
                        user_points = conn.execute(
                            'SELECT total_points FROM users WHERE id = 1'
                        ).fetchone()['total_points']
                        other_user_points = conn.execute(
                            'SELECT total_points FROM users WHERE id = 3'
                        ).fetchone()['total_points']
                        attempts = conn.execute('''
                            SELECT COUNT(*) FROM ai_duplicate_attempts
                            WHERE original_ai_log_id = ?
                        ''', (log_id,)).fetchone()[0]
                        activity_count = conn.execute('''
                            SELECT COUNT(*) FROM activity_history
                            WHERE id = ?
                        ''', (activity_id,)).fetchone()[0]
                        recorded_activity = conn.execute('''
                                SELECT points_earned, points_status, points_pending,
                                       bag_size
                                FROM activity_history WHERE id = ?
                            ''', (activity_id,)).fetchone()
                    self.assertEqual(original['detected_count'], 2)
                    self.assertRegex(original['image_sha256'], r'^[0-9a-f]{64}$')
                    self.assertEqual(user_points, before_user['total_points'])
                    self.assertEqual(
                        other_user_points, before_other_user['total_points']
                    )
                    self.assertEqual(attempts, 1)
                    self.assertEqual(activity_count, 1)
                    self.assertEqual(recorded_activity['points_earned'], 0)
                    self.assertEqual(recorded_activity['points_status'], 'pending')
                    self.assertEqual(recorded_activity['points_pending'], 10)
                    self.assertEqual(
                        recorded_activity['bag_size'], '大袋（45L相当）'
                    )

                    self._login_as(2, 'admin')
                    response = self.client.get('/admin/ai/flags')
                    self.assertEqual(response.status_code, 200)
                    page = response.get_data(as_text=True)
                    self.assertIn('同一画像の再送信', page)
                    self.assertIn('ログ #' + str(log_id), page)
            finally:
                with database_connection() as conn:
                    if log_id is not None:
                        conn.execute(
                            'DELETE FROM ai_duplicate_attempts WHERE original_ai_log_id = ?',
                            (log_id,),
                        )
                        conn.execute(
                            'DELETE FROM ai_logs WHERE id = ?', (log_id,)
                        )
                    if activity_id is not None:
                        conn.execute(
                            'DELETE FROM activity_point_history WHERE activity_id = ?',
                            (activity_id,),
                        )
                        conn.execute(
                            'DELETE FROM activity_history WHERE id = ?',
                            (activity_id,),
                        )
                    conn.execute(
                        'UPDATE users SET total_points = ? WHERE id = ?',
                        (before_user['total_points'], 1),
                    )
                    conn.execute(
                        'DELETE FROM trash_bins WHERE id = ?', (bin_id,)
                    )

    def test_ai_points_wait_for_verification_and_reversals_are_audited(self):
        created_activity_id = None
        created_log_id = None
        with database_connection() as conn:
            original_roles = {
                row['id']: row['role']
                for row in conn.execute(
                    'SELECT id, role FROM users WHERE id IN (3, 4)'
                )
            }
            conn.execute("UPDATE users SET role = 'admin' WHERE id IN (3, 4)")
            starting_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']
            activity_cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, type, title, trash_count, ai_detected_count,
                    points_earned, points_status, points_pending
                ) VALUES (1, 'trash_bin', 'Point hold verification test',
                          2, 2, 0, 'pending', 10)
            ''')
            created_activity_id = activity_cursor.lastrowid
            log_cursor = conn.execute('''
                INSERT INTO ai_logs (
                    user_id, activity_id, detected_count, confidence,
                    image_path, detected_classes_json
                ) VALUES (1, ?, 2, 0.9, 'point-hold-test.jpg', ?)
            ''', (
                created_activity_id,
                json.dumps({'bottle': 2, 'cup': 0}),
            ))
            created_log_id = log_cursor.lastrowid
            conn.execute('''
                INSERT INTO activity_point_history (
                    activity_id, user_id, event_type, pending_points, reason
                ) VALUES (?, 1, 'pending', 10, 'Test pending point record')
            ''', (created_activity_id,))

        def submit_review(reviewer_id, bottle_count=None, cup_count=None):
            self._login_as(reviewer_id, 'admin')
            data = {'csrf_token': 'test-csrf-token', 'status': 'confirmed'}
            if bottle_count is not None:
                data['verified_bottle_count'] = str(bottle_count)
                data['verified_cup_count'] = str(cup_count)
            return self.client.post(
                f'/admin/activity-verifications/ai_result/{created_log_id}',
                data=data,
            )

        try:
            self.assertEqual(submit_review(2, 1, 0).status_code, 302)
            self.assertEqual(submit_review(3, 2, 0).status_code, 302)
            with database_connection() as conn:
                held = conn.execute('''
                    SELECT a.points_earned, a.points_status, a.points_pending,
                           u.total_points
                    FROM activity_history a
                    JOIN users u ON u.id = a.user_id
                    WHERE a.id = ?
                ''', (created_activity_id,)).fetchone()
            self.assertEqual(held['points_earned'], 0)
            self.assertEqual(held['points_status'], 'pending')
            self.assertEqual(held['points_pending'], 10)
            self.assertEqual(held['total_points'], starting_points)

            adjudication = submit_review(4, 3, 0)
            self.assertEqual(adjudication.status_code, 302)
            self.assertEqual(submit_review(4, 3, 0).status_code, 409)
            with database_connection() as conn:
                awarded = conn.execute('''
                    SELECT a.points_earned, a.points_status, a.points_pending,
                           u.total_points
                    FROM activity_history a
                    JOIN users u ON u.id = a.user_id
                    WHERE a.id = ?
                ''', (created_activity_id,)).fetchone()
                adjudication_state = conn.execute('''
                    SELECT adjudicated_bottle_count, adjudicated_cup_count
                    FROM activity_verifications WHERE ai_log_id = ?
                ''', (created_log_id,)).fetchone()
            self.assertEqual(
                tuple(adjudication_state), (3, 0),
                msg=adjudication.get_data(as_text=True),
            )
            self.assertEqual(awarded['points_earned'], 15)
            self.assertEqual(awarded['points_status'], 'awarded')
            self.assertEqual(awarded['points_pending'], 0)
            self.assertEqual(awarded['total_points'], starting_points + 15)

            self._login_as(2, 'admin')
            reset = self.client.post(
                f'/admin/activity-verifications/ai_result/{created_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'unreviewed',
                },
            )
            self.assertEqual(reset.status_code, 302)
            self.assertEqual(submit_review(2, 1, 0).status_code, 302)
            self.assertEqual(submit_review(3, 1, 0).status_code, 302)
            with database_connection() as conn:
                corrected = conn.execute('''
                    SELECT a.points_earned, a.points_status, a.points_pending,
                           u.total_points
                    FROM activity_history a
                    JOIN users u ON u.id = a.user_id
                    WHERE a.id = ?
                ''', (created_activity_id,)).fetchone()
                point_events = conn.execute('''
                    SELECT event_type, points_delta
                    FROM activity_point_history
                    WHERE activity_id = ? ORDER BY id
                ''', (created_activity_id,)).fetchall()
            self.assertEqual(corrected['points_earned'], 5)
            self.assertEqual(corrected['points_status'], 'awarded')
            self.assertEqual(corrected['points_pending'], 0)
            self.assertEqual(corrected['total_points'], starting_points + 5)

            self._login_as(2, 'admin')
            reset = self.client.post(
                f'/admin/activity-verifications/ai_result/{created_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'unreviewed',
                },
            )
            self.assertEqual(reset.status_code, 302)
            self.assertEqual(submit_review(2, 0, 0).status_code, 302)
            self.assertEqual(submit_review(3, 0, 0).status_code, 302)
            with database_connection() as conn:
                cancelled = conn.execute('''
                    SELECT a.points_earned, a.points_status, a.points_pending,
                           u.total_points
                    FROM activity_history a
                    JOIN users u ON u.id = a.user_id
                    WHERE a.id = ?
                ''', (created_activity_id,)).fetchone()
                point_events = conn.execute('''
                    SELECT event_type, points_delta
                    FROM activity_point_history
                    WHERE activity_id = ? ORDER BY id
                ''', (created_activity_id,)).fetchall()
            self.assertEqual(cancelled['points_earned'], 0)
            self.assertEqual(cancelled['points_status'], 'cancelled')
            self.assertEqual(cancelled['points_pending'], 0)
            self.assertEqual(cancelled['total_points'], starting_points)
            self.assertEqual(
                [(row['event_type'], row['points_delta']) for row in point_events],
                [
                    ('pending', 0),
                    ('awarded', 15),
                    ('reversed', -15),
                    ('awarded', 5),
                    ('reversed', -5),
                    ('cancelled', 0),
                ],
            )
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM activity_verification_history WHERE ai_log_id = ?',
                    (created_log_id,),
                )
                conn.execute(
                    'DELETE FROM activity_verifications WHERE ai_log_id = ?',
                    (created_log_id,),
                )
                conn.execute(
                    'DELETE FROM ai_logs WHERE id = ?', (created_log_id,)
                )
                if created_activity_id is not None:
                    conn.execute(
                        'DELETE FROM activity_point_history WHERE activity_id = ?',
                        (created_activity_id,),
                    )
                    conn.execute(
                        'DELETE FROM activity_history WHERE id = ?',
                        (created_activity_id,),
                    )
                conn.execute(
                    'UPDATE users SET total_points = ? WHERE id = ?',
                    (starting_points, 1),
                )
                for user_id, role in original_roles.items():
                    conn.execute(
                        'UPDATE users SET role = ? WHERE id = ?', (role, user_id)
                    )

    def test_concurrent_duplicate_images_create_one_pending_activity(self):
        bin_name = 'Concurrent Duplicate Image Test Bin'
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()['id']
            starting_user_points = {
                row['id']: row['total_points']
                for row in conn.execute('''
                    SELECT id, total_points FROM users WHERE id IN (1, 3)
                ''').fetchall()
            }
            starting_points = sum(starting_user_points.values())

        class DetectedBox:
            cls = 39
            conf = 0.9

        class DetectionResult:
            boxes = [DetectedBox(), DetectedBox()]

        barrier = threading.Barrier(2)

        class ConcurrentDetectionModel:
            def predict(self, *args, **kwargs):
                barrier.wait(timeout=10)
                return [DetectionResult()]

        image_buffer = BytesIO()
        Image.new('RGB', (2, 2), color='blue').save(image_buffer, format='PNG')
        image_bytes = image_buffer.getvalue()
        image_sha256 = hashlib.sha256(image_bytes).hexdigest()

        def image_upload():
            return BytesIO(image_bytes)

        clients = [cleanstep.app.test_client(), cleanstep.app.test_client()]
        for client, user_id in zip(clients, (1, 3)):
            self._use_mobile_user_agent(client)
            with client.session_transaction() as user_session:
                user_session['user_id'] = user_id
                user_session['role'] = 'user'
                user_session['csrf_token'] = 'test-csrf-token'

        def submit(client, filename):
            return client.post(
                '/trash-bin/deposit',
                data={
                    'csrf_token': 'test-csrf-token',
                    'bin_id': str(bin_id),
                    'trash_count': '2',
                    'garbage_image': (image_upload(), filename),
                },
                content_type='multipart/form-data',
            )

        log_ids = []
        activity_ids = []
        with tempfile.TemporaryDirectory() as upload_dir:
            try:
                with patch.object(cleanstep, 'UPLOAD_FOLDER', upload_dir):
                    with patch.object(
                        cleanstep,
                        'get_model',
                        return_value=ConcurrentDetectionModel(),
                    ):
                        with ThreadPoolExecutor(max_workers=2) as executor:
                            responses = list(executor.map(
                                lambda args: submit(*args),
                                zip(clients, ('concurrent-a.png', 'concurrent-b.png')),
                            ))
                self.assertEqual(
                    sorted(response.status_code for response in responses),
                    [302, 409],
                )
                with database_connection() as conn:
                    rows = conn.execute('''
                        SELECT id, activity_id FROM ai_logs
                        WHERE image_sha256 = ?
                    ''', (image_sha256,)).fetchall()
                    log_ids = [row['id'] for row in rows]
                    activity_ids = [
                        row['activity_id'] for row in rows
                        if row['activity_id'] is not None
                    ]
                    total_points = conn.execute('''
                        SELECT SUM(total_points) FROM users WHERE id IN (1, 3)
                    ''').fetchone()[0]
                    attempts = conn.execute('''
                        SELECT COUNT(*) FROM ai_duplicate_attempts
                        WHERE image_sha256 = ?
                    ''', (image_sha256,)).fetchone()[0]
                self.assertEqual(len(log_ids), 1)
                self.assertEqual(len(activity_ids), 1)
                self.assertEqual(total_points, starting_points)
                self.assertEqual(attempts, 1)
            finally:
                with database_connection() as conn:
                    conn.execute(
                        'DELETE FROM ai_duplicate_attempts WHERE image_sha256 = ?',
                        (image_sha256,),
                    )
                    if log_ids:
                        placeholders = ','.join('?' for _ in log_ids)
                        conn.execute(
                            f'DELETE FROM ai_logs WHERE id IN ({placeholders})',
                            log_ids,
                        )
                    if activity_ids:
                        placeholders = ','.join('?' for _ in activity_ids)
                        conn.execute(
                            f'DELETE FROM activity_point_history WHERE activity_id IN ({placeholders})',
                            activity_ids,
                        )
                        conn.execute(
                            f'DELETE FROM activity_history WHERE id IN ({placeholders})',
                            activity_ids,
                        )
                    conn.executemany(
                        'UPDATE users SET total_points = ? WHERE id = ?',
                        [
                            (points, user_id)
                            for user_id, points in starting_user_points.items()
                        ],
                    )
                    conn.execute(
                        'DELETE FROM trash_bins WHERE id = ?', (bin_id,)
                    )

    def test_failed_point_history_write_rolls_back_activity_and_ai_log(self):
        bin_name = 'Rollback Deposit Test Bin'
        trigger_name = 'test_abort_point_history_insert'
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()['id']
            before_user = conn.execute('''
                SELECT total_points,
                       (SELECT COUNT(*) FROM activity_history WHERE user_id = users.id)
                           AS activities,
                       (SELECT COUNT(*) FROM ai_logs WHERE user_id = users.id)
                           AS logs
                FROM users WHERE id = 1
            ''').fetchone()
            conn.execute(f'''
                CREATE TRIGGER {trigger_name}
                BEFORE INSERT ON activity_point_history
                WHEN NEW.user_id = 1
                BEGIN
                    SELECT RAISE(ABORT, 'simulated point history failure');
                END
            ''')

        class DetectedBox:
            cls = 39
            conf = 0.9

        class DetectionResult:
            boxes = [DetectedBox(), DetectedBox()]

        class DetectionModel:
            def predict(self, *args, **kwargs):
                return [DetectionResult()]

        image = BytesIO()
        Image.new('RGB', (2, 2), color='green').save(image, format='PNG')
        image_bytes = image.getvalue()
        image_sha256 = hashlib.sha256(image_bytes).hexdigest()
        self._login_as(1)
        self._use_mobile_user_agent()
        with tempfile.TemporaryDirectory() as upload_dir:
            try:
                with patch.object(cleanstep, 'UPLOAD_FOLDER', upload_dir):
                    with patch.object(
                        cleanstep, 'get_model', return_value=DetectionModel()
                    ):
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '2',
                                'garbage_image': (
                                    BytesIO(image_bytes), 'rollback.png'
                                ),
                            },
                            content_type='multipart/form-data',
                        )
                self.assertEqual(response.status_code, 500)
                with database_connection() as conn:
                    after_user = conn.execute('''
                        SELECT total_points,
                               (SELECT COUNT(*) FROM activity_history
                                WHERE user_id = users.id) AS activities,
                               (SELECT COUNT(*) FROM ai_logs
                                WHERE user_id = users.id) AS logs
                        FROM users WHERE id = 1
                    ''').fetchone()
                    matching_logs = conn.execute(
                        'SELECT COUNT(*) FROM ai_logs WHERE image_sha256 = ?',
                        (image_sha256,),
                    ).fetchone()[0]
                self.assertEqual(after_user['total_points'], before_user['total_points'])
                self.assertEqual(after_user['activities'], before_user['activities'])
                self.assertEqual(after_user['logs'], before_user['logs'])
                self.assertEqual(matching_logs, 0)
            finally:
                with database_connection() as conn:
                    conn.execute(f'DROP TRIGGER IF EXISTS {trigger_name}')
                    conn.execute(
                        'DELETE FROM trash_bins WHERE id = ?', (bin_id,)
                    )

    def test_ai_zero_detection_and_failure_are_logged_without_points(self):
        bin_name = 'AI Result Status Test Bin'
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()['id']
            before_user = conn.execute('''
                SELECT total_points,
                       (SELECT COUNT(*) FROM activity_history WHERE user_id = users.id)
                           AS activity_count
                FROM users WHERE id = 1
            ''').fetchone()

        class NoDetectionModel:
            def predict(self, *args, **kwargs):
                return []

        class FailedModel:
            def predict(self, *args, **kwargs):
                raise RuntimeError('simulated inference failure')

        def image_upload(color='white'):
            image = BytesIO()
            Image.new('RGB', (2, 2), color=color).save(image, format='PNG')
            image.seek(0)
            return image

        self._login_as(1)
        self._use_mobile_user_agent()
        log_ids = []
        with tempfile.TemporaryDirectory() as upload_dir:
            try:
                with patch.object(cleanstep, 'UPLOAD_FOLDER', upload_dir):
                    with patch.object(cleanstep, 'get_model', return_value=NoDetectionModel()):
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '1',
                                'garbage_image': (image_upload(), 'zero.png'),
                            },
                            content_type='multipart/form-data',
                        )
                    self.assertEqual(response.status_code, 422)

                    with patch.object(cleanstep, 'get_model', return_value=NoDetectionModel()):
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '1',
                                'garbage_image': (image_upload(), 'duplicate.png'),
                            },
                            content_type='multipart/form-data',
                        )
                    self.assertEqual(response.status_code, 409)

                    with patch.object(cleanstep, 'get_model', return_value=FailedModel()):
                        response = self.client.post(
                            '/trash-bin/deposit',
                            data={
                                'csrf_token': 'test-csrf-token',
                                'bin_id': str(bin_id),
                                'trash_count': '1',
                                'garbage_image': (image_upload(color='black'), 'failed.png'),
                            },
                            content_type='multipart/form-data',
                        )
                    self.assertEqual(response.status_code, 503)

                    with database_connection() as conn:
                        logs = conn.execute('''
                            SELECT id, result_status, detected_count, activity_id,
                                       detected_classes_json, image_sha256
                                FROM ai_logs WHERE user_id = 1
                            ORDER BY id DESC LIMIT 2
                        ''').fetchall()
                        log_ids = [log['id'] for log in logs]
                        after_user = conn.execute('''
                            SELECT total_points,
                                   (SELECT COUNT(*) FROM activity_history
                                    WHERE user_id = users.id) AS activity_count
                            FROM users WHERE id = 1
                        ''').fetchone()
                    by_status = {log['result_status']: log for log in logs}
                    self.assertEqual(set(by_status), {'no_detection', 'failed'})
                    self.assertEqual(by_status['no_detection']['detected_count'], 0)
                    self.assertEqual(
                        json.loads(by_status['no_detection']['detected_classes_json']),
                        {'bottle': 0, 'cup': 0},
                    )
                    self.assertTrue(by_status['no_detection']['image_sha256'])
                    self.assertIsNone(by_status['no_detection']['activity_id'])
                    self.assertIsNone(by_status['failed']['detected_count'])
                    self.assertIsNone(by_status['failed']['image_sha256'])
                    self.assertIsNone(by_status['failed']['activity_id'])
                    self.assertEqual(after_user['total_points'], before_user['total_points'])
                    self.assertEqual(
                        after_user['activity_count'], before_user['activity_count']
                    )

                    self._login_as(2, 'admin')
                    response = self.client.get('/admin/ai')
                    self.assertEqual(response.status_code, 200)
                    logs_page = response.get_data(as_text=True)
                    self.assertIn('検出0件', logs_page)
                    self.assertIn('判定失敗', logs_page)
                    self.assertIn('—', logs_page)
                    for log_id in log_ids:
                        response = self.client.get(f'/admin/ai/{log_id}')
                        self.assertEqual(response.status_code, 200)
                        detail_page = response.get_data(as_text=True)
                        self.assertIn('判定結果：', detail_page)
                        self.assertIn('未記録', detail_page)
                    response = self.client.get('/admin/activity-report')
                    self.assertEqual(response.status_code, 200)
                    report_page = response.get_data(as_text=True)
                    self.assertRegex(report_page, r'検出0件\s+1 件')
                    self.assertRegex(report_page, r'判定失敗\s+1 件')
                    self.assertRegex(report_page, r'画像ログ上の検出数合計\s+0')
            finally:
                with database_connection() as conn:
                    if log_ids:
                        placeholders = ','.join('?' for _ in log_ids)
                        conn.execute(
                            f'DELETE FROM activity_verification_history '
                            f'WHERE ai_log_id IN ({placeholders})',
                            log_ids,
                        )
                        conn.execute(
                            f'DELETE FROM activity_verifications '
                            f'WHERE ai_log_id IN ({placeholders})',
                            log_ids,
                        )
                        conn.execute(
                            f'DELETE FROM ai_duplicate_attempts '
                            f'WHERE original_ai_log_id IN ({placeholders})',
                            log_ids,
                        )
                        conn.execute(
                            f'DELETE FROM ai_logs WHERE id IN ({placeholders})',
                            log_ids,
                        )
                    conn.execute('DELETE FROM trash_bins WHERE id = ?', (bin_id,))

    def test_admin_ai_image_route_requires_generated_uuid_filename(self):
        image_name = '12345678-1234-1234-1234-123456789abc.png'
        with tempfile.TemporaryDirectory() as upload_dir:
            image_path = Path(upload_dir) / image_name
            image_path.write_bytes(b'validated image')
            self._login_as(2, 'admin')
            with patch.object(cleanstep, 'UPLOAD_FOLDER', upload_dir):
                response = self.client.get(f'/admin/ai/image/{image_name}')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data, b'validated image')
                response.close()
                self.assertEqual(
                    self.client.get('/admin/ai/image/not-a-uuid.png').status_code,
                    404,
                )
                self.assertEqual(
                    self.client.get(
                        '/admin/ai/image/12345678-1234-1234-1234-123456789abc.txt'
                    ).status_code,
                    404,
                )
                self.assertEqual(
                    self.client.get(
                        '/admin/ai/image/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.png'
                    ).status_code,
                    404,
                )

    def test_existing_user_and_admin_views_keep_working(self):
        csrf_token = self._csrf_token()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "email": "owner@example.test",
                "password": "ownerpass",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/organizer")
        home_response = self.client.get("/home")
        self.assertEqual(home_response.status_code, 200)
        self.assertIn("基本の活動記録".encode(), home_response.data)
        page = home_response.get_data(as_text=True)
        self.assertNotIn("実績・目標進捗", page)
        self.assertNotIn("最も近い目標", page)
        self.assertNotIn("ミッションクリア", page)
        self.assertNotIn("未達成", page)
        self.assertNotIn("清掃委託費 削減貢献", page)
        self.assertNotIn("解放されます", page)
        self.assertIn("イベント一覧", page)
        self.assertNotIn("開催中のクリーン作戦", page)

        self._login_as(2, "admin")
        response = self.client.get("/admin/events")
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Legacy Organization", response.get_data()
        )
        response = self.client.get("/admin/activity-report")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<table>", response.data)

    def test_regular_user_login_still_redirects_to_home(self):
        user_id = 992
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO users (id, email, password, name, role, total_points)
                VALUES (?, ?, ?, 'Regular User', 'user', 0)
            ''', (
                user_id,
                "regular-login@example.test",
                generate_password_hash("userpass"),
            ))

        try:
            csrf_token = self._csrf_token()
            response = self.client.post(
                "/login",
                data={
                    "csrf_token": csrf_token,
                    "email": "regular-login@example.test",
                    "password": "userpass",
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/home")
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM users WHERE id = ?', (user_id,))

    def test_login_and_registration_reject_missing_csrf_token(self):
        login_response = self.client.post(
            '/login',
            data={'email': 'owner@example.test', 'password': 'ownerpass'},
        )
        register_response = self.client.post(
            '/register',
            data={
                'name': 'New User',
                'email': 'new-user@example.test',
                'password': 'validpass123',
            },
        )
        self.assertEqual(login_response.status_code, 400)
        self.assertEqual(register_response.status_code, 400)

    def test_login_failures_are_rate_limited(self):
        test_ip = '198.51.100.10'
        self.client.environ_base['REMOTE_ADDR'] = test_ip
        csrf_token = self._csrf_token()
        email = 'blocked-login@example.test'
        for _ in range(10):
            response = self.client.post(
                '/login',
                data={
                    'csrf_token': csrf_token,
                    'email': email,
                    'password': 'wrong-password',
                },
            )
            self.assertEqual(response.status_code, 200)

        blocked_response = self.client.post(
            '/login',
            data={
                'csrf_token': csrf_token,
                'email': email,
                'password': 'wrong-password',
            },
        )
        self.assertEqual(blocked_response.status_code, 429)
        with cleanstep.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': test_ip}
        ):
            email_rate_key = cleanstep._auth_rate_key('login-email', email)
            ip_rate_key = cleanstep._auth_rate_key('login-ip')
        with database_connection() as conn:
            conn.executemany(
                'DELETE FROM auth_rate_limits WHERE rate_key = ?',
                [(email_rate_key,), (ip_rate_key,)],
            )

    def test_successful_login_clears_rate_limit_counters(self):
        test_ip = '198.51.100.11'
        self.client.environ_base['REMOTE_ADDR'] = test_ip
        csrf_token = self._csrf_token()
        email = 'owner@example.test'
        for _ in range(9):
            response = self.client.post(
                '/login',
                data={
                    'csrf_token': csrf_token,
                    'email': email,
                    'password': 'wrong-password',
                },
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.post(
            '/login',
            data={
                'csrf_token': csrf_token,
                'email': email,
                'password': 'ownerpass',
            },
        )
        self.assertEqual(response.status_code, 302)
        with cleanstep.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': test_ip}
        ):
            rate_keys = (
                cleanstep._auth_rate_key('login-email', email),
                cleanstep._auth_rate_key('login-ip'),
            )
        try:
            with database_connection() as conn:
                counts = [
                    conn.execute(
                        'SELECT COUNT(*) FROM auth_rate_limits WHERE rate_key = ?',
                        (rate_key,),
                    ).fetchone()[0]
                    for rate_key in rate_keys
                ]
            self.assertEqual(counts, [0, 0])
        finally:
            with database_connection() as conn:
                conn.executemany(
                    'DELETE FROM auth_rate_limits WHERE rate_key = ?',
                    [(rate_key,) for rate_key in rate_keys],
                )

    def test_registration_attempt_limit_counts_invalid_submissions(self):
        test_ip = '198.51.100.12'
        self.client.environ_base['REMOTE_ADDR'] = test_ip
        csrf_token = self._csrf_token('/register')
        for _ in range(5):
            response = self.client.post(
                '/register',
                data={
                    'csrf_token': csrf_token,
                    'name': 'Invalid Signup',
                    'email': 'not-an-email',
                    'password': 'short',
                },
            )
            self.assertEqual(response.status_code, 200)

        with cleanstep.app.test_request_context(
            '/', environ_base={'REMOTE_ADDR': test_ip}
        ):
            rate_key = cleanstep._auth_rate_key('register')
        try:
            with database_connection() as conn:
                attempt_count = conn.execute(
                    'SELECT COUNT(*) FROM auth_rate_limits WHERE rate_key = ?',
                    (rate_key,),
                ).fetchone()[0]
            self.assertEqual(attempt_count, 5)

            blocked_response = self.client.post(
                '/register',
                data={
                    'csrf_token': csrf_token,
                    'name': 'Valid Signup',
                    'email': 'valid-signup@example.test',
                    'password': 'validpassword123',
                },
            )
            self.assertEqual(blocked_response.status_code, 429)
            with database_connection() as conn:
                user = conn.execute(
                    'SELECT id FROM users WHERE email = ?',
                    ('valid-signup@example.test',),
                ).fetchone()
            self.assertIsNone(user)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM auth_rate_limits WHERE rate_key = ?', (rate_key,)
                )

    def test_registration_normalizes_email_and_validates_password(self):
        csrf_token = self._csrf_token('/register')
        invalid_response = self.client.post(
            '/register',
            data={
                'csrf_token': csrf_token,
                'name': 'New User',
                'email': 'NEW-USER@example.test',
                'password': 'short',
            },
        )
        self.assertEqual(invalid_response.status_code, 200)
        self.assertIn('8〜128文字'.encode(), invalid_response.data)

        valid_response = self.client.post(
            '/register',
            data={
                'csrf_token': csrf_token,
                'name': 'New User',
                'email': 'NEW-USER@example.test',
                'password': 'validpass123',
            },
        )
        self.assertEqual(valid_response.status_code, 302)
        try:
            with database_connection() as conn:
                user = conn.execute(
                    'SELECT email FROM users WHERE email = ?',
                    ('new-user@example.test',),
                ).fetchone()
            self.assertIsNotNone(user)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM users WHERE email = ?',
                    ('new-user@example.test',),
                )

    def test_organization_registration_submits_application_for_admin_review(self):
        email = 'signup-organization@example.test'
        csrf_token = self._csrf_token('/register')
        try:
            response = self.client.post(
                '/register',
                data={
                    'csrf_token': csrf_token,
                    'name': '団体担当者',
                    'email': email,
                    'password': 'validpass123',
                    'account_type': 'organization',
                    'organization_name': '地域清掃チーム',
                    'organization_contact': 'contact@example.test',
                    'organization_purpose': '地域清掃イベントの企画・運営',
                },
            )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, '/login')

            with database_connection() as conn:
                application = conn.execute('''
                    SELECT u.id AS user_id, u.role, a.organization_name,
                           a.contact, a.purpose, a.status
                    FROM users u
                    JOIN organizer_applications a ON a.user_id = u.id
                    WHERE u.email = ?
                ''', (email,)).fetchone()
            self.assertIsNotNone(application)
            self.assertEqual(application['role'], 'user')
            self.assertEqual(application['organization_name'], '地域清掃チーム')
            self.assertEqual(application['contact'], 'contact@example.test')
            self.assertEqual(
                application['purpose'], '地域清掃イベントの企画・運営'
            )
            self.assertEqual(application['status'], 'pending')

            self._login_as(2, 'admin')
            review_page = self.client.get('/admin/organizer-applications')
            self.assertEqual(review_page.status_code, 200)
            self.assertIn('地域清掃チーム', review_page.get_data(as_text=True))
            self.assertIn('審査待ち', review_page.get_data(as_text=True))
        finally:
            with database_connection() as conn:
                user = conn.execute(
                    'SELECT id FROM users WHERE email = ?', (email,)
                ).fetchone()
                if user:
                    conn.execute(
                        'DELETE FROM organizer_applications WHERE user_id = ?',
                        (user['id'],),
                    )
                    conn.execute('DELETE FROM users WHERE id = ?', (user['id'],))

    def test_admin_role_is_rechecked_against_database(self):
        self._login_as(2, 'admin')
        with database_connection() as conn:
            conn.execute("UPDATE users SET role = 'user' WHERE id = 2")
        try:
            response = self.client.get('/admin/events')
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, '/login')
            with self.client.session_transaction() as user_session:
                self.assertNotIn('user_id', user_session)
        finally:
            with database_connection() as conn:
                conn.execute("UPDATE users SET role = 'admin' WHERE id = 2")

    def test_admin_can_change_login_destination_without_revoking_organization(self):
        admin_client = cleanstep.app.test_client()
        with admin_client.session_transaction() as admin_session:
            admin_session.update({
                "user_id": 2,
                "role": "admin",
                "csrf_token": "test-csrf-token",
            })

        page = admin_client.get("/admin/users").get_data(as_text=True)
        self.assertIn("ログイン後の画面", page)
        self.assertIn('value="organizer"', page)

        response = admin_client.post(
            "/admin/users/1/login-destination",
            data={
                "csrf_token": "test-csrf-token",
                "login_destination": "user",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            membership = conn.execute('''
                SELECT om.status, o.status AS organization_status,
                       a.status AS application_status
                FROM organization_members om
                JOIN organizations o ON o.id = om.organization_id
                JOIN organizer_applications a ON a.id = o.application_id
                WHERE om.user_id = 1
            ''').fetchone()
            self.assertEqual(membership["status"], "active")
            self.assertEqual(membership["organization_status"], "approved")
            self.assertEqual(membership["application_status"], "approved")

        user_client = cleanstep.app.test_client()
        user_client.get('/login')
        with user_client.session_transaction() as user_session:
            csrf_token = user_session['csrf_token']
        response = user_client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "email": "owner@example.test",
                "password": "ownerpass",
            },
        )
        self.assertEqual(response.location, "/home")

        response = admin_client.post(
            "/admin/users/1/login-destination",
            data={
                "csrf_token": "test-csrf-token",
                "login_destination": "organizer",
            },
        )
        self.assertEqual(response.status_code, 302)
        organizer_client = cleanstep.app.test_client()
        organizer_client.get('/login')
        with organizer_client.session_transaction() as user_session:
            csrf_token = user_session['csrf_token']
        response = organizer_client.post(
            "/login",
            data={
                "csrf_token": csrf_token,
                "email": "owner@example.test",
                "password": "ownerpass",
            },
        )
        self.assertEqual(response.location, "/organizer")

        response = admin_client.post(
            "/admin/users/5/login-destination",
            data={
                "csrf_token": "test-csrf-token",
                "login_destination": "organizer",
            },
        )
        self.assertEqual(response.status_code, 409)

    def test_migration_preserves_approved_organization_and_legacy_records(self):
        cleanstep.init_db()

        with database_connection() as conn:
            organization = conn.execute('''
                SELECT o.id, o.name, a.organization_id
                FROM organizations o
                JOIN organizer_applications a ON a.id = o.application_id
                WHERE a.id = 1
            ''').fetchone()
            owner = conn.execute('''
                SELECT role FROM organization_members
                WHERE organization_id = ? AND user_id = 1
            ''', (organization["id"],)).fetchone()
            event = conn.execute(
                'SELECT organization_id FROM events WHERE id = 1'
            ).fetchone()
            user = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()
            activity = conn.execute(
                'SELECT title, gps_measured FROM activity_history WHERE id = 1'
            ).fetchone()
            verification_tables = conn.execute('''
                SELECT COUNT(*) FROM sqlite_master
                WHERE type = 'table' AND name IN (
                    'activity_verifications', 'activity_verification_history'
                )
            ''').fetchone()[0]
            counts = conn.execute('''
                SELECT
                    (SELECT COUNT(*) FROM organizations
                     WHERE application_id = 1) AS organizations,
                    (SELECT COUNT(*) FROM organization_members
                     WHERE organization_id = ? AND role = 'owner') AS owners
            ''', (organization["id"],)).fetchone()

        self.assertEqual(organization["name"], "Legacy Organization")
        self.assertEqual(organization["organization_id"], organization["id"])
        self.assertEqual(owner["role"], "owner")
        self.assertEqual(event["organization_id"], organization["id"])
        self.assertEqual(user["total_points"], 350)
        self.assertEqual(activity["title"], "Legacy activity")
        self.assertEqual(activity["gps_measured"], 0)
        self.assertEqual(verification_tables, 2)
        self.assertEqual(counts["organizations"], 1)
        self.assertEqual(counts["owners"], 1)

    def test_activity_verifications_are_admin_only_and_track_independent_targets(self):
        created_activity_ids = []
        created_log_ids = []
        original_roles = {}
        with database_connection() as conn:
            original_roles = {
                row['id']: row['role']
                for row in conn.execute(
                    'SELECT id, role FROM users WHERE id IN (3, 4)'
                )
            }
            conn.execute("UPDATE users SET role = 'admin' WHERE id IN (3, 4)")
            declaration_cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, type, title, user_declared_count, points_earned, date
                ) VALUES (1, 'trash_bin', 'Verification Test Bin', 5, 0, ?)
            ''', (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),))
            declaration_activity_id = declaration_cursor.lastrowid
            created_activity_ids.append(declaration_activity_id)
            ai_cursor = conn.execute('''
                INSERT INTO ai_logs (
                    user_id, activity_id, detected_count, confidence, image_path,
                    detected_classes_json
                ) VALUES (1, NULL, 4, 0.9, 'verification-test.jpg', ?)
            ''', (json.dumps({'bottle': 3, 'cup': 1}),))
            ai_log_id = ai_cursor.lastrowid
            created_log_ids.append(ai_log_id)
            second_ai_cursor = conn.execute('''
                INSERT INTO ai_logs (
                    user_id, activity_id, detected_count, confidence, image_path,
                    detected_classes_json
                ) VALUES (1, NULL, 2, 0.8, 'verification-test-second.jpg', ?)
            ''', (json.dumps({'bottle': 2, 'cup': 0}),))
            second_ai_log_id = second_ai_cursor.lastrowid
            created_log_ids.append(second_ai_log_id)

            gps_cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, type, title, steps, distance, calories,
                    gps_measured, points_earned, date
                ) VALUES (1, 'event', 'GPS Verification Test', 0, 0, 0, 1, 0, ?)
            ''', (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),))
            gps_activity_id = gps_cursor.lastrowid
            created_activity_ids.append(gps_activity_id)
            unrecorded_gps_cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, type, title, steps, distance, calories,
                    gps_measured, points_earned, date
                ) VALUES (1, 'event', 'Unrecorded GPS Report Test',
                          NULL, NULL, NULL, 1, 0, ?)
            ''', (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),))
            unrecorded_gps_activity_id = unrecorded_gps_cursor.lastrowid
            created_activity_ids.append(unrecorded_gps_activity_id)

        try:
            self._login_as(1)
            response = self.client.get('/admin/activity-verifications')
            self.assertEqual(response.status_code, 302)
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{ai_log_id}',
                data={'csrf_token': 'test-csrf-token', 'status': 'confirmed'},
            )
            self.assertEqual(response.status_code, 302)

            self._login_as(2, 'admin')
            response = self.client.get('/admin/activity-verifications')
            self.assertEqual(response.status_code, 200)
            page = response.get_data(as_text=True)
            self.assertIn(f'id="ai_result-{ai_log_id}"', page)
            self.assertIn(f'id="ai_result-{second_ai_log_id}"', page)
            self.assertIn(f'id="user_declaration-{declaration_activity_id}"', page)
            self.assertIn(f'id="gps_distance-{gps_activity_id}"', page)
            self.assertIn(f'id="gps_steps-{gps_activity_id}"', page)
            self.assertIn(f'id="gps_calories-{gps_activity_id}"', page)
            self.assertIn('AI判定値は非表示'.encode(), response.data)
            self.assertNotIn('4 個 / 信頼度 90.0%', page)
            self.assertNotIn(f'/admin/ai/{ai_log_id}', page)
            self.assertIn('0.000 km', page)
            self.assertIn('0 歩', page)
            self.assertIn('0 kcal', page)

            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '3',
                    'verified_cup_count': '1',
                },
            )
            self.assertEqual(response.status_code, 302)
            same_reviewer_second_pass = self.client.post(
                f'/admin/activity-verifications/ai_result/{ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '3',
                    'verified_cup_count': '1',
                },
            )
            self.assertEqual(same_reviewer_second_pass.status_code, 302)
            with database_connection() as conn:
                one_reviewer = conn.execute('''
                    SELECT reviewer_id, reviewer2_id
                    FROM activity_verifications
                    WHERE target_type = 'ai_result' AND ai_log_id = ?
                ''', (ai_log_id,)).fetchone()
            self.assertEqual(one_reviewer['reviewer_id'], 2)
            self.assertIsNone(one_reviewer['reviewer2_id'])
            missing_reference_counts = self.client.post(
                f'/admin/activity-verifications/ai_result/{second_ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                },
            )
            self.assertEqual(missing_reference_counts.status_code, 400)
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{second_ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '2',
                    'verified_cup_count': '0',
                },
            )
            self.assertEqual(response.status_code, 302)
            self._login_as(3, 'admin')
            second_review_page = self.client.get('/admin/activity-verifications')
            self.assertEqual(second_review_page.status_code, 200)
            second_review_html = second_review_page.get_data(as_text=True)
            first_log_row = re.search(
                rf'<tr id="ai_result-{ai_log_id}".*?</tr>',
                second_review_html,
                re.DOTALL,
            )
            self.assertIsNotNone(first_log_row)
            self.assertIn('一次確認とは独立して'.encode(), second_review_page.data)
            self.assertNotIn('ボトル 3 個 / カップ 1 個', first_log_row.group(0))
            self.assertNotIn('4 個 / 信頼度 90.0%', first_log_row.group(0))
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '3',
                    'verified_cup_count': '1',
                },
            )
            self.assertEqual(response.status_code, 302)
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{second_ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '1',
                    'verified_cup_count': '1',
                },
            )
            self.assertEqual(response.status_code, 302)
            self._login_as(4, 'admin')
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{second_ai_log_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'confirmed',
                    'verified_bottle_count': '1',
                    'verified_cup_count': '1',
                },
            )
            self.assertEqual(response.status_code, 302)
            self._login_as(2, 'admin')
            response = self.client.post(
                f'/admin/activity-verifications/user_declaration/{declaration_activity_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'correction_required',
                    'review_note': '申告内容の再確認が必要です。',
                },
            )
            self.assertEqual(response.status_code, 302)
            response = self.client.post(
                f'/admin/activity-verifications/gps_steps/{gps_activity_id}',
                data={'csrf_token': 'test-csrf-token', 'status': 'confirmed'},
            )
            self.assertEqual(response.status_code, 302)

            with database_connection() as conn:
                statuses = {
                    (row['target_type'], row['ai_log_id'] or row['activity_id']): row['status']
                    for row in conn.execute('''
                        SELECT target_type, ai_log_id, activity_id, status
                        FROM activity_verifications
                    ''')
                }
                history = conn.execute('''
                    SELECT target_type, status, reviewer_id, reviewed_at,
                           review_note, verified_bottle_count, verified_cup_count
                    FROM activity_verification_history
                    ORDER BY id
                ''').fetchall()
                ai_reference_rows = conn.execute('''
                    SELECT verified_bottle_count, verified_cup_count
                    FROM activity_verifications WHERE target_type = 'ai_result'
                    ORDER BY ai_log_id
                ''').fetchall()
                second_log_consensus = conn.execute('''
                    SELECT reviewer_id, reviewer2_id, adjudicator_id,
                           verified_bottle_count, verified_cup_count,
                           verified_bottle_count_2, verified_cup_count_2,
                           adjudicated_bottle_count, adjudicated_cup_count
                    FROM activity_verifications
                    WHERE target_type = 'ai_result' AND ai_log_id = ?
                ''', (second_ai_log_id,)).fetchone()
            self.assertEqual(statuses[('ai_result', ai_log_id)], 'confirmed')
            self.assertEqual(
                statuses[('user_declaration', declaration_activity_id)],
                'correction_required',
            )
            self.assertEqual(statuses[('ai_result', second_ai_log_id)], 'confirmed')
            self.assertEqual(statuses[('gps_steps', gps_activity_id)], 'confirmed')
            self.assertEqual(len(history), 8)
            self.assertEqual(
                {row['reviewer_id'] for row in history},
                {2, 3, 4},
            )
            self.assertTrue(all(row['reviewed_at'] for row in history))
            self.assertEqual(history[6]['review_note'], '申告内容の再確認が必要です。')
            self.assertEqual(history[0]['verified_bottle_count'], 3)
            self.assertEqual(history[0]['verified_cup_count'], 1)
            self.assertEqual(len(ai_reference_rows), 2)
            self.assertEqual(
                [(row['verified_bottle_count'], row['verified_cup_count'])
                 for row in ai_reference_rows],
                [(3, 1), (2, 0)],
            )
            self.assertEqual(second_log_consensus['reviewer_id'], 2)
            self.assertEqual(second_log_consensus['reviewer2_id'], 3)
            self.assertEqual(second_log_consensus['adjudicator_id'], 4)
            self.assertEqual(second_log_consensus['verified_bottle_count'], 2)
            self.assertEqual(second_log_consensus['verified_cup_count'], 0)
            self.assertEqual(second_log_consensus['verified_bottle_count_2'], 1)
            self.assertEqual(second_log_consensus['verified_cup_count_2'], 1)
            self.assertEqual(second_log_consensus['adjudicated_bottle_count'], 1)
            self.assertEqual(second_log_consensus['adjudicated_cup_count'], 1)

            response = self.client.get('/admin/activity-report')
            self.assertEqual(response.status_code, 200)
            report = response.get_data(as_text=True)
            self.assertIn('画像ごとの目視確認によるAI判定比較'.encode(), response.data)
            self.assertIn('完全一致率'.encode(), response.data)
            self.assertIn('100.0%', response.get_data(as_text=True))
            self.assertIn('100.0%', response.get_data(as_text=True))
            self.assertIn('20.0%', response.get_data(as_text=True))
            self.assertIn('50.0%', response.get_data(as_text=True))
            self.assertIn('二重確認 2 件'.encode(), response.data)
            self.assertIn('直近12か月'.encode(), response.data)
            for label, expected in (
                ('AI画像判定', ['2', '0', '0', '0', '0']),
                ('ユーザー申告数', ['0', '0', '1', '0', '0']),
                ('GPS移動距離', ['0', '1', '0', '0', '1']),
                ('GPS推定歩数', ['1', '0', '0', '0', '1']),
                ('GPS概算カロリー', ['0', '1', '0', '0', '1']),
            ):
                status_row = re.search(
                    rf'<tr>\s*<td>{re.escape(label)}</td>(.*?)</tr>',
                    report,
                    re.DOTALL,
                )
                self.assertIsNotNone(status_row)
                cells = re.findall(
                    r'<td>(.*?)</td>', status_row.group(0), re.DOTALL
                )
                self.assertEqual([cell.strip() for cell in cells[1:]], expected)

            with database_connection() as conn:
                conn.execute(
                    'UPDATE ai_logs SET detected_classes_json = ? WHERE id = ?',
                    (json.dumps({'bottle': 2, 'cup': 0}), ai_log_id),
                )
            response = self.client.get('/admin/activity-verifications')
            self.assertEqual(response.status_code, 200)
            page = response.get_data(as_text=True)
            ai_row = re.search(
                rf'<tr id="ai_result-{ai_log_id}".*?</tr>',
                page,
                re.DOTALL,
            )
            self.assertIsNotNone(ai_row)
            self.assertIn('値の変更により再確認が必要', ai_row.group(0))
            self.assertIn('未確認', ai_row.group(0))

            response = self.client.post(
                f'/admin/activity-verifications/user_declaration/{declaration_activity_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'status': 'correction_required',
                },
            )
            self.assertEqual(response.status_code, 400)
            response = self.client.post(
                f'/admin/activity-verifications/gps_steps/{gps_activity_id}',
                data={'csrf_token': 'bad-token', 'status': 'confirmed'},
            )
            self.assertEqual(response.status_code, 400)

            response = self.client.post(
                f'/admin/activity-verifications/user_declaration/{declaration_activity_id}',
                data={'csrf_token': 'test-csrf-token', 'status': 'unreviewed'},
            )
            self.assertEqual(response.status_code, 302)
            with database_connection() as conn:
                current_declaration = conn.execute('''
                    SELECT 1 FROM activity_verifications
                    WHERE target_type = 'user_declaration' AND activity_id = ?
                ''', (declaration_activity_id,)).fetchone()
                last_history_status = conn.execute('''
                    SELECT status FROM activity_verification_history
                    WHERE target_type = 'user_declaration' AND activity_id = ?
                    ORDER BY id DESC LIMIT 1
                ''', (declaration_activity_id,)).fetchone()['status']
            self.assertIsNone(current_declaration)
            self.assertEqual(last_history_status, 'unreviewed')

            cleanstep.init_db()
            with database_connection() as conn:
                persisted_review = conn.execute('''
                    SELECT status FROM activity_verifications
                    WHERE target_type = 'ai_result' AND ai_log_id = ?
                ''', (ai_log_id,)).fetchone()
                history_count = conn.execute('''
                    SELECT COUNT(*) FROM activity_verification_history
                    WHERE ai_log_id IN (?, ?)
                ''', (ai_log_id, second_ai_log_id)).fetchone()[0]
            self.assertEqual(persisted_review['status'], 'confirmed')
            self.assertEqual(history_count, 6)

            self._login_as(1)
            response = self.client.post(
                f'/admin/activity-verifications/ai_result/{ai_log_id}',
                data={'csrf_token': 'test-csrf-token', 'status': 'confirmed'},
            )
            self.assertEqual(response.status_code, 302)
        finally:
            with database_connection() as conn:
                if created_log_ids:
                    placeholders = ','.join('?' for _ in created_log_ids)
                    conn.execute(
                        f'DELETE FROM activity_verification_history WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_verifications WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM ai_logs WHERE id IN ({placeholders})',
                        created_log_ids,
                    )
                if created_activity_ids:
                    placeholders = ','.join('?' for _ in created_activity_ids)
                    conn.execute(
                        f'DELETE FROM activity_point_history WHERE activity_id IN ({placeholders})',
                        created_activity_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_verification_history WHERE activity_id IN ({placeholders})',
                        created_activity_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_verifications WHERE activity_id IN ({placeholders})',
                        created_activity_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_history WHERE id IN ({placeholders})',
                        created_activity_ids,
                    )
                for user_id, role in original_roles.items():
                    conn.execute(
                        'UPDATE users SET role = ? WHERE id = ?', (role, user_id)
                    )

    def test_admin_activity_report_compares_accuracy_by_ai_confidence_band(self):
        created_log_ids = []
        test_logs = [
            (0.4, 1, 2, 1, 0, 2, 0),
            (0.6, 2, 2, 1, 1, 1, 1),
            (0.8, 2, 1, 1, 1, 1, 0),
            (0.95, 3, 3, 2, 1, 2, 1),
            (None, 2, 2, 1, 1, 1, 1),
            (0.95, 0, 0, 0, 0, 0, 0),
        ]
        try:
            with database_connection() as conn:
                for (
                    confidence, detected_count, verified_count,
                    bottle_detected, cup_detected, bottle_verified, cup_verified,
                ) in test_logs:
                    cursor = conn.execute('''
                        INSERT INTO ai_logs (
                            user_id, detected_count, confidence, result_status,
                            detected_classes_json
                        ) VALUES (1, ?, ?, 'detected', ?)
                    ''', (
                        detected_count,
                        confidence,
                        json.dumps({
                            'bottle': bottle_detected,
                            'cup': cup_detected,
                        }),
                    ))
                    log_id = cursor.lastrowid
                    created_log_ids.append(log_id)
                    log = conn.execute(
                        'SELECT * FROM ai_logs WHERE id = ?', (log_id,)
                    ).fetchone()
                    conn.execute('''
                        INSERT INTO activity_verifications (
                            target_type, ai_log_id, status, reviewer_id,
                            reviewer2_id, verified_bottle_count,
                            verified_cup_count, verified_bottle_count_2,
                            verified_cup_count_2, source_fingerprint
                        ) VALUES (
                            'ai_result', ?, 'confirmed', 2, 3, ?, ?, ?, ?, ?
                        )
                    ''', (
                        log_id,
                        bottle_verified,
                        cup_verified,
                        bottle_verified,
                        cup_verified,
                        cleanstep.verification_fingerprint('ai_result', log),
                    ))

            self._login_as(2, 'admin')
            response = self.client.get('/admin/activity-report')
            self.assertEqual(response.status_code, 200)
            report = response.get_data(as_text=True)
            confidence_table = re.search(
                r'<table id="ai-confidence-accuracy">(.*?)</table>',
                report,
                re.DOTALL,
            )
            self.assertIsNotNone(confidence_table)
            rows = re.findall(
                r'<tr>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*'
                r'<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>',
                confidence_table.group(1),
                re.DOTALL,
            )
            self.assertEqual(
                rows,
                [
                    (
                        '25%以上 - 50%未満',
                        '0 / 1 件（0.0%）',
                        '0 / 1 件（0.0%）',
                        '1 / 1 件（100.0%）',
                    ),
                    (
                        '50%以上 - 75%未満',
                        '1 / 1 件（100.0%）',
                        '1 / 1 件（100.0%）',
                        '1 / 1 件（100.0%）',
                    ),
                    (
                        '75%以上 - 90%未満',
                        '0 / 1 件（0.0%）',
                        '1 / 1 件（100.0%）',
                        '0 / 1 件（0.0%）',
                    ),
                    (
                        '90%以上 - 100%以下',
                        '1 / 1 件（100.0%）',
                        '1 / 1 件（100.0%）',
                        '1 / 1 件（100.0%）',
                    ),
                ],
            )
        finally:
            with database_connection() as conn:
                if created_log_ids:
                    placeholders = ','.join('?' for _ in created_log_ids)
                    conn.execute(
                        f'DELETE FROM activity_verification_history '
                        f'WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_verifications '
                        f'WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM ai_logs WHERE id IN ({placeholders})',
                        created_log_ids,
                    )

    def test_verified_ai_dataset_export_contains_only_fresh_two_reviewer_agreement(self):
        created_log_ids = []
        test_image_dir = tempfile.TemporaryDirectory()
        original_roles = {}
        labels = [
            {
                'name': 'agreed',
                'reviewer2_id': 3,
                'second_counts': (2, 1),
                'adjudicated': False,
                'fingerprint': 'fresh',
            },
            {
                'name': 'disagreement',
                'reviewer2_id': 3,
                'second_counts': (1, 0),
                'adjudicated': False,
                'fingerprint': 'fresh',
            },
            {
                'name': 'adjudicated',
                'reviewer2_id': 3,
                'second_counts': (1, 0),
                'adjudicated': True,
                'fingerprint': 'fresh',
            },
            {
                'name': 'stale',
                'reviewer2_id': 3,
                'second_counts': (2, 1),
                'adjudicated': False,
                'fingerprint': 'stale',
            },
            {
                'name': 'missing-image',
                'reviewer2_id': 3,
                'second_counts': (2, 1),
                'adjudicated': False,
                'fingerprint': 'fresh',
                'missing_image': True,
            },
        ]
        with database_connection() as conn:
            original_roles = {
                row['id']: row['role']
                for row in conn.execute(
                    'SELECT id, role FROM users WHERE id IN (2, 3)'
                )
            }
            conn.execute("UPDATE users SET role = 'admin' WHERE id IN (2, 3)")
            for label in labels:
                image_name = f'{uuid.uuid4()}.jpg'
                if not label.get('missing_image'):
                    (Path(test_image_dir.name) / image_name).write_bytes(
                        f"image-{label['name']}".encode()
                    )
                log_cursor = conn.execute('''
                    INSERT INTO ai_logs (
                        user_id, detected_count, confidence, image_path,
                        result_status, detected_classes_json
                    ) VALUES (
                        1, 3, 0.9, ?, 'detected',
                        '{"bottle":2,"cup":1}'
                    )
                ''', (image_name,))
                log_id = log_cursor.lastrowid
                created_log_ids.append(log_id)
                log = conn.execute(
                    'SELECT * FROM ai_logs WHERE id = ?', (log_id,)
                ).fetchone()
                fingerprint = cleanstep.verification_fingerprint('ai_result', log)
                if label['fingerprint'] == 'stale':
                    fingerprint = 'outdated-source-fingerprint'
                bottle_2, cup_2 = label['second_counts']
                conn.execute('''
                    INSERT INTO activity_verifications (
                        target_type, ai_log_id, status, reviewer_id,
                        reviewer2_id, verified_bottle_count, verified_cup_count,
                        verified_bottle_count_2, verified_cup_count_2,
                        adjudicated_bottle_count, adjudicated_cup_count,
                        adjudicator_id, adjudicated_at, source_fingerprint
                    ) VALUES (
                        'ai_result', ?, ?, 2, 3, 2, 1, ?, ?,
                        ?, ?, ?, ?, ?
                    )
                ''', (
                    log_id,
                    'correction_required' if label['name'] == 'disagreement' else 'confirmed',
                    bottle_2, cup_2,
                    2 if label['adjudicated'] else None,
                    1 if label['adjudicated'] else None,
                    4 if label['adjudicated'] else None,
                    '2026-11-12 10:00:00' if label['adjudicated'] else None,
                    fingerprint,
                ))

        try:
            self._login_as(1)
            denied = self.client.get('/admin/ai/verified-dataset.zip')
            self.assertEqual(denied.status_code, 302)

            self._login_as(2, 'admin')
            with patch.object(cleanstep, 'UPLOAD_FOLDER', test_image_dir.name):
                response = self.client.get('/admin/ai/verified-dataset.zip')
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.mimetype, 'application/zip')
                with zipfile.ZipFile(BytesIO(response.data)) as archive:
                    self.assertEqual(
                        set(archive.namelist()),
                        {
                            'README.txt',
                            'manifest.jsonl',
                            next(
                                name for name in archive.namelist()
                                if name.startswith('images/')
                            ),
                        },
                    )
                    manifest = [
                        json.loads(line)
                        for line in archive.read('manifest.jsonl')
                        .decode('utf-8').splitlines()
                    ]
                    readme = archive.read('README.txt').decode('utf-8')
                    self.assertEqual(len(manifest), 1)
                    self.assertEqual(
                        manifest[0]['label_source'],
                        'independent_two_reviewer_agreement',
                    )
                    self.assertEqual(
                        manifest[0]['verified_counts'],
                        {'bottle': 2, 'cup': 1},
                    )
                    self.assertEqual(
                        archive.read(manifest[0]['image']),
                        b'image-agreed',
                    )
                    self.assertNotIn('user_id', manifest[0])
                    self.assertIn('矩形アノテーションは含まれない', readme)
                    self.assertIn(
                        '第三者が裁定したデータは、この高一致データセットには含めていません。',
                        readme,
                    )
                    self.assertIn('画像ファイル不足・形式不正で除外: 1 件', readme)
            empty_uploads = tempfile.TemporaryDirectory()
            try:
                with patch.object(cleanstep, 'UPLOAD_FOLDER', empty_uploads.name):
                    missing_files = self.client.get('/admin/ai/verified-dataset.zip')
                self.assertEqual(missing_files.status_code, 404)
                self.assertIn('利用可能な学習用データ'.encode(), missing_files.data)
            finally:
                empty_uploads.cleanup()
        finally:
            with database_connection() as conn:
                if created_log_ids:
                    placeholders = ','.join('?' for _ in created_log_ids)
                    conn.execute(
                        f'DELETE FROM activity_verification_history '
                        f'WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM activity_verifications '
                        f'WHERE ai_log_id IN ({placeholders})',
                        created_log_ids,
                    )
                    conn.execute(
                        f'DELETE FROM ai_logs WHERE id IN ({placeholders})',
                        created_log_ids,
                    )
                for user_id, role in original_roles.items():
                    conn.execute(
                        'UPDATE users SET role = ? WHERE id = ?', (role, user_id)
                    )
            test_image_dir.cleanup()

    def test_unrecorded_gps_metrics_are_not_shown_as_zero_or_reviewable(self):
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO activity_history (
                    user_id, type, title, steps, distance, calories,
                    gps_measured, points_earned, date
                ) VALUES (1, 'event', 'Unrecorded GPS Test', NULL, NULL, NULL, 1, 0, ?)
            ''', (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),))
            activity_id = cursor.lastrowid

        try:
            self._login_as(2, 'admin')
            response = self.client.get('/admin/activity-verifications')
            self.assertEqual(response.status_code, 200)
            page = response.get_data(as_text=True)
            for target_type in ('gps_distance', 'gps_steps', 'gps_calories'):
                row = re.search(
                    rf'<tr id="{target_type}-{activity_id}".*?</tr>',
                    page,
                    re.DOTALL,
                )
                self.assertIsNotNone(row)
                self.assertIn('未記録', row.group(0))
                self.assertIn('値が未記録のため確認対象外です。', row.group(0))
                self.assertNotIn('<form', row.group(0))
                response = self.client.post(
                    f'/admin/activity-verifications/{target_type}/{activity_id}',
                    data={
                        'csrf_token': 'test-csrf-token',
                        'status': 'confirmed',
                    },
                )
                self.assertEqual(response.status_code, 404)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM activity_history WHERE id = ?', (activity_id,)
                )

    def test_admin_approval_creates_organization_and_owner_membership(self):
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO organizer_applications (
                    user_id, organization_name, contact, purpose
                ) VALUES (3, 'New Organization', 'new@example.test', 'Community')
            ''')
            application_id = cursor.lastrowid

        self._login_as(2, "admin")
        response = self.client.post(
            f"/admin/organizer-applications/{application_id}/review",
            data={"decision": "approved", "csrf_token": "test-csrf-token"},
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            result = conn.execute('''
                SELECT a.status, o.name, m.user_id, m.role,
                       u.login_destination
                FROM organizer_applications a
                JOIN organizations o ON o.id = a.organization_id
                JOIN organization_members m ON m.organization_id = o.id
                JOIN users u ON u.id = m.user_id
                WHERE a.id = ?
            ''', (application_id,)).fetchone()

        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["name"], "New Organization")
        self.assertEqual(result["user_id"], 3)
        self.assertEqual(result["role"], "owner")
        self.assertEqual(result["login_destination"], "organizer")

    def test_event_management_is_scoped_to_organization_membership(self):
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")
        with database_connection() as conn:
            organization_id = conn.execute(
                'SELECT id FROM organizations WHERE application_id = 1'
            ).fetchone()["id"]
            other_organization_id = conn.execute('''
                SELECT organization_id FROM organizer_applications
                WHERE user_id = 3 AND status = 'approved'
                ORDER BY id DESC LIMIT 1
            ''').fetchone()["organization_id"]
            conn.execute('''
                INSERT INTO organization_members (
                    organization_id, user_id, role
                ) VALUES (?, 4, 'event_manager')
            ''', (organization_id,))
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, organizer_id,
                    organization_id
                ) VALUES (
                    'Other Organization Event', 'Other Location',
                    '2035-03-01 10:00', 10, 3, ?
                )
            ''', (other_organization_id,))
            foreign_event_id = cursor.lastrowid

        self._login_as(4)
        response = self.client.get("/organizer/events/new")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="event-map"', response.data)
        self.assertIn(b"nominatim.openstreetmap.org/search", response.data)
        response = self.client.post(
            "/organizer/events/new",
            data={
                "csrf_token": "test-csrf-token",
                "name": "Team Event",
                "location": "Community Center",
                "latitude": "35.681236",
                "longitude": "139.767125",
                "datetime": event_datetime,
                "bonus_points": "25",
                "reward_details": "なし",
                "category": "環境学習・交流",
            },
        )
        self.assertEqual(
            response.status_code, 302, response.get_data(as_text=True)
        )

        with database_connection() as conn:
            created_event = conn.execute('''
                SELECT organizer_id, organization_id, review_status, latitude,
                       longitude, category
                FROM events WHERE name = 'Team Event'
            ''').fetchone()

        self.assertEqual(created_event["organizer_id"], 4)
        self.assertEqual(created_event["organization_id"], organization_id)
        self.assertEqual(created_event["review_status"], "pending")
        self.assertEqual(created_event["category"], "環境学習・交流")
        self.assertAlmostEqual(created_event["latitude"], 35.681236)
        self.assertAlmostEqual(created_event["longitude"], 139.767125)
        response = self.client.get("/organizer/events?month=2035-02")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"2035", response.data)

        response = self.client.get(
            f"/organizer/events/{foreign_event_id}/edit"
        )
        self.assertEqual(response.status_code, 404)
        response = self.client.post(
            f"/organizer/events/{foreign_event_id}/cancel",
            data={"csrf_token": "test-csrf-token"},
        )
        self.assertEqual(response.status_code, 404)
        with database_connection() as conn:
            foreign_event = conn.execute(
                'SELECT status FROM events WHERE id = ?', (foreign_event_id,)
            ).fetchone()
        self.assertEqual(foreign_event["status"], "open")

        with self.client.session_transaction() as user_session:
            user_session.clear()
            user_session["user_id"] = 5
            user_session["role"] = "user"
        response = self.client.get("/organizer/events")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/organizer/apply", response.location)

    def test_organizer_events_require_review_and_resubmission_after_changes(self):
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")
        self._login_as(4)
        response = self.client.post(
            "/organizer/events/new",
            data={
                "csrf_token": "test-csrf-token",
                "name": "Review Workflow Event",
                "location": "Community Center",
                "latitude": "35.681236",
                "longitude": "139.767125",
                "datetime": event_datetime,
                "bonus_points": "30",
                "reward_details": "なし",
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            event = conn.execute('''
                SELECT id, review_status FROM events
                WHERE name = 'Review Workflow Event'
            ''').fetchone()
        event_id = event["id"]
        self.assertEqual(event["review_status"], "pending")

        self._login_as(1)
        response = self.client.get("/home")
        self.assertNotIn(b"Review Workflow Event", response.data)
        response = self.client.get(f"/event/reserve/{event_id}")
        self.assertEqual(response.status_code, 404)

        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "approved",
            },
        )
        self.assertEqual(response.status_code, 302)

        self._login_as(2, "admin")
        response = self.client.get("/admin/events/review")
        self.assertIn(b"Review Workflow Event", response.data)
        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "changes_requested",
            },
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "changes_requested",
                "review_comment": "開催場所の詳細を追記してください。",
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            event = conn.execute('''
                SELECT review_status, review_comment, reviewed_by
                FROM events WHERE id = ?
            ''', (event_id,)).fetchone()
        self.assertEqual(event["review_status"], "changes_requested")
        self.assertEqual(event["reviewed_by"], 2)
        self.assertIn("開催場所", event["review_comment"])

        self._login_as(4)
        response = self.client.get("/organizer/events")
        self.assertIn("イベント審査のお知らせ".encode(), response.data)
        self.assertIn("開催場所の詳細を追記してください。".encode(), response.data)
        response = self.client.post(
            f"/organizer/events/{event_id}/edit",
            data={
                "csrf_token": "test-csrf-token",
                "name": "Review Workflow Event Updated",
                "location": "Community Center, Room 2",
                "latitude": "35.682000",
                "longitude": "139.768000",
                "datetime": event_datetime,
                "bonus_points": "30",
                "reward_details": "なし",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            event = conn.execute('''
                SELECT review_status, review_comment, location, latitude, longitude
                FROM events WHERE id = ?
            ''', (event_id,)).fetchone()
        self.assertEqual(event["review_status"], "pending")
        self.assertIsNone(event["review_comment"])
        self.assertEqual(event["location"], "Community Center, Room 2")
        self.assertAlmostEqual(event["latitude"], 35.682)
        self.assertAlmostEqual(event["longitude"], 139.768)

        self._login_as(2, "admin")
        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "approved",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            event = conn.execute(
                'SELECT review_status FROM events WHERE id = ?', (event_id,)
            ).fetchone()
        self.assertEqual(event["review_status"], "approved")

        self._login_as(1)
        response = self.client.get("/events")
        self.assertIn(b"Review Workflow Event Updated", response.data)
        response = self.client.get(f"/event/reserve/{event_id}")
        self.assertEqual(response.status_code, 200)

    def test_event_feedback_submission_and_organizer_reflection_flow(self):
        with database_connection() as conn:
            organization_id = conn.execute(
                'SELECT id FROM organizations WHERE application_id = 1'
            ).fetchone()['id']
            event_cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, organizer_id,
                    organization_id, status, review_status
                ) VALUES (
                    'Feedback Flow Test', 'Test Park', '2035-01-01 10:00',
                    20, 1, ?, 'open', 'approved'
                )
            ''', (organization_id,))
            event_id = event_cursor.lastrowid
            activity_id = conn.execute('''
                INSERT INTO activity_history (
                    user_id, event_id, type, title, duration, points_earned
                ) VALUES (1, ?, 'event', 'Feedback Flow Test', 900, 20)
            ''', (event_id,)).lastrowid
            existing_membership = conn.execute('''
                SELECT 1 FROM organization_members
                WHERE organization_id = ? AND user_id = 4
            ''', (organization_id,)).fetchone()
            if not existing_membership:
                conn.execute('''
                    INSERT INTO organization_members (
                        organization_id, user_id, role, status
                    ) VALUES (?, 4, 'event_manager', 'active')
                ''', (organization_id,))

        membership_was_added = existing_membership is None
        try:
            self._login_as(1)
            self._use_mobile_user_agent()
            mypage = self.client.get('/mypage')
            self.assertEqual(mypage.status_code, 200)
            self.assertIn(f'/event/survey/{activity_id}'.encode(), mypage.data)
            self.assertIn('振り返りを記入'.encode(), mypage.data)

            response = self.client.get(f'/event/survey/{activity_id}')
            self.assertEqual(response.status_code, 200)
            self.assertIn('回答内容は主催団体に共有'.encode(), response.data)
            self.assertIn(b'name="csrf_token"', response.data)

            answer = {
                'csrf_token': 'test-csrf-token',
                'satisfaction': '5',
                'time_fit': 'just_right',
                'next_participation': 'yes',
                'comment': '次回は開始時間を少し遅くしてほしい',
            }
            response = self.client.post(
                f'/event/survey/{activity_id}', data=answer
            )
            self.assertEqual(response.status_code, 302)
            result_page = self.client.get(response.location)
            self.assertIn('アンケートへのご協力ありがとうございます。'.encode(), result_page.data)
            mypage = self.client.get('/mypage')
            self.assertIn('活動後の振り返りと次の行動'.encode(), mypage.data)
            self.assertIn('振り返りに記録された行動の推移'.encode(), mypage.data)
            self.assertIn('次回は開始時間を少し遅くしてほしい'.encode(), mypage.data)
            self.assertNotIn(f'/event/survey/{activity_id}'.encode(), mypage.data)

            duplicate = self.client.post(
                f'/event/survey/{activity_id}', data=answer
            )
            self.assertEqual(duplicate.status_code, 302)
            with database_connection() as conn:
                self.assertEqual(
                    conn.execute(
                        'SELECT COUNT(*) FROM event_feedback WHERE activity_id = ?',
                        (activity_id,),
                    ).fetchone()[0],
                    1,
                )
                feedback_id = conn.execute(
                    'SELECT id FROM event_feedback WHERE activity_id = ?',
                    (activity_id,),
                ).fetchone()['id']

            self._login_as(4)
            report = self.client.get(
                f'/organizer/events/{event_id}/participants'
            )
            self.assertEqual(report.status_code, 200)
            self.assertIn('回答率 100.0%'.encode(), report.data)
            self.assertIn('次回は開始時間を少し遅くしてほしい'.encode(), report.data)

            response = self.client.post(
                f'/organizer/events/{event_id}/feedback/{feedback_id}',
                data={
                    'csrf_token': 'test-csrf-token',
                    'action_status': 'addressed',
                    'action_note': '次回から開始時刻を調整する',
                },
            )
            self.assertEqual(response.status_code, 302)
            report = self.client.get(response.location)
            self.assertIn('100.0%（1/1件）'.encode(), report.data)
            self.assertIn('次回から開始時刻を調整する'.encode(), report.data)
            with database_connection() as conn:
                feedback = conn.execute('''
                    SELECT action_status, action_note FROM event_feedback
                    WHERE id = ?
                ''', (feedback_id,)).fetchone()
            self.assertEqual(feedback['action_status'], 'addressed')
            self.assertEqual(feedback['action_note'], '次回から開始時刻を調整する')
            self._login_as(1)
            mypage = self.client.get('/mypage')
            self.assertIn('次回から開始時刻を調整する'.encode(), mypage.data)
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM event_feedback WHERE event_id = ?', (event_id,))
                conn.execute('DELETE FROM activity_history WHERE event_id = ?', (event_id,))
                conn.execute('DELETE FROM event_reservations WHERE event_id = ?', (event_id,))
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))
                if membership_was_added:
                    conn.execute('''
                        DELETE FROM organization_members
                        WHERE organization_id = ? AND user_id = 4
                    ''', (organization_id,))

    def test_organizer_participant_list_is_scoped_to_organization(self):
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, 1, 'reserved')
                ON CONFLICT(user_id, event_id) DO UPDATE SET status = 'reserved'
            ''')
            conn.execute('''
                INSERT INTO activity_history (
                    user_id, event_id, type, title, points_earned
                ) VALUES (5, 1, 'event', 'Historical attendance', 50)
                ON CONFLICT(user_id, event_id) DO NOTHING
            ''')

        self._login_as(4)
        response = self.client.get("/organizer/events/1/participants")
        self.assertEqual(response.status_code, 200)
        participant_page = response.get_data(as_text=True)
        # 参加者一覧では連絡先メールアドレスを表示しない。
        self.assertNotIn("owner@example.test", participant_page)
        self.assertNotIn("outsider@example.test", participant_page)
        self.assertIn("Owner", participant_page)
        self.assertIn("Outsider", participant_page)
        self.assertIn("予約中", participant_page)

        response = self.client.get("/organizer/events")
        self.assertEqual(response.status_code, 200)
        organizer_report = response.get_data(as_text=True)
        self.assertIn("イベント参加記録（延べ）", organizer_report)
        self.assertIn("参加者に付与されたポイント", organizer_report)
        self.assertIn("Legacy Event", organizer_report)
        self.assertNotIn("outsider@example.test", organizer_report)
        self.assertRegex(
            organizer_report,
            r'<span class="summary-number">1</span>\s*'
            r'<span class="summary-label">イベント参加記録（延べ）</span>',
        )
        self.assertRegex(
            organizer_report,
            r'<span class="summary-number">50</span>\s*'
            r'<span class="summary-label">参加者に付与されたポイント</span>',
        )

        self._login_as(3)
        response = self.client.get("/organizer/events/1/participants")
        self.assertEqual(response.status_code, 404)
        response = self.client.get("/organizer/events")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Legacy Event", response.get_data(as_text=True))

    def test_admin_cannot_review_an_event_they_organized(self):
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, organizer_id,
                    review_status
                ) VALUES (
                    'Admin Self Review Event', 'Town Hall',
                    '2035-05-01 10:00', 10, 2, 'pending'
                )
            ''')
            event_id = cursor.lastrowid

        self._login_as(2, "admin")
        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "approved",
            },
        )
        self.assertEqual(response.status_code, 403)
        with database_connection() as conn:
            review_status = conn.execute(
                'SELECT review_status FROM events WHERE id = ?', (event_id,)
            ).fetchone()["review_status"]
        self.assertEqual(review_status, "pending")

    def test_pc_approval_mobile_participation_and_pc_reporting_flow(self):
        event_name = "Cross-device Integration Event"
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(hours=2)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")

        with database_connection() as conn:
            organization_id = conn.execute(
                'SELECT id FROM organizations WHERE application_id = 1'
            ).fetchone()["id"]
            conn.execute('''
                INSERT OR IGNORE INTO organization_members (
                    organization_id, user_id, role
                ) VALUES (?, 4, 'event_manager')
            ''', (organization_id,))

        self._login_as(4)
        response = self.client.post(
            "/organizer/events/new",
            data={
                "csrf_token": "test-csrf-token",
                "name": event_name,
                "location": "Integration Test Park",
                "latitude": "35.700000",
                "longitude": "139.700000",
                "datetime": event_datetime,
                "bonus_points": "37",
                "reward_details": "なし",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            event = conn.execute(
                "SELECT id FROM events WHERE name = ?", (event_name,)
            ).fetchone()
        self.assertIsNotNone(event, response.get_data(as_text=True))
        event_id = event["id"]

        self._login_as(2, "admin")
        response = self.client.post(
            f"/admin/events/{event_id}/review",
            data={
                "csrf_token": "test-csrf-token",
                "decision": "approved",
            },
        )
        self.assertEqual(response.status_code, 302)

        self._login_as(1)
        response = self.client.get("/home")
        self.assertIn(event_name.encode(), response.data)
        response = self.client.post(
            f"/event/reserve/{event_id}",
            data={"csrf_token": "test-csrf-token", "action": "reserve"},
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            conn.execute(
                'UPDATE events SET datetime = ? WHERE id = ?',
                (
                    (datetime.now(cleanstep.JST) - timedelta(minutes=1)).strftime(
                        "%Y-%m-%d %H:%M"
                    ),
                    event_id,
                ),
            )
        self._use_mobile_user_agent()
        response = self.client.get(f"/event/live/{event_id}")
        self.assertEqual(response.status_code, 200)
        started_at = datetime.now(cleanstep.JST) - timedelta(seconds=901)
        with self.client.session_transaction() as user_session:
            user_session[f"event_started_at_{event_id}"] = started_at.isoformat()
        response = self.client.post(
            f"/event/complete/{event_id}",
            data={
                "csrf_token": "test-csrf-token",
                "duration": "900",
                "steps": "0",
                "distance": "0",
                "calories": "0",
                "detox_duration": "0",
                "gps_points": json.dumps([{
                    "lat": 35.7,
                    "lon": 139.7,
                    "accuracy": 5,
                    "ts": datetime.now(cleanstep.JST).timestamp() * 1000,
                }]),
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            activity = conn.execute('''
                SELECT a.points_earned, r.status, u.total_points
                FROM activity_history a
                JOIN event_reservations r
                    ON r.user_id = a.user_id AND r.event_id = a.event_id
                JOIN users u ON u.id = a.user_id
                WHERE a.user_id = 1 AND a.event_id = ?
            ''', (event_id,)).fetchone()
        self.assertEqual(activity["points_earned"], 37)
        self.assertEqual(activity["status"], "completed")
        self.assertGreaterEqual(activity["total_points"], 387)

        self._login_as(4)
        response = self.client.get(
            f"/organizer/events/{event_id}/participants"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"owner@example.test", response.data)
        self.assertIn("参加完了", response.get_data(as_text=True))
        self.assertIn(b"37", response.data)

        self._login_as(2, "admin")
        response = self.client.get("/admin/activity-report")
        self.assertEqual(response.status_code, 200)
        report = response.get_data(as_text=True)
        self.assertIn("<table>", report)
        self.assertIn("イベント別参加実績", report)
        self.assertIn("場所別ごみ捨て記録", report)
        self.assertIn(event_name, report)
        self.assertIn("Legacy activity", report)
        self.assertIn("画像ログ上の検出数合計", report)
        self.assertIn("ユーザー申告数（記録あり分）", report)
        self.assertIn("重量・体積", report)
        self.assertNotIn("owner@example.test", report)
        event_count = re.search(
            r'<div class="number">(\d+)</div><div class="label">イベント参加記録（延べ）</div>',
            report,
        )
        points_earned = re.search(
            r'<div class="number">(\d+)</div><div class="label">獲得ポイント</div>',
            report,
        )
        self.assertIsNotNone(event_count)
        self.assertIsNotNone(points_earned)
        self.assertGreaterEqual(int(event_count.group(1)), 1)
        self.assertGreaterEqual(int(points_earned.group(1)), 37)

    def test_admin_activity_report_separates_recorded_and_unclassified_counts(self):
        self._login_as(2, "admin")
        before = self.client.get("/admin/activity-report")
        self.assertEqual(before.status_code, 200)
        before_report = before.get_data(as_text=True)
        month = datetime.now(cleanstep.JST).strftime("%Y-%m")

        def summary_values(report, label):
            coverage_pattern = (
                r'<div class="coverage">判定ログ (\d+)件</div>'
                if label == "画像ログ上の検出数合計"
                else r'<div class="coverage">記録あり (\d+)件</div>'
            )
            summary_pattern = (
                rf'<div class="number">([^<]+)</div>\s*'
                rf'<div class="label">{re.escape(label)}</div>\s*'
                + coverage_pattern
            )
            match = re.search(
                summary_pattern,
                report,
            )
            self.assertIsNotNone(match)
            value = match.group(1)
            return (int(value) if value.isdigit() else None, int(match.group(2)))

        def month_values(report):
            match = re.search(
                rf'<tr>\s*<td>{re.escape(month)}</td>(.*?)</tr>',
                report,
                re.DOTALL,
            )
            self.assertIsNotNone(match)
            cells = re.findall(r'<td>(.*?)</td>', match.group(0), re.DOTALL)

            def recorded_value(cell):
                value = re.fullmatch(r'(\d+) / (\d+)件', cell)
                return (int(value.group(1)), int(value.group(2))) if value else (0, 0)

            return (
                recorded_value(cells[5]),
                int(cells[6]),
                recorded_value(cells[7]),
                int(cells[8]),
            )

        before_ai = summary_values(before_report, "画像ログ上の検出数合計")
        before_declared = summary_values(
            before_report, "ユーザー申告数（記録あり分）"
        )
        before_month = month_values(before_report)

        created_activity_ids = []
        test_location = "Report Source Test"
        zero_location = "Report Zero Test"
        recorded_activities = [
            (test_location, 80, 4, 7, 4),
            (test_location, 90, 2, 3, 2),
            (test_location, 99, 0, 0, None),
            (zero_location, 25, 0, 1, 0),
        ]
        try:
            with database_connection() as conn:
                for location, legacy_count, ai_count, declared_count, logged_ai_count in recorded_activities:
                    cursor = conn.execute('''
                        INSERT INTO activity_history (
                            user_id, type, title, trash_count, ai_detected_count,
                            user_declared_count, points_earned, date
                        ) VALUES (1, 'trash_bin', ?, ?, ?, ?, 0, ?)
                    ''', (
                        location, legacy_count, ai_count, declared_count,
                        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    ))
                    activity_id = cursor.lastrowid
                    created_activity_ids.append(activity_id)
                    if logged_ai_count is not None:
                        conn.execute('''
                            INSERT INTO ai_logs (
                                user_id, activity_id, detected_count, confidence
                            ) VALUES (1, ?, ?, 0.9)
                        ''', (activity_id, logged_ai_count))

            response = self.client.get("/admin/activity-report")
            self.assertEqual(response.status_code, 200)
            report = response.get_data(as_text=True)
            after_ai = summary_values(report, "画像ログ上の検出数合計")
            after_declared = summary_values(
                report, "ユーザー申告数（記録あり分）"
            )
            self.assertEqual(after_ai[0], (before_ai[0] or 0) + 6)
            self.assertEqual(after_ai[1], before_ai[1] + 3)
            self.assertEqual(after_declared[0], (before_declared[0] or 0) + 11)
            self.assertEqual(after_declared[1], before_declared[1] + 3)

            after_month = month_values(report)
            self.assertEqual(after_month[0][0], before_month[0][0] + 6)
            self.assertEqual(after_month[0][1], before_month[0][1] + 3)
            self.assertEqual(after_month[1], before_month[1] + 1)
            self.assertEqual(after_month[2][0], before_month[2][0] + 11)
            self.assertEqual(after_month[2][1], before_month[2][1] + 3)
            self.assertEqual(after_month[3], before_month[3] + 1)

            location_row = re.search(
                rf'<tr>\s*<td>{re.escape(test_location)}</td>(.*?)</tr>',
                report,
                re.DOTALL,
            )
            self.assertIsNotNone(location_row)
            location_cells = re.findall(
                r'<td>(.*?)</td>', location_row.group(0), re.DOTALL
            )
            self.assertEqual(
                [cell.strip() for cell in location_cells],
                [test_location, "1", "3", "6 / 2件", "1", "10 / 2件", "1"],
            )

            zero_row = re.search(
                rf'<tr>\s*<td>{re.escape(zero_location)}</td>(.*?)</tr>',
                report,
                re.DOTALL,
            )
            self.assertIsNotNone(zero_row)
            zero_cells = re.findall(r'<td>(.*?)</td>', zero_row.group(0), re.DOTALL)
            self.assertEqual(zero_cells[3].strip(), "0 / 1件")
            self.assertEqual(zero_cells[4].strip(), "0")
            self.assertEqual(zero_cells[5].strip(), "1 / 1件")
            self.assertEqual(zero_cells[6].strip(), "0")
        finally:
            with database_connection() as conn:
                if created_activity_ids:
                    placeholders = ",".join("?" for _ in created_activity_ids)
                    conn.execute(
                        f"DELETE FROM ai_logs WHERE activity_id IN ({placeholders})",
                        created_activity_ids,
                    )
                    conn.execute(
                        f"DELETE FROM activity_history WHERE id IN ({placeholders})",
                        created_activity_ids,
                    )

    def test_mobile_trash_form_provides_csrf_and_rejects_missing_token(self):
        bin_name = "Trash Test Bin"
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()["id"]

        self._login_as(1)
        self._use_mobile_user_agent()
        response = self.client.get("/trash-bin")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="csrf_token"', response.get_data())
        self.assertIn(b'accept="image/*"', response.get_data())
        self.assertIn(b"marker=35.6812360,139.7671250", response.get_data())

        response = self.client.post(
            "/trash-bin/deposit",
            data={"bin_id": str(bin_id), "trash_count": "1"},
        )
        self.assertEqual(response.status_code, 400)
        response = self.client.post(
            "/trash-bin/deposit",
            data={
                "csrf_token": "test-csrf-token",
                "bin_id": str(bin_id),
                "trash_count": "3",
            },
        )
        self.assertIn(b'value="3" selected', response.data)

        image = BytesIO()
        Image.new("RGB", (1, 1), color="white").save(image, format="PNG")
        image.seek(0)
        with patch.object(cleanstep, "get_model", return_value=None):
            response = self.client.post(
                "/trash-bin/deposit",
                data={
                    "csrf_token": "test-csrf-token",
                    "bin_id": str(bin_id),
                    "trash_count": "1",
                    "garbage_image": (image, "sample.png"),
                },
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn(b'role="alert"', response.get_data())
        with database_connection() as conn:
            failed_log = conn.execute('''
                SELECT id, result_status, detected_count
                FROM ai_logs WHERE user_id = 1
                ORDER BY id DESC LIMIT 1
            ''').fetchone()
            if failed_log:
                conn.execute(
                    'DELETE FROM ai_logs WHERE id = ?', (failed_log['id'],)
                )
            conn.execute('DELETE FROM trash_bins WHERE id = ?', (bin_id,))
        self.assertIsNotNone(failed_log)
        self.assertEqual(failed_log['result_status'], 'failed')
        self.assertIsNone(failed_log['detected_count'])

    def test_trash_deposit_rejects_unknown_bag_size_before_ai(self):
        bin_name = 'Bag Size Validation Test Bin'
        with database_connection() as conn:
            conn.execute('''
                INSERT INTO trash_bins (name, description, lat, lng)
                VALUES (?, 'Test location', 35.681236, 139.767125)
            ''', (bin_name,))
            bin_id = conn.execute(
                'SELECT id FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()['id']

        image = BytesIO()
        Image.new('RGB', (1, 1), color='white').save(image, format='PNG')
        image.seek(0)
        self._login_as(1)
        self._use_mobile_user_agent()
        try:
            with patch.object(cleanstep, 'get_model') as model_lookup:
                response = self.client.post(
                    '/trash-bin/deposit',
                    data={
                        'csrf_token': 'test-csrf-token',
                        'bin_id': str(bin_id),
                        'trash_count': '1',
                        'bag_size': 'unrecognized size',
                        'garbage_image': (image, 'invalid-bag-size.png'),
                    },
                    content_type='multipart/form-data',
                )
            self.assertEqual(response.status_code, 400)
            self.assertIn('袋サイズの選択内容が不正'.encode(), response.data)
            model_lookup.assert_not_called()
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM trash_bins WHERE id = ?', (bin_id,)
                )

    def test_admin_activity_report_summarizes_declared_bag_size(self):
        self._login_as(2, 'admin')
        before_response = self.client.get('/admin/activity-report')
        self.assertEqual(before_response.status_code, 200)

        def bag_size_counts(report):
            table = re.search(
                r'<table id="bag-size-summary">(.*?)</table>',
                report,
                re.DOTALL,
            )
            self.assertIsNotNone(table)
            rows = re.findall(
                r'<tr>\s*<td>(.*?)</td>\s*<td>(\d+) 件</td>\s*</tr>',
                table.group(1),
                re.DOTALL,
            )
            return {label: int(count) for label, count in rows}

        before = bag_size_counts(before_response.get_data(as_text=True))
        sizes = (*cleanstep.TRASH_BAG_SIZE_OPTIONS, 'legacy unknown label')
        created_ids = []
        try:
            with database_connection() as conn:
                for index, size in enumerate(sizes):
                    cursor = conn.execute('''
                        INSERT INTO activity_history (
                            user_id, type, title, trash_count, ai_detected_count,
                            user_declared_count, points_earned, bag_size, date
                        ) VALUES (
                            1, 'trash_bin', ?, 0, 0, 0, 0, ?, ?
                        )
                    ''', (
                        f'Bag Size Report Test {index}',
                        size,
                        datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                    ))
                    created_ids.append(cursor.lastrowid)

            response = self.client.get('/admin/activity-report')
            self.assertEqual(response.status_code, 200)
            after = bag_size_counts(response.get_data(as_text=True))
            for size in cleanstep.TRASH_BAG_SIZE_OPTIONS:
                self.assertEqual(after[size], before[size] + 1)
            self.assertEqual(
                after['未分類・旧記録'],
                before['未分類・旧記録'] + 1,
            )
        finally:
            with database_connection() as conn:
                if created_ids:
                    placeholders = ','.join('?' for _ in created_ids)
                    conn.execute(
                        f'DELETE FROM activity_history WHERE id IN ({placeholders})',
                        created_ids,
                    )

    def test_admin_can_register_bin_pin_and_users_see_selected_map(self):
        self._login_as(2, "admin")
        response = self.client.get("/admin/bins")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'href="/admin/bins/add"', response.data)

        response = self.client.get("/admin/bins/add")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"id=\"bin-map\"", response.data)
        self.assertIn(b"OpenStreetMap contributors", response.data)

        bin_name = "Registered Test Bin"
        response = self.client.post(
            "/admin/bins/add",
            data={
                "csrf_token": "test-csrf-token",
                "name": bin_name,
                "description": "Test Park entrance",
                "lat": "35.658580",
                "lng": "139.745433",
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            registered_bin = conn.execute(
                'SELECT * FROM trash_bins WHERE name = ?', (bin_name,)
            ).fetchone()
        self.assertIsNotNone(registered_bin)
        bin_id = registered_bin["id"]

        self._login_as(1)
        self._use_mobile_user_agent()
        response = self.client.get(f"/trash-bin?bin_id={bin_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"marker=35.6585800,139.7454330", response.data)
        self.assertIn(f'value="{bin_id}"'.encode(), response.data)

        self._login_as(2, "admin")
        response = self.client.post(
            f"/admin/bins/{bin_id}/edit",
            data={
                "csrf_token": "test-csrf-token",
                "name": bin_name,
                "description": "Updated test location",
                "lat": "35.658581",
                "lng": "139.745434",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            updated_bin = conn.execute(
                'SELECT lat, lng FROM trash_bins WHERE id = ?', (bin_id,)
            ).fetchone()
        self.assertAlmostEqual(updated_bin["lat"], 35.658581)
        self.assertAlmostEqual(updated_bin["lng"], 139.745434)

        response = self.client.post(
            f"/admin/bins/{bin_id}/delete",
            data={"csrf_token": "test-csrf-token"},
        )
        self.assertEqual(response.status_code, 302)

    def test_admin_event_form_saves_map_pin_and_uses_shared_map(self):
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")
        self._login_as(2, "admin")
        response = self.client.get("/admin/events/add")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="event-map"', response.data)
        self.assertIn(b"nominatim.openstreetmap.org/search", response.data)
        self.assertIn(b"OpenStreetMap contributors", response.data)

        event_name = "海岸清掃 Admin Mapped Event"
        response = self.client.post(
            "/admin/events/add",
            data={
                "csrf_token": "test-csrf-token",
                "name": event_name,
                "location": "Test Civic Center",
                "latitude": "35.680000",
                "longitude": "139.760000",
                "datetime": event_datetime,
                "bonus_points": "20",
                "category": "auto",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            event = conn.execute(
                "SELECT id, latitude, longitude, category FROM events WHERE name = ?",
                (event_name,),
            ).fetchone()
        self.assertIsNotNone(event)
        self.assertAlmostEqual(event["latitude"], 35.68)
        self.assertAlmostEqual(event["longitude"], 139.76)
        self.assertEqual(event["category"], "海岸清掃")

        response = self.client.get(f"/admin/events/{event['id']}/edit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'id="event-map"', response.data)
        self.assertIn(b"value=\"35.68\"", response.data)
        response = self.client.post(
            f"/admin/events/{event['id']}/edit",
            data={
                "csrf_token": "test-csrf-token",
                "name": event_name,
                "location": "",
                "latitude": "35.680000",
                "longitude": "139.760000",
                "datetime": event_datetime,
                "bonus_points": "20",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("開催場所を1〜200文字で入力してください。".encode(), response.data)
        self.assertIn(
            f"/admin/events/{event['id']}/edit".encode(), response.data
        )
        self.assertIn(b'name="location" value=""', response.data)
        response = self.client.post(
            f"/admin/events/{event['id']}/edit",
            data={
                "csrf_token": "test-csrf-token",
                "name": event_name,
                "location": "Updated Test Civic Center",
                "latitude": "35.681000",
                "longitude": "139.761000",
                "datetime": event_datetime,
                "bonus_points": "20",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            event = conn.execute(
                "SELECT id, latitude, longitude FROM events WHERE name = ?",
                (event_name,),
            ).fetchone()
        self.assertAlmostEqual(event["latitude"], 35.681)
        self.assertAlmostEqual(event["longitude"], 139.761)

        self._login_as(1)
        response = self.client.get(f"/event/reserve/{event['id']}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"openstreetmap.org/export/embed.html", response.data)
        self.assertIn(b"marker=35.6810000,139.7610000", response.data)
        self.assertIn(
            b"google.com/maps/search/?api=1&amp;query=35.6810000%2C139.7610000",
            response.data,
        )

        self._login_as(2, "admin")
        with database_connection() as conn:
            conn.execute("DELETE FROM events WHERE id = ?", (event["id"],))

    def test_admin_events_prompts_for_missing_map_pins(self):
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points
                ) VALUES (
                    'Missing Pin Admin Event', 'Test Location',
                    '2035-01-01 10:00', 10
                )
            ''')
            event_id = cursor.lastrowid
        self._login_as(2, "admin")

        try:
            response = self.client.get("/admin/events")

            self.assertEqual(response.status_code, 200)
            self.assertIn("地図のピンが未設定のイベントが".encode(), response.data)
            self.assertIn("参加者に正確な集合場所を案内".encode(), response.data)
            self.assertIn("地図ピン未設定".encode(), response.data)
            self.assertIn("位置を設定".encode(), response.data)
            self.assertIn(
                f"/admin/events/{event_id}/location".encode(), response.data
            )
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_admin_can_add_map_pin_to_reserved_event_without_changing_it(self):
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points
                ) VALUES (
                    'Reserved Missing Pin Event', 'Original Location',
                    ?, 25
                )
            ''', (event_datetime,))
            event_id = cursor.lastrowid
            conn.execute(
                'INSERT INTO event_reservations (user_id, event_id) VALUES (?, ?)',
                (5, event_id),
            )
            conn.execute('''
                INSERT INTO activity_history (
                    user_id, event_id, type, title, points_earned
                ) VALUES (1, ?, 'event', 'Completed activity', 25)
            ''', (event_id,))
        self._login_as(2, "admin")

        try:
            response = self.client.get(f"/admin/events/{event_id}/location")
            self.assertEqual(response.status_code, 200)
            self.assertIn("予約・参加記録は変更されません".encode(), response.data)
            self.assertIn(
                b'id="location" type="text" value="Original Location" readonly',
                response.data,
            )
            self.assertIn(
                b'id="event-location-search"', response.data
            )
            self.assertEqual(
                self.client.get(f"/admin/events/{event_id}/edit").status_code,
                409,
            )

            response = self.client.post(
                f"/admin/events/{event_id}/location",
                data={
                    "csrf_token": "test-csrf-token",
                    "latitude": "35.6590597",
                    "longitude": "139.7006279",
                },
            )
            self.assertEqual(response.status_code, 302)
            with database_connection() as conn:
                event = conn.execute(
                    'SELECT name, location, datetime, latitude, longitude '
                    'FROM events WHERE id = ?',
                    (event_id,),
                ).fetchone()
                reservation = conn.execute(
                    'SELECT status FROM event_reservations '
                    'WHERE user_id = 5 AND event_id = ?',
                    (event_id,),
                ).fetchone()
                activity = conn.execute(
                    'SELECT title, points_earned FROM activity_history '
                    'WHERE user_id = 1 AND event_id = ?',
                    (event_id,),
                ).fetchone()
            self.assertEqual(event["name"], "Reserved Missing Pin Event")
            self.assertEqual(event["location"], "Original Location")
            self.assertAlmostEqual(event["latitude"], 35.6590597)
            self.assertAlmostEqual(event["longitude"], 139.7006279)
            self.assertEqual(reservation["status"], "reserved")
            self.assertEqual(activity["title"], "Completed activity")
            self.assertEqual(activity["points_earned"], 25)

            self._login_as(5)
            reserve_response = self.client.get(f"/event/reserve/{event_id}")
            self.assertEqual(reserve_response.status_code, 200)
            self.assertIn(
                b"marker=35.6590597,139.7006279", reserve_response.data
            )
            self.assertIn(
                b"google.com/maps/search/?api=1&amp;query=35.6590597%2C139.7006279",
                reserve_response.data,
            )
            self.assertIn("Original Location".encode(), reserve_response.data)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM event_reservations WHERE event_id = ?',
                    (event_id,),
                )
                conn.execute(
                    'DELETE FROM activity_history WHERE event_id = ?',
                    (event_id,),
                )
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_mobile_event_search_reserve_and_cancel_flow(self):
        event_datetime = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            conn.execute(
                'UPDATE events SET datetime = ? WHERE id = 1',
                (event_datetime,),
            )
        self._login_as(1)
        self._use_mobile_user_agent()
        response = self.client.get("/home")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Legacy Event", response.get_data())
        self.assertIn(b'href="/events"', response.get_data())
        self.assertIn(b'href="/my/reservations"', response.get_data())
        self.assertIn(b"openstreetmap.org/search?query=Central%20Park", response.get_data())
        self.assertNotIn(b"<iframe", response.get_data())

        response = self.client.get("/events")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Legacy Event", response.get_data())
        self.assertIn(b'name="q"', response.get_data())

        response = self.client.get("/events?q=Central%20Park")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Legacy Event", response.get_data())

        response = self.client.get("/events?q=Missing%20Event")
        self.assertEqual(response.status_code, 200)
        self.assertIn("一致するイベントはありません".encode(), response.get_data())
        self.assertNotIn(b"Legacy Event", response.get_data())

        response = self.client.get("/my/reservations")
        self.assertEqual(response.status_code, 200)
        self.assertIn("予約中のイベントはありません".encode(), response.get_data())

        response = self.client.get("/event/reserve/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'name="csrf_token"', response.get_data())
        self.assertIn(
            b"openstreetmap.org/search?query=Central%20Park",
            response.get_data(),
        )
        self.assertNotIn(b"maps.google.com", response.get_data())
        self.assertNotIn(b"<iframe", response.get_data())
        self.assertIn(
            b"google.com/maps/search/?api=1&amp;query=Central%20Park",
            response.get_data(),
        )
        self.assertIn(
            "位置が登録されていません".encode(),
            response.get_data(),
        )
        self.assertIn(b'rel="noopener noreferrer"', response.get_data())

        response = self.client.post(
            "/event/reserve/1",
            data={
                "csrf_token": "test-csrf-token",
                "action": "reserve",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/event/reservation/1/complete")
        response = self.client.get(response.location)
        self.assertEqual(response.status_code, 200)
        self.assertIn("予約を受け付けました".encode(), response.get_data())

        with database_connection() as conn:
            reservation = conn.execute('''
                SELECT status FROM event_reservations
                WHERE user_id = 1 AND event_id = 1
            ''').fetchone()
        self.assertEqual(reservation["status"], "reserved")
        response = self.client.get("/my/reservations")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Legacy Event", response.get_data())
        self.assertIn(b"/event/reserve/1", response.get_data())
        home_response = self.client.get("/home")
        self.assertIn("予約したイベント".encode(), home_response.data)
        self.assertNotIn("予約したイベント（1）".encode(), home_response.data)
        self.assertNotIn(b"/event/live/1", home_response.data)
        self.assertIn(b"/event/reserve/1", home_response.data)
        self.assertIn("開催前".encode(), home_response.data)
        self.assertIn(
            b"openstreetmap.org/search?query=Central%20Park",
            home_response.data,
        )
        self.assertNotIn(b"<iframe", home_response.data)

        event_started_at = (
            datetime.now(cleanstep.JST) - timedelta(minutes=5)
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            conn.execute(
                'UPDATE events SET datetime = ? WHERE id = 1',
                (event_started_at,),
            )
        response = self.client.get("/my/reservations")
        self.assertIn("計測を開始".encode(), response.get_data())
        response = self.client.get("/event/live/1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("活動計測".encode(), response.get_data())

        with database_connection() as conn:
            conn.execute(
                'UPDATE events SET datetime = ? WHERE id = 1',
                (event_datetime,),
            )
        response = self.client.post(
            "/event/reserve/1",
            data={
                "csrf_token": "test-csrf-token",
                "action": "cancel",
            },
        )
        self.assertEqual(response.status_code, 302)
        with database_connection() as conn:
            reservation = conn.execute('''
                SELECT status FROM event_reservations
                WHERE user_id = 1 AND event_id = 1
            ''').fetchone()
            conn.execute(
                'DELETE FROM event_reservations WHERE user_id = 1 AND event_id = 1'
            )
            conn.execute(
                "UPDATE events SET datetime = '2035-01-01 10:00' WHERE id = 1"
            )
        self.assertEqual(reservation["status"], "cancelled")
        home_response = self.client.get("/home")
        self.assertNotIn("予約したイベント（0）".encode(), home_response.data)
        self.assertIn("予約したイベントはまだありません".encode(), home_response.data)

    def test_event_completion_requires_minimum_time_and_event_location(self):
        event_datetime = (
            datetime.now(cleanstep.JST) - timedelta(minutes=5)
        ).strftime('%Y-%m-%d %H:%M')
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, latitude, longitude,
                    status, review_status
                ) VALUES (
                    'Location Check Test', 'Test Site', ?, 20, 35.0, 139.0,
                    'open', 'approved'
                )
            ''', (event_datetime,))
            event_id = cursor.lastrowid
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, ?, 'reserved')
            ''', (event_id,))
            original_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']

        self._login_as(1)
        self._use_mobile_user_agent()
        try:
            live_response = self.client.get(f'/event/live/{event_id}')
            self.assertEqual(live_response.status_code, 200)
            with self.client.session_transaction() as user_session:
                session_start = datetime.fromisoformat(
                    user_session[f'event_started_at_{event_id}']
                )
            self.assertEqual(session_start.utcoffset(), timedelta(hours=9))

            def set_started_at(minutes_ago):
                with self.client.session_transaction() as user_session:
                    user_session[f'event_started_at_{event_id}'] = (
                        datetime.now(cleanstep.JST) - timedelta(minutes=minutes_ago)
                    ).isoformat()

            def submit_completion(gps_points=None):
                form_data = {
                    'csrf_token': 'test-csrf-token',
                    'duration': '1',
                    'detox_duration': '0',
                }
                if gps_points is not None:
                    form_data['gps_points'] = json.dumps(gps_points)
                return self.client.post(
                    f'/event/complete/{event_id}', data=form_data
                )

            set_started_at(14)
            response = submit_completion([{
                'lat': 35.0, 'lon': 139.0, 'accuracy': 5,
                'ts': datetime.now(cleanstep.JST).timestamp() * 1000,
            }])
            self.assertEqual(response.status_code, 400)
            self.assertIn('最低15分間', response.get_data(as_text=True))

            set_started_at(16)
            self.assertEqual(submit_completion().status_code, 400)
            outside_location = [{
                'lat': 36.0, 'lon': 139.0, 'accuracy': 5,
                'ts': datetime.now(cleanstep.JST).timestamp() * 1000,
            }]
            self.assertEqual(
                submit_completion(outside_location).status_code, 400
            )
            stale_location = [{
                'lat': 35.0, 'lon': 139.0, 'accuracy': 5,
                'ts': (datetime.now(cleanstep.JST).timestamp() - 121) * 1000,
            }]
            self.assertEqual(submit_completion(stale_location).status_code, 400)
            malformed_location = [{
                'lat': '35.0', 'lon': '139.0', 'accuracy': 'invalid',
                'ts': datetime.now(cleanstep.JST).timestamp() * 1000,
            }]
            self.assertEqual(submit_completion(malformed_location).status_code, 400)

            event_location = [{
                'lat': '35.0', 'lon': '139.0', 'accuracy': '5',
                'ts': str(datetime.now(cleanstep.JST).timestamp() * 1000),
            }]
            response = submit_completion(event_location)
            self.assertEqual(response.status_code, 302)

            with database_connection() as conn:
                activity = conn.execute('''
                    SELECT duration, points_earned FROM activity_history
                    WHERE user_id = 1 AND event_id = ?
                ''', (event_id,)).fetchone()
                current_points = conn.execute(
                    'SELECT total_points FROM users WHERE id = 1'
                ).fetchone()['total_points']
            self.assertGreaterEqual(
                activity['duration'], cleanstep.EVENT_MIN_DURATION_SECONDS
            )
            self.assertEqual(activity['points_earned'], 20)
            self.assertEqual(current_points, original_points + 20)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM activity_history WHERE event_id = ?', (event_id,)
                )
                conn.execute(
                    'DELETE FROM event_reservations WHERE event_id = ?', (event_id,)
                )
                conn.execute(
                    'UPDATE users SET total_points = ? WHERE id = ?',
                    (original_points, 1),
                )
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_event_activity_records_real_elapsed_time_and_unmeasured_metrics(self):
        with database_connection() as conn:
            original_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']
            conn.execute('''
                UPDATE events SET datetime = ? WHERE id = 1
            ''', ((datetime.now(cleanstep.JST) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"),))
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, 1, 'reserved')
                ON CONFLICT(user_id, event_id) DO UPDATE SET status = 'reserved'
            ''')

        self._login_as(1)
        self._use_mobile_user_agent()
        response = self.client.get("/event/live/1")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as user_session:
            user_session["event_started_at_1"] = (
                datetime.now(cleanstep.JST) - timedelta(minutes=20)
            ).isoformat()
        page = response.get_data(as_text=True)
        self.assertIn('id="gps_toggle"', page)
        self.assertIn('id="steps_val"', page)
        self.assertIn("未計測", page)
        self.assertNotIn("steps += 12", page)

        response = self.client.post(
            "/event/complete/1",
            data={
                "csrf_token": "test-csrf-token",
                "duration": "900",
                "steps": "0",
                "distance": "0",
                "calories": "0",
                "detox_duration": "0",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/event/result/", response.location)

        with database_connection() as conn:
            result = conn.execute('''
                SELECT a.duration, a.steps, a.distance, a.calories,
                       a.gps_measured, a.points_earned, u.total_points
                FROM activity_history a
                JOIN users u ON u.id = a.user_id
                WHERE a.user_id = 1 AND a.event_id = 1
            ''').fetchone()
        self.assertGreaterEqual(result["duration"], 900)
        self.assertEqual(result["steps"], 0)
        self.assertEqual(result["distance"], 0)
        self.assertEqual(result["calories"], 0)
        self.assertEqual(result["gps_measured"], 0)
        self.assertEqual(result["points_earned"], 50)
        self.assertEqual(result["total_points"], original_points + 50)

        response = self.client.get(response.location)
        self.assertEqual(response.status_code, 200)
        result_page = response.get_data(as_text=True)
        self.assertIn("未計測", result_page)
        self.assertIn("未計測", result_page)

        with database_connection() as conn:
            conn.execute(
                'DELETE FROM activity_history WHERE user_id = 1 AND event_id = 1'
            )
            conn.execute('DELETE FROM event_reservations WHERE user_id = 1 AND event_id = 1')
            conn.execute(
                'UPDATE users SET total_points = ? WHERE id = 1',
                (original_points,),
            )
            conn.execute(
                "UPDATE events SET datetime = '2035-01-01 10:00' WHERE id = 1"
            )

    def test_event_scheduled_two_days_ago_can_be_completed(self):
        event_datetime = (
            datetime.now(cleanstep.JST) - timedelta(days=2)
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            original_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']
            conn.execute(
                'UPDATE events SET datetime = ? WHERE id = 1',
                (event_datetime,),
            )
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, 1, 'reserved')
                ON CONFLICT(user_id, event_id) DO UPDATE SET status = 'reserved'
            ''')

        self._login_as(1)
        self._use_mobile_user_agent()
        self.client.get("/event/live/1")
        self._use_mobile_user_agent()
        with self.client.session_transaction() as user_session:
            user_session["event_started_at_1"] = (
                datetime.now(cleanstep.JST) - timedelta(minutes=20)
            ).isoformat()

        response = self.client.post(
            "/event/complete/1",
            data={
                "csrf_token": "test-csrf-token",
                "duration": "900",
                "detox_duration": "0",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/event/result/", response.location)

        with database_connection() as conn:
            conn.execute(
                'DELETE FROM activity_history WHERE user_id = 1 AND event_id = 1'
            )
            conn.execute(
                'DELETE FROM event_reservations WHERE user_id = 1 AND event_id = 1'
            )
            conn.execute(
                'UPDATE users SET total_points = ? WHERE id = 1',
                (original_points,),
            )
            conn.execute(
                "UPDATE events SET datetime = '2035-01-01 10:00' WHERE id = 1"
            )

    def test_naive_event_datetime_is_interpreted_as_japan_local_time(self):
        naive_datetime = datetime(2026, 10, 26, 10, 30)

        parsed = cleanstep.parse_event_datetime(naive_datetime.isoformat())

        self.assertEqual(parsed, naive_datetime.replace(tzinfo=cleanstep.JST))
        utc_datetime = datetime(2026, 10, 26, 1, 30, tzinfo=timezone.utc)
        self.assertEqual(cleanstep.parse_event_datetime(utc_datetime.isoformat()), parsed)

    def test_database_initialization_is_available_as_flask_cli_command(self):
        result = cleanstep.app.test_cli_runner().invoke(args=['init-db'])

        self.assertEqual(result.exit_code, 0, result.output)

    def test_startup_qr_uses_public_url_and_saves_image(self):
        with tempfile.TemporaryDirectory() as app_root:
            static_dir = Path(app_root) / 'static'
            static_dir.mkdir()
            output = StringIO()
            with (
                patch.dict(
                    os.environ,
                    {'CLEANSTEP_PUBLIC_URL': 'https://example.test/phone'},
                ),
                patch.object(cleanstep.app, 'root_path', app_root),
                redirect_stdout(output),
            ):
                cleanstep._print_startup_qr()

            self.assertIn('https://example.test/phone', output.getvalue())
            self.assertTrue(
                (Path(static_dir) / 'phone_access_qr.png').is_file()
            )

    def test_startup_qr_is_requested_for_flask_run_command_only(self):
        with (
            patch.dict(
                os.environ,
                {'FLASK_RUN_FROM_CLI': 'true'},
                clear=False,
            ),
            patch.object(sys, 'argv', ['flask', '--app', 'app', 'run']),
        ):
            self.assertTrue(cleanstep._should_print_startup_qr())

        with (
            patch.dict(
                os.environ,
                {'FLASK_RUN_FROM_CLI': 'true'},
                clear=False,
            ),
            patch.object(sys, 'argv', ['flask', '--app', 'app', 'routes']),
        ):
            self.assertFalse(cleanstep._should_print_startup_qr())

        with (
            patch.dict(
                os.environ,
                {
                    'FLASK_RUN_FROM_CLI': 'true',
                    'WERKZEUG_RUN_MAIN': 'true',
                },
                clear=False,
            ),
            patch.object(sys, 'argv', ['flask', '--app', 'app', 'run']),
        ):
            self.assertFalse(cleanstep._should_print_startup_qr())

    def test_future_reserved_event_returns_to_reservation_page_without_completing(self):
        event_datetime = (
            datetime.now(cleanstep.JST) + timedelta(days=2)
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, status, review_status
                ) VALUES (
                    'Future Reserved Test Event', 'Test Location', ?, 20,
                    'open', 'approved'
                )
            ''', (event_datetime,))
            event_id = cursor.lastrowid
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, ?, 'reserved')
            ''', (event_id,))
            original_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']

        self._login_as(1)
        self._use_mobile_user_agent()
        try:
            response = self.client.get(f"/event/live/{event_id}")
            self.assertEqual(response.status_code, 302)
            response = self.client.get(response.location)
            page = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("イベント開催前のため、活動計測はまだ開始できません", page)

            with self.client.session_transaction() as user_session:
                user_session[f"event_started_at_{event_id}"] = (
                    datetime.now(cleanstep.JST) - timedelta(seconds=10)
                ).isoformat()
            response = self.client.post(
                f"/event/complete/{event_id}",
                data={
                    "csrf_token": "test-csrf-token",
                    "duration": "8",
                    "detox_duration": "0",
                },
            )
            self.assertEqual(response.status_code, 302)
            response = self.client.get(response.location)
            self.assertIn("イベント開催前のため、活動は完了できません", response.get_data(as_text=True))

            self._use_pc_user_agent()
            reservation_page = self.client.get("/my/reservations")
            self.assertIn("Future Reserved Test Event", reservation_page.get_data(as_text=True))
            self.assertIn("開催前・予約内容", reservation_page.get_data(as_text=True))

            with database_connection() as conn:
                reservation = conn.execute('''
                    SELECT status FROM event_reservations
                    WHERE user_id = 1 AND event_id = ?
                ''', (event_id,)).fetchone()
                activity = conn.execute('''
                    SELECT 1 FROM activity_history
                    WHERE user_id = 1 AND event_id = ?
                ''', (event_id,)).fetchone()
                points = conn.execute(
                    'SELECT total_points FROM users WHERE id = 1'
                ).fetchone()['total_points']
            self.assertEqual(reservation['status'], 'reserved')
            self.assertIsNone(activity)
            self.assertEqual(points, original_points)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM event_reservations WHERE event_id = ?', (event_id,)
                )
                conn.execute(
                    'DELETE FROM activity_history WHERE event_id = ?', (event_id,)
                )
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_event_gps_metrics_are_calculated_and_only_totals_are_saved(self):
        started_at = datetime.now(cleanstep.JST) - timedelta(minutes=20)
        with database_connection() as conn:
            original_points = conn.execute(
                'SELECT total_points FROM users WHERE id = 1'
            ).fetchone()['total_points']
            conn.execute('''
                UPDATE events SET datetime = ? WHERE id = 1
            ''', ((datetime.now(cleanstep.JST) - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M"),))
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, 1, 'reserved')
                ON CONFLICT(user_id, event_id) DO UPDATE SET status = 'reserved'
            ''')

        self._login_as(1)
        self._use_mobile_user_agent()
        self.client.get("/event/live/1")
        with self.client.session_transaction() as user_session:
            user_session["event_started_at_1"] = started_at.isoformat()

        points = [
            {
                "lat": 35.0 + index * 0.0001,
                "lon": 139.0,
                "accuracy": 10,
                "ts": (started_at.timestamp() + 5 + index * 60) * 1000,
            }
            for index in range(3)
        ]
        invalid_response = self.client.post(
            "/event/complete/1",
            data={
                "csrf_token": "test-csrf-token",
                "duration": "120",
                "detox_duration": "0",
                "gps_points": json.dumps([{
                    "lat": 91,
                    "lon": 139,
                    "accuracy": 10,
                    "ts": points[0]["ts"],
                }]),
            },
        )
        self.assertEqual(invalid_response.status_code, 400)

        response = self.client.post(
            "/event/complete/1",
            data={
                "csrf_token": "test-csrf-token",
                "duration": "120",
                "steps": "99999",
                "distance": "499",
                "calories": "19999",
                "detox_duration": "0",
                "gps_points": json.dumps(points),
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            activity = conn.execute('''
                SELECT duration, steps, distance, calories, gps_measured,
                       points_earned
                FROM activity_history WHERE user_id = 1 AND event_id = 1
            ''').fetchone()
            activity_columns = {
                row["name"] for row in conn.execute(
                    "PRAGMA table_info(activity_history)"
                ).fetchall()
            }
        self.assertGreaterEqual(
            activity["duration"], cleanstep.EVENT_MIN_DURATION_SECONDS
        )
        self.assertEqual(activity["steps"], 29)
        self.assertAlmostEqual(activity["distance"], 0.0222, places=3)
        self.assertGreaterEqual(activity["calories"], 80)
        self.assertEqual(activity["gps_measured"], 1)
        self.assertEqual(activity["points_earned"], 50)
        self.assertNotIn("gps_points", activity_columns)

        result_response = self.client.get(response.location)
        self.assertEqual(result_response.status_code, 200)
        result_page = result_response.get_data(as_text=True)
        self.assertIn("GPS推定歩数", result_page)
        self.assertIn("概算", result_page)

        with database_connection() as conn:
            conn.execute('DELETE FROM activity_history WHERE user_id = 1 AND event_id = 1')
            conn.execute('DELETE FROM event_reservations WHERE user_id = 1 AND event_id = 1')
            conn.execute(
                'UPDATE users SET total_points = ? WHERE id = 1',
                (original_points,),
            )
            conn.execute(
                "UPDATE events SET datetime = '2035-01-01 10:00' WHERE id = 1"
            )

    def test_gps_metrics_match_original_api_for_fast_and_sparse_samples(self):
        started_at = datetime.now(cleanstep.JST)
        points = [
            {
                "lat": 35.0 + index * 0.0001,
                "lon": 139.0,
                "accuracy": 10,
                "ts": (started_at.timestamp() + offset) * 1000,
            }
            for index, offset in enumerate((5, 6, 250, 260))
        ]

        metrics = cleanstep.calculate_gps_metrics(
            points, started_at, started_at + timedelta(seconds=300)
        )

        self.assertEqual(metrics['validated_points'][0]['lat'], 35.0)
        self.assertIsInstance(metrics['validated_points'][0]['lat'], float)
        self.assertIsInstance(metrics['validated_points'][0]['accuracy'], float)
        self.assertIsInstance(metrics['validated_points'][0]['timestamp'], float)
        self.assertEqual(metrics["steps"], 44)
        self.assertAlmostEqual(metrics["distance"], 0.0333, places=3)
        self.assertEqual(metrics["calories"], 20)
        self.assertTrue(metrics["gps_measured"])

    def test_user_pages_show_personalized_lists_and_calendar(self):
        event_date = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%d %H:%M")
        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (name, location, datetime, bonus_points)
                VALUES ('Personal Page Event', 'Test Park', ?, 10)
            ''', (event_date,))
            event_id = cursor.lastrowid
            conn.execute('''
                INSERT INTO event_reservations (user_id, event_id, status)
                VALUES (1, ?, 'reserved')
            ''', (event_id,))

        self._login_as(1)
        try:
            response = self.client.get("/home")
            page = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Personal Page Event", page)
            self.assertIn("イベント一覧を開く", page)

            response = self.client.get("/mypage")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Owner さんのマイページ", response.get_data(as_text=True))
            self.assertIn("活動カレンダー", response.get_data(as_text=True))

            response = self.client.get("/events")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Personal Page Event", response.get_data(as_text=True))

            response = self.client.get("/my/reservations")
            self.assertEqual(response.status_code, 200)
            self.assertIn("Personal Page Event", response.get_data(as_text=True))
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM event_reservations WHERE event_id = ?', (event_id,)
                )
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_organizer_dashboard_links_application_management_and_editing(self):
        event_name = "Organizer Dashboard Editable Event"
        with database_connection() as conn:
            organization_id = conn.execute(
                'SELECT id FROM organizations WHERE application_id = 1'
            ).fetchone()["id"]
            cursor = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, organizer_id,
                    organization_id, review_status
                ) VALUES (?, 'Community Park', '2035-01-01 10:00', 25, 1, ?, 'approved')
            ''', (event_name, organization_id))
            event_id = cursor.lastrowid

        self._login_as(1)
        try:
            response = self.client.get("/home")
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('href="/organizer"', response.get_data(as_text=True))

            response = self.client.get("/organizer")
            page = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("団体ダッシュボード", page)
            self.assertIn("イベント申請", page)
            self.assertIn("イベント管理", page)
            self.assertIn("イベント編集", page)
            self.assertIn('class="section-grid"', page)
            self.assertIn('class="section-card"', page)
            self.assertIn("イベント管理セクション", page)

            response = self.client.get("/organizer/events/edit")
            self.assertEqual(response.status_code, 200)
            self.assertIn(event_name, response.get_data(as_text=True))
            self.assertIn(
                f"/organizer/events/{event_id}/edit",
                response.get_data(as_text=True),
            )

            response = self.client.get("/organizer/events")
            self.assertEqual(response.status_code, 200)
            self.assertIn(event_name, response.get_data(as_text=True))
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_event_location_coordinates_are_optional_and_reservations_are_capped(self):
        event_date = (datetime.now(cleanstep.JST) + timedelta(days=30)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%dT%H:%M")
        too_far_date = (datetime.now(cleanstep.JST) + timedelta(days=366)).replace(
            second=0, microsecond=0
        ).strftime("%Y-%m-%d %H:%M")
        self._login_as(2, "admin")
        response = self.client.post(
            "/admin/events/add",
            data={
                "csrf_token": "test-csrf-token",
                "name": "No Coordinates Event",
                "location": "Text Address",
                "datetime": event_date,
                "bonus_points": "10",
            },
        )
        self.assertEqual(response.status_code, 302)

        with database_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO events (name, location, datetime, bonus_points)
                VALUES ('Far Future Event', 'Test Park', ?, 10)
            ''', (too_far_date,))
            far_event_id = cursor.lastrowid
            event = conn.execute('''
                SELECT id, latitude, longitude FROM events
                WHERE name = 'No Coordinates Event'
            ''').fetchone()
        self.assertIsNone(event["latitude"])
        self.assertIsNone(event["longitude"])

        self._login_as(1)
        self.assertEqual(
            self.client.get(f"/event/reserve/{far_event_id}").status_code, 400
        )
        try:
            response = self.client.get(f"/event/reserve/{event['id']}")
            self.assertEqual(response.status_code, 200)
        finally:
            with database_connection() as conn:
                conn.execute('DELETE FROM events WHERE id IN (?, ?)', (
                    event["id"], far_event_id
                ))

    def test_logout_requires_confirmation_and_post(self):
        self._login_as(1)
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertIn("ログアウトしますか？".encode(), response.data)
        with self.client.session_transaction() as user_session:
            self.assertEqual(user_session["user_id"], 1)

        response = self.client.post(
            "/logout", data={"csrf_token": "test-csrf-token"}
        )
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as user_session:
            self.assertNotIn("user_id", user_session)

    def test_view_mode_always_follows_user_agent(self):
        self._login_as(1)
        mobile_user_agent = {
            'User-Agent': (
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile'
            )
        }
        desktop_user_agent = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0'
            )
        }

        mobile_response = self.client.get('/home', headers=mobile_user_agent)
        self.assertEqual(mobile_response.status_code, 200)
        mobile_page = mobile_response.get_data(as_text=True)
        self.assertIn('data-view-mode="mobile"', mobile_page)
        self.assertNotIn('view-mode-switch', mobile_page)
        self.assertNotIn('スマートフォン画面（現場アクション優先モード）', mobile_page)
        self.assertIn('基本の活動記録', mobile_page)
        self.assertIn('最近の活動履歴', mobile_page)
        self.assertIn('href="/trash-bin"', mobile_page)
        self.assertIn('href="/events"', mobile_page)
        self.assertIn('href="/my/reservations"', mobile_page)
        self.assertNotIn('おすすめイベント', mobile_page)

        for event_path in ('/events', '/my/reservations'):
            response = self.client.get(event_path, headers=mobile_user_agent)
            self.assertEqual(response.status_code, 200)

        fixed_pc_response = self.client.get(
            '/view-mode/pc?next=/home',
            headers=mobile_user_agent,
            follow_redirects=True,
        )
        self.assertEqual(fixed_pc_response.status_code, 200)
        self.assertIn(
            'data-view-mode="mobile"',
            fixed_pc_response.get_data(as_text=True),
        )

        with self.client.session_transaction() as user_session:
            user_session['view_mode'] = 'mobile'

        desktop_response = self.client.get('/home', headers=desktop_user_agent)
        desktop_page = desktop_response.get_data(as_text=True)
        self.assertIn(
            'data-view-mode="pc"',
            desktop_page,
        )
        self.assertNotIn('view-mode-switch', desktop_page)
        self.assertIn('おすすめイベント', desktop_page)
        self.assertIn('href="/events"', desktop_page)
        self.assertIn('href="/my/reservations"', desktop_page)
        self.assertIn('href="/issues/report"', desktop_page)
        self.assertIn('class="user-app-notify"', desktop_page)
        self.assertNotIn('通知を確認', desktop_page)
        self.assertNotIn('href="/trash-bin"', desktop_page)

        issue_report_desktop = self.client.get(
            '/issues/report', headers=desktop_user_agent
        )
        self.assertEqual(issue_report_desktop.status_code, 200)

        for mobile_only_path in ('/trash-bin', '/event/live/1'):
            response = self.client.get(mobile_only_path, headers=desktop_user_agent)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, '/home')

    def test_user_navigation_and_internal_error_page_have_return_actions(self):
        self._login_as(1)
        home_response = self.client.get('/home')
        self.assertEqual(home_response.status_code, 200)
        home_page = home_response.get_data(as_text=True)
        self.assertIn('class="user-page-back-row"', home_page)
        self.assertIn('← 戻る', home_page)
        self.assertIn(
            '.user-page-back-row { margin: 12px 16px; text-align: left; }',
            home_page,
        )
        self.assertLess(
            home_page.index('class="hero-banner"'),
            home_page.index('class="user-page-back-row"'),
        )
        self.assertLess(
            home_page.index('class="user-page-back-row"'),
            home_page.index('class="container"'),
        )
        app_bar = home_page.index('class="user-app-bar"')
        app_bar_end = home_page.index('</div>', app_bar)
        self.assertNotIn('user-page-back', home_page[app_bar:app_bar_end])

        with cleanstep.app.test_request_context('/broken'):
            error_page, status = cleanstep.handle_internal_server_error(
                RuntimeError('simulated failure')
            )
        self.assertEqual(status, 500)
        self.assertIn('前の画面に戻る', error_page)
        self.assertIn('ホームへ', error_page)

    def test_mobile_pc_view_mode_and_issue_report_to_map_flow(self):
        self._login_as(1)
        try:
            mobile_user_agent = {
                'User-Agent': self.MOBILE_USER_AGENT
            }
            mobile_resp = self.client.get(
                '/home', headers=mobile_user_agent
            )
            self.assertEqual(mobile_resp.status_code, 200)
            mobile_page = mobile_resp.get_data(as_text=True)
            self.assertIn('data-view-mode="mobile"', mobile_page)
            self.assertNotIn("スマートフォン画面（現場アクション優先モード）", mobile_page)

            desktop_user_agent = {'User-Agent': self.PC_USER_AGENT}
            pc_resp = self.client.get('/home', headers=desktop_user_agent)
            self.assertEqual(pc_resp.status_code, 200)
            pc_page = pc_resp.get_data(as_text=True)
            self.assertIn('data-view-mode="pc"', pc_page)
            self.assertIn("曜日別の活動傾向", pc_page)
            self.assertNotIn("あなたの活動スタイルと発見実績", pc_page)

            report_get = self.client.get("/issues/report", headers=mobile_user_agent)
            self.assertEqual(report_get.status_code, 200)
            self.assertIn("地域のゴミ・課題を報告", report_get.get_data(as_text=True))

            event_datetime = (
                datetime.now(cleanstep.JST) + timedelta(days=14)
            ).strftime("%Y-%m-%d %H:%M")
            with database_connection() as conn:
                event_cursor = conn.execute('''
                    INSERT INTO events (
                        name, location, latitude, longitude, datetime,
                        bonus_points, capacity, status, review_status
                    ) VALUES (
                        '駅前課題連携清掃イベント', '横浜駅西口ロータリー',
                        35.465833, 139.622313, ?, 20, 20, 'open', 'approved'
                    )
                ''', (event_datetime,))
                event_id = event_cursor.lastrowid

            report_post = self.client.post(
                "/issues/report",
                headers=mobile_user_agent,
                data={
                    "csrf_token": "test-csrf-token",
                    "title": "駅前ペットボトル散乱テスト",
                    "location": "横浜駅西口ロータリー",
                    "latitude": "35.465833",
                    "longitude": "139.622313",
                    "trash_type": "ペットボトル・飲料容器",
                    "severity": "high",
                    "description": "自販機横にごみ箱がない",
                },
            )
            self.assertEqual(report_post.status_code, 302)
            self.assertRegex(report_post.location, r"^/map\?issue_id=\d+$")
            issue_id = int(report_post.location.rsplit("=", 1)[1])

            map_resp = self.client.get(report_post.location)
            self.assertEqual(map_resp.status_code, 200)
            map_page = map_resp.get_data(as_text=True)
            self.assertIn("報告した課題を地図と一覧で表示しています".encode(), map_resp.data)
            self.assertIn("駅前ペットボトル散乱テスト", map_page)
            self.assertIn("横浜駅西口ロータリー", map_page)
            self.assertIn('id="issue-{}'.format(issue_id), map_page)
            self.assertIn("駅前課題連携清掃イベント", map_page)
            self.assertIn(f"/event/reserve/{event_id}", map_page)
            self.assertIn(f"/proposals?issue_id={issue_id}", map_page)

            proposal_resp = self.client.get(
                f"/proposals?issue_id={issue_id}&location=横浜駅西口ロータリー"
            )
            self.assertEqual(proposal_resp.status_code, 200)
            proposal_page = proposal_resp.get_data(as_text=True)
            self.assertIn(
                "横浜駅西口ロータリーの清掃・環境改善",
                proposal_page,
            )
            self.assertIn("重点清掃イベントの開催", proposal_page)
            self.assertIn(
                "自販機横にごみ箱がない",
                proposal_page,
            )
        finally:
            with database_connection() as conn:
                conn.execute(
                    "DELETE FROM events WHERE name = '駅前課題連携清掃イベント'"
                )
                conn.execute(
                    "DELETE FROM issue_reports WHERE title = '駅前ペットボトル散乱テスト'"
                )
                conn.execute(
                    "DELETE FROM user_notifications WHERE title LIKE '地域課題を報告しました：%'"
                )

    def test_proposals_and_admin_issue_management_flow(self):
        self._login_as(1)
        self._use_mobile_user_agent()
        try:
            prop_post = self.client.post(
                "/proposals",
                data={
                    "csrf_token": "test-csrf-token",
                    "title": "みなとみらいベンチ横ごみ箱増設案",
                    "location": "横浜みなとみらい公園",
                    "proposal_type": "ごみ箱の増設・配置見直し",
                    "description": "週末のカップごみ散乱を防ぐため分別ごみ箱を1基増設する",
                },
                follow_redirects=True,
            )
            self.assertEqual(prop_post.status_code, 200)
            self.assertIn("みなとみらいベンチ横ごみ箱増設案", prop_post.get_data(as_text=True))

            self.client.post(
                "/issues/report",
                data={
                    "csrf_token": "test-csrf-token",
                    "title": "公園ベンチ裏の空き缶溜まり",
                    "location": "横浜みなとみらい公園",
                    "trash_type": "空き缶・ビン",
                    "severity": "medium",
                    "description": "日曜夕方に毎回発生",
                },
            )
            with database_connection() as conn:
                issue_id = conn.execute(
                    "SELECT id FROM issue_reports WHERE title = '公園ベンチ裏の空き缶溜まり' ORDER BY id DESC LIMIT 1"
                ).fetchone()["id"]
                previous_month = (
                    datetime.now(timezone.utc).date().replace(day=1)
                    - timedelta(days=1)
                ).replace(day=1)
                conn.execute(
                    'UPDATE issue_reports SET created_at = ? WHERE id = ?',
                    (f'{previous_month:%Y-%m}-15 12:00:00', issue_id),
                )
                proposal_id = conn.execute(
                    "SELECT id FROM improvement_proposals WHERE title = 'みなとみらいベンチ横ごみ箱増設案' ORDER BY id DESC LIMIT 1"
                ).fetchone()["id"]

            self._login_as(2, "admin")
            admin_issues_get = self.client.get("/admin/issues")
            self.assertEqual(admin_issues_get.status_code, 200)
            self.assertIn("公園ベンチ裏の空き缶溜まり", admin_issues_get.get_data(as_text=True))
            self.assertIn("対応状況と環境変化は別々に集計".encode(), admin_issues_get.data)
            self.assertIn("対応状況からは環境改善を判断していません".encode(), admin_issues_get.data)
            self.assertIn("地域課題の月別推移（直近12か月）".encode(), admin_issues_get.data)
            with database_connection() as conn:
                regional_data = cleanstep._load_regional_issue_analytics(conn)
                monthly_rows = regional_data[
                    'issue_time_series'
                ]
                self.assertIsNone(next(
                    issue for issue in regional_data['issues']
                    if issue['id'] == issue_id
                )['reporter_name'])
                self.assertIsNone(next(
                    proposal for proposal in regional_data['proposals']
                    if proposal['id'] == proposal_id
                )['author_name'])
                admin_data = cleanstep._load_regional_issue_analytics(
                    conn, include_personal_info=True
                )
                self.assertIsNotNone(next(
                    issue for issue in admin_data['issues']
                    if issue['id'] == issue_id
                )['reporter_name'])
                self.assertIsNotNone(next(
                    proposal for proposal in admin_data['proposals']
                    if proposal['id'] == proposal_id
                )['author_name'])
            self.assertEqual(len(monthly_rows), 12)
            self.assertEqual(monthly_rows[-1]['month'], datetime.now(timezone.utc).strftime('%Y-%m'))
            previous_month_row = next(
                row for row in monthly_rows
                if row['month'] == previous_month.strftime('%Y-%m')
            )
            self.assertGreaterEqual(previous_month_row['report_count'], 1)

            status_post = self.client.post(
                f"/admin/issues/{issue_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "in_progress",
                    "action_note": "次回イベントの重点清掃対象に設定しました",
                },
            )
            self.assertEqual(status_post.status_code, 302)
            with database_connection() as conn:
                issue = conn.execute('''
                    SELECT status, environment_status, environment_note
                    FROM issue_reports WHERE id = ?
                ''', (issue_id,)).fetchone()
            self.assertEqual(issue['status'], 'in_progress')
            self.assertEqual(issue['environment_status'], 'unverified')
            self.assertEqual(issue['environment_note'], '')

            missing_evidence = self.client.post(
                f"/admin/issues/{issue_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "resolved",
                    "environment_status": "improved",
                    "environment_note": "",
                },
            )
            self.assertEqual(missing_evidence.status_code, 400)

            resolved_post = self.client.post(
                f"/admin/issues/{issue_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "resolved",
                    "action_note": "ごみを回収しました",
                    "environment_status": "improved",
                    "environment_note": "翌週の現地確認で散乱が減少していることを確認",
                },
            )
            self.assertEqual(resolved_post.status_code, 302)
            with database_connection() as conn:
                issue = conn.execute('''
                    SELECT status, environment_status, environment_note,
                           environment_checked_by, environment_checked_at
                    FROM issue_reports WHERE id = ?
                ''', (issue_id,)).fetchone()
            self.assertEqual(issue['status'], 'resolved')
            self.assertEqual(issue['environment_status'], 'improved')
            self.assertIn('現地確認で散乱が減少', issue['environment_note'])
            self.assertEqual(issue['environment_checked_by'], 2)
            self.assertTrue(issue['environment_checked_at'])

            prop_status_post = self.client.post(
                f"/admin/proposals/{proposal_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "adopted",
                    "admin_comment": "来月の設置候補として採用しました",
                },
            )
            self.assertEqual(prop_status_post.status_code, 302)
            missing_execution_record = self.client.post(
                f"/admin/proposals/{proposal_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "completed",
                    "admin_comment": "対策を実施しました",
                },
            )
            self.assertEqual(missing_execution_record.status_code, 400)
            invalid_execution_date = self.client.post(
                f"/admin/proposals/{proposal_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "completed",
                    "implementation_details": "分別ごみ箱を1基設置",
                    "implemented_on": "来月",
                    "outcome_note": "ごみの散乱が減少",
                },
            )
            self.assertEqual(invalid_execution_date.status_code, 400)
            completed_post = self.client.post(
                f"/admin/proposals/{proposal_id}/status",
                data={
                    "csrf_token": "test-csrf-token",
                    "status": "completed",
                    "admin_comment": "現地確認済み",
                    "implementation_details": "分別ごみ箱を1基設置",
                    "implemented_on": "2026-11-10",
                    "outcome_note": "翌週の現地確認で散乱の減少を確認",
                },
            )
            self.assertEqual(completed_post.status_code, 302)
            with database_connection() as conn:
                proposal = conn.execute('''
                    SELECT status, implementation_details, implemented_on,
                           outcome_note
                    FROM improvement_proposals WHERE id = ?
                ''', (proposal_id,)).fetchone()
            self.assertEqual(proposal['status'], 'completed')
            self.assertEqual(proposal['implementation_details'], '分別ごみ箱を1基設置')
            self.assertEqual(proposal['implemented_on'], '2026-11-10')
            self.assertEqual(proposal['outcome_note'], '翌週の現地確認で散乱の減少を確認')
            completed_page = self.client.get('/admin/issues')
            self.assertIn('実施記録'.encode(), completed_page.data)
            self.assertIn('分別ごみ箱を1基設置'.encode(), completed_page.data)
            self.assertIn('翌週の現地確認で散乱の減少を確認'.encode(), completed_page.data)
        finally:
            with database_connection() as conn:
                conn.execute(
                    "DELETE FROM improvement_proposal_supports WHERE proposal_id IN (SELECT id FROM improvement_proposals WHERE title = 'みなとみらいベンチ横ごみ箱増設案')"
                )
                conn.execute(
                    "DELETE FROM improvement_proposals WHERE title = 'みなとみらいベンチ横ごみ箱増設案'"
                )
                conn.execute('''
                    DELETE FROM issue_status_history
                    WHERE issue_id IN (
                        SELECT id FROM issue_reports
                        WHERE title = '公園ベンチ裏の空き缶溜まり'
                    )
                ''')
                conn.execute(
                    "DELETE FROM issue_reports WHERE title = '公園ベンチ裏の空き缶溜まり'"
                )
                conn.execute(
                    "DELETE FROM user_notifications WHERE title LIKE '%公園ベンチ裏の空き缶溜まり%'"
                )

    def test_location_recurrence_analysis_reports_repeat_interval(self):
        location = "再発分析テスト地点"
        report_date = datetime.now(timezone.utc).replace(
            hour=12, minute=0, second=0, microsecond=0
        )
        try:
            with database_connection() as conn:
                conn.executemany('''
                    INSERT INTO issue_reports (
                        user_id, title, location, trash_type, severity,
                        environment_status, created_at
                    ) VALUES (
                        1, ?, ?, '空き缶・ビン', 'medium', ?, ?
                    )
                ''', [
                    (
                        '再発分析初回報告',
                        location,
                        'improved',
                        (report_date - timedelta(days=5)).strftime(
                            '%Y-%m-%d %H:%M:%S'
                        ),
                    ),
                    (
                        '再発分析再報告',
                        location,
                        'recurred',
                        report_date.strftime('%Y-%m-%d %H:%M:%S'),
                    ),
                ])
                recurrence = next(
                    row for row in cleanstep._load_regional_issue_analytics(conn)[
                        'location_recurrence'
                    ]
                    if row['location'] == location
                )

            self.assertEqual(recurrence['report_count'], 2)
            self.assertEqual(recurrence['repeat_report_count'], 1)
            self.assertEqual(recurrence['average_days_between_reports'], 5.0)
            self.assertEqual(recurrence['confirmed_recurrence_count'], 1)
            self._login_as(2, 'admin')
            response = self.client.get('/admin/issues')
            self.assertEqual(response.status_code, 200)
            self.assertIn('同じ場所での再報告・再発分析'.encode(), response.data)
            self.assertIn(location.encode(), response.data)
            self.assertIn('再報告は同じ場所で報告が繰り返された'.encode(), response.data)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM issue_reports WHERE location = ?', (location,)
                )

    def test_issue_analysis_groups_reports_by_nearest_bin_distance(self):
        location = 'ごみ箱距離分析テスト地点'
        first_bin = 'ごみ箱距離分析テスト設置A'
        second_bin = 'ごみ箱距離分析テスト設置B'
        issue_titles = [
            '距離分析テスト報告100m以内',
            '距離分析テスト報告300m以内',
            '距離分析テスト報告300m超',
            '距離分析テスト座標なし',
        ]
        with database_connection() as conn:
            baseline_without_coordinates = conn.execute('''
                SELECT COUNT(*) FROM issue_reports
                WHERE latitude IS NULL OR longitude IS NULL
            ''').fetchone()[0]
            conn.executemany('''
                INSERT INTO trash_bins (name, description, lat, lng, waste_types)
                VALUES (?, '距離分析テスト用', ?, ?, 'テスト容器')
            ''', [
                (first_bin, -80.0, -150.0),
                (second_bin, -80.0, -149.0),
            ])
            conn.executemany('''
                INSERT INTO issue_reports (
                    user_id, title, location, latitude, longitude,
                    trash_type, severity
                ) VALUES (1, ?, ?, ?, ?, ?, 'medium')
            ''', [
                (issue_titles[0], location, -79.9995, -150.0, '距離分析テスト容器'),
                (issue_titles[1], location, -79.998, -150.0, '距離分析テスト容器'),
                (issue_titles[2], location, -79.995, -150.0, '距離分析テスト容器'),
                (issue_titles[3], location, None, None, '距離分析テスト缶'),
            ])

        try:
            with database_connection() as conn:
                data = cleanstep._load_regional_issue_analytics(conn)

            test_groups = {
                row['distance_band']: row
                for row in data['bin_proximity_summary']
                if row['trash_type'] == '距離分析テスト容器'
            }
            self.assertEqual(
                set(test_groups),
                {'100m以内', '100m超〜300m以内', '300m超'},
            )
            self.assertEqual(test_groups['100m以内']['report_count'], 1)
            self.assertEqual(test_groups['100m超〜300m以内']['report_count'], 1)
            self.assertEqual(test_groups['300m超']['report_count'], 1)
            self.assertEqual(
                test_groups['100m以内']['average_distance_m'],
                round(cleanstep._haversine_distance_meters(
                    -79.9995, -150.0, -80.0, -150.0
                )),
            )
            nearest_report = next(
                row for row in data['issue_bin_proximity']
                if row['title'] == issue_titles[0]
            )
            self.assertEqual(nearest_report['nearest_bin_name'], first_bin)
            self.assertEqual(nearest_report['nearest_bin_waste_types'], 'テスト容器')
            self.assertEqual(
                data['issues_without_coordinates'],
                baseline_without_coordinates + 1,
            )

            self._login_as(2, 'admin')
            response = self.client.get('/admin/issues')
            self.assertEqual(response.status_code, 200)
            self.assertIn('課題報告地点と登録ごみ箱の距離分析'.encode(), response.data)
            self.assertIn(first_bin.encode(), response.data)
            self.assertIn('登録場所との距離関係を示す記述的な集計'.encode(), response.data)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM issue_reports WHERE title LIKE ?',
                    ('距離分析テスト%',),
                )
                conn.execute(
                    'DELETE FROM trash_bins WHERE name LIKE ?',
                    ('ごみ箱距離分析テスト設置%',),
                )

    def test_event_state_comparison_groups_self_reported_transitions(self):
        location = '活動前後比較テスト地点'
        event_name = '活動前後比較テストイベント'
        before_state = '広範囲にごみが散乱していた'
        after_state = 'きれいになったが再発注意'
        with database_connection() as conn:
            event_id = conn.execute('''
                INSERT INTO events (
                    name, location, datetime, bonus_points, status, review_status
                ) VALUES (?, ?, '2035-01-01 10:00', 0, 'open', 'approved')
            ''', (event_name, location)).lastrowid
            conn.executemany('''
                INSERT INTO activity_history (
                    user_id, event_id, type, title, before_state, after_state
                ) VALUES (?, ?, 'event', ?, ?, ?)
            ''', [
                (1, event_id, event_name, before_state, after_state),
                (3, event_id, event_name, before_state, after_state),
            ])

        try:
            with database_connection() as conn:
                data = cleanstep._load_regional_issue_analytics(conn)
            comparison = next(
                row for row in data['event_state_comparisons']
                if row['location'] == location
            )
            self.assertEqual(comparison['activity_count'], 2)
            self.assertEqual(comparison['before_state'], before_state)
            self.assertEqual(comparison['after_state'], after_state)
            record = next(
                row for row in data['event_state_changes']
                if row['location'] == location
            )
            self.assertEqual(
                record['comparison_result'],
                '改善・再発注意（参加者評価）',
            )

            self._login_as(2, 'admin')
            response = self.client.get('/admin/issues')
            self.assertEqual(response.status_code, 200)
            self.assertIn('清掃前後の状態比較（参加者の自己評価）'.encode(), response.data)
            self.assertIn(location.encode(), response.data)
            self.assertIn('改善・再発注意'.encode(), response.data)
            self.assertIn('実測値や独立した現地検証ではなく'.encode(), response.data)
        finally:
            with database_connection() as conn:
                conn.execute(
                    'DELETE FROM activity_history WHERE event_id = ?', (event_id,)
                )
                conn.execute('DELETE FROM events WHERE id = ?', (event_id,))

    def test_part3_bin_management_and_issue_to_event_prefill(self):
        self._login_as(1)
        self._use_mobile_user_agent()
        try:
            self.client.post(
                "/issues/report",
                data={
                    "csrf_token": "test-csrf-token",
                    "title": "海岸遊歩道のプラ容器散乱",
                    "location": "臨港パーク海沿い",
                    "latitude": "35.460000",
                    "longitude": "139.638000",
                    "trash_type": "ペットボトル・飲料容器",
                    "severity": "high",
                    "description": "強風時にプラ容器が溜まりやすい",
                },
            )
            with database_connection() as conn:
                issue_id = conn.execute(
                    "SELECT id FROM issue_reports WHERE title = '海岸遊歩道のプラ容器散乱' ORDER BY id DESC LIMIT 1"
                ).fetchone()["id"]

            org_prefill = self.client.get(f"/organizer/events/new?from_issue={issue_id}")
            self.assertEqual(org_prefill.status_code, 200)
            org_html = org_prefill.get_data(as_text=True)
            self.assertIn("臨港パーク海沿い 課題解決クリーンイベント", org_html)
            self.assertIn("海岸遊歩道のプラ容器散乱", org_html)

            mypage_resp = self.client.get("/mypage")
            self.assertEqual(mypage_resp.status_code, 200)
            self.assertIn("地域課題ウォッチャー", mypage_resp.get_data(as_text=True))

            map_resp = self.client.get("/map")
            self.assertEqual(map_resp.status_code, 200)
            self.assertIn("地域環境の自動分析", map_resp.get_data(as_text=True))

            self._login_as(2, "admin")
            admin_prefill = self.client.get(f"/admin/events/add?from_issue={issue_id}")
            self.assertEqual(admin_prefill.status_code, 200)
            self.assertIn("臨港パーク海沿い 課題解決クリーンイベント", admin_prefill.get_data(as_text=True))

            bin_post = self.client.post(
                "/admin/bins/add",
                data={
                    "csrf_token": "test-csrf-token",
                    "name": "臨港パーク分別エコボックス",
                    "description": "海沿いベンチ横",
                    "waste_types": "ペットボトル・プラ容器・空き缶",
                    "bin_status": "full_reported",
                    "lat": "35.460100",
                    "lng": "139.638100",
                },
                follow_redirects=True,
            )
            self.assertEqual(bin_post.status_code, 200)
            bins_html = bin_post.get_data(as_text=True)
            self.assertIn("ペットボトル・プラ容器・空き缶", bins_html)
            self.assertIn("満杯報告あり", bins_html)
        finally:
            with database_connection() as conn:
                conn.execute(
                    "DELETE FROM trash_bins WHERE name = '臨港パーク分別エコボックス'"
                )
                conn.execute(
                    "DELETE FROM issue_reports WHERE title = '海岸遊歩道のプラ容器散乱'"
                )
                conn.execute(
                    "DELETE FROM user_notifications WHERE title LIKE '%海岸遊歩道のプラ容器散乱%'"
                )


if __name__ == "__main__":
    unittest.main()
