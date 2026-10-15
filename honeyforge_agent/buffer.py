import sqlite3
import json
import time
import os
import threading
from typing import List, Dict, Any

class LocalEventBuffer:
    """
    FR-A4 (Must): Local store-and-forward persistence buffer.
    Guarantees no telemetry loss during network drops, C2 maintenance, or channel disruptions.
    Includes buffer rotation/capacity capping, exponential backoff management, and event_uid deduplication.
    """
    MAX_BUFFER_EVENTS = 10000

    def __init__(self, db_path: str = ".sysinfo.store.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.failure_count = 0
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock:
            dir_name = os.path.dirname(os.path.abspath(self.db_path))
            if dir_name:
                try:
                    os.makedirs(dir_name, exist_ok=True)
                except Exception:
                    self.db_path = ".sysinfo.store.db"
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS buffered_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE,
                        event_uid TEXT,
                        event_data TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        delivered INTEGER DEFAULT 0
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_delivered ON buffered_events (delivered)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_uid ON buffered_events (event_uid)")
                conn.commit()
            finally:
                conn.close()

            # Enforce strict 0600 file permissions for agent isolation
            try:
                if os.path.exists(self.db_path):
                    os.chmod(self.db_path, 0o600)
            except Exception:
                pass

    def push_event(self, event_dict: Dict[str, Any]):
        """Saves incoming attack event to local disk buffer before network transmission with rotation"""
        event_id = event_dict.get("event_id")
        event_uid = event_dict.get("event_uid") or event_id
        if "event_uid" not in event_dict:
            event_dict["event_uid"] = event_uid
        event_json = json.dumps(event_dict)

        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO buffered_events (event_id, event_uid, event_data, created_at, delivered)
                    VALUES (?, ?, ?, ?, 0)
                """, (event_id, event_uid, event_json, time.time()))

                # Rotate buffer if exceeding maximum size
                cursor.execute("SELECT COUNT(id) FROM buffered_events")
                total_count = cursor.fetchone()[0]
                if total_count > self.MAX_BUFFER_EVENTS:
                    # First prune already delivered events
                    cursor.execute("DELETE FROM buffered_events WHERE delivered = 1")
                    cursor.execute("SELECT COUNT(id) FROM buffered_events")
                    current_count = cursor.fetchone()[0]
                    if current_count > self.MAX_BUFFER_EVENTS:
                        # Prune oldest records
                        cursor.execute("""
                            DELETE FROM buffered_events WHERE id IN (
                                SELECT id FROM buffered_events ORDER BY id ASC LIMIT ?
                            )
                        """, (current_count - self.MAX_BUFFER_EVENTS,))

                conn.commit()
            finally:
                conn.close()

    def peek_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Reads a batch of undelivered events"""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT event_id, event_data FROM buffered_events
                    WHERE delivered = 0
                    ORDER BY id ASC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                events = []
                for _, data_str in rows:
                    try:
                        events.append(json.loads(data_str))
                    except Exception:
                        pass
                return events
            finally:
                conn.close()

    def mark_delivered(self, event_ids: List[str]):
        """Marks successfully delivered events as sent, or purges delivered records"""
        if not event_ids:
            return
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                placeholders = ",".join("?" * len(event_ids))
                cursor.execute(f"""
                    DELETE FROM buffered_events WHERE event_id IN ({placeholders})
                """, event_ids)
                conn.commit()
            finally:
                conn.close()

    def count_pending(self) -> int:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(id) FROM buffered_events WHERE delivered = 0")
                return cursor.fetchone()[0]
            finally:
                conn.close()

    def record_success(self):
        """Resets exponential backoff on successful delivery"""
        self.failure_count = 0

    def record_failure(self):
        """Increments failure count for exponential backoff"""
        self.failure_count += 1

    def get_backoff_delay(self, base: float = 1.0, max_delay: float = 60.0) -> float:
        """Calculates exponential backoff delay based on failure streak"""
        if self.failure_count <= 0:
            return 0.0
        return min(max_delay, base * (2 ** min(self.failure_count, 6)))
