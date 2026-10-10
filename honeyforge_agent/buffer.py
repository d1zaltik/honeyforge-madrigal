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
    """
    def __init__(self, db_path: str = ".sysinfo.store.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS buffered_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE,
                        event_data TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        delivered INTEGER DEFAULT 0
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_delivered ON buffered_events (delivered)")
                conn.commit()
            finally:
                conn.close()

    def push_event(self, event_dict: Dict[str, Any]):
        """Saves incoming attack event to local disk buffer before network transmission"""
        event_id = event_dict.get("event_id")
        event_json = json.dumps(event_dict)
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO buffered_events (event_id, event_data, created_at, delivered)
                    VALUES (?, ?, ?, 0)
                """, (event_id, event_json, time.time()))
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
