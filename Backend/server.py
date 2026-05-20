from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import sqlite3
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from event_importer import fetch_all_sources, events_as_dicts


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "eventradar.sqlite3"
HOST = os.environ.get("EVENTRADAR_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT") or os.environ.get("EVENTRADAR_PORT", "8000"))
TOKEN_TTL_DAYS = 7


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def json_dumps(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def parse_json_field(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return f"{salt}${base64.b64encode(digest).decode('ascii')}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt).split("$", 1)[1], expected)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
  city TEXT DEFAULT '',
  district TEXT DEFAULT '',
  country TEXT DEFAULT 'Turkey',
  email_notifications INTEGER NOT NULL DEFAULT 0,
  pic TEXT,
  joined TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  cat TEXT NOT NULL CHECK(cat IN ('theater','cinema','sports','concerts')),
  loc TEXT NOT NULL,
  dist REAL NOT NULL DEFAULT 0,
  date_raw TEXT NOT NULL,
  description TEXT DEFAULT '',
  details TEXT DEFAULT '',
  poster TEXT,
  source TEXT DEFAULT 'Manual',
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
  icon TEXT DEFAULT '📅',
  tickets TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS follows (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, event_id)
);

CREATE TABLE IF NOT EXISTS event_sources (
  source_name TEXT NOT NULL,
  external_id TEXT NOT NULL,
  source_url TEXT NOT NULL,
  event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  last_seen_at TEXT NOT NULL,
  PRIMARY KEY (source_name, external_id)
);

CREATE TABLE IF NOT EXISTS import_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  imported_count INTEGER NOT NULL,
  updated_count INTEGER NOT NULL,
  error_count INTEGER NOT NULL,
  errors TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS notification_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  created_at TEXT NOT NULL
);
"""


SEED_EVENTS = [
    {
        "title": "Dune: Part Two",
        "cat": "cinema",
        "loc": "IMAX Kanyon",
        "dist": 1.5,
        "days": 0,
        "hour": 20,
        "minute": 30,
        "description": "Paul Atreides unites with Chani and the Fremen while seeking revenge.",
        "details": "Directed by Denis Villeneuve. Runtime: 166 minutes.",
        "poster": "https://images.unsplash.com/photo-1440404653325-ab127d49abc1?w=600&h=320&fit=crop",
        "source": "TMDB",
        "icon": "🎬",
        "tickets": [{"site": "Biletinial", "url": "https://www.biletinial.com", "price": "180-320 TL"}],
    },
    {
        "title": "Coldplay: Music of the Spheres",
        "cat": "concerts",
        "loc": "Atatürk Stadium",
        "dist": 4.2,
        "days": 17,
        "hour": 20,
        "minute": 0,
        "description": "Coldplay brings their Music of the Spheres World Tour to Istanbul.",
        "details": "Doors open 18:00. Main show 20:30.",
        "poster": "https://images.unsplash.com/photo-1470229722913-7c0e2dbbafd3?w=600&h=320&fit=crop",
        "source": "Ticketmaster",
        "icon": "🎸",
        "tickets": [{"site": "Passo", "url": "https://www.passo.com.tr", "price": "700-2500 TL"}],
    },
    {
        "title": "Galatasaray vs Fenerbahçe",
        "cat": "sports",
        "loc": "Rams Park",
        "dist": 3.5,
        "days": 9,
        "hour": 20,
        "minute": 0,
        "description": "The biggest derby in Turkish football.",
        "details": "Turnstiles open 18:00. ID required for all ticket holders.",
        "poster": "https://images.unsplash.com/photo-1431324155629-1a6deb1dec8d?w=600&h=320&fit=crop",
        "source": "API-Sports",
        "icon": "⚽",
        "tickets": [{"site": "Passo", "url": "https://www.passo.com.tr", "price": "280-1600 TL"}],
    },
    {
        "title": "The Phantom of the Opera",
        "cat": "theater",
        "loc": "Zorlu PSM",
        "dist": 1.2,
        "days": 7,
        "hour": 20,
        "minute": 0,
        "description": "Andrew Lloyd Webber's iconic musical returns to Istanbul.",
        "details": "Running time: 2 hours 30 min. Suitable for ages 10+.",
        "poster": "https://images.unsplash.com/photo-1507676184212-d03ab07a01bf?w=600&h=320&fit=crop",
        "source": "Biletinial",
        "icon": "🎭",
        "tickets": [{"site": "Biletinial", "url": "https://www.biletinial.com", "price": "280-1200 TL"}],
    },
]


def init_db() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        migrate_db(conn)
        clean_fake_events(conn)
        archive_past_events(conn)
        merge_duplicate_events(conn)
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            conn.execute(
                """
                INSERT INTO users(username,email,password_hash,role,city,district,country,joined,created_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    "Admin",
                    "admin@eventradar.com",
                    hash_password("admin123"),
                    "admin",
                    "Istanbul",
                    "Beyoğlu",
                    "Turkey",
                    "January 2024",
                    utcnow().isoformat(),
                ),
            )
        if False and conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
            now = utcnow()
            for item in SEED_EVENTS:
                event_date = now + timedelta(days=item["days"])
                event_date = event_date.replace(hour=item["hour"], minute=item["minute"], second=0, microsecond=0)
                conn.execute(
                    """
                    INSERT INTO events(title,cat,loc,dist,date_raw,description,details,poster,source,status,icon,tickets,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        item["title"],
                        item["cat"],
                        item["loc"],
                        item["dist"],
                        event_date.isoformat(),
                        item["description"],
                        item["details"],
                        item["poster"],
                        item["source"],
                        "active",
                        item["icon"],
                        json.dumps(item["tickets"], ensure_ascii=False),
                        now.isoformat(),
                        now.isoformat(),
                    ),
                )



def migrate_db(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "email_notifications" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN email_notifications INTEGER NOT NULL DEFAULT 0")


def clean_fake_events(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM events
        WHERE source IN ('TMDB','Ticketmaster','API-Sports','Passo')
          AND id NOT IN (SELECT event_id FROM event_sources)
        """
    )


def archive_past_events(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        """
        UPDATE events
        SET status = 'archived', updated_at = ?
        WHERE status = 'active'
          AND datetime(date_raw) < datetime(?)
        """,
        (utcnow().isoformat(), utcnow().isoformat()),
    )
    return cur.rowcount


def normalize_match_text(value: str) -> str:
    normalized = value.casefold()
    normalized = "".join(ch for ch in normalized if ch.isalnum())
    return normalized


def event_match_key(title: str, cat: str, date_raw: str) -> tuple[str, str, str]:
    return (normalize_match_text(title), cat, date_raw[:10])


def merge_sources(*sources: str | None) -> str:
    merged: list[str] = []
    for source in sources:
        for part in str(source or "").split(","):
            part = part.strip()
            if part and part not in merged:
                merged.append(part)
    return ", ".join(merged) or "Manual"


def merge_tickets(existing_json: str | None, new_tickets_json: str | None) -> str:
    tickets = parse_json_field(existing_json, [])
    new_tickets = parse_json_field(new_tickets_json, [])
    if not isinstance(tickets, list):
        tickets = []
    if not isinstance(new_tickets, list):
        new_tickets = []

    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for ticket in [*tickets, *new_tickets]:
        if not isinstance(ticket, dict):
            continue
        site = str(ticket.get("site") or "Tickets").strip()
        url = str(ticket.get("url") or "").strip()
        key = (site.casefold(), url)
        if not url or key in seen:
            continue
        seen.add(key)
        merged.append(
            {
                "site": site,
                "url": url,
                "price": str(ticket.get("price") or "See source"),
            }
        )
    return json.dumps(merged, ensure_ascii=False)


def find_matching_event(conn: sqlite3.Connection, payload: dict[str, Any]) -> sqlite3.Row | None:
    wanted = event_match_key(payload["title"], payload["cat"], payload["date_raw"])
    rows = conn.execute(
        """
        SELECT * FROM events
        WHERE cat = ?
          AND date(date_raw) = date(?)
          AND status = 'active'
        """,
        (payload["cat"], payload["date_raw"]),
    ).fetchall()
    for row in rows:
        if event_match_key(row["title"], row["cat"], row["date_raw"]) == wanted:
            return row
    return None


def merge_duplicate_events(conn: sqlite3.Connection) -> int:
    rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    keepers: dict[tuple[str, str, str], sqlite3.Row] = {}
    merged_count = 0
    for row in rows:
        key = event_match_key(row["title"], row["cat"], row["date_raw"])
        keeper = keepers.get(key)
        if not keeper:
            keepers[key] = row
            continue

        keeper_id = keeper["id"]
        duplicate_id = row["id"]
        merged_tickets = merge_tickets(keeper["tickets"], row["tickets"])
        merged_source = merge_sources(keeper["source"], row["source"])
        conn.execute(
            """
            UPDATE events
            SET tickets=?, source=?, poster=COALESCE(poster, ?), updated_at=?
            WHERE id=?
            """,
            (merged_tickets, merged_source, row["poster"], utcnow().isoformat(), keeper_id),
        )
        conn.execute("UPDATE event_sources SET event_id=? WHERE event_id=?", (keeper_id, duplicate_id))
        follower_rows = conn.execute("SELECT user_id, created_at FROM follows WHERE event_id=?", (duplicate_id,)).fetchall()
        for follower in follower_rows:
            conn.execute(
                "INSERT OR IGNORE INTO follows(user_id,event_id,created_at) VALUES(?,?,?)",
                (follower["user_id"], keeper_id, follower["created_at"]),
            )
        conn.execute("DELETE FROM follows WHERE event_id=?", (duplicate_id,))
        conn.execute("DELETE FROM events WHERE id=?", (duplicate_id,))
        keepers[key] = conn.execute("SELECT * FROM events WHERE id=?", (keeper_id,)).fetchone()
        merged_count += 1
    return merged_count


def user_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "city": row["city"],
        "district": row["district"],
        "country": row["country"],
        "emailNotifications": bool(row["email_notifications"]),
        "pic": row["pic"],
        "joined": row["joined"],
    }


def event_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "cat": row["cat"],
        "loc": row["loc"],
        "dist": row["dist"],
        "dateRaw": row["date_raw"],
        "desc": row["description"],
        "details": row["details"],
        "poster": row["poster"],
        "source": row["source"],
        "status": row["status"],
        "icon": row["icon"],
        "tickets": parse_json_field(row["tickets"], []),
    }


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


class Handler(BaseHTTPRequestHandler):
    server_version = "EventRadarBackend/1.0"

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.end_headers()

    def do_GET(self) -> None:
        self.route("GET")

    def do_POST(self) -> None:
        self.route("POST")

    def do_PUT(self) -> None:
        self.route("PUT")

    def do_PATCH(self) -> None:
        self.route("PATCH")

    def do_DELETE(self) -> None:
        self.route("DELETE")

    def route(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            body = self.read_json() if method in {"POST", "PUT", "PATCH"} else {}

            if path == "/api/health" and method == "GET":
                self.ok({"ok": True, "service": "EventRadar backend"})
            elif path == "/api/auth/register" and method == "POST":
                self.register(body)
            elif path == "/api/auth/login" and method == "POST":
                self.login(body)
            elif path == "/api/auth/google" and method == "POST":
                self.google_login(body)
            elif path == "/api/auth/logout" and method == "POST":
                self.logout()
            elif path == "/api/me" and method == "GET":
                self.ok({"user": user_public(self.require_user())})
            elif path == "/api/me" and method == "PUT":
                self.update_me(body)
            elif path == "/api/me" and method == "DELETE":
                self.delete_me()
            elif path == "/api/me/followed" and method == "GET":
                self.followed_events()
            elif path == "/api/me/notifications" and method == "POST":
                self.send_followed_notifications()
            elif path == "/api/events" and method == "GET":
                self.list_events(query)
            elif path == "/api/events" and method == "POST":
                self.save_event(body)
            elif path == "/api/import-events" and method == "GET":
                self.preview_import(query)
            elif path == "/api/import-events" and method == "POST":
                self.import_external_events(query)
            elif path.startswith("/api/events/"):
                self.event_route(path, method, body)
            elif path == "/api/users" and method == "GET":
                self.list_users()
            elif path == "/api/users" and method == "POST":
                self.save_user(body)
            elif path.startswith("/api/users/"):
                self.user_route(path, method, body)
            else:
                raise ApiError(404, "Endpoint not found")
        except ApiError as exc:
            self.error(exc.status, exc.message)
        except Exception as exc:
            self.error(500, f"Server error: {exc}")

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            raise ApiError(400, "Invalid JSON body")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON body must be an object")
        return data

    def ok(self, data: Any, status: int = 200) -> None:
        payload = json_dumps(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def error(self, status: int, message: str) -> None:
        self.ok({"error": message}, status)

    def token(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            return header.split(" ", 1)[1].strip()
        return None

    def require_user(self) -> sqlite3.Row:
        token = self.token()
        if not token:
            raise ApiError(401, "Authentication required")
        with db() as conn:
            row = conn.execute(
                """
                SELECT users.* FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.token = ? AND sessions.expires_at > ?
                """,
                (token, utcnow().isoformat()),
            ).fetchone()
        if not row:
            raise ApiError(401, "Invalid or expired token")
        return row

    def require_admin(self) -> sqlite3.Row:
        user = self.require_user()
        if user["role"] != "admin":
            raise ApiError(403, "Admin access required")
        return user

    def register(self, body: dict[str, Any]) -> None:
        username = str(body.get("username", "")).strip()
        email = str(body.get("email", "")).strip().lower()
        password = str(body.get("password", ""))
        if not username or not email or not password:
            raise ApiError(400, "username, email and password are required")
        with db() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users(username,email,password_hash,role,city,district,country,pic,joined,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        username,
                        email,
                        hash_password(password),
                        "user",
                        str(body.get("city", "")).strip(),
                        str(body.get("district", "")).strip(),
                        str(body.get("country", "Turkey")).strip() or "Turkey",
                        body.get("pic"),
                        utcnow().strftime("%B %Y"),
                        utcnow().isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                raise ApiError(409, "Email already exists")
        self.login({"email": email, "password": password})

    def login(self, body: dict[str, Any]) -> None:
        email = str(body.get("email", "")).strip().lower()
        password = str(body.get("password", ""))
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                raise ApiError(401, "Invalid email or password")
            token = secrets.token_urlsafe(32)
            expires = utcnow() + timedelta(days=TOKEN_TTL_DAYS)
            conn.execute(
                "INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                (token, user["id"], expires.isoformat(), utcnow().isoformat()),
            )
        self.ok({"token": token, "user": user_public(user)})

    def google_login(self, body: dict[str, Any]) -> None:
        credential = str(body.get("credential", "")).strip()
        try:
            payload_part = credential.split(".")[1]
            payload_part += "=" * (-len(payload_part) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_part.encode("ascii")).decode("utf-8"))
        except Exception:
            raise ApiError(400, "Invalid Google credential")

        email = str(payload.get("email", "")).strip().lower()
        username = str(payload.get("name") or email.split("@", 1)[0]).strip()
        picture = payload.get("picture")
        if not email or not username:
            raise ApiError(400, "Google account did not provide a usable email")

        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user:
                conn.execute(
                    "UPDATE users SET username=?, pic=COALESCE(?, pic) WHERE id=?",
                    (username, picture, user["id"]),
                )
                user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
            else:
                conn.execute(
                    """
                    INSERT INTO users(username,email,password_hash,role,city,district,country,pic,joined,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        username,
                        email,
                        hash_password(secrets.token_urlsafe(24)),
                        "user",
                        "",
                        "",
                        "Turkey",
                        picture,
                        utcnow().strftime("%B %Y"),
                        utcnow().isoformat(),
                    ),
                )
                user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

            token = secrets.token_urlsafe(32)
            expires = utcnow() + timedelta(days=TOKEN_TTL_DAYS)
            conn.execute(
                "INSERT INTO sessions(token,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                (token, user["id"], expires.isoformat(), utcnow().isoformat()),
            )
        self.ok({"token": token, "user": user_public(user)})

    def logout(self) -> None:
        token = self.token()
        if token:
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.ok({"ok": True})

    def update_me(self, body: dict[str, Any]) -> None:
        user = self.require_user()
        fields = ["username", "email", "city", "district", "country", "pic"]
        updates = {name: body[name] for name in fields if name in body}
        if "emailNotifications" in body:
            updates["email_notifications"] = 1 if body["emailNotifications"] else 0
        if "password" in body and body["password"]:
            if not verify_password(str(body.get("currentPassword", "")), user["password_hash"]):
                raise ApiError(400, "Current password is incorrect")
            updates["password_hash"] = hash_password(str(body["password"]))
        if not updates:
            raise ApiError(400, "No update fields provided")
        with db() as conn:
            if "email" in updates:
                updates["email"] = str(updates["email"]).strip().lower()
            assignments = ", ".join(f"{key}=?" for key in updates)
            try:
                conn.execute(f"UPDATE users SET {assignments} WHERE id=?", (*updates.values(), user["id"]))
            except sqlite3.IntegrityError:
                raise ApiError(409, "Email already exists")
            updated = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        self.ok({"user": user_public(updated)})

    def delete_me(self) -> None:
        user = self.require_user()
        with db() as conn:
            if user["role"] == "admin":
                admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
                if admin_count <= 1:
                    raise ApiError(400, "Cannot delete the last admin")
            conn.execute("DELETE FROM users WHERE id=?", (user["id"],))
        self.ok({"ok": True})

    def list_events(self, query: dict[str, list[str]]) -> None:
        where: list[str] = []
        params: list[Any] = []
        if value := first(query, "status"):
            where.append("status = ?")
            params.append(value)
        if value := first(query, "cat"):
            where.append("cat = ?")
            params.append(value)
        if value := first(query, "search"):
            where.append("(LOWER(title) LIKE ? OR LOWER(loc) LIKE ? OR LOWER(description) LIKE ?)")
            term = f"%{value.lower()}%"
            params.extend([term, term, term])
        if value := first(query, "dateStart"):
            where.append("date(date_raw) >= date(?)")
            params.append(value)
        if value := first(query, "dateEnd"):
            where.append("date(date_raw) <= date(?)")
            params.append(value)
        if value := first(query, "maxDist"):
            where.append("dist <= ?")
            params.append(float(value))

        sort = first(query, "sort") or "date"
        order = "date_raw ASC"
        if sort == "distance":
            order = "dist ASC"
        elif sort == "title":
            order = "title COLLATE NOCASE ASC"

        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY {order}"
        with db() as conn:
            archive_past_events(conn)
            merge_duplicate_events(conn)
            rows = conn.execute(sql, params).fetchall()
        self.ok({"events": [event_public(row) for row in rows]})

    def preview_import(self, query: dict[str, list[str]]) -> None:
        self.require_admin()
        limit = int(first(query, "limit") or 100)
        imported, errors = fetch_all_sources(limit)
        self.ok({"events": events_as_dicts(imported), "count": len(imported), "errors": errors})

    def import_external_events(self, query: dict[str, list[str]]) -> None:
        self.require_admin()
        limit = int(first(query, "limit") or 100)
        started_at = utcnow().isoformat()
        imported, errors = fetch_all_sources(limit)
        created_count = 0
        updated_count = 0
        now = utcnow().isoformat()
        with db() as conn:
            for imported_event in imported:
                payload = imported_event.to_event_payload()
                source_row = conn.execute(
                    "SELECT event_id FROM event_sources WHERE source_name=? AND external_id=?",
                    (imported_event.source, imported_event.external_id),
                ).fetchone()
                if source_row:
                    event_id = source_row["event_id"]
                    existing_event = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
                    merged_tickets = merge_tickets(existing_event["tickets"] if existing_event else "[]", payload["tickets"])
                    merged_source = merge_sources(existing_event["source"] if existing_event else None, payload["source"])
                    conn.execute(
                        """
                        UPDATE events
                        SET title=?, cat=?, loc=?, dist=?, date_raw=?, description=?, details=?, poster=?,
                            source=?, status=?, icon=?, tickets=?, updated_at=?
                        WHERE id=?
                        """,
                        (
                            payload["title"],
                            payload["cat"],
                            payload["loc"],
                            payload["dist"],
                            payload["date_raw"],
                            payload["description"],
                            payload["details"],
                            payload["poster"],
                            merged_source,
                            payload["status"],
                            payload["icon"],
                            merged_tickets,
                            now,
                            event_id,
                        ),
                    )
                    conn.execute(
                        "UPDATE event_sources SET source_url=?, last_seen_at=? WHERE source_name=? AND external_id=?",
                        (imported_event.source_url, now, imported_event.source, imported_event.external_id),
                    )
                    updated_count += 1
                else:
                    matching_event = find_matching_event(conn, payload)
                    if matching_event:
                        event_id = matching_event["id"]
                        conn.execute(
                            """
                            UPDATE events
                            SET tickets=?, source=?, poster=COALESCE(poster, ?), updated_at=?
                            WHERE id=?
                            """,
                            (
                                merge_tickets(matching_event["tickets"], payload["tickets"]),
                                merge_sources(matching_event["source"], payload["source"]),
                                payload["poster"],
                                now,
                                event_id,
                            ),
                        )
                        updated_count += 1
                    else:
                        cur = conn.execute(
                            """
                            INSERT INTO events(title,cat,loc,dist,date_raw,description,details,poster,source,status,icon,tickets,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                payload["title"],
                                payload["cat"],
                                payload["loc"],
                                payload["dist"],
                                payload["date_raw"],
                                payload["description"],
                                payload["details"],
                                payload["poster"],
                                payload["source"],
                                payload["status"],
                                payload["icon"],
                                payload["tickets"],
                                now,
                                now,
                            ),
                        )
                        event_id = cur.lastrowid
                        created_count += 1
                    conn.execute(
                        """
                        INSERT INTO event_sources(source_name,external_id,source_url,event_id,last_seen_at)
                        VALUES(?,?,?,?,?)
                        """,
                        (imported_event.source, imported_event.external_id, imported_event.source_url, event_id, now),
                    )
            conn.execute(
                """
                INSERT INTO import_runs(started_at,finished_at,imported_count,updated_count,error_count,errors)
                VALUES(?,?,?,?,?,?)
                """,
                (started_at, utcnow().isoformat(), created_count, updated_count, len(errors), json.dumps(errors, ensure_ascii=False)),
            )
            archived_count = archive_past_events(conn)
            merged_count = merge_duplicate_events(conn)
        self.ok(
            {
                "ok": True,
                "created": created_count,
                "updated": updated_count,
                "archived": archived_count,
                "merged": merged_count,
                "errors": errors,
                "totalFetched": len(imported),
            }
        )

    def save_event(self, body: dict[str, Any], event_id: int | None = None) -> None:
        self.require_admin()
        title = str(body.get("title", "")).strip()
        cat = str(body.get("cat", "")).strip()
        loc = str(body.get("loc", "")).strip()
        date_raw = str(body.get("dateRaw") or body.get("date_raw") or "").strip()
        if not title or cat not in {"theater", "cinema", "sports", "concerts"} or not loc or not date_raw:
            raise ApiError(400, "title, valid cat, loc and dateRaw are required")

        values = {
            "title": title,
            "cat": cat,
            "loc": loc,
            "dist": float(body.get("dist", 0) or 0),
            "date_raw": date_raw,
            "description": str(body.get("desc") or body.get("description") or ""),
            "details": str(body.get("details") or ""),
            "poster": body.get("poster"),
            "source": str(body.get("source") or "Manual"),
            "status": str(body.get("status") or "active"),
            "icon": str(body.get("icon") or "📅"),
            "tickets": json.dumps(body.get("tickets") or [], ensure_ascii=False),
            "updated_at": utcnow().isoformat(),
        }
        created = event_id is None
        with db() as conn:
            if event_id is None:
                values["created_at"] = utcnow().isoformat()
                keys = ",".join(values.keys())
                placeholders = ",".join("?" for _ in values)
                cur = conn.execute(f"INSERT INTO events({keys}) VALUES({placeholders})", tuple(values.values()))
                event_id = cur.lastrowid
            else:
                if not conn.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone():
                    raise ApiError(404, "Event not found")
                assignments = ", ".join(f"{key}=?" for key in values)
                conn.execute(f"UPDATE events SET {assignments} WHERE id=?", (*values.values(), event_id))
            row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        self.ok({"event": event_public(row)}, 201 if created else 200)

    def event_route(self, path: str, method: str, body: dict[str, Any]) -> None:
        parts = path.split("/")
        try:
            event_id = int(parts[3])
        except (IndexError, ValueError):
            raise ApiError(404, "Event not found")

        if len(parts) == 4 and method == "GET":
            with db() as conn:
                row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if not row:
                raise ApiError(404, "Event not found")
            self.ok({"event": event_public(row)})
        elif len(parts) == 4 and method in {"PUT", "PATCH"}:
            self.save_event(body, event_id)
        elif len(parts) == 4 and method == "DELETE":
            self.require_admin()
            with db() as conn:
                cur = conn.execute("DELETE FROM events WHERE id=?", (event_id,))
            if cur.rowcount == 0:
                raise ApiError(404, "Event not found")
            self.ok({"ok": True})
        elif len(parts) == 5 and parts[4] == "follow" and method in {"POST", "DELETE"}:
            self.follow_event(event_id, method)
        else:
            raise ApiError(404, "Endpoint not found")

    def follow_event(self, event_id: int, method: str) -> None:
        user = self.require_user()
        followed_event = None
        with db() as conn:
            archive_past_events(conn)
            followed_event = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if not followed_event:
                raise ApiError(404, "Event not found")
            if followed_event["status"] != "active":
                raise ApiError(400, "Archived events cannot be followed")
            if method == "POST":
                conn.execute(
                    "INSERT OR IGNORE INTO follows(user_id,event_id,created_at) VALUES(?,?,?)",
                    (user["id"], event_id, utcnow().isoformat()),
                )
            else:
                conn.execute("DELETE FROM follows WHERE user_id=? AND event_id=?", (user["id"], event_id))
        notification = None
        if method == "POST" and user["email_notifications"]:
            ev = event_public(followed_event)
            notification = self.deliver_email(
                user,
                "EventRadar follow confirmation",
                f"You are now following {ev['title']} at {ev['loc']} on {ev['dateRaw']}."
            )
        self.ok({"ok": True, "notification": notification})

    def followed_events(self) -> None:
        user = self.require_user()
        with db() as conn:
            archive_past_events(conn)
            rows = conn.execute(
                """
                SELECT events.* FROM follows
                JOIN events ON events.id = follows.event_id
                WHERE follows.user_id = ? AND events.status = 'active'
                ORDER BY events.date_raw ASC
                """,
                (user["id"],),
            ).fetchall()
        self.ok({"events": [event_public(row) for row in rows]})

    def deliver_email(self, user: sqlite3.Row, subject: str, body: str) -> dict[str, Any]:
        status = "logged"
        error = None
        smtp_host = os.environ.get("EVENTRADAR_SMTP_HOST")
        smtp_port = int(os.environ.get("EVENTRADAR_SMTP_PORT", "587"))
        smtp_user = os.environ.get("EVENTRADAR_SMTP_USER")
        smtp_password = os.environ.get("EVENTRADAR_SMTP_PASSWORD")
        sender = os.environ.get("EVENTRADAR_SMTP_FROM") or smtp_user or "no-reply@eventradar.local"
        if smtp_host and smtp_user and smtp_password:
            try:
                msg = EmailMessage()
                msg["Subject"] = subject
                msg["From"] = sender
                msg["To"] = user["email"]
                msg.set_content(body)
                with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
                    smtp.starttls()
                    smtp.login(smtp_user, smtp_password)
                    smtp.send_message(msg)
                status = "sent"
            except Exception as exc:
                status = "failed"
                error = str(exc)
        with db() as conn:
            conn.execute(
                """
                INSERT INTO notification_logs(user_id,email,subject,body,status,error,created_at)
                VALUES(?,?,?,?,?,?,?)
                """,
                (user["id"], user["email"], subject, body, status, error, utcnow().isoformat()),
            )
        return {"status": status, "error": error}

    def send_followed_notifications(self) -> None:
        user = self.require_user()
        with db() as conn:
            archive_past_events(conn)
            rows = conn.execute(
                """
                SELECT events.* FROM follows
                JOIN events ON events.id = follows.event_id
                WHERE follows.user_id = ? AND events.status = 'active'
                ORDER BY events.date_raw ASC
                """,
                (user["id"],),
            ).fetchall()
        if not rows:
            raise ApiError(400, "No followed events to notify")
        lines = ["Here are the events you follow on EventRadar:", ""]
        for row in rows:
            ev = event_public(row)
            tickets = ev.get("tickets") or []
            ticket_url = tickets[0].get("url") if tickets else ""
            lines.append(f"- {ev['title']} | {ev['loc']} | {ev['dateRaw']}")
            if ticket_url:
                lines.append(f"  Tickets: {ticket_url}")
        result = self.deliver_email(user, "EventRadar followed events", "\n".join(lines))
        self.ok({"ok": result["status"] != "failed", **result})
    def list_users(self) -> None:
        self.require_admin()
        with db() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        self.ok({"users": [user_public(row) for row in rows]})

    def save_user(self, body: dict[str, Any]) -> None:
        self.require_admin()
        username = str(body.get("username", "")).strip()
        email = str(body.get("email", "")).strip().lower()
        password = str(body.get("password", ""))
        role = str(body.get("role", "user")).strip()
        if not username or not email or not password or role not in {"user", "admin"}:
            raise ApiError(400, "username, email, password and valid role are required")
        with db() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO users(username,email,password_hash,role,city,district,country,pic,joined,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        username,
                        email,
                        hash_password(password),
                        role,
                        str(body.get("city", "")).strip(),
                        str(body.get("district", "")).strip(),
                        str(body.get("country", "Turkey")).strip() or "Turkey",
                        body.get("pic"),
                        utcnow().strftime("%B %Y"),
                        utcnow().isoformat(),
                    ),
                )
                row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            except sqlite3.IntegrityError:
                raise ApiError(409, "Email already exists")
        self.ok({"user": user_public(row)}, 201)

    def user_route(self, path: str, method: str, body: dict[str, Any]) -> None:
        self.require_admin()
        email = unquote(path.split("/", 3)[3]).lower()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if not user:
                raise ApiError(404, "User not found")
            if method in {"PUT", "PATCH"}:
                updates = {
                    key: body[key]
                    for key in ["username", "email", "role", "city", "district", "country", "pic"]
                    if key in body
                }
                if "password" in body and body["password"]:
                    updates["password_hash"] = hash_password(str(body["password"]))
                if updates:
                    assignments = ", ".join(f"{key}=?" for key in updates)
                    conn.execute(f"UPDATE users SET {assignments} WHERE id=?", (*updates.values(), user["id"]))
                user = conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
                self.ok({"user": user_public(user)})
            elif method == "DELETE":
                if user["role"] == "admin":
                    admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
                    if admin_count <= 1:
                        raise ApiError(400, "Cannot delete the last admin")
                conn.execute("DELETE FROM users WHERE id=?", (user["id"],))
                self.ok({"ok": True})
            else:
                raise ApiError(405, "Method not allowed")


def first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    value = values[0].strip()
    return value or None


def main() -> None:
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"EventRadar backend running at http://{HOST}:{PORT}")
    print("Default admin: admin@eventradar.com / admin123")
    server.serve_forever()


if __name__ == "__main__":
    main()
