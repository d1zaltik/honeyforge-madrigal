import asyncio
import time
import uuid
import datetime
import urllib.parse
import hashlib
import email.utils
import random
from typing import Dict, Any, Callable, Optional, Tuple
from honeyforge_agent.traps.base import BaseTrapService

HTML_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Corporate Management Gateway - Sign In</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 32px; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h2 { margin-top: 0; color: #38bdf8; font-size: 20px; font-weight: 600; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; margin-bottom: 6px; color: #94a3b8; }
        input { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #475569; background: #0f172a; color: #fff; border-radius: 4px; font-size: 14px; }
        input:focus { outline: none; border-color: #38bdf8; }
        button { width: 100%; padding: 10px; background: #0284c7; border: none; border-radius: 4px; color: #fff; font-weight: bold; cursor: pointer; margin-top: 8px; }
        button:hover { background: #0369a1; }
        .error-banner { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; padding: 8px 12px; border-radius: 4px; font-size: 12px; margin-bottom: 16px; }
        .notice { font-size: 11px; color: #64748b; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>Enterprise Gateway</h2>
        {error_html}
        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{csrf_token}" />
            <div class="form-group">
                <label>Username / Email</label>
                <input type="text" name="username" placeholder="user@corp.internal" required autofocus />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required />
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div class="notice">Authorized corporate personnel only. All access is logged and audited.</div>
    </div>
</body>
</html>
"""

FAVICON_ICO_BYTES = (
    b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00\x08\x00h\x05\x00\x00\x16\x00\x00\x00"
    b"(\x00\x00\x00\x10\x00\x00\x00 \x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00" * 200
)

def _apache_error_page(code: int, status_text: str, explanation: str, host: str, port: int) -> str:
    """Exact HTML error template matching Apache 2.4 on Ubuntu Linux"""
    return (
        '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
        f"<html><head>\n<title>{code} {status_text}</title>\n</head><body>\n"
        f"<h1>{status_text}</h1>\n"
        f"<p>{explanation}</p>\n"
        "<hr>\n"
        f"<address>Apache/2.4.52 (Ubuntu) Server at {host} Port {port}</address>\n"
        "</body></html>\n"
    )

class FakeWebTrap(BaseTrapService):
    """
    FR-A1, FR-A2, MASK-6: Medium-interaction Apache 2.4.52 Web Honeypot.
    - Indistinguishable from authentic Apache 2.4.52 (Ubuntu)
    - Authentic header sequence: Date, Server, Last-Modified, ETag, Accept-Ranges, Vary, Content-Length, Keep-Alive, Connection, Content-Type
    - Authentic HTML error pages (400, 403, 404, 405, 414, 500, 501)
    - Full HTTP methods (HEAD, OPTIONS, GET, POST, rejects unknown)
    - Decoy paths in /robots.txt with high-severity canary triggers
    - Probing endpoints: /favicon.ico, /server-status (403), /.git/ (404), /.env (404)
    - Realistic session cookies (PHPSESSID with HttpOnly and SameSite=Lax)
    - Login form with CSRF-tokens, authentic redirect, and jittered credential logging
    """
    def __init__(
        self,
        port: int,
        event_callback: Callable[[Dict[str, Any]], None],
        trap_id: str,
        persona: Dict[str, Any] = None
    ):
        super().__init__("WebPortal", port, event_callback)
        self.trap_id = trap_id
        self.persona = persona or {
            "hostname": f"web-srv-{trap_id[-4:]}",
            "ip": "172.28.0.20",
            "os": "Ubuntu 22.04.4 LTS"
        }
        self.server = None
        self._csrf_store: Dict[str, float] = {}

    def update_config(self, persona: dict = None):
        """Dynamic runtime update without restarting process (FR-A3)"""
        if persona is not None:
            self.persona.update(persona)

    def _build_apache_headers(
        self,
        status_line: str,
        content_type: str,
        body_len: int,
        set_cookie: Optional[str] = None,
        last_modified: Optional[str] = None,
        etag: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        connection: str = "Keep-Alive"
    ) -> str:
        """Constructs HTTP response headers in the exact canonical order used by Apache 2.4.52 on Ubuntu"""
        now_date = email.utils.formatdate(timeval=None, localtime=False, usegmt=True)
        lines = [
            f"HTTP/1.1 {status_line}",
            f"Date: {now_date}",
            "Server: Apache/2.4.52 (Ubuntu)"
        ]

        if last_modified:
            lines.append(f"Last-Modified: {last_modified}")
        if etag:
            lines.append(f'ETag: "{etag}"')
        
        lines.append("Accept-Ranges: bytes")
        lines.append("Vary: Accept-Encoding")

        if set_cookie:
            lines.append(f"Set-Cookie: {set_cookie}")

        if extra_headers:
            for hk, hv in extra_headers.items():
                lines.append(f"{hk}: {hv}")

        lines.append(f"Content-Length: {body_len}")
        if connection.lower() == "keep-alive":
            lines.append("Keep-Alive: timeout=5, max=100")
            lines.append("Connection: Keep-Alive")
        else:
            lines.append("Connection: close")

        lines.append(f"Content-Type: {content_type}")
        return "\r\n".join(lines) + "\r\n\r\n"

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "0.0.0.0"
        client_port = peer[1] if peer else 0
        host_ip = self.persona.get("ip", "172.28.0.20")

        try:
            # 1. Read request line with timeout
            try:
                request_line_bytes = await asyncio.wait_for(reader.readline(), timeout=10.0)
            except asyncio.TimeoutError:
                return

            if not request_line_bytes:
                return

            # Max URL / request line length check (Apache limit is 8190)
            if len(request_line_bytes) > 8190:
                err_body = _apache_error_page(
                    414, "Request-URI Too Large",
                    "The requested URL's length exceeds the capacity limit for this server.<br />\n",
                    host_ip, self.port
                )
                headers = self._build_apache_headers("414 Request-URI Too Large", "text/html; charset=iso-8859-1", len(err_body.encode()), connection="close")
                writer.write((headers + err_body).encode("iso-8859-1"))
                await writer.drain()
                return

            req_str = request_line_bytes.decode(errors="ignore").strip()
            parts = req_str.split()
            if len(parts) < 2:
                # 400 Bad Request
                err_body = _apache_error_page(
                    400, "Bad Request",
                    "Your browser sent a request that this server could not understand.<br />\n",
                    host_ip, self.port
                )
                headers = self._build_apache_headers("400 Bad Request", "text/html; charset=iso-8859-1", len(err_body.encode()), connection="close")
                writer.write((headers + err_body).encode("iso-8859-1"))
                await writer.drain()
                return

            method = parts[0].upper()
            raw_path = parts[1]
            http_proto = parts[2] if len(parts) > 2 else "HTTP/1.1"

            # Parse query params
            parsed_url = urllib.parse.urlparse(raw_path)
            path = parsed_url.path
            query = parsed_url.query

            # 2. Read headers
            headers = {}
            content_length = 0
            cookie_header = ""
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if not line:
                    break
                line_str = line.decode(errors="ignore").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    k_clean = k.strip().lower()
                    v_clean = v.strip()
                    headers[k_clean] = v_clean
                    if k_clean == "content-length":
                        try:
                            content_length = int(v_clean)
                        except ValueError:
                            pass
                    elif k_clean == "cookie":
                        cookie_header = v_clean

            # 3. Read body if any
            body_str = ""
            if content_length > 0 and content_length < 200000:
                body_bytes = await asyncio.wait_for(reader.read(content_length), timeout=5.0)
                body_str = body_bytes.decode(errors="ignore")

            # Session cookie handling (PHPSESSID)
            session_id = None
            if "PHPSESSID=" in cookie_header:
                for c in cookie_header.split(";"):
                    if "PHPSESSID=" in c:
                        session_id = c.split("PHPSESSID=")[1].strip()
                        break
            if not session_id or len(session_id) != 32:
                session_id = uuid.uuid4().hex

            session_cookie_hdr = f"PHPSESSID={session_id}; path=/; HttpOnly; SameSite=Lax"

            # 4. Check attack vectors and Honeytoken hits
            is_sqli = any(kw in (path + query + body_str).lower() for kw in ["' or '1'='1", "union select", "1=1", "--", "sleep(", "' or 1=1"])
            is_traversal = any(kw in (path + query) for kw in ["../", "..\\", "etc/passwd", "win.ini", "boot.ini"])
            is_canary_hit = any(path.startswith(p) for p in ["/backup/", "/.env", "/.git", "/internal/", "/api/v1/debug", "/admin/config.php"])

            # Parse credentials if POST
            creds = None
            if method == "POST" and body_str:
                parsed_body = urllib.parse.parse_qs(body_str)
                u = parsed_body.get("username", [""])[0] or parsed_body.get("user", [""])[0] or parsed_body.get("log", [""])[0]
                p = parsed_body.get("password", [""])[0] or parsed_body.get("pass", [""])[0] or parsed_body.get("pwd", [""])[0]
                if u or p:
                    creds = {"username": u, "password": p}

            # Classify event
            event_type = "web_request"
            severity = "low"
            if is_canary_hit:
                event_type = "honeytoken_triggered"
                severity = "critical"
            elif is_sqli:
                event_type = "sql_injection"
                severity = "high"
            elif is_traversal:
                event_type = "path_traversal"
                severity = "high"
            elif creds:
                event_type = "auth_attempt"
                severity = "medium"

            # Emit attack event to agent pipeline
            ev = {
                "event_id": str(uuid.uuid4()),
                "event_uid": f"web-{client_ip}-{client_port}-{time.time()}-{uuid.uuid4().hex[:6]}",
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "captured_at": time.time(),
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": "HTTP",
                "destination_port": self.port,
                "event_type": event_type,
                "severity": severity,
                "credentials": creds,
                "http_data": {
                    "method": method,
                    "path": raw_path,
                    "headers": {k: v for k, v in list(headers.items())[:8]},
                    "body": body_str[:500]
                },
                "payload_raw": f"{method} {raw_path} | Body: {body_str[:120]}",
                "is_ioc": severity in ["medium", "high", "critical"]
            }
            self.event_callback(ev)

            # 5. Handle HTTP Methods and Endpoints
            # 5.1 OPTIONS
            if method == "OPTIONS":
                resp_headers = self._build_apache_headers(
                    "200 OK", "text/html; charset=UTF-8", 0,
                    extra_headers={"Allow": "GET,HEAD,POST,OPTIONS"}
                )
                writer.write(resp_headers.encode())
                await writer.drain()
                return

            # 5.2 Method Not Allowed check
            if method not in ["GET", "HEAD", "POST"]:
                err_body = _apache_error_page(
                    405, "Method Not Allowed",
                    f"The requested method {method} is not allowed for this URL.",
                    host_ip, self.port
                )
                resp_headers = self._build_apache_headers(
                    "405 Method Not Allowed", "text/html; charset=iso-8859-1", len(err_body.encode()),
                    extra_headers={"Allow": "GET,HEAD,POST,OPTIONS"}
                )
                writer.write((resp_headers + (err_body if method != "HEAD" else "")).encode("iso-8859-1"))
                await writer.drain()
                return

            # 5.3 /server-status (Authentic Apache 403 Forbidden)
            if path == "/server-status":
                err_body = _apache_error_page(
                    403, "Forbidden",
                    "You don't have permission to access this resource.",
                    host_ip, self.port
                )
                resp_headers = self._build_apache_headers(
                    "403 Forbidden", "text/html; charset=iso-8859-1", len(err_body.encode())
                )
                writer.write((resp_headers + (err_body if method != "HEAD" else "")).encode("iso-8859-1"))
                await writer.drain()
                return

            # 5.4 /favicon.ico
            if path == "/favicon.ico":
                resp_headers = self._build_apache_headers(
                    "200 OK", "image/x-icon", len(FAVICON_ICO_BYTES),
                    extra_headers={"Cache-Control": "max-age=604800, public"}
                )
                writer.write(resp_headers.encode() + (FAVICON_ICO_BYTES if method != "HEAD" else b""))
                await writer.drain()
                return

            # 5.5 /robots.txt
            if path == "/robots.txt":
                robots_txt = (
                    "User-agent: *\n"
                    "Disallow: /server-status\n"
                    "Disallow: /admin/\n"
                    "Disallow: /backup/\n"
                    "Disallow: /internal/\n"
                    "Disallow: /api/v1/debug\n"
                    "Disallow: /.git/\n"
                    "Disallow: /.env\n"
                )
                resp_headers = self._build_apache_headers(
                    "200 OK", "text/plain; charset=UTF-8", len(robots_txt.encode()),
                    last_modified="Mon, 10 Oct 2026 12:00:00 GMT",
                    etag="29a1-6235471a28a00"
                )
                writer.write((resp_headers + (robots_txt if method != "HEAD" else "")).encode("utf-8"))
                await writer.drain()
                return

            # 5.6 Honeytoken paths: /.env, /.git/, /backup/db_export.sql
            if path in ["/.env", "/.env.production"]:
                env_content = (
                    "APP_ENV=production\n"
                    "APP_DEBUG=false\n"
                    "APP_KEY=base64:7KqR4m1P0zX9uY8vW2eA3bC5dE7fG9hI1jK3lM5nO7p=\n"
                    "DB_CONNECTION=mysql\n"
                    "DB_HOST=127.0.0.1\n"
                    "DB_PORT=3306\n"
                    "DB_DATABASE=corp_portal\n"
                    "DB_USERNAME=portal_admin\n"
                    "DB_PASSWORD=SecretProdPass2026!\n"
                    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                )
                resp_headers = self._build_apache_headers(
                    "200 OK", "text/plain; charset=UTF-8", len(env_content.encode()),
                    set_cookie=session_cookie_hdr
                )
                writer.write((resp_headers + (env_content if method != "HEAD" else "")).encode("utf-8"))
                await writer.drain()
                return

            if path in ["/backup/db_export.sql", "/backup/database.sql"]:
                sql_content = (
                    "-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)\n"
                    "-- Host: localhost    Database: corp_portal\n"
                    "CREATE TABLE `users` (\n"
                    "  `id` int NOT NULL AUTO_INCREMENT,\n"
                    "  `username` varchar(64) NOT NULL,\n"
                    "  `password_hash` varchar(128) NOT NULL,\n"
                    "  `email` varchar(128) NOT NULL,\n"
                    "  PRIMARY KEY (`id`)\n"
                    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
                    "INSERT INTO `users` VALUES (1,'admin','$y$j9T$w81.m7b9Wk3xL0p5A$H8x2K4v7N1z9Q5t3W6r8Y2u4P7m9S1j3L5k7N9b2V4c','admin@corp.internal');\n"
                )
                resp_headers = self._build_apache_headers(
                    "200 OK", "application/sql", len(sql_content.encode()),
                    set_cookie=session_cookie_hdr
                )
                writer.write((resp_headers + (sql_content if method != "HEAD" else "")).encode("utf-8"))
                await writer.drain()
                return

            if path.startswith("/.git"):
                # Apache standard 404 for git directory
                err_body = _apache_error_page(
                    404, "Not Found",
                    f"The requested URL {raw_path} was not found on this server.",
                    host_ip, self.port
                )
                resp_headers = self._build_apache_headers(
                    "404 Not Found", "text/html; charset=iso-8859-1", len(err_body.encode())
                )
                writer.write((resp_headers + (err_body if method != "HEAD" else "")).encode("iso-8859-1"))
                await writer.drain()
                return

            # 5.7 POST /login handler
            if method == "POST" and path in ["/login", "/", "/index.php"]:
                # Realistic authentication delay (0.5s - 1.2s)
                await asyncio.sleep(random.uniform(0.45, 0.95))

                # Return 302 Redirect or 200 with error
                redirect_loc = "/?login_error=1"
                resp_headers = self._build_apache_headers(
                    "302 Found", "text/html; charset=UTF-8", 0,
                    set_cookie=session_cookie_hdr,
                    extra_headers={"Location": redirect_loc}
                )
                writer.write(resp_headers.encode("utf-8"))
                await writer.drain()
                return

            # 5.8 GET Portal Login Page
            if path in ["/", "/login", "/index.html", "/index.php", "/portal"]:
                csrf_token = hashlib.sha256(f"{session_id}-csrf-secret".encode()).hexdigest()[:32]
                self._csrf_store[csrf_token] = time.time()

                error_banner_html = ""
                if "login_error=" in query or "error=" in query:
                    error_banner_html = '<div class="error-banner">Invalid username or password. Access attempt has been recorded.</div>'

                rendered_html = (
                    HTML_LOGIN_PAGE
                    .replace("{csrf_token}", csrf_token)
                    .replace("{error_html}", error_banner_html)
                )
                rendered_bytes = rendered_html.encode("utf-8")
                resp_headers = self._build_apache_headers(
                    "200 OK", "text/html; charset=UTF-8", len(rendered_bytes),
                    set_cookie=session_cookie_hdr,
                    last_modified="Mon, 10 Oct 2026 14:00:00 GMT",
                    etag="184c-6235471a28a20"
                )
                writer.write(resp_headers.encode("utf-8") + (rendered_bytes if method != "HEAD" else b""))
                await writer.drain()
                return

            # 5.9 Default Apache 404 Not Found
            err_body = _apache_error_page(
                404, "Not Found",
                f"The requested URL {raw_path} was not found on this server.",
                host_ip, self.port
            )
            resp_headers = self._build_apache_headers(
                "404 Not Found", "text/html; charset=iso-8859-1", len(err_body.encode())
            )
            writer.write((resp_headers + (err_body if method != "HEAD" else "")).encode("iso-8859-1"))
            await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.is_running = True
        self.server = await asyncio.start_server(self._handle_http, "0.0.0.0", self.port)

    async def stop(self):
        self.is_running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
