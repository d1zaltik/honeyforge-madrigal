import asyncio
import uuid
import datetime
import urllib.parse
from typing import Dict, Any, Callable
from honeyforge_agent.traps.base import BaseTrapService

HTML_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Gateway Portal - Sign In</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .login-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 32px; width: 360px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
        h2 { margin-top: 0; color: #38bdf8; font-size: 20px; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-size: 13px; margin-bottom: 6px; color: #94a3b8; }
        input { width: 100%; box-sizing: border-box; padding: 10px; border: 1px solid #475569; background: #0f172a; color: #fff; border-radius: 4px; font-size: 14px; }
        button { width: 100%; padding: 10px; background: #0284c7; border: none; border-radius: 4px; color: #fff; font-weight: bold; cursor: pointer; margin-top: 8px; }
        button:hover { background: #0369a1; }
        .notice { font-size: 11px; color: #64748b; margin-top: 16px; text-align: center; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>Corporate SSO Access</h2>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username / Email</label>
                <input type="text" name="username" placeholder="user@corp.internal" required />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required />
            </div>
            <button type="submit">Authenticate</button>
        </form>
        <div class="notice">Authorized system personnel only. All actions monitored.</div>
    </div>
</body>
</html>
"""

class FakeWebTrap(BaseTrapService):
    """
    FR-A1, FR-A2 (Must): Medium-interaction Fake Web Portal.
    Emulates admin login interface, traps credential attempts and web application exploits.
    """
    def __init__(self, port: int, event_callback: Callable[[Dict[str, Any]], None], trap_id: str):
        super().__init__("FakeWebPortal", port, event_callback)
        self.trap_id = trap_id
        self.server = None

    async def _handle_http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info('peername')
        client_ip = peer[0] if peer else "0.0.0.0"
        client_port = peer[1] if peer else 0

        try:
            request_line = await reader.readline()
            if not request_line:
                return

            req_str = request_line.decode(errors="ignore").strip()
            parts = req_str.split()
            method = parts[0] if len(parts) > 0 else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            # Read headers
            headers = {}
            content_length = 0
            while True:
                line = await reader.readline()
                line_str = line.decode(errors="ignore").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                    if k.strip().lower() == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            pass

            body_str = ""
            if content_length > 0 and content_length < 100000:
                body_bytes = await reader.read(content_length)
                body_str = body_bytes.decode(errors="ignore")

            # Check attack vectors
            is_sqli = any(kw in (path + body_str).lower() for kw in ["' or '1'='1", "union select", "1=1", "--", "sleep("])
            is_traversal = any(kw in path for kw in ["../", "..\\", "etc/passwd", "win.ini"])
            
            # Parse credentials if POST
            creds = None
            if method == "POST" and body_str:
                parsed = urllib.parse.parse_qs(body_str)
                user = parsed.get("username", [""])[0] or parsed.get("user", [""])[0] or parsed.get("log", [""])[0]
                pwd = parsed.get("password", [""])[0] or parsed.get("pass", [""])[0] or parsed.get("pwd", [""])[0]
                if user or pwd:
                    creds = {"username": user, "password": pwd}

            event_type = "web_request"
            severity = "low"
            if is_sqli:
                event_type = "sql_injection"
                severity = "high"
            elif is_traversal:
                event_type = "path_traversal"
                severity = "high"
            elif creds:
                event_type = "auth_attempt"
                severity = "medium"

            # Emit attack event
            event = {
                "event_id": str(uuid.uuid4()),
                "trap_id": self.trap_id,
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "source_ip": client_ip,
                "source_port": client_port,
                "protocol": "HTTP",
                "destination_port": self.port,
                "event_type": event_type,
                "severity": severity,
                "credentials": creds,
                "http_data": {
                    "method": method,
                    "path": path,
                    "headers": {k: v for k, v in list(headers.items())[:8]},
                    "body": body_str[:500]
                },
                "payload_raw": f"{method} {path} | Body: {body_str[:120]}",
                "is_ioc": severity in ["medium", "high", "critical"]
            }
            self.event_callback(event)

            # Response
            if method == "POST":
                # Simulated failed login
                resp_body = "<html><body><h3>Authentication Failed</h3><p>Invalid credentials or security token expired.</p><a href='/'>Retry</a></body></html>"
                resp = (
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "Server: Apache/2.4.52 (Ubuntu)\r\n"
                    "Content-Type: text/html\r\n"
                    f"Content-Length: {len(resp_body)}\r\n"
                    "Connection: close\r\n\r\n" + resp_body
                )
            else:
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.52 (Ubuntu)\r\n"
                    "Content-Type: text/html; charset=UTF-8\r\n"
                    f"Content-Length: {len(HTML_LOGIN_PAGE.encode())}\r\n"
                    "Connection: close\r\n\r\n" + HTML_LOGIN_PAGE
                )
            writer.write(resp.encode())
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
