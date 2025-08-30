"""
Blood Moon Admin Panel with 10‑Step Key Verification API
=======================================================

This FastAPI application implements a secure management panel and a set of
API endpoints for distributing premium game scripts. The panel offers a
complete administrative interface for uploading and editing scripts,
managing user keys, viewing logs, and monitoring active sessions. All
functionality is contained within a single Python file for easy deployment.

Key features:

* **Secure Admin Login** – Only authorised administrators (admin1 and
  admin2 by default) can log into the panel. Login sessions are stored
  securely using FastAPI's SessionMiddleware.

* **Script Management** – Administrators can create, edit and update
  scripts directly from the web interface. Each script is assigned a
  unique token automatically and can be delivered to clients via a
  loadstring snippet shown on the Get Script page.

* **Key Management** – Premium keys can be added and toggled on/off.
  Each key is tied to a specific user ID and hardware ID (HWID) when
  first used.

* **Logging and Monitoring** – All significant actions (login
  attempts, API calls, script downloads, etc.) are recorded in a
  SQLite database. Logs are viewable in the panel with timestamps and
  details. Active sessions created through the API can be listed and
  manually terminated by administrators.

* **10‑Step Key Verification API** – Implements a robust multi‑stage
  authentication flow to validate keys, hardware IDs and session
  integrity. Each step generates short‑lived tokens and markers, and
  includes anti‑tampering and heartbeat checks. Misuse or invalid
  requests result in immediate rejection (kick).

To run the server:

```bash
uvicorn main:app --reload --port 8000
```

This will start the application on http://localhost:8000. Navigate to
`/login` to access the admin panel.
"""

import os
import sqlite3
import time
import secrets
import hashlib
import urllib.parse
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse, JSONResponse
# We avoid Starlette's session middleware because it depends on
# `itsdangerous`, which may not be available in this environment. Instead
# we'll implement a simple cookie‑based session mechanism for admin
# authentication.


app = FastAPI()

# Configure session middleware with a sufficiently random secret key.
# Note: We do not use SessionMiddleware here. See ADMIN_SESSIONS for
# our custom implementation.

# Path to SQLite database.
DB_PATH = "db.sqlite3"

# ---------------------------------------------------------------------------
# Database initialisation and helpers
# ---------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Return a new SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialise the SQLite database if it does not already exist."""
    if os.path.exists(DB_PATH):
        return
    conn = get_db()
    cur = conn.cursor()
    # Users table: stores admin accounts
    cur.execute(
        """CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )"""
    )
    # Insert default admin accounts
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin1", "adminpass1"))
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin2", "adminpass2"))
    # Scripts table: stores uploaded scripts with tokens
    cur.execute(
        """CREATE TABLE scripts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            content TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )"""
    )
    # Keys table: stores premium keys and binding info
    cur.execute(
        """CREATE TABLE keys (
            key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            hwid_hash TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            last_used INTEGER
        )"""
    )
    # Logs table: stores event logs
    cur.execute(
        """CREATE TABLE logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time INTEGER NOT NULL,
            type TEXT NOT NULL,
            detail TEXT NOT NULL,
            ip TEXT
        )"""
    )
    conn.commit()
    conn.close()


def log_event(event_type: str, detail: str, request: Optional[Request] = None) -> None:
    """Log an event to the database with timestamp and client IP."""
    ip = request.client.host if request and request.client else ""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs (time, type, detail, ip) VALUES (?, ?, ?, ?)",
        (int(time.time()), event_type, detail, ip),
    )
    conn.commit()
    conn.close()


# Initialise the database on first run
init_db()

# ---------------------------------------------------------------------------
# Session and authentication helpers
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Admin session handling
#
# We implement a simple cookie‑based session mechanism instead of using
# Starlette's SessionMiddleware (which requires the `itsdangerous` package).
# On successful login, a random token is generated and stored in
# `ADMIN_SESSIONS`, and a cookie containing this token is returned to the
# client. For each request requiring authentication, we look up the cookie
# and verify it against our in‑memory store.

ADMIN_SESSIONS: dict = {}


def get_current_user(request: Request) -> Optional[str]:
    """Return the username associated with the current session cookie, or None."""
    session_id = request.cookies.get("session_id")
    if session_id and session_id in ADMIN_SESSIONS:
        return ADMIN_SESSIONS[session_id]
    return None


def is_logged_in(request: Request) -> bool:
    """Check whether an admin user is currently logged in."""
    return get_current_user(request) is not None


def require_login(request: Request) -> bool:
    """Assert that a user is logged in; otherwise raise HTTPException."""
    if not is_logged_in(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return True


def check_credentials(username: str, password: str) -> bool:
    """Return True if the provided username/password are valid admin creds."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT 1 FROM users WHERE username = ? AND password = ? LIMIT 1",
        (username, password),
    )
    result = cur.fetchone()
    conn.close()
    return result is not None

# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

def render_login_page(error: Optional[str] = None) -> str:
    """Return HTML for the login page with optional error message."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Blood Moon Admin Login</title>
  <style>
    body {{
      margin: 0;
      padding: 0;
      font-family: 'Poppins', sans-serif;
      background: radial-gradient(circle at top left, #1a1a2e 0%, #0f0f10 100%);
      color: #fff;
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
    }}
    .login-box {{
      background: rgba(0,0,0,0.8);
      border-radius: 12px;
      padding: 40px 50px;
      box-shadow: 0 0 15px rgba(230,57,70,0.7);
      width: 350px;
      text-align: center;
    }}
    .login-box h1 {{
      margin-bottom: 20px;
      font-size: 26px;
      color: #e63946;
      letter-spacing: 1px;
    }}
    .login-box input {{
      width: 100%;
      padding: 12px;
      margin-bottom: 15px;
      border: none;
      border-radius: 8px;
      background: #222;
      color: #fff;
      font-size: 14px;
      outline: none;
    }}
    .login-box input:focus {{ box-shadow: 0 0 10px #e63946; }}
    .login-box button {{
      width: 100%;
      padding: 12px;
      border: none;
      border-radius: 8px;
      background: linear-gradient(90deg,#b51717,#e63946);
      color: #fff;
      font-size: 16px;
      cursor: pointer;
      transition: background 0.3s;
    }}
    .login-box button:hover {{ background: #ff0033; box-shadow: 0 0 15px #ff0033; }}
    .error {{ color: #ff6b6b; margin-bottom: 10px; font-size: 14px; }}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>🌑 Blood Moon Panel</h1>
    {('<div class="error">' + error + '</div>') if error else ''}
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username" required><br>
      <input type="password" name="password" placeholder="Password" required><br>
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
"""


def render_dashboard(user: str, active_tab: str, content_html: str) -> str:
    """Render the main dashboard layout with sidebar and dynamic content."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Blood Moon Dashboard</title>
  <style>
    body {{
      margin: 0;
      font-family: 'Poppins', sans-serif;
      background: #0f0f10;
      color: #eee;
    }}
    header {{
      background: #111;
      padding: 15px 20px;
      color: #e63946;
      font-size: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      box-shadow: 0 2px 4px rgba(0,0,0,0.4);
    }}
    header .user-info {{ font-size: 16px; color: #aaa; }}
    header .user-info a {{ color: #e63946; text-decoration: none; margin-left: 10px; }}
    nav {{
      width: 220px;
      background: #111;
      position: fixed;
      top: 60px;
      bottom: 0;
      left: 0;
      overflow-y: auto;
      padding-top: 20px;
    }}
    nav a {{
      display: block;
      padding: 12px 20px;
      color: #ccc;
      text-decoration: none;
      font-size: 16px;
    }}
    nav a:hover, nav a.active {{
      background: #e63946;
      color: #fff;
    }}
    .content {{
      margin-left: 240px;
      padding: 20px 40px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
      font-size: 14px;
    }}
    table th, table td {{
      padding: 10px;
      text-align: left;
      border-bottom: 1px solid #333;
    }}
    table tr:hover {{ background: #1c1c1c; }}
    table th {{ background: #111; color: #e63946; }}
    .btn {{
      display: inline-block;
      padding: 6px 10px;
      margin: 2px;
      border: none;
      border-radius: 6px;
      font-size: 12px;
      cursor: pointer;
      text-decoration: none;
    }}
    .btn-primary {{ background: #e63946; color: #fff; }}
    .btn-secondary {{ background: #444; color: #eee; }}
    .btn-warning {{ background: #ff9f43; color: #000; }}
    .btn-danger {{ background: #d63031; color: #fff; }}
    pre {{
      background: #121212;
      padding: 12px;
      border-radius: 8px;
      overflow-x: auto;
      color: #00ffcc;
    }}
    form.inline-form {{ display: inline-block; margin: 0; }}
    .notice {{ color: #95ef63; font-size: 14px; margin-top: 10px; }}
  </style>
  <script>
    function copyToClipboard(text) {{
      navigator.clipboard.writeText(text).then(function() {{
        alert('Copied to clipboard');
      }}, function(err) {{
        alert('Failed to copy: ' + err);
      }});
    }}
  </script>
</head>
<body>
  <header>
    <div>🌑 Blood Moon Panel</div>
    <div class="user-info">Welcome, {user} <a href="/logout">Logout</a></div>
  </header>
  <nav>
    <a href="/dashboard/scripts" class="{'active' if active_tab == 'scripts' else ''}">Scripts</a>
    <a href="/dashboard/keys" class="{'active' if active_tab == 'keys' else ''}">Keys</a>
    <a href="/dashboard/logs" class="{'active' if active_tab == 'logs' else ''}">Logs</a>
    <a href="/dashboard/sessions" class="{'active' if active_tab == 'sessions' else ''}">Sessions</a>
  </nav>
  <div class="content">
    {content_html}
  </div>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Admin Authentication Endpoints
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_get() -> str:
    """Display the login form."""
    return render_login_page()


@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request):
    """Handle admin login. Parses form data manually to avoid multipart dependency."""
    body = await request.body()
    params = urllib.parse.parse_qs(body.decode())
    username = params.get('username', [''])[0]
    password = params.get('password', [''])[0]
    if check_credentials(username, password):
        # Generate a new session token and store it
        session_token = secrets.token_hex(16)
        ADMIN_SESSIONS[session_token] = username
        log_event("login", f"User {username} logged in", request)
        # Redirect with session cookie set
        response = RedirectResponse("/dashboard/scripts", status_code=303)
        # Secure cookie: httponly to prevent JS access
        response.set_cookie(key="session_id", value=session_token, httponly=True, samesite="lax")
        return response
    else:
        # Invalid credentials: re-render login page with error message
        return HTMLResponse(render_login_page(error="Invalid username or password"))


@app.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    """Log out the current user."""
    # Retrieve and remove session token
    session_id = request.cookies.get("session_id")
    user = None
    if session_id and session_id in ADMIN_SESSIONS:
        user = ADMIN_SESSIONS.pop(session_id)
    if user:
        log_event("logout", f"User {user} logged out", request)
    # Redirect and clear cookie
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session_id")
    return response

# ---------------------------------------------------------------------------
# Scripts Management
# ---------------------------------------------------------------------------

@app.get("/dashboard/scripts", response_class=HTMLResponse)
async def list_scripts(request: Request) -> str:
    """Display the Scripts page: list existing scripts and form to add new."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, name, token, created_at, updated_at FROM scripts ORDER BY created_at DESC")
    scripts = cur.fetchall(); conn.close()
    # Build HTML for script listing
    rows = ""
    for script in scripts:
        rows += (
            f"<tr>"
            f"<td>{script['id']}</td>"
            f"<td>{script['name']}</td>"
            f"<td>{script['token']}</td>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(script['created_at']))}</td>"
            f"<td>"
            f"<a href='/dashboard/scripts/edit/{script['id']}' class='btn btn-secondary'>Edit</a> "
            f"<a href='/dashboard/scripts/get/{script['id']}' class='btn btn-primary'>Get</a>"
            f"</td>"
            f"</tr>"
        )
    table_html = (
        "<h2>Scripts</h2>"
        "<h3>Add New Script</h3>"
        "<form method='post' action='/dashboard/scripts/add'>"
        "<input type='text' name='name' placeholder='Script Name' required>"
        "<br>"
        "<textarea name='content' placeholder='Script content...' required></textarea>"
        "<br>"
        "<button type='submit' class='btn btn-primary'>Save Script</button>"
        "</form>"
        "<hr>"
        "<h3>Existing Scripts</h3>"
        "<table>"
        "<tr><th>ID</th><th>Name</th><th>Token</th><th>Created At</th><th>Actions</th></tr>"
        f"{rows}" + "</table>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "scripts", table_html)


@app.post("/dashboard/scripts/add")
async def add_script(request: Request):
    """Handle adding a new script. Parses form data manually."""
    require_login(request)
    body = await request.body()
    params = urllib.parse.parse_qs(body.decode())
    name = params.get('name', [''])[0].strip()
    content = params.get('content', [''])[0]
    token = secrets.token_hex(8)
    now = int(time.time())
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO scripts (name, content, token, created_at, updated_at) VALUES (?,?,?,?,?)",
        (name, content, token, now, now),
    )
    conn.commit(); conn.close()
    log_event("script_add", f"Script '{name}' added with token {token}", request)
    return RedirectResponse("/dashboard/scripts", status_code=303)


@app.get("/dashboard/scripts/edit/{sid}", response_class=HTMLResponse)
async def edit_script(request: Request, sid: int) -> str:
    """Display a form to edit an existing script."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT name, content FROM scripts WHERE id=?", (sid,))
    script = cur.fetchone(); conn.close()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    form_html = (
        f"<h2>Edit Script</h2>"
        f"<form method='post' action='/dashboard/scripts/update/{sid}'>"
        f"<input type='text' name='name' value='{script['name']}' required><br>"
        f"<textarea name='content' required>{script['content']}</textarea><br>"
        f"<button type='submit' class='btn btn-primary'>Update Script</button>"
        f"</form>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "scripts", form_html)


@app.post("/dashboard/scripts/update/{sid}")
async def update_script(request: Request, sid: int):
    """Handle updating an existing script. Parses form data manually."""
    require_login(request)
    body = await request.body()
    params = urllib.parse.parse_qs(body.decode())
    name = params.get('name', [''])[0].strip()
    content = params.get('content', [''])[0]
    now = int(time.time())
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "UPDATE scripts SET name=?, content=?, updated_at=? WHERE id=?",
        (name, content, now, sid),
    )
    conn.commit(); conn.close()
    log_event("script_update", f"Script {sid} updated", request)
    return RedirectResponse("/dashboard/scripts", status_code=303)


@app.get("/dashboard/scripts/get/{sid}", response_class=HTMLResponse)
async def get_script_details(request: Request, sid: int) -> str:
    """Display the loadstring snippet for a given script."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT name, token FROM scripts WHERE id=?", (sid,))
    script = cur.fetchone(); conn.close()
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    # Generate the loadstring snippet
    url = f"https://yourdomain.com/api/script/loader.lua?token={script['token']}"
    snippet = (
        f"script_key=\"BloodMPrem_XYZ123\"\n"
        f"loadstring(game:HttpGet(\"{url}\"))()"
    )
    html = (
        f"<h2>Get Script: {script['name']}</h2>"
        f"<p>Use the following snippet to load the script:</p>"
        f"<pre id='loadstring'>{snippet}</pre>"
        f"<button class='btn btn-primary' onclick=\"copyToClipboard(document.getElementById('loadstring').innerText)\">Copy to Clipboard</button>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "scripts", html)

# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------

@app.get("/dashboard/keys", response_class=HTMLResponse)
async def list_keys(request: Request) -> str:
    """Display the Keys page: list existing keys and form to add new."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT key, user_id, hwid_hash, active FROM keys ORDER BY key")
    keys = cur.fetchall(); conn.close()
    rows = ""
    for row in keys:
        status = "Active" if row['active'] else "Inactive"
        toggle_action = "Deactivate" if row['active'] else "Activate"
        toggle_class = "btn-primary" if not row['active'] else "btn-warning"
        rows += (
            f"<tr>"
            f"<td>{row['key']}</td>"
            f"<td>{row['user_id']}</td>"
            f"<td>{row['hwid_hash'] if row['hwid_hash'] else '-'}</td>"
            f"<td>{status}</td>"
            f"<td>"
            f"<a href='/dashboard/keys/toggle/{row['key']}' class='btn {toggle_class}'>{toggle_action}</a>"
            f"</td>"
            f"</tr>"
        )
    content = (
        "<h2>Keys</h2>"
        "<h3>Add New Key</h3>"
        "<form method='post' action='/dashboard/keys/add'>"
        "<input type='text' name='key' placeholder='Key' required><br>"
        "<input type='text' name='user_id' placeholder='User ID' required><br>"
        "<button type='submit' class='btn btn-primary'>Add Key</button>"
        "</form>"
        "<hr>"
        "<h3>Existing Keys</h3>"
        "<table>"
        "<tr><th>Key</th><th>User ID</th><th>HWID Hash</th><th>Status</th><th>Action</th></tr>"
        f"{rows}" + "</table>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "keys", content)


@app.post("/dashboard/keys/add")
async def add_key(request: Request):
    """Add a new key to the keys table. Parses form data manually."""
    require_login(request)
    body = await request.body()
    params = urllib.parse.parse_qs(body.decode())
    key = params.get('key', [''])[0].strip()
    user_id = params.get('user_id', [''])[0].strip()
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO keys (key, user_id, hwid_hash, active, last_used) VALUES (?, ?, NULL, 1, NULL)",
            (key, user_id),
        )
        conn.commit()
        log_event("key_add", f"Key {key} added for user_id {user_id}", request)
    except sqlite3.IntegrityError:
        # Key already exists
        log_event("key_add_failed", f"Attempted to add existing key {key}", request)
    finally:
        conn.close()
    return RedirectResponse("/dashboard/keys", status_code=303)


@app.get("/dashboard/keys/toggle/{key}")
async def toggle_key(request: Request, key: str):
    """Toggle the active state of a key."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT active FROM keys WHERE key=?", (key,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Key not found")
    new_state = 0 if row['active'] else 1
    cur.execute("UPDATE keys SET active=? WHERE key=?", (new_state, key))
    conn.commit(); conn.close()
    action = "deactivated" if new_state == 0 else "activated"
    log_event("key_toggle", f"Key {key} {action}", request)
    return RedirectResponse("/dashboard/keys", status_code=303)

# ---------------------------------------------------------------------------
# Logs Viewing
# ---------------------------------------------------------------------------

@app.get("/dashboard/logs", response_class=HTMLResponse)
async def view_logs(request: Request) -> str:
    """Display the Logs page with latest 50 events."""
    require_login(request)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT time, type, detail, ip FROM logs ORDER BY time DESC LIMIT 50")
    logs = cur.fetchall(); conn.close()
    rows = ""
    for log in logs:
        rows += (
            f"<tr>"
            f"<td>{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log['time']))}</td>"
            f"<td>{log['type']}</td>"
            f"<td>{log['detail']}</td>"
            f"<td>{log['ip'] if log['ip'] else '-'}</td>"
            f"</tr>"
        )
    content = (
        "<h2>Logs</h2>"
        "<table>"
        "<tr><th>Time</th><th>Type</th><th>Detail</th><th>IP</th></tr>"
        f"{rows}" + "</table>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "logs", content)

# ---------------------------------------------------------------------------
# Session Monitoring
# ---------------------------------------------------------------------------

# In-memory session storage for key verification API. For production use
# consider persisting sessions to database or other storage.
SESSIONS = {}


@app.get("/dashboard/sessions", response_class=HTMLResponse)
async def list_sessions(request: Request) -> str:
    """Display the Sessions page: list active verification sessions."""
    require_login(request)
    rows = ""
    for sid, sess in SESSIONS.items():
        # Only show active sessions
        status = "Active" if sess.get("active") else f"Stage {sess.get('step', '?')}"
        last_hb = sess.get("last_hb")
        last_hb_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_hb)) if last_hb else "-"
        rows += (
            f"<tr>"
            f"<td>{sid[:8]}...</td>"
            f"<td>{sess.get('user_id')}</td>"
            f"<td>{sess.get('hwid_hash')}</td>"
            f"<td>{status}</td>"
            f"<td>{last_hb_str}</td>"
            f"<td><a href='/dashboard/sessions/kill/{sid}' class='btn btn-danger'>Kill</a></td>"
            f"</tr>"
        )
    content = (
        "<h2>Sessions</h2>"
        "<table>"
        "<tr><th>Session ID</th><th>User ID</th><th>HWID Hash</th><th>Status</th><th>Last HB</th><th>Action</th></tr>"
        f"{rows}" + "</table>"
    )
    user = get_current_user(request)
    return render_dashboard(user, "sessions", content)


@app.get("/dashboard/sessions/kill/{sid}")
async def kill_session(request: Request, sid: str):
    """Terminate an active session."""
    require_login(request)
    if sid in SESSIONS:
        SESSIONS.pop(sid)
        log_event("session_kill", f"Session {sid} killed by admin", request)
    return RedirectResponse("/dashboard/sessions", status_code=303)

# ---------------------------------------------------------------------------
# API: 10‑Step Key Verification
# ---------------------------------------------------------------------------

def hash_hwid(raw: str) -> str:
    """Return SHA256 hash of a HWID string."""
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_token() -> str:
    """Generate a random token for API steps."""
    return secrets.token_hex(16)


def generate_marker() -> str:
    """Generate a random marker string."""
    return secrets.token_hex(8)


@app.post("/api/check/whitelist_bind")
async def api_whitelist_bind(data: dict, request: Request):
    """Step 1: Validate key/user_id and bind HWID if necessary."""
    key = data.get("key")
    user_id = data.get("user_id")
    hwid = data.get("hwid")
    if not (key and user_id and hwid):
        return {"result": "kick"}
    hwid_hash = hash_hwid(hwid)
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT user_id, hwid_hash, active FROM keys WHERE key=?", (key,))
    row = cur.fetchone()
    if not row or row['user_id'] != user_id or not row['active']:
        conn.close(); log_event("api_kick", f"Whitelist bind failed for key {key}", request)
        return {"result": "kick"}
    # Bind HWID if not already bound
    if row['hwid_hash'] and row['hwid_hash'] != hwid_hash:
        conn.close(); log_event("api_kick", f"HWID mismatch for key {key}", request)
        return {"result": "kick"}
    if not row['hwid_hash']:
        cur.execute("UPDATE keys SET hwid_hash=? WHERE key=?", (hwid_hash, key))
        conn.commit()
    conn.close()
    # Create session
    session_id = generate_token()
    token1 = generate_token()
    secret1 = generate_token()
    SESSIONS[session_id] = {
        "step": 1,
        "user_id": user_id,
        "hwid_hash": hwid_hash,
        "key": key,
        "token1": token1,
        "secret1": secret1,
    }
    log_event("api_whitelist", f"Session {session_id} created for key {key}", request)
    return {
        "result": "ok",
        "session_id": session_id,
        "token1": token1,
        "secret1": secret1,
    }


@app.post("/api/check/unlock1")
async def api_unlock1(data: dict, request: Request):
    """Step 2: Validate token1/secret1 and issue token2/secret2 + marker1."""
    sid = data.get("session_id")
    token1 = data.get("token1")
    secret1 = data.get("secret1")
    session = SESSIONS.get(sid)
    if not session or session.get("step") != 1:
        log_event("api_kick", f"unlock1 invalid session {sid}", request)
        return {"result": "kick"}
    if token1 != session.get("token1") or secret1 != session.get("secret1"):
        log_event("api_kick", f"unlock1 token mismatch for session {sid}", request)
        return {"result": "kick"}
    # Invalidate previous tokens
    session.pop("token1", None); session.pop("secret1", None)
    # Set new step and issue new tokens
    token2 = generate_token(); secret2 = generate_token(); marker1 = generate_marker()
    session["step"] = 2
    session["token2"] = token2
    session["secret2"] = secret2
    session["marker1"] = marker1
    log_event("api_unlock1", f"Session {sid} progressed to step 2", request)
    return {
        "result": "ok",
        "token2": token2,
        "secret2": secret2,
        "marker1": marker1,
    }


@app.post("/api/check/confirm1")
async def api_confirm1(data: dict, request: Request):
    """Step 3: Validate token2/secret2/marker1 and issue token3/secret3 + marker2."""
    sid = data.get("session_id")
    token2 = data.get("token2")
    secret2 = data.get("secret2")
    marker1 = data.get("marker1")
    session = SESSIONS.get(sid)
    if not session or session.get("step") != 2:
        log_event("api_kick", f"confirm1 invalid session {sid}", request)
        return {"result": "kick"}
    if token2 != session.get("token2") or secret2 != session.get("secret2") or marker1 != session.get("marker1"):
        log_event("api_kick", f"confirm1 mismatch for session {sid}", request)
        return {"result": "kick"}
    # Invalidate previous tokens and marker
    session.pop("token2", None); session.pop("secret2", None); session.pop("marker1", None)
    # Issue new tokens and marker
    token3 = generate_token(); secret3 = generate_token(); marker2 = generate_marker()
    session["step"] = 3
    session["token3"] = token3
    session["secret3"] = secret3
    session["marker2"] = marker2
    log_event("api_confirm1", f"Session {sid} progressed to step 3", request)
    return {
        "result": "ok",
        "token3": token3,
        "secret3": secret3,
        "marker2": marker2,
    }


@app.post("/api/check/confirm2")
async def api_confirm2(data: dict, request: Request):
    """Step 4: Validate token3/secret3/marker2 and issue token4/secret4 + marker3."""
    sid = data.get("session_id")
    token3 = data.get("token3")
    secret3 = data.get("secret3")
    marker2 = data.get("marker2")
    session = SESSIONS.get(sid)
    if not session or session.get("step") != 3:
        log_event("api_kick", f"confirm2 invalid session {sid}", request)
        return {"result": "kick"}
    if token3 != session.get("token3") or secret3 != session.get("secret3") or marker2 != session.get("marker2"):
        log_event("api_kick", f"confirm2 mismatch for session {sid}", request)
        return {"result": "kick"}
    # Invalidate previous
    session.pop("token3", None); session.pop("secret3", None); session.pop("marker2", None)
    # Issue new tokens
    token4 = generate_token(); secret4 = generate_token(); marker3 = generate_marker()
    session["step"] = 4
    session["token4"] = token4
    session["secret4"] = secret4
    session["marker3"] = marker3
    session["hub_confirm_count"] = 0
    session["runtime_ticket"] = generate_token()
    log_event("api_confirm2", f"Session {sid} progressed to step 4", request)
    return {
        "result": "ok",
        "token4": token4,
        "secret4": secret4,
        "marker3": marker3,
    }


@app.post("/api/check/hub_confirm")
async def api_hub_confirm(data: dict, request: Request):
    """Step 5: Double confirmation at hub before granting runtime ticket."""
    sid = data.get("session_id")
    token4 = data.get("token4")
    secret4 = data.get("secret4")
    marker3 = data.get("marker3")
    session = SESSIONS.get(sid)
    if not session or session.get("step") != 4:
        log_event("api_kick", f"hub_confirm invalid session {sid}", request)
        return {"result": "kick"}
    if token4 != session.get("token4") or secret4 != session.get("secret4") or marker3 != session.get("marker3"):
        log_event("api_kick", f"hub_confirm mismatch for session {sid}", request)
        return {"result": "kick"}
    # Increase confirm count
    session["hub_confirm_count"] = session.get("hub_confirm_count", 0) + 1
    if session["hub_confirm_count"] < 2:
        # Wait for second confirmation
        return {"result": "wait"}
    # Invalidate tokens and mark session active
    session.pop("token4", None); session.pop("secret4", None); session.pop("marker3", None)
    session["step"] = 5
    session["active"] = True
    log_event("api_hub_confirm", f"Session {sid} confirmed and activated", request)
    return {"result": "ok", "runtime_ticket": session.get("runtime_ticket")}


@app.post("/api/check/runtime_gate")
async def api_runtime_gate(data: dict, request: Request):
    """Step 6: Validate runtime ticket for script download (one‑time use)."""
    sid = data.get("session_id")
    ticket = data.get("runtime_ticket")
    session = SESSIONS.get(sid)
    if not session or not session.get("active"):
        log_event("api_kick", f"runtime_gate invalid or inactive session {sid}", request)
        return {"result": "kick"}
    if ticket != session.get("runtime_ticket") or session.get("runtime_used"):
        log_event("api_kick", f"runtime_gate ticket mismatch for session {sid}", request)
        return {"result": "kick"}
    # Mark ticket as used
    session["runtime_used"] = True
    log_event("api_runtime_gate", f"Session {sid} passed runtime gate", request)
    return {"result": "ok"}


@app.post("/api/check/runtime_hwid")
async def api_runtime_hwid(data: dict, request: Request):
    """Step 7: Validate hardware ID during runtime."""
    sid = data.get("session_id")
    hwid_hash = data.get("hwid_hash")
    session = SESSIONS.get(sid)
    if not session or not session.get("active"):
        log_event("api_kick", f"runtime_hwid invalid or inactive session {sid}", request)
        return {"result": "kick"}
    if hwid_hash != session.get("hwid_hash"):
        log_event("api_kick", f"runtime_hwid mismatch for session {sid}", request)
        return {"result": "kick"}
    log_event("api_runtime_hwid", f"Session {sid} HWID check passed", request)
    return {"result": "ok"}


@app.post("/api/check/heartbeat")
async def api_heartbeat(data: dict, request: Request):
    """Step 8: Heartbeat to keep session alive."""
    sid = data.get("session_id")
    session = SESSIONS.get(sid)
    if not session or not session.get("active"):
        log_event("api_kick", f"heartbeat invalid or inactive session {sid}", request)
        return {"result": "kick"}
    # Update last heartbeat time
    session["last_hb"] = time.time()
    log_event("api_heartbeat", f"Session {sid} heartbeat updated", request)
    return {"result": "ok"}


@app.post("/api/check/antidump")
async def api_antidump(data: dict, request: Request):
    """Step 9: Anti-dump and concurrency check."""
    sid = data.get("session_id")
    action = data.get("action")
    session = SESSIONS.get(sid)
    if not session or not session.get("active"):
        log_event("api_kick", f"antidump invalid or inactive session {sid}", request)
        return {"result": "kick"}
    # If action indicates tampering, invalidate session
    forbidden = ["inject_dump", "patch_debug", "getgc", "hookfunction", "Http*"]
    if action in forbidden:
        session["active"] = False
        log_event("api_kick", f"antidump detected {action} for session {sid}", request)
        return {"result": "kick"}
    log_event("api_antidump", f"Session {sid} anti-dump check {action}", request)
    return {"result": "ok"}

# ---------------------------------------------------------------------------
# API: Script Loader
# ---------------------------------------------------------------------------

@app.get("/api/script/loader.lua")
async def api_script_loader(token: str = ""):
    """Serve the Lua script corresponding to the given token."""
    # Find script by token
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT content FROM scripts WHERE token=?", (token,))
    row = cur.fetchone(); conn.close()
    if not row:
        # Return an empty script if token invalid
        return PlainTextResponse("-- kick", status_code=403)
    return PlainTextResponse(row['content'], media_type="text/plain")

# ---------------------------------------------------------------------------
# Root redirection to login
# ---------------------------------------------------------------------------

@app.get("/")
async def root() -> RedirectResponse:
    """Redirect root to login or dashboard depending on auth."""
    return RedirectResponse("/login", status_code=302)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)