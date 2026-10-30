"""
SecureShare - a minimal file-sharing web app used as the lab target for
CYC386 Midterm Sprint (Fall 2026).

!!! VULNERABLE BASELINE - LAB USE ONLY !!!
This revision intentionally contains four web vulnerability classes
required by the assignment brief:
    1. IDOR          -> view_file()      (no ownership check)
    2. CSRF          -> delete_file()    (no anti-CSRF token)
    3. Clickjacking   -> no X-Frame-Options / CSP on any response
    4. Command Injection -> export_file() (shell=True with user input)

Each is fixed on its own fix/* branch later in the git history; see
docs/SECURITY_IMPLEMENTATION.md for before/after evidence of every fix.
Never deploy this revision outside an isolated lab environment.
"""
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from flask import (
    Flask, g, request, redirect, url_for, render_template,
    session, flash, send_from_directory, abort
)
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
EXPORT_DIR = BASE_DIR / "exports"
DB_PATH = BASE_DIR / "secureshare.db"
# FIX (Buffer Overflow, CWE-121): the app now calls the remediated
# native/parser_fixed binary (bounds-checked snprintf, built with
# -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie) instead of the
# vulnerable native/parser. See native/parser.c vs native/parser_fixed.c
# and docs/SECURITY_IMPLEMENTATION.md for the before/after evidence.
NATIVE_PARSER = BASE_DIR.parent / "native" / "parser_fixed"
TITLE_MAX_LEN = 63  # must match TITLE_MAX-1 in native/parser_fixed.c

UPLOAD_DIR.mkdir(exist_ok=True)
EXPORT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "lab-only-dev-secret-change-me"  # dev fallback only
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

# --------------------------------------------------------------------------
# FIX (CSRF, CWE-352): synchronizer-token CSRF protection on every
# state-changing (POST/PUT/PATCH/DELETE) request, plus SameSite cookies
# as defense-in-depth. See fix/csrf branch / docs/SECURITY_IMPLEMENTATION.md.
# --------------------------------------------------------------------------
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
csrf = CSRFProtect(app)


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )
    db.commit()
    db.close()


# --------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return row


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# FIX (IDOR, CWE-639): centralized object-level authorization.
#
# Every route that touches a `files` row MUST go through this helper
# instead of querying `files` directly by id. It enforces that the
# requesting user owns the resource before it is ever returned, so
# authorization can never be accidentally skipped on a new endpoint.
# Security requirement satisfied: "object-level authorization on every
# resource access" (docs/PNE_Report.md).
# --------------------------------------------------------------------------
def get_owned_file_or_403(db, file_id, user):
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if file_row["owner_id"] != user["id"]:
        app.logger.warning(
            "IDOR attempt blocked: user_id=%s tried to access file_id=%s "
            "owned by user_id=%s", user["id"], file_id, file_row["owner_id"],
        )
        abort(403)
    return file_row


# --------------------------------------------------------------------------
# Routes - auth
# --------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Username already taken.")
            return render_template("register.html")
        flash("Account created. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------------------
# Routes - dashboard / upload
# --------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    user = current_user()
    files = get_db().execute(
        "SELECT * FROM files WHERE owner_id = ? ORDER BY id DESC", (user["id"],)
    ).fetchall()
    return render_template("dashboard.html", user=user, files=files)


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    user = current_user()
    if request.method == "POST":
        f = request.files.get("file")
        title = request.form.get("title", "").strip() or "untitled"
        if not f or f.filename == "":
            flash("Choose a file first.")
            return render_template("upload.html")

        # FIX (defense-in-depth for CWE-121, see fix/buffer-overflow):
        # reject an over-long title at the web layer too, in addition to
        # native/parser_fixed.c's own bounds check, so bad input is
        # rejected as early as possible and the native helper is never
        # even invoked with it.
        if len(title.encode("utf-8")) > TITLE_MAX_LEN:
            flash(f"Title is too long (max {TITLE_MAX_LEN} characters).")
            return render_template("upload.html")

        safe_name = secure_filename(f.filename)
        stored_name = f"{user['id']}_{os.urandom(4).hex()}_{safe_name}"
        f.save(UPLOAD_DIR / stored_name)

        db = get_db()
        db.execute(
            "INSERT INTO files (owner_id, display_name, stored_name, title) "
            "VALUES (?, ?, ?, ?)",
            (user["id"], safe_name, stored_name, title),
        )
        db.commit()
        flash("File uploaded.")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")


# --------------------------------------------------------------------------
# FIXED (was VULNERABILITY 1: IDOR / CWE-639) - see fix/idor branch.
# Every lookup now goes through get_owned_file_or_403(), which returns
# 403 Forbidden for any file the caller does not own, instead of
# returning the first row that matches the id regardless of ownership.
# --------------------------------------------------------------------------
@app.route("/file/<int:file_id>")
@login_required
def view_file(file_id):
    db = get_db()
    user = current_user()
    file_row = get_owned_file_or_403(db, file_id, user)

    # Native helper call used to render the file's "title" field.
    # (This is also the Buffer Overflow attack surface - see native/parser.c)
    title_out = ""
    try:
        result = subprocess.run(
            [str(NATIVE_PARSER), file_row["title"]],
            capture_output=True, text=True, timeout=3,
        )
        title_out = result.stdout
    except Exception as exc:  # noqa: BLE001 - lab demo, broad is fine here
        title_out = f"(parser error: {exc})"

    return render_template("file_view.html", file=file_row, parser_output=title_out)


@app.route("/file/<int:file_id>/download")
@login_required
def download_file(file_id):
    db = get_db()
    user = current_user()
    file_row = get_owned_file_or_403(db, file_id, user)
    return send_from_directory(UPLOAD_DIR, file_row["stored_name"])


# --------------------------------------------------------------------------
# VULNERABILITY 2: CSRF (no anti-CSRF token on a state-changing POST)
# --------------------------------------------------------------------------
@app.route("/file/<int:file_id>/delete", methods=["POST"])
@login_required
def delete_file(file_id):
    db = get_db()
    user = current_user()
    file_row = get_owned_file_or_403(db, file_id, user)
    # FIXED (was VULNERABILITY 2: CSRF / CWE-352): this POST is now
    # covered by app-wide CSRFProtect (see csrf = CSRFProtect(app) above).
    # Flask-WTF validates the hidden csrf_token field on every POST and
    # rejects the request with a 400 if it is missing or invalid, so a
    # forged cross-site form submission can no longer delete this file.
    (UPLOAD_DIR / file_row["stored_name"]).unlink(missing_ok=True)
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    return redirect(url_for("dashboard"))


# FIXED (was VULNERABILITY 3: Command Injection / CWE-78) - see
# fix/command-injection branch.
#
# Two independent layers, either of which alone would have stopped the
# original exploit:
#   1. No shell is invoked at all anymore. The file copy is done with
#      shutil.copyfile(), a pure Python/libc call - there is no command
#      string for shell metacharacters to break out of.
#   2. `export_name` is still validated against a strict allow-list
#      (letters, digits, dot, dash, underscore) before use, and rejected
#      otherwise, as defense-in-depth against path traversal etc. even
#      though it is never passed to a shell.
# --------------------------------------------------------------------------
SAFE_EXPORT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


@app.route("/file/<int:file_id>/export", methods=["POST"])
@login_required
def export_file(file_id):
    db = get_db()
    user = current_user()
    file_row = get_owned_file_or_403(db, file_id, user)

    export_name = request.form.get("export_name", "export")
    if not SAFE_EXPORT_NAME.match(export_name):
        flash("Invalid export name: use only letters, numbers, '.', '-', '_'.")
        return redirect(url_for("view_file", file_id=file_id))

    src = UPLOAD_DIR / file_row["stored_name"]
    dst = EXPORT_DIR / export_name

    # FIX: no shell, no string-built command - shutil.copyfile() calls
    # the OS copy syscalls directly, so there is nothing for shell
    # metacharacters (; | && `` $() ) to inject into.
    shutil.copyfile(src, dst)

    flash(f"Exported as {export_name}")
    return redirect(url_for("view_file", file_id=file_id))


# --------------------------------------------------------------------------
# FIX (was VULNERABILITY 4: Clickjacking) - see fix/clickjacking branch.
#
# Every response now carries X-Frame-Options: DENY and a CSP
# frame-ancestors 'none' directive (sent together for defence in depth;
# frame-ancestors is the modern replacement and is honoured by browsers
# that support CSP, X-Frame-Options covers the rest). This instructs the
# browser to refuse to render any SecureShare page inside a frame/iframe
# on any origin, which blocks the UI-redressing attack demonstrated in
# docs/SECURITY_IMPLEMENTATION.md.
# --------------------------------------------------------------------------
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    # Small extra hardening, same spirit as the mandatory header above:
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


if __name__ == "__main__":
    if not DB_PATH.exists():
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
