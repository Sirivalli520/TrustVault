import os
import re
import hmac
import hashlib
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask, abort, flash, g, redirect, render_template, request,
    send_file, session, url_for, current_app
)

ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg", "csv"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me"),
        DATABASE=os.environ.get("DATABASE_PATH", os.path.join(app.instance_path, "trustvault.sqlite3")),
        UPLOAD_FOLDER=os.environ.get("UPLOAD_FOLDER", os.path.join(app.instance_path, "uploads")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", MAX_UPLOAD_BYTES)),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # Set True behind HTTPS in production.
    )
    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    init_db(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
        return response

    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        g.user = None
        if user_id is not None:
            db = get_db()
            g.user = db.execute(
                "SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if g.user is None:
                session.clear()

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("documents"))
        return render_template("index.html")

    @app.route("/register", methods=("GET", "POST"))
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "owner")
            error = None
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
                error = "Username must be 3–32 characters (letters, numbers, dot, underscore, hyphen)."
            elif len(password) < 10:
                error = "Password must be at least 10 characters."
            elif role not in {"owner", "viewer"}:
                error = "Choose a valid account role."
            elif username.lower() == "admin":
                error = "That username is reserved."
            if error is None:
                db = get_db()
                try:
                    db.execute(
                        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                        (username, generate_password_hash(password), role, utc_now()),
                    )
                    db.commit()
                except sqlite3.IntegrityError:
                    error = "That username is already registered."
                if error is None:
                    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
                    session.clear()
                    session["user_id"] = user["id"]
                    flash("Account created. Keep your password private.", "success")
                    return redirect(url_for("documents"))
            flash(error, "error")
        return render_template("register.html")

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = get_db().execute(
                "SELECT id, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user is None or not check_password_hash(user["password_hash"], password):
                # Same message for unknown user and wrong password.
                flash("Invalid username or password.", "error")
            else:
                session.clear()
                session["user_id"] = user["id"]
                flash("Signed in successfully.", "success")
                return redirect(url_for("documents"))
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        require_user()
        session.clear()
        return redirect(url_for("index"))

    @app.route("/documents")
    def documents():
        require_user()
        db = get_db()
        term = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "").strip()[:80]
        date = request.args.get("date", "").strip()[:10]
        sql = """
            SELECT DISTINCT d.*, u.username AS owner_name,
                COALESCE(p.can_read, CASE WHEN d.owner_id = ? THEN 1 ELSE 0 END) AS readable
            FROM documents d
            JOIN users u ON u.id = d.owner_id
            LEFT JOIN permissions p ON p.document_id = d.id AND p.user_id = ?
            WHERE (d.owner_id = ? OR (p.user_id = ? AND p.can_read = 1))
        """
        params = [g.user["id"], g.user["id"], g.user["id"], g.user["id"]]
        if term:
            sql += " AND (d.filename LIKE ? OR d.description LIKE ? OR u.username LIKE ?)"
            like = f"%{term}%"
            params += [like, like, like]
        if category:
            sql += " AND d.category = ?"
            params.append(category)
        if date:
            sql += " AND substr(d.created_at, 1, 10) = ?"
            params.append(date)
        sql += " ORDER BY d.created_at DESC"
        rows = db.execute(sql, params).fetchall()
        categories = db.execute(
            "SELECT DISTINCT category FROM documents WHERE owner_id = ? ORDER BY category",
            (g.user["id"],)
        ).fetchall()
        return render_template("documents.html", documents=rows, q=term, category=category,
                               date=date, categories=categories)

    @app.route("/upload", methods=("GET", "POST"))
    def upload():
        require_user()
        if request.method == "POST":
            uploaded = request.files.get("file")
            description = request.form.get("description", "").strip()[:500]
            category = request.form.get("category", "").strip()[:80] or "General"
            error = validate_upload(uploaded)
            if error:
                flash(error, "error")
                return redirect(url_for("upload"))
            original = secure_filename(uploaded.filename)
            if not original:
                flash("The filename is invalid.", "error")
                return redirect(url_for("upload"))
            # Opaque server-side name prevents path traversal and filename collisions.
            stored = secrets.token_hex(16) + Path(original).suffix.lower()
            target = Path(current_app.config["UPLOAD_FOLDER"]) / stored
            uploaded.save(target)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            db = get_db()
            cur = db.execute(
                """INSERT INTO documents
                   (owner_id, filename, stored_name, description, category, sha256, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (g.user["id"], original, stored, description, category, digest, utc_now(), utc_now())
            )
            document_id = cur.lastrowid
            audit(db, g.user["id"], document_id, "upload", f"Uploaded {original}")
            db.commit()
            flash("Document uploaded securely.", "success")
            return redirect(url_for("document_detail", document_id=document_id))
        return render_template("upload.html")

    @app.route("/documents/<int:document_id>")
    def document_detail(document_id):
        require_user()
        doc = get_document_or_404(document_id, "read")
        db = get_db()
        grants = db.execute(
            """SELECT p.user_id, u.username, p.can_read, p.can_edit, p.granted_at
               FROM permissions p JOIN users u ON u.id = p.user_id
               WHERE p.document_id = ? ORDER BY u.username""", (document_id,)
        ).fetchall() if doc["owner_id"] == g.user["id"] or g.user["role"] == "admin" else []
        users = db.execute(
            "SELECT id, username FROM users WHERE id != ? ORDER BY username", (g.user["id"],)
        ).fetchall() if doc["owner_id"] == g.user["id"] else []
        return render_template("detail.html", doc=doc, grants=grants, users=users,
                               can_edit=can_access(document_id, "edit"))

    @app.route("/documents/<int:document_id>/download")
    def download(document_id):
        require_user()
        doc = get_document_or_404(document_id, "read")
        audit(get_db(), g.user["id"], document_id, "download", f"Downloaded {doc['filename']}")
        get_db().commit()
        path = Path(current_app.config["UPLOAD_FOLDER"]) / doc["stored_name"]
        if not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=doc["filename"], mimetype="application/octet-stream")

    @app.route("/documents/<int:document_id>/edit", methods=("GET", "POST"))
    def edit_document(document_id):
        require_user()
        doc = get_document_or_404(document_id, "edit")
        if request.method == "POST":
            filename = secure_filename(request.form.get("filename", "").strip())
            description = request.form.get("description", "").strip()[:500]
            category = request.form.get("category", "").strip()[:80] or "General"
            if not filename:
                flash("A valid filename is required.", "error")
            else:
                db = get_db()
                db.execute("UPDATE documents SET filename=?, description=?, category=?, updated_at=? WHERE id=?",
                           (filename, description, category, utc_now(), document_id))
                audit(db, g.user["id"], document_id, "edit", f"Updated metadata for {filename}")
                db.commit()
                flash("Document details updated.", "success")
                return redirect(url_for("document_detail", document_id=document_id))
        return render_template("edit.html", doc=doc)

    @app.post("/documents/<int:document_id>/delete")
    def delete_document(document_id):
        require_user()
        doc = get_document_or_404(document_id, "edit")
        db = get_db()
        # Audit before deletion; record is retained even after document metadata is removed.
        audit(db, g.user["id"], document_id, "delete", f"Deleted {doc['filename']}")
        db.execute("DELETE FROM permissions WHERE document_id = ?", (document_id,))
        db.execute("DELETE FROM documents WHERE id = ?", (document_id,))
        db.commit()
        path = Path(current_app.config["UPLOAD_FOLDER"]) / doc["stored_name"]
        try:
            path.unlink(missing_ok=True)
        except OSError:
            current_app.logger.exception("Could not remove stored document")
        flash("Document deleted.", "success")
        return redirect(url_for("documents"))

    @app.post("/documents/<int:document_id>/permissions")
    def set_permission(document_id):
        require_user()
        doc = get_document_or_404(document_id, "owner")
        user_id = request.form.get("user_id", type=int)
        action = request.form.get("action", "grant")
        db = get_db()
        target = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None or target["id"] == doc["owner_id"]:
            flash("Choose a valid user.", "error")
            return redirect(url_for("document_detail", document_id=document_id))
        if action == "revoke":
            db.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?", (document_id, user_id))
            audit(db, g.user["id"], document_id, "permission_revoke", f"Revoked access for {target['username']}")
        else:
            can_read = 1
            can_edit = 1 if request.form.get("can_edit") == "1" else 0
            db.execute("""INSERT INTO permissions(document_id,user_id,can_read,can_edit,granted_at)
                          VALUES(?,?,?,?,?)
                          ON CONFLICT(document_id,user_id) DO UPDATE SET
                          can_read=excluded.can_read, can_edit=excluded.can_edit, granted_at=excluded.granted_at""",
                       (document_id, user_id, can_read, can_edit, utc_now()))
            audit(db, g.user["id"], document_id, "permission_grant",
                  f"Granted {'read/edit' if can_edit else 'read'} access to {target['username']}")
        db.commit()
        flash("Permissions updated.", "success")
        return redirect(url_for("document_detail", document_id=document_id))

    @app.route("/admin")
    def admin_dashboard():
        require_user()
        if g.user["role"] != "admin":
            abort(403)
        logs = get_db().execute(
            """SELECT a.*, u.username, d.filename
               FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
               LEFT JOIN documents d ON d.id=a.document_id
               ORDER BY a.id DESC LIMIT 500"""
        ).fetchall()
        users = get_db().execute(
            "SELECT id, username, role, created_at FROM users ORDER BY id"
        ).fetchall()
        return render_template("admin.html", logs=logs, users=users)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to access this resource."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="The requested resource was not found."), 404

    @app.errorhandler(413)
    def too_large(_error):
        return render_template("error.html", code=413, message="Upload exceeds the configured size limit (10 MB by default)."), 413

    return app


def get_db():
    if "db" not in g:
        db = sqlite3.connect(current_app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        g.db = db
    return g.db


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    with app.app_context():
        db = sqlite3.connect(app.config["DATABASE"])
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'General',
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS permissions (
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            can_read INTEGER NOT NULL DEFAULT 1 CHECK(can_read IN (0,1)),
            can_edit INTEGER NOT NULL DEFAULT 0 CHECK(can_edit IN (0,1)),
            granted_at TEXT NOT NULL,
            PRIMARY KEY(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            document_id INTEGER,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
        CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions(user_id, document_id);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
        """)
        # A first-run admin is created only when explicitly configured. Never ship a known default password.
        admin_username = os.environ.get("TRUSTVAULT_ADMIN_USERNAME")
        admin_password = os.environ.get("TRUSTVAULT_ADMIN_PASSWORD")
        if admin_username and admin_password:
            existing = db.execute("SELECT id FROM users WHERE username=?", (admin_username,)).fetchone()
            if not existing and len(admin_password) >= 14:
                db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                           (admin_username, generate_password_hash(admin_password), "admin", utc_now()))
        db.commit()
        db.close()
    app.teardown_appcontext(close_db)


def require_user():
    if getattr(g, "user", None) is None:
        abort(403)


def can_access(document_id, action):
    if getattr(g, "user", None) is None:
        return False
    db = get_db()
    doc = db.execute("SELECT owner_id FROM documents WHERE id=?", (document_id,)).fetchone()
    if doc is None:
        return False
    if g.user["role"] == "admin" or doc["owner_id"] == g.user["id"]:
        return True
    grant = db.execute("SELECT can_read, can_edit FROM permissions WHERE document_id=? AND user_id=?",
                       (document_id, g.user["id"])).fetchone()
    if not grant:
        return False
    if action == "read":
        return bool(grant["can_read"])
    if action == "edit":
        return bool(grant["can_edit"])
    if action == "owner":
        return False
    return False


def get_document_or_404(document_id, action):
    doc = get_db().execute(
        "SELECT d.*, u.username AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?",
        (document_id,)
    ).fetchone()
    if doc is None:
        abort(404)
    # Explicit owner-only permission management; admin can oversee but cannot change owner grants through this endpoint.
    if action == "owner":
        if doc["owner_id"] != g.user["id"]:
            abort(403)
    elif not can_access(document_id, action):
        abort(403)
    return doc


def audit(db, actor_id, document_id, action, details):
    db.execute("INSERT INTO audit_logs(actor_id, document_id, action, details, created_at) VALUES(?,?,?,?,?)",
               (actor_id, document_id, action, details[:500], utc_now()))


def validate_upload(uploaded):
    if uploaded is None or not uploaded.filename:
        return "Choose a file to upload."
    filename = secure_filename(uploaded.filename)
    if not filename or "." not in filename:
        return "File must have an allowed extension."
    ext = filename.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return "Unsupported file type. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS))
    # Stream content to avoid reading an unbounded upload into memory.
    uploaded.stream.seek(0, os.SEEK_END)
    size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    if size > current_app.config["MAX_CONTENT_LENGTH"]:
        return "File is too large."
    if size == 0:
        return "Empty files are not accepted."
    return None


app = create_app()

if __name__ == "__main__":
    # For local development only. Use a production WSGI server and HTTPS for deployment.
    app.run(debug=False)
