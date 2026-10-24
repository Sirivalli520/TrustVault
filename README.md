# TrustVault — Secure Document Sharing with a Real Audit Trail

A Flask + SQLite prototype for the Snovasys Fresher Hiring Challenge 2026. It implements role-based login, document-level access grants, uploads, search, audit logging, and a restricted admin dashboard.

> **Honest status:** This is a runnable educational prototype, not a production-certified document vault. Review `THREATS.md` and `WHAT_IS_DONE.md` before deployment. Do not upload real confidential files.

## Requirements covered

| # | Requirement | Implementation |
|---|---|---|
| 1 | Authentication and three roles | Login/signup; owner and viewer self-registration; admin is provisioned from environment variables |
| 2 | Upload, organize, search, manage | Upload, categories, metadata edit, delete, search by name/owner/category/date |
| 3 | Per-document read/edit permissions | Explicit named-user grants stored by document ID; edit permission controls metadata editing |
| 4 | Grant and revoke | Owner-only grant/revoke form |
| 5 | Deny ungranted access | Server-side authorization on detail, download, edit, delete, and permission endpoints |
| 6 | Audit trail | Upload, download, metadata edit, delete, permission grant/revoke |
| 7 | Search by name, owner, category, date | Search filters in document list |
| 8 | Validate uploads | Extension allowlist, safe filename handling, size limit, reject empty file |
| 9 | Administrative view | Admin-only user and audit dashboard |
| 10 | Automated isolation tests | Pytest tests for isolation, permissions, invalid roles/uploads, audit events, and admin route |

## Run locally

Python 3.10+ recommended.

### 1. Create a virtual environment

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure a strong secret and admin account

Set environment variables before first run. Use your own strong values; do not commit them.

**macOS/Linux**
```bash
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TRUSTVAULT_ADMIN_USERNAME="vaultadmin"
export TRUSTVAULT_ADMIN_PASSWORD="use-a-unique-password-at-least-14-chars"
python app.py
```

**Windows PowerShell**
```powershell
$env:FLASK_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:TRUSTVAULT_ADMIN_USERNAME = "vaultadmin"
$env:TRUSTVAULT_ADMIN_PASSWORD = "use-a-unique-password-at-least-14-chars"
python app.py
```

Open `http://127.0.0.1:5000`. Admin is created only on first database initialization if both environment variables are set and the password is at least 14 characters. The application never ships a known default admin password.

### 3. Run tests

```bash
pip install pytest
python -m pytest -q
```

### Optional configuration

- `DATABASE_PATH`: database file path; defaults to `instance/trustvault.sqlite3`.
- `UPLOAD_FOLDER`: storage directory; defaults to `instance/uploads`.
- `MAX_CONTENT_LENGTH`: request upload limit in bytes; default 10 MiB.

## Demo walkthrough (3–5 minutes)

1. Create an owner account (`alice`) and upload `sample.txt`.
2. Create a viewer account (`bob`) in a separate browser/private window.
3. As Alice, open the document and grant Bob read-only access.
4. As Bob, verify the document appears and downloads; try the edit URL and confirm it is denied.
5. As Alice, revoke Bob's grant. Verify Bob can no longer open or download the document.
6. Sign in as the provisioned admin and show the audit dashboard.
7. Run tests and show the test output.

## Architecture

- `app.py`: Flask routes, authorization, SQLite schema, upload validation, audit events.
- `templates/`: server-rendered UI with escaped Jinja templates.
- `tests/`: authorization and feature tests.
- `THREATS.md`: security assumptions and risks.
- `PROMPTS.md`: example AI-assisted development log. Replace/add entries to match the prompts you actually used.
- `WHAT_IS_DONE.md`: explicit completed and unfinished items.

## Security notes

- Passwords are hashed with Werkzeug's password hashing helpers.
- SQL statements use placeholders for user-supplied values.
- Stored filenames are opaque random names; original filenames are display metadata only.
- Authorization is checked server-side per document.
- Uploaded file types are extension-allowlisted, but **extension validation is not malware scanning or MIME/content verification**.
- Audit records are append-oriented in the UI, but a database administrator can modify SQLite directly; this is not tamper-proof logging.
- CSRF protection is not yet implemented. Add Flask-WTF/CSRFProtect before deployment.
- Session cookies are HttpOnly and SameSite=Lax. `SESSION_COOKIE_SECURE` must be enabled behind HTTPS in production.
- Development server is not suitable for public deployment. Use a production WSGI server, HTTPS, backups, monitoring, and access-controlled storage.

## License

For challenge/demo use. Add a license if you plan to distribute it.
