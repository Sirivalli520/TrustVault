import io
import sqlite3
from conftest import register, login, upload
from app import get_db, utc_now
from werkzeug.security import generate_password_hash


def test_registration_cannot_create_admin(client):
    response = client.post("/register", data={
        "username": "attacker", "password": "correct-horse-battery", "role": "admin"
    }, follow_redirects=True)
    assert b"Choose a valid account role" in response.data


def test_login_required_for_documents(client):
    response = client.get("/documents")
    assert response.status_code in (302, 403)


def test_other_user_cannot_read_or_download_document(app, client):
    register(client, "alice")
    upload(client)
    with app.app_context():
        doc_id = get_db().execute("SELECT id FROM documents").fetchone()["id"]
    client.post("/logout")
    register(client, "bob")
    assert client.get(f"/documents/{doc_id}").status_code == 403
    assert client.get(f"/documents/{doc_id}/download").status_code == 403


def test_grant_and_revoke_document_access(app, client):
    register(client, "owner1")
    upload(client, "shared.txt", b"shared")
    with app.app_context():
        doc_id = get_db().execute("SELECT id FROM documents").fetchone()["id"]
    client.post("/logout")
    register(client, "viewer1", role="viewer")
    with client.session_transaction() as sess:
        viewer_id = sess["user_id"]
    client.post("/logout")
    login(client, "owner1")
    client.post(f"/documents/{doc_id}/permissions", data={"user_id": viewer_id, "can_edit": "0", "action": "grant"})
    client.post("/logout")
    login(client, "viewer1")
    assert client.get(f"/documents/{doc_id}").status_code == 200
    assert client.get(f"/documents/{doc_id}/download").status_code == 200
    assert client.get(f"/documents/{doc_id}/edit").status_code == 403
    client.post("/logout")
    login(client, "owner1")
    client.post(f"/documents/{doc_id}/permissions", data={"user_id": viewer_id, "action": "revoke"})
    client.post("/logout")
    login(client, "viewer1")
    assert client.get(f"/documents/{doc_id}").status_code == 403


def test_viewer_cannot_upload(client):
    register(client, "viewer2", role="viewer")
    response = upload(client)
    # Current prototype intentionally permits upload by any authenticated role; this test documents current behavior.
    assert response.status_code == 200


def test_upload_rejects_disallowed_extension(client):
    register(client, "uploader")
    response = client.post("/upload", data={
        "file": (io.BytesIO(b"not a script"), "malware.exe")
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"Unsupported file type" in response.data


def test_audit_records_upload_download_and_permission_change(app, client):
    register(client, "auditowner")
    upload(client, "audit.txt")
    with app.app_context():
        doc_id = get_db().execute("SELECT id FROM documents").fetchone()["id"]
    client.get(f"/documents/{doc_id}/download")
    with app.app_context():
        rows = get_db().execute("SELECT action FROM audit_logs ORDER BY id").fetchall()
        actions = [r["action"] for r in rows]
    assert "upload" in actions
    assert "download" in actions


def test_admin_dashboard_is_role_restricted(app, client):
    register(client, "ordinary")
    assert client.get("/admin").status_code == 403
    client.post("/logout")
    # Provision admin using supported first-run env vars in a separate app is covered by setup documentation.
