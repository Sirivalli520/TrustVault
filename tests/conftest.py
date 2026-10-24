import io
import pytest
from app import create_app, get_db

@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "MAX_CONTENT_LENGTH": 1024 * 1024,
    })
    yield app

@pytest.fixture()
def client(app):
    return app.test_client()

def register(client, username, role="owner", password="correct-horse-battery"):
    return client.post("/register", data={
        "username": username, "password": password, "role": role
    }, follow_redirects=True)

def login(client, username, password="correct-horse-battery"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)

def upload(client, filename="note.txt", content=b"secret text"):
    return client.post("/upload", data={
        "file": (io.BytesIO(content), filename),
        "description": "test document",
        "category": "Test",
    }, content_type="multipart/form-data", follow_redirects=True)
