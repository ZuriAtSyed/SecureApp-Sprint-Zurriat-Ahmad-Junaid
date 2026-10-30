"""
Shared pytest fixtures for the SecureShare test/security suite.
Each test gets an isolated temp SQLite DB and temp upload dir so tests
never touch the real app/secureshare.db used for manual demos.
"""
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))
import app as app_module  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_secureshare.db"
    upload_dir = tmp_path / "uploads"
    export_dir = tmp_path / "exports"
    upload_dir.mkdir()
    export_dir.mkdir()

    monkeypatch.setattr(app_module, "DB_PATH", db_path)
    monkeypatch.setattr(app_module, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(app_module, "EXPORT_DIR", export_dir)

    app_module.init_db()
    app_module.app.config.update(TESTING=True)

    with app_module.app.test_client() as c:
        yield c


def register_and_login(client, username, password="Passw0rd!123"):
    client.post("/register", data={"username": username, "password": password})
    client.post("/login", data={"username": username, "password": password})


def upload_file(client, title, content=b"secret content", filename="f.txt"):
    import io

    resp = client.post(
        "/upload",
        data={"title": title, "file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    return resp
