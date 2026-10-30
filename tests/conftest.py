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


def get_csrf_token(client, url):
    """Fetch `url` and pull the csrf_token hidden-field value out of the
    rendered HTML, the way a real browser submitting that form would."""
    import re

    page = client.get(url).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert m, f"csrf_token hidden field not found on {url}"
    return m.group(1)


def register_and_login(client, username, password="Passw0rd!123"):
    token = get_csrf_token(client, "/register")
    client.post("/register", data={
        "username": username, "password": password, "csrf_token": token,
    })
    token = get_csrf_token(client, "/login")
    client.post("/login", data={
        "username": username, "password": password, "csrf_token": token,
    })


def upload_file(client, title, content=b"secret content", filename="f.txt"):
    import io

    token = get_csrf_token(client, "/upload")
    resp = client.post(
        "/upload",
        data={
            "title": title, "file": (io.BytesIO(content), filename),
            "csrf_token": token,
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    return resp
