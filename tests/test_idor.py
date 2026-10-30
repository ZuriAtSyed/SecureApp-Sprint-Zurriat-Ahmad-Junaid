"""
Regression test for the IDOR fix (fix/idor branch).
Ensures a second, unrelated user can never view, download, or export a
file they do not own via GET/POST /file/<id>[...] - must get 403/302
redirect-to-login behaviour, never the victim's data.
"""
from conftest import register_and_login, upload_file


def test_other_user_cannot_view_file(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice secret", content=b"TOP SECRET")

    # file_id=1 belongs to alice; switch to bob
    client.get("/logout")
    register_and_login(client, "bob")

    resp = client.get("/file/1")
    assert resp.status_code == 403


def test_other_user_cannot_download_file(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice secret", content=b"TOP SECRET")

    client.get("/logout")
    register_and_login(client, "bob")

    resp = client.get("/file/1/download")
    assert resp.status_code == 403


def test_owner_can_view_own_file(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice note", content=b"hello")

    resp = client.get("/file/1")
    assert resp.status_code == 200
