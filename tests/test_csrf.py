"""
Regression test for the CSRF fix (fix/csrf branch).
A forged POST with no csrf_token (simulating a cross-site form
submission) must be rejected; the legitimate request flow (which reads
the token from the form, as the real templates do) must still work.
"""
from conftest import register_and_login, upload_file, get_csrf_token


def test_forged_delete_without_csrf_token_is_rejected(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice secret", content=b"TOP SECRET")

    # Simulates the attacker's cross-site auto-submitting form: a raw
    # POST with no csrf_token field, using alice's live session cookies
    # (the test client keeps them automatically).
    resp = client.post("/file/1/delete")
    assert resp.status_code == 400  # Flask-WTF CSRF validation failure

    # File must still exist - the forged request did not succeed.
    resp = client.get("/file/1")
    assert resp.status_code == 200


def test_legitimate_delete_with_csrf_token_succeeds(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice note", content=b"hello")

    # Pull the real csrf token out of the dashboard page, the way the
    # browser-rendered <form> would, then submit it.
    token = get_csrf_token(client, "/")

    resp = client.post("/file/1/delete", data={"csrf_token": token},
                        follow_redirects=True)
    assert resp.status_code == 200
    assert b"No files yet" in resp.data
