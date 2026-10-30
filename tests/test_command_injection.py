"""
Regression test for the Command Injection fix (fix/command-injection
branch). Reproduces the exact payload used in the original exploit
(docs/SECURITY_IMPLEMENTATION.md) and asserts it can no longer execute
a second command, plus checks legitimate export names still work.
"""
import os

from conftest import register_and_login, upload_file, get_csrf_token


def test_shell_metacharacter_payload_is_rejected(client, tmp_path):
    register_and_login(client, "alice")
    upload_file(client, title="Alice note", content=b"hello")

    marker = tmp_path / "pwned_marker.txt"
    payload = f"x'; touch {marker}; echo '"

    token = get_csrf_token(client, "/file/1")
    resp = client.post(
        "/file/1/export",
        data={"export_name": payload, "csrf_token": token},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Invalid export name" in resp.data
    # The injected `touch` must NOT have run.
    assert not marker.exists()


def test_legitimate_export_name_still_works(client):
    register_and_login(client, "alice")
    upload_file(client, title="Alice note", content=b"hello")

    token = get_csrf_token(client, "/file/1")
    resp = client.post(
        "/file/1/export",
        data={"export_name": "report-v1.txt", "csrf_token": token},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Exported as report-v1.txt" in resp.data
