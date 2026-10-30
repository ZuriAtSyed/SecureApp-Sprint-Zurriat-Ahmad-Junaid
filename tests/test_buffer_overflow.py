"""
Regression test for the Buffer Overflow fix (fix/buffer-overflow
branch). Covers both layers of the fix:
  1. Web layer: an over-long title is rejected at /upload before it
     ever reaches the native helper.
  2. Native layer: even if an over-long title reaches
     native/parser_fixed (e.g. legacy data inserted before this fix),
     the app must not crash - the fixed binary rejects it safely
     instead of overflowing, unlike native/parser (see
     docs/SECURITY_IMPLEMENTATION.md for the raw ./parser / ASan
     evidence captured directly against the compiled binaries).
"""
import sqlite3

from conftest import register_and_login


def test_overlong_title_rejected_at_upload(client):
    import io

    from conftest import get_csrf_token

    register_and_login(client, "alice")
    token = get_csrf_token(client, "/upload")
    long_title = "A" * 100  # exceeds TITLE_MAX_LEN (63)

    resp = client.post(
        "/upload",
        data={
            "title": long_title,
            "file": (io.BytesIO(b"data"), "f.txt"),
            "csrf_token": token,
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert b"too long" in resp.data

    # No file row should have been created.
    resp = client.get("/", follow_redirects=True)
    assert b"No files yet" in resp.data


def test_legacy_overlong_title_does_not_crash_view(client, monkeypatch):
    """Simulates a pre-existing DB row with an over-long title (e.g.
    from before this fix shipped) and confirms the fixed native binary
    rejects it safely instead of segfaulting the way native/parser did.
    """
    import app as app_module

    register_and_login(client, "alice")

    # Insert a file row directly, bypassing the /upload length check,
    # to simulate legacy data.
    db = sqlite3.connect(app_module.DB_PATH)
    db.execute(
        "INSERT INTO files (owner_id, display_name, stored_name, title) "
        "VALUES (1, 'legacy.txt', 'legacy.txt', ?)",
        ("A" * 200,),
    )
    db.commit()
    db.close()
    (app_module.UPLOAD_DIR / "legacy.txt").write_text("legacy data")

    resp = client.get("/file/1")
    # Must not be a 500 - the fixed native binary exits cleanly (code 2)
    # on oversized input instead of crashing, and app.py handles a
    # non-crashing subprocess result gracefully either way.
    assert resp.status_code == 200
