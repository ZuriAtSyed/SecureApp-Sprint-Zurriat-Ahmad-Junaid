"""
Regression test for the Clickjacking fix (fix/clickjacking branch).
Every response must carry X-Frame-Options: DENY and a
Content-Security-Policy with frame-ancestors 'none', so the app can no
longer be embedded in a third-party <iframe> for UI redressing.
"""


def test_login_page_sends_anti_framing_headers(client):
    resp = client.get("/login")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in resp.headers.get(
        "Content-Security-Policy", ""
    )


def test_dashboard_sends_anti_framing_headers(client):
    from conftest import register_and_login

    register_and_login(client, "alice")
    resp = client.get("/")
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "frame-ancestors 'none'" in resp.headers.get(
        "Content-Security-Policy", ""
    )
