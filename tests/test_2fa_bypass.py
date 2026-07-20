"""The WebAuthn second factor must be enforced server-side.

Regression test for the 2FA bypass (GHSA-5q9h-4gp6-3fg3): /complete-2fa logged the
account in from `pending_2fa_user_id`, which /login sets after the password check
alone. The passkey ceremony (/webauthn/authenticate/complete) verified the assertion
but recorded nothing, so a caller with only the password could skip it and POST
straight to /complete-2fa. The fix has the WebAuthn route set `2fa_verified_user_id`
and requires it in /complete-2fa.
"""

from unittest.mock import Mock, patch

from app.models import AdminAccount, WebAuthnCredential

USERNAME = "admin2fa"
PASSWORD = "TestPass123"
CREDENTIAL_ID = b"cred-1"


def _admin_with_passkey(session):
    admin = AdminAccount(username=USERNAME)
    admin.set_password(PASSWORD)
    session.add(admin)
    session.commit()
    session.add(
        WebAuthnCredential(
            admin_account_id=admin.id,
            credential_id=CREDENTIAL_ID,
            public_key=b"public-key",
            sign_count=0,
            name="test key",
        )
    )
    session.commit()
    return admin


def _password_login(client):
    return client.post(
        "/login",
        data={"auth_method": "local", "username": USERNAME, "password": PASSWORD},
    )


def _is_authenticated(client):
    # /admin is @login_required; 200 means logged in, 302 -> /login means not.
    return client.get("/admin").status_code == 200


def test_password_alone_cannot_complete_2fa(client, session):
    """The reported bypass: password, then POST /complete-2fa with no passkey."""
    _admin_with_passkey(session)

    resp = _password_login(client)
    assert resp.status_code == 200  # served the 2FA prompt
    assert not _is_authenticated(client)  # not logged in yet

    resp = client.post("/complete-2fa")
    assert resp.status_code == 401
    assert not _is_authenticated(client)


def test_completion_succeeds_after_passkey_verified(client, session):
    """With the marker the WebAuthn route sets, completion logs the account in."""
    admin = _admin_with_passkey(session)
    _password_login(client)

    with client.session_transaction() as sess:
        sess["2fa_verified_user_id"] = admin.id

    resp = client.post("/complete-2fa")
    assert resp.status_code == 302
    assert _is_authenticated(client)


def test_login_clears_stale_verified_marker(client, session):
    """A marker left in the session can't satisfy a fresh password step."""
    admin = _admin_with_passkey(session)

    with client.session_transaction() as sess:
        sess["2fa_verified_user_id"] = admin.id

    _password_login(client)  # must invalidate the stale marker
    resp = client.post("/complete-2fa")
    assert resp.status_code == 401
    assert not _is_authenticated(client)


def test_marker_for_other_account_is_rejected(client, session):
    """A verification for a different account must not satisfy this one."""
    admin = _admin_with_passkey(session)
    _password_login(client)

    with client.session_transaction() as sess:
        sess["2fa_verified_user_id"] = admin.id + 999

    resp = client.post("/complete-2fa")
    assert resp.status_code == 401
    assert not _is_authenticated(client)


def test_webauthn_complete_sets_marker_in_2fa_mode(client, session):
    """Producer side: a verified assertion records the marker, not a login."""
    admin = _admin_with_passkey(session)
    _password_login(client)

    with client.session_transaction() as sess:
        sess["webauthn_challenge"] = "challenge"

    with (
        patch(
            "app.blueprints.webauthn.routes.parse_authentication_credential_json",
            return_value=Mock(raw_id=CREDENTIAL_ID),
        ),
        patch(
            "app.blueprints.webauthn.routes.get_rp_config",
            return_value=("example.com", "Wizarr", "https://example.com"),
        ),
        patch(
            "app.blueprints.webauthn.routes.verify_authentication_response",
            return_value=Mock(new_sign_count=1),
        ),
    ):
        resp = client.post("/webauthn/authenticate/complete", json={"credential": {}})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["verified"] is True
    assert "complete-2fa" in body["redirect"]
    # the ceremony records verification but does NOT log in by itself
    assert not _is_authenticated(client)
    with client.session_transaction() as sess:
        assert sess.get("2fa_verified_user_id") == admin.id
