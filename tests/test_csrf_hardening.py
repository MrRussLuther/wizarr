"""CSRF hardening for state-changing admin endpoints.

Two things this covers:

1. GET /users/table must not delete. It rendered the table but also deleted users
   from `?delete=` / `?delete_multi=` query params, so a single top-level navigation
   could destroy accounts. SameSite=Lax does not stop a top-level GET, so the delete
   handling was removed; the UI already deletes via POST /users/bulk-delete.
2. The session cookie is SameSite=Lax + HttpOnly, so it does not ride along on a
   cross-site POST/fetch to the endpoints that carry no CSRF token.
"""

from app.extensions import db
from app.models import AdminAccount, MediaServer, User

USERNAME = "admincsrf"
PASSWORD = "TestPass123"


def _login(client, session):
    admin = AdminAccount(username=USERNAME)
    admin.set_password(PASSWORD)
    session.add(admin)
    session.commit()
    resp = client.post(
        "/login",
        data={"auth_method": "local", "username": USERNAME, "password": PASSWORD},
    )
    assert resp.status_code in {200, 302, 303}
    return admin


def _a_user(session):
    server = MediaServer(
        name="Plex", server_type="plex", url="http://plex.local", api_key="token"
    )
    session.add(server)
    session.commit()
    user = User(
        email="victim@example.com",
        username="victim",
        token="None",
        code="None",
        server_id=server.id,
    )
    session.add(user)
    session.commit()
    return user


def test_get_users_table_does_not_delete(client, session):
    """The reported CSRF vector: GET with ?delete must not remove the user."""
    _login(client, session)
    user = _a_user(session)

    resp = client.get(f"/users/table?delete={user.id}")
    assert resp.status_code == 200
    assert db.session.get(User, user.id) is not None

    resp = client.get(f"/users/table?delete_multi={user.id}")
    assert resp.status_code == 200
    assert db.session.get(User, user.id) is not None


def test_bulk_delete_still_works(client, session):
    """The legitimate POST path must still delete, so we didn't break the UI."""
    _login(client, session)
    user = _a_user(session)
    uid = user.id

    resp = client.post("/users/bulk-delete", data={"uids": str(uid)})
    assert resp.status_code == 200
    assert db.session.get(User, uid) is None


def test_session_cookie_is_hardened(app):
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True


def test_login_sets_samesite_lax_cookie(client, session):
    """Behavioural check: the cookie the app actually sets carries SameSite=Lax."""
    admin = AdminAccount(username=USERNAME)
    admin.set_password(PASSWORD)
    session.add(admin)
    session.commit()

    resp = client.post(
        "/login",
        data={"auth_method": "local", "username": USERNAME, "password": PASSWORD},
    )
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in set_cookie
    assert "HttpOnly" in set_cookie
