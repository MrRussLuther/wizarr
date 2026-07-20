"""Creating an invite with the library picker opened but every box cleared is
rejected, replacing the silent "unchecked all -> grant every enabled library"
surprise with an explicit error. An invite whose picker was never opened is
unaffected and still falls back to all enabled libraries at redeem time.
"""

from app.models import AdminAccount, Invitation, Library, MediaServer

# /invite is an HTMX-only endpoint (it redirects to the dashboard otherwise).
HX = {"HX-Request": "true", "HX-Current-URL": "http://localhost/admin/invites"}


def _login(client, session):
    admin = AdminAccount(username="testadmin")
    admin.set_password("TestPass123")
    session.add(admin)
    session.commit()
    resp = client.post(
        "/login", data={"username": "testadmin", "password": "TestPass123"}
    )
    assert resp.status_code in {200, 302, 303}
    return admin


def _server(session):
    server = MediaServer(
        name="Plex", server_type="plex", url="http://plex.local", api_key="token"
    )
    session.add(server)
    session.commit()
    return server


def test_opened_picker_but_cleared_is_rejected(client, session):
    """Marker present + zero boxes checked -> 400 and no invite is created."""
    _login(client, session)
    server = _server(session)

    resp = client.post(
        "/invite",
        data={
            "server_ids": str(server.id),
            "expires": "never",
            "library_picker_used": "1",
        },
        headers=HX,
    )
    assert resp.status_code == 400
    assert b"at least one library" in resp.data
    assert Invitation.query.count() == 0


def test_picker_with_a_selection_is_created(client, session):
    """Marker present + a library kept -> invite created with exactly that library."""
    _login(client, session)
    server = _server(session)
    lib = Library(external_id="1", name="Movies", server_id=server.id, enabled=True)
    session.add(lib)
    session.commit()

    resp = client.post(
        "/invite",
        data={
            "server_ids": str(server.id),
            "expires": "never",
            "library_picker_used": "1",
            "libraries": str(lib.id),
        },
        headers=HX,
    )
    assert resp.status_code == 200
    inv = Invitation.query.one()
    assert [library.id for library in inv.libraries] == [lib.id]


def test_untouched_picker_is_allowed(client, session):
    """No marker (picker never opened) -> allowed; redeem-time fallback still applies."""
    _login(client, session)
    server = _server(session)

    resp = client.post(
        "/invite",
        data={"server_ids": str(server.id), "expires": "never"},
        headers=HX,
    )
    assert resp.status_code == 200
    inv = Invitation.query.one()
    assert list(inv.libraries) == []
