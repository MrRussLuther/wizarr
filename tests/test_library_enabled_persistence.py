"""Library.enabled is the admin's saved default for new invites.

It is written by the server edit form, rendered as `checked` by
partials/library_checkboxes.html, and used by _invite_user as the fallback library
set for invites that carry none of their own. Library scans must therefore not
reset it, and the legacy settings scan must not delete rows it does not own.
"""

from unittest.mock import patch

from app.models import AdminAccount, Library, MediaServer


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


def _server(session, name="Plex"):
    server = MediaServer(
        name=name, server_type="plex", url="http://plex.local", api_key="token"
    )
    session.add(server)
    session.commit()
    return server


def _libs(session, server, spec):
    """spec: {external_id: (name, enabled)}"""
    for ext, (name, enabled) in spec.items():
        session.add(
            Library(external_id=ext, name=name, server_id=server.id, enabled=enabled)
        )
    session.commit()


def _enabled_map(server_id):
    return {
        lib.external_id: lib.enabled
        for lib in Library.query.filter_by(server_id=server_id).all()
    }


SCAN_RESULT = {"1": "Movies", "2": "TV Shows", "3": "Home Video"}


def test_invite_scan_preserves_disabled_libraries(client, session):
    """Opening the invite modal rescans; it must not re-enable what the admin turned off."""
    _login(client, session)
    server = _server(session)
    _libs(
        session,
        server,
        {"1": ("Movies", True), "2": ("TV Shows", True), "3": ("Home Video", False)},
    )

    with patch(
        "app.blueprints.admin.routes.scan_libraries_for_server",
        return_value=SCAN_RESULT,
    ):
        resp = client.post(
            "/invite/scan-libraries", data={"server_ids": str(server.id)}
        )
    assert resp.status_code == 200

    assert _enabled_map(server.id) == {"1": True, "2": True, "3": False}


def test_invite_scan_rendered_checkboxes_match_enabled(client, session):
    """The rendered form must offer every library but pre-check only the enabled ones."""
    _login(client, session)
    server = _server(session)
    _libs(
        session,
        server,
        {"1": ("Movies", True), "2": ("TV Shows", False), "3": ("Home Video", False)},
    )

    with patch(
        "app.blueprints.admin.routes.scan_libraries_for_server",
        return_value=SCAN_RESULT,
    ):
        resp = client.post(
            "/invite/scan-libraries", data={"server_ids": str(server.id)}
        )

    html = resp.get_data(as_text=True)
    assert html.count('name="libraries"') == 3
    assert html.count("checked") == 1


def test_server_edit_scan_preserves_disabled_libraries(client, session):
    """Same reset existed on the per-server scan the edit form opens with."""
    _login(client, session)
    server = _server(session)
    _libs(session, server, {"1": ("Movies", True), "3": ("Home Video", False)})

    with patch(
        "app.blueprints.media_servers.routes.scan_libraries_for_server",
        return_value=SCAN_RESULT,
    ):
        resp = client.post(f"/settings/servers/{server.id}/scan-libraries")
    assert resp.status_code == 200

    enabled = _enabled_map(server.id)
    assert enabled["1"] is True
    assert enabled["3"] is False


def test_newly_discovered_library_defaults_to_enabled(client, session):
    """A library that appears for the first time should not be silently withheld."""
    _login(client, session)
    server = _server(session)
    _libs(session, server, {"1": ("Movies", True)})

    with patch(
        "app.blueprints.admin.routes.scan_libraries_for_server",
        return_value=SCAN_RESULT,
    ):
        client.post("/invite/scan-libraries", data={"server_ids": str(server.id)})

    enabled = _enabled_map(server.id)
    assert enabled["2"] is True
    assert enabled["3"] is True


def test_legacy_settings_scan_does_not_delete_other_servers_libraries(client, session):
    """The legacy route owns only unbound rows; it must not touch real servers'."""
    _login(client, session)
    server = _server(session, name="Existing")
    _libs(session, server, {"1": ("Movies", True), "3": ("Home Video", False)})
    session.add(Library(external_id="stale", name="Stale", server_id=None))
    session.commit()

    bound_ids_before = {
        lib.id for lib in Library.query.filter_by(server_id=server.id).all()
    }

    with patch(
        "app.blueprints.settings.routes.scan_media", return_value={"9": "Fresh"}
    ):
        resp = client.post(
            "/settings/scan-libraries",
            data={
                "server_type": "plex",
                "server_url": "http://plex.local",
                "api_key": "token",
            },
        )
    assert resp.status_code == 200

    bound_after = Library.query.filter_by(server_id=server.id).all()
    assert {lib.id for lib in bound_after} == bound_ids_before
    assert _enabled_map(server.id) == {"1": True, "3": False}

    # the unbound staging rows are still replaced, which is this route's job
    unbound = {lib.external_id for lib in Library.query.filter_by(server_id=None).all()}
    assert unbound == {"9"}
