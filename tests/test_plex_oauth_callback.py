"""Plex OAuth returns the user to Wizarr instead of stranding them on plex.tv.

Sign-in happens on app.plex.tv in a second window. Without a ``forwardUrl`` the
browser has nowhere to go once Plex is done, so the user is left sitting on
Plex's own screen while the invite page waits behind it - on mobile, where the
second window is a whole tab, there is no way back at all.
"""

from pathlib import Path

PLEX_OAUTH_JS = Path(__file__).resolve().parents[1] / "app/static/js/plex-oauth.js"


def test_callback_route_is_public(client):
    """Plex forwards the browser here with no session of its own to present."""
    resp = client.get("/plex/callback")
    assert resp.status_code == 200


def test_callback_page_can_complete_the_join_on_its_own(client):
    """The callback carries the form it needs when the opener is gone."""
    html = client.get("/plex/callback").get_data(as_text=True)

    assert 'action="/join"' in html
    assert 'name="code"' in html
    assert 'name="token"' in html


def test_callback_page_loads_the_shared_oauth_helpers(client):
    """Guards against the template referencing a script that is not shipped."""
    html = client.get("/plex/callback").get_data(as_text=True)

    assert "js/plex-oauth.js" in html
    assert PLEX_OAUTH_JS.exists()


def test_shared_helpers_expose_the_coordination_api():
    """The invite page and the callback page share this state via localStorage."""
    source = PLEX_OAUTH_JS.read_text()

    for helper in (
        "function plexOAuthRead",
        "function plexOAuthWrite",
        "function plexOAuthClear",
        "function plexOAuthClaim",
        "async function plexOAuthPollToken",
    ):
        assert helper in source


def test_invite_page_asks_plex_to_forward_back(client):
    """The regression itself: without forwardUrl the user never comes back."""
    # No code renders the invite page with an error, which is enough to get the
    # Plex sign-in markup without standing up an invitation.
    html = client.post("/join", data={}).get_data(as_text=True)

    assert "forwardUrl" in html
    assert "/plex/callback" in html


def test_invite_page_closes_the_plex_window(client):
    """A popup left open on top of the wizard is the desktop half of the bug."""
    html = client.post("/join", data={}).get_data(as_text=True)

    assert "popup.close()" in html
