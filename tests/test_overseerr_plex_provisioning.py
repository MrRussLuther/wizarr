"""Invited Plex users get their Overseerr account made for them.

Overseerr does not import Plex users in the background - it creates them the
first time they sign in. So an invited user lands on a login screen before
anything knows who they are, and watchlist syncing has no token to work with
until they get around to it. Wizarr holds their Plex token during the invite,
which is everything that first sign-in would have supplied.
"""

from unittest.mock import Mock, patch

from app.services.companions import get_companion_client
from app.services.companions.overseerr import (
    _PROVISION_BACKOFF_SECONDS,
    OverseerrClient,
)
from app.services.ombi_client import (
    has_plex_provisioning_connections,
    provision_plex_user_on_connections,
)


def _connection(url="http://seerr.local:5055"):
    # spec'd so a typo'd attribute fails loudly instead of auto-vivifying,
    # which is how a broken patch once passed its tests.
    conn = Mock(spec=["url", "api_key", "name", "connection_type"])
    conn.url = url
    conn.api_key = None
    conn.name = "Seerr"
    conn.connection_type = "overseerr"
    return conn


def test_posts_the_plex_token_to_the_login_route():
    client = OverseerrClient()

    with patch("app.services.companions.overseerr.requests.post") as post:
        post.return_value = Mock(ok=True, status_code=200)
        result = client.provision_plex_user("plex-token-abc", _connection())

    assert result["status"] == "success"
    (url,) = post.call_args[0]
    assert url == "http://seerr.local:5055/api/v1/auth/plex"
    assert post.call_args[1]["json"] == {"authToken": "plex-token-abc"}


def test_no_api_key_is_sent():
    """/api/v1/auth/plex is the public login route; an API key would be wrong."""
    client = OverseerrClient()

    with patch("app.services.companions.overseerr.requests.post") as post:
        post.return_value = Mock(ok=True, status_code=200)
        client.provision_plex_user("plex-token-abc", _connection())

    assert "headers" not in post.call_args[1]


def test_trailing_slash_on_the_url_does_not_double_up():
    client = OverseerrClient()

    with patch("app.services.companions.overseerr.requests.post") as post:
        post.return_value = Mock(ok=True, status_code=200)
        client.provision_plex_user("t", _connection("http://seerr.local:5055/"))

    (url,) = post.call_args[0]
    assert url == "http://seerr.local:5055/api/v1/auth/plex"


def test_retries_while_the_share_is_not_visible_yet():
    """403 means plex.tv cannot see the brand new share; it may resolve."""
    client = OverseerrClient()

    with (
        patch("app.services.companions.overseerr.requests.post") as post,
        patch("app.services.companions.overseerr.time.sleep"),
    ):
        post.side_effect = [
            Mock(ok=False, status_code=403),
            Mock(ok=True, status_code=200),
        ]
        result = client.provision_plex_user("t", _connection())

    assert result["status"] == "success"
    assert post.call_count == 2


def test_keeps_retrying_for_minutes_not_seconds():
    """Measured against a real invite, plex.tv still reported no access ~8s in,
    so a schedule that gives up in seconds never succeeds."""
    client = OverseerrClient()

    with (
        patch("app.services.companions.overseerr.requests.post") as post,
        patch("app.services.companions.overseerr.time.sleep") as sleep,
    ):
        post.return_value = Mock(ok=False, status_code=403)
        client.provision_plex_user("t", _connection())

    waited = sum(call[0][0] for call in sleep.call_args_list)
    assert waited >= 300, f"only retried across {waited}s"
    assert post.call_count == len(_PROVISION_BACKOFF_SECONDS) + 1


def test_gives_up_immediately_on_errors_that_will_not_fix_themselves():
    client = OverseerrClient()

    with (
        patch("app.services.companions.overseerr.requests.post") as post,
        patch("app.services.companions.overseerr.time.sleep"),
    ):
        post.return_value = Mock(ok=False, status_code=500)
        result = client.provision_plex_user("t", _connection())

    assert result["status"] == "error"
    assert post.call_count == 1


def test_skipped_when_no_url_is_configured():
    """Info-only connections carry no URL and must stay a no-op."""
    client = OverseerrClient()

    with patch("app.services.companions.overseerr.requests.post") as post:
        result = client.provision_plex_user("t", _connection(url=None))

    assert result["status"] == "skipped"
    post.assert_not_called()


def test_a_companion_that_cannot_provision_is_a_no_op():
    """Ombi provisions its own way; the hook must not change its behaviour."""
    client = get_companion_client("ombi")()

    result = client.provision_plex_user("t", _connection())

    assert result["status"] == "not_supported"


def test_only_opted_in_connections_are_queried(app):
    """Most instances have no request system, and an existing connection that
    predates the flag must not start provisioning on upgrade."""
    with (
        app.app_context(),
        patch("app.services.ombi_client.Connection") as connection_model,
    ):
        connection_model.query.filter_by.return_value.all.return_value = []

        results = provision_plex_user_on_connections("t", server_id=7)

    assert results == []
    connection_model.query.filter_by.assert_called_once_with(
        media_server_id=7, provision_plex_users=True
    )


def test_no_background_work_when_nothing_opted_in(app):
    """Gates spawning the retry thread, so instances without a request system
    pay nothing on every invite."""
    with (
        app.app_context(),
        patch("app.services.ombi_client.Connection") as connection_model,
    ):
        connection_model.query.filter_by.return_value.count.return_value = 0

        assert has_plex_provisioning_connections(7) is False

        connection_model.query.filter_by.return_value.count.return_value = 1

        assert has_plex_provisioning_connections(7) is True


def test_connection_failure_is_reported_not_raised():
    """A companion being down must never fail an invite the user just accepted."""
    client = OverseerrClient()

    with (
        patch("app.services.companions.overseerr.requests.post") as post,
        patch("app.services.companions.overseerr.time.sleep"),
    ):
        post.side_effect = OSError("connection refused")
        result = client.provision_plex_user("t", _connection())

    assert result["status"] == "error"
    assert "connection refused" in result["message"]
