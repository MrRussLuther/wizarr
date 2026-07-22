"""
Overseerr/Jellyseerr companion client implementation.
"""

import logging
import time

import requests

from app.models import Connection

from .base import CompanionClient

# The share Wizarr just created has to be visible to plex.tv before Overseerr
# will accept the sign-in, and that is not always instant.
_PROVISION_ATTEMPTS = 3
_PROVISION_RETRY_SECONDS = 3


class OverseerrClient(CompanionClient):
    """Client for integrating with Overseerr/Jellyseerr (info-only)."""

    @property
    def requires_api_call(self) -> bool:
        return False

    @property
    def display_name(self) -> str:
        return "Overseerr/Jellyseerr"

    def invite_user(
        self,
        username: str,  # noqa: ARG002
        email: str,  # noqa: ARG002
        connection: Connection,  # noqa: ARG002
        password: str = "",  # noqa: ARG002
    ) -> dict[str, str]:
        """
        Overseerr connections are info-only, no actual API calls needed.

        Args:
            username: Username to invite (unused - info-only)
            email: Email address (unused - info-only)
            connection: Connection object with URL and API key (unused - info-only)
            password: Password for the user (unused - info-only)

        Returns:
            Dict with 'status' and 'message' keys
        """
        return {
            "status": "info_only",
            "message": "Overseerr auto-imports users automatically",
        }

    def delete_user(self, username: str, connection: Connection) -> dict[str, str]:  # noqa: ARG002
        """
        Overseerr connections are info-only, no deletion needed.

        Args:
            username: Username to delete (unused - info-only)
            connection: Connection object with URL and API key (unused - info-only)

        Returns:
            Dict with 'status' and 'message' keys
        """
        return {
            "status": "info_only",
            "message": "Overseerr users managed automatically",
        }

    def test_connection(self, connection: Connection) -> dict[str, str]:  # noqa: ARG002
        """
        Test connection for Overseerr (info-only).

        Args:
            connection: Connection object with URL and API key (unused - info-only)

        Returns:
            Dict with 'status' and 'message' keys
        """
        return {
            "status": "info_only",
            "message": "Overseerr connections are informational only - no API testing required",
        }

    def provision_plex_user(
        self, auth_token: str, connection: Connection
    ) -> dict[str, str]:
        """
        Create the Overseerr account for a freshly invited Plex user.

        Overseerr does not import Plex users in the background; it creates them
        the first time they sign in. That leaves an invited user having to go and
        log in by hand before anything knows who they are, and before watchlist
        syncing has a token to work with. Posting their Plex token to the same
        endpoint the login page uses does exactly what that visit would have.

        Needs no API key: /api/v1/auth/plex is the public login route. It creates
        the user only when they can already reach the media server and
        newPlexLogin is enabled, so this cannot grant access Overseerr would have
        refused. The session cookie it returns is discarded.

        Args:
            auth_token: The invited user's Plex auth token
            connection: Connection object with URL and API key

        Returns:
            Dict with 'status' and 'message' keys
        """
        if not connection.url:
            return {
                "status": "skipped",
                "message": "No Overseerr URL configured",
            }

        url = f"{connection.url.rstrip('/')}/api/v1/auth/plex"
        last_message = "Unknown error"

        for attempt in range(1, _PROVISION_ATTEMPTS + 1):
            try:
                resp = requests.post(
                    url,
                    json={"authToken": auth_token},
                    timeout=10,
                )
            except Exception as exc:
                last_message = str(exc)
                logging.warning(
                    "Overseerr provisioning attempt %s/%s failed: %s",
                    attempt,
                    _PROVISION_ATTEMPTS,
                    exc,
                )
            else:
                if resp.ok:
                    logging.info("Overseerr provisioned Plex user via %s", url)
                    return {
                        "status": "success",
                        "message": "User created in Overseerr",
                    }

                last_message = f"HTTP {resp.status_code}"
                # 403 means the share is not visible to plex.tv yet. Anything
                # else is not going to fix itself, so stop early.
                if resp.status_code != 403:
                    break
                logging.info(
                    "Overseerr does not see the share yet (attempt %s/%s)",
                    attempt,
                    _PROVISION_ATTEMPTS,
                )

            if attempt < _PROVISION_ATTEMPTS:
                time.sleep(_PROVISION_RETRY_SECONDS)

        logging.warning("Overseerr provisioning gave up: %s", last_message)
        return {"status": "error", "message": last_message}
