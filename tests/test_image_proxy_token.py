"""Confidentiality and integrity tests for image-proxy tokens.

Proxy tokens are embedded in pages served to invited users (the
``recently_added_media`` wizard widget, among others), so they must never
disclose the media server's admin credentials or the internal upstream URL.
"""

import base64
import json

import pytest

import app.services.image_proxy as image_proxy_module
from app.services.image_proxy import ImageProxyService

PLEX_TOKEN = "sUpErSeCrEtAdM1nT0k3n"  # test fixture, not a real credential
POSTER_URL = (
    "http://plex.internal:32400/library/metadata/12345/thumb/1700000000"
    f"?X-Plex-Token={PLEX_TOKEN}"
)
POSTER_URL_CLEAN = "http://plex.internal:32400/library/metadata/12345/thumb/1700000000"


def _decode(token: str) -> bytes:
    """Base64url-decode a token the way an attacker with the HTML would."""
    padding = (4 - len(token) % 4) % 4
    return base64.urlsafe_b64decode(token + ("=" * padding))


@pytest.fixture(autouse=True)
def _clear_caches():
    """validate_token() short-circuits on the token cache, so isolate every test."""
    ImageProxyService._token_cache.clear()
    ImageProxyService._cipher_key_cache.clear()
    yield
    ImageProxyService._token_cache.clear()
    ImageProxyService._cipher_key_cache.clear()


# ─── Confidentiality ────────────────────────────────────────────────────────


def test_token_does_not_disclose_admin_token(app):
    """The whole point: nothing recoverable from the token the browser receives."""
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=1)

    assert PLEX_TOKEN not in token

    raw = _decode(token)
    assert PLEX_TOKEN.encode() not in raw
    assert b"X-Plex-Token" not in raw
    assert b"plex.internal" not in raw
    assert b"library/metadata" not in raw


@pytest.mark.parametrize(
    "param",
    [
        "X-Plex-Token",
        "x-plex-token",
        "X-Emby-Token",
        "X-MediaBrowser-Token",
        "X-API-Key",
        "api_key",
        "apikey",
        "token",
    ],
)
def test_known_credential_params_are_stripped(app, param):
    url = f"http://media.internal:8096/Items/1/Images/Primary?{param}=SECRETVALUE&maxWidth=300"

    with app.app_context():
        token = ImageProxyService.generate_token(url, server_id=3)
        ImageProxyService._token_cache.clear()
        mapping = ImageProxyService.validate_token(token)

    assert mapping is not None
    assert "SECRETVALUE" not in mapping["url"]
    # Non-credential parameters must survive or artwork requests break
    assert "maxWidth=300" in mapping["url"]


def test_userinfo_credentials_are_stripped(app):
    with app.app_context():
        token = ImageProxyService.generate_token(
            "http://admin:hunter2@plex.internal:32400/thumb.jpg", server_id=1
        )
        ImageProxyService._token_cache.clear()
        mapping = ImageProxyService.validate_token(token)

    assert mapping is not None
    assert mapping["url"] == "http://plex.internal:32400/thumb.jpg"


def test_url_kept_without_server_id_but_still_opaque(app):
    """Legacy installs have no MediaServer row, so the URL is the only auth path.

    It must still be unreadable by the client.
    """
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=None)
        ImageProxyService._token_cache.clear()
        mapping = ImageProxyService.validate_token(token)

    assert mapping is not None
    assert mapping["url"] == POSTER_URL
    assert PLEX_TOKEN.encode() not in _decode(token)


# ─── Integrity ──────────────────────────────────────────────────────────────


def test_round_trip(app):
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=7)
        ImageProxyService._token_cache.clear()
        mapping = ImageProxyService.validate_token(token)

    assert mapping == {"url": POSTER_URL_CLEAN, "server_id": 7}


def test_tampered_token_rejected(app):
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=1)
        ImageProxyService._token_cache.clear()

        idx = len(token) // 2
        replacement = "A" if token[idx] != "A" else "B"
        tampered = token[:idx] + replacement + token[idx + 1 :]

        assert ImageProxyService.validate_token(tampered) is None


def test_hand_crafted_payload_rejected(app):
    """An attacker cannot mint a token for an arbitrary URL (SSRF)."""
    payload = json.dumps(
        {
            "url": "http://169.254.169.254/latest/meta-data/",
            "server_id": None,
            "bucket": 0,
        }
    )
    forged = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")

    with app.app_context():
        assert ImageProxyService.validate_token(forged) is None


def test_token_from_a_different_secret_rejected(app):
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=1)

    ImageProxyService._token_cache.clear()
    ImageProxyService._cipher_key_cache.clear()

    original = app.config["SECRET_KEY"]
    app.config["SECRET_KEY"] = "a-completely-different-secret"
    try:
        with app.app_context():
            assert ImageProxyService.validate_token(token) is None
    finally:
        app.config["SECRET_KEY"] = original


@pytest.mark.parametrize("token", ["", "not-a-token", "a.b", "AAAA"])
def test_malformed_tokens_rejected(app, token):
    with app.app_context():
        assert ImageProxyService.validate_token(token) is None


# ─── Caching behaviour ──────────────────────────────────────────────────────


def test_token_is_stable_for_the_same_url(app):
    """Deterministic tokens keep the token/image caches effective across workers."""
    with app.app_context():
        first = ImageProxyService.generate_token(POSTER_URL, server_id=1)
        ImageProxyService._token_cache.clear()
        second = ImageProxyService.generate_token(POSTER_URL, server_id=1)

    assert first == second


def test_expired_token_rejected(app, monkeypatch):
    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=1)

    ImageProxyService._token_cache.clear()

    real_time = image_proxy_module.time.time
    skew = ImageProxyService.TOKEN_EXPIRY + ImageProxyService.TOKEN_BUCKET_SECONDS

    class _LaterTime:
        @staticmethod
        def time():
            return real_time() + skew

    monkeypatch.setattr(image_proxy_module, "time", _LaterTime)

    with app.app_context():
        assert ImageProxyService.validate_token(token) is None


# ─── End-to-end through the /image-proxy route ──────────────────────────────


def test_proxy_reattaches_credentials_server_side(app, client, session, monkeypatch):
    """The stripped credential must come back as a header on the upstream request.

    This is what keeps artwork rendering after the token is removed from the URL.
    """
    from app.models import MediaServer

    server = MediaServer(
        name="Plex",
        server_type="plex",
        url="http://plex.internal:32400",
        api_key=PLEX_TOKEN,
    )
    session.add(server)
    session.commit()

    ImageProxyService._server_header_cache.clear()

    captured = {}

    class _FakeResponse:
        headers = {"Content-Type": "image/jpeg"}
        content = b"\xff\xd8\xff\xe0-jpeg-bytes"

        def raise_for_status(self):
            return None

    class _FakeSession:
        def get(self, url, headers=None, timeout=None):
            captured["url"] = url
            captured["headers"] = headers or {}
            return _FakeResponse()

    monkeypatch.setattr(
        ImageProxyService,
        "get_session",
        classmethod(lambda cls, url, server_id: _FakeSession()),
    )

    with app.app_context():
        token = ImageProxyService.generate_token(POSTER_URL, server_id=server.id)

    resp = client.get(f"/image-proxy?token={token}")

    assert resp.status_code == 200
    assert resp.data == _FakeResponse.content

    # The credential was stripped from the URL...
    assert "X-Plex-Token" not in captured["url"]
    assert PLEX_TOKEN not in captured["url"]
    # ...and re-attached as a header from the MediaServer row
    assert captured["headers"].get("X-Plex-Token") == PLEX_TOKEN
