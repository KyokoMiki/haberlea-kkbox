"""KKBOX wire-protocol helpers (pure, host-independent).

These functions implement the KKBOX login signing, KC1 decryption and session
extraction logic with **no dependency on the** ``haberlea`` **host package**.

Keeping them here lets both the in-app API client
(:mod:`haberlea_kkbox.kkbox_api`) and the standalone remote-login entry point
(:mod:`haberlea_kkbox.remote_login`, runnable via ``uvx`` on a device in a
supported region) share the exact same protocol implementation.

All functions are pure: they never perform I/O and never mutate their inputs.
"""

from random import randrange
from time import time
from typing import Any

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD5

# Default KKBOX keys, mirrored from ``module_information.global_settings``.
DEFAULT_KC1_KEY = "7f1a68f00b747f4ac1469c72e7ef492c"
DEFAULT_SECRET_KEY = "0ff29b7c9bd8fb60a3abd6b3d402b02c"

# KKBOX Android client version used for request signing.
APP_VER = "06120082"

# Static query parameters shared by every API request. Treat as immutable:
# build a new dict with ``{**BASE_PARAMS, ...}`` instead of mutating it.
BASE_PARAMS: dict[str, str] = {
    "enc": "u",
    "ver": APP_VER,
    "os": "android",
    "osver": "13",
    "lang": "en",
    "ui_lang": "en",
    "dist": "0021",
    "dist2": "0021",
    "resolution": "411x841",
    "of": "j",
    "oenc": "kc1",
}

# Login status codes that indicate an active, usable session.
LOGIN_SUCCESS_STATUSES: frozenset[int] = frozenset({2, 3})

# Login status returned when the requesting IP is in an unsupported region.
REGION_BLOCKED_STATUS = -4


def api_url(host: str, path: str) -> str:
    """Build a fully qualified KKBOX API URL.

    Args:
        host: API host identifier (e.g. ``"login"``, ``"ds"``, ``"ticket"``).
        path: API endpoint path.

    Returns:
        The full ``https://`` URL for the endpoint.
    """
    return f"https://api-{host}.kkbox.com.tw/{path}"


def kc1_decrypt(kc1_key: bytes, data: bytes) -> str:
    """Decrypt KC1 (RC4) encrypted response data.

    Args:
        kc1_key: KC1 key as ASCII bytes.
        data: Encrypted response bytes.

    Returns:
        Decrypted UTF-8 string.
    """
    cipher = ARC4.new(kc1_key)
    return cipher.decrypt(data).decode("utf-8")


def hash_password(password: str) -> str:
    """Hash a plaintext password the way KKBOX login expects.

    Args:
        password: Plaintext account password.

    Returns:
        Lowercase hex MD5 digest.
    """
    md5 = MD5.new()
    md5.update(password.encode("utf-8"))
    return md5.hexdigest()


def create_secret(secret_key: bytes, timestamp: int, ver: str = APP_VER) -> str:
    """Create the per-request ``secret`` signature.

    Args:
        secret_key: API secret key as ASCII bytes.
        timestamp: Unix timestamp (seconds) used for signing.
        ver: Client version string. Defaults to :data:`APP_VER`.

    Returns:
        Hex MD5 digest of ``ver + timestamp + secret_key``.
    """
    md5 = MD5.new()
    md5.update(ver.encode("ascii"))
    md5.update(str(timestamp).encode("ascii"))
    md5.update(secret_key)
    return md5.hexdigest()


def build_request_params(
    secret_key: bytes, timestamp: int | None = None
) -> dict[str, str]:
    """Build the signed query parameters for an API request.

    Args:
        secret_key: API secret key as ASCII bytes.
        timestamp: Unix timestamp (seconds). Defaults to the current time.

    Returns:
        New dict combining :data:`BASE_PARAMS` with ``secret``/``timestamp``.
    """
    ts = int(time()) if timestamp is None else timestamp
    return {
        **BASE_PARAMS,
        "secret": create_secret(secret_key, ts),
        "timestamp": str(ts),
    }


def generate_kkid() -> str:
    """Generate a random 32-character uppercase-hex device identifier.

    Returns:
        Random device identifier string.
    """
    return f"{randrange(16**32):032X}"


def build_login_payload(email: str, pswd_hash: str, kkid: str) -> dict[str, str]:
    """Build the ``login.php`` POST payload.

    Args:
        email: Account email / user id.
        pswd_hash: MD5-hashed password (see :func:`hash_password`).
        kkid: Device identifier.

    Returns:
        Form payload dict for ``login.php``.
    """
    return {
        "uid": email,
        "passwd": pswd_hash,
        "kkid": kkid,
        "registration_id": "",
    }


def login_status(resp: dict[str, Any]) -> int | None:
    """Read the integer ``status`` field from a login response.

    Args:
        resp: Decoded login response.

    Returns:
        The status value, or None if absent or non-integer.
    """
    status = resp.get("status")
    return status if isinstance(status, int) else None


def is_login_success(status: int | None) -> bool:
    """Check whether a login status indicates an active session.

    Args:
        status: Status value from :func:`login_status`.

    Returns:
        True if the status is a success code.
    """
    return status in LOGIN_SUCCESS_STATUSES


def extract_session_data(resp: dict[str, Any]) -> dict[str, Any]:
    """Extract the minimal session fields needed to restore a session.

    Args:
        resp: Decoded login response.

    Returns:
        Dict with ``sid``, ``lic_content_key`` and ``high_quality``.
    """
    return {
        "sid": resp["sid"],
        "lic_content_key": resp["lic_content_key"],
        "high_quality": resp.get("high_quality", 0),
    }
