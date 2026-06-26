"""Standalone remote-login entry point for KKBOX.

Run this on a device located in a KKBOX-supported region when the main host is
region blocked (``login.php`` returns status ``-4``). It performs the full
login **and KC1 decryption** locally, so it can verify whether the login
actually succeeded, then prints a single short JSON line containing only the
session fields the host needs (``sid``, ``lic_content_key``, ``high_quality``).

All credentials are passed as command-line arguments; the host prints a
ready-to-run command, so there is nothing to type interactively.

Usage:
    uvx --from "git+https://github.com/KyokoMiki/haberlea-kkbox" \
        remote-login EMAIL PSWD_HASH KKID KC1_KEY SECRET_KEY

This module only depends on the standard library plus ``msgspec`` and
``pycryptodomex`` (declared dependencies of ``haberlea-kkbox``); it does **not**
import the ``haberlea`` host package, so it works in an isolated ``uvx``
environment.
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .protocol import (
    REGION_BLOCKED_STATUS,
    api_url,
    build_login_payload,
    build_request_params,
    extract_session_data,
    is_login_success,
    kc1_decrypt,
    login_status,
)

_HEADERS = {"user-agent": "okhttp/3.14.9"}
_TIMEOUT_SECONDS = 30


def _post_login(
    email: str,
    pswd_hash: str,
    kkid: str,
    kc1_key: str,
    secret_key: str,
) -> dict[str, Any]:
    """Perform the ``login.php`` request and KC1-decrypt the response.

    Args:
        email: Account email / user id.
        pswd_hash: MD5-hashed password.
        kkid: Device identifier.
        kc1_key: KC1 decryption key (32-char hex).
        secret_key: API secret key (32-char hex).

    Returns:
        Decoded login response dictionary.

    Raises:
        urllib.error.URLError: If the HTTP request fails.
        ValueError: If the decrypted body is not valid JSON.
        UnicodeDecodeError: If decryption produced invalid UTF-8 (bad keys).
    """
    params = build_request_params(secret_key.encode("ascii"))
    url = api_url("login", "login.php") + "?" + urllib.parse.urlencode(params)
    payload = urllib.parse.urlencode(
        build_login_payload(email, pswd_hash, kkid)
    ).encode("ascii")
    request = urllib.request.Request(url, data=payload, headers=_HEADERS)
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        raw: bytes = response.read()
    decoded: dict[str, Any] = json.loads(kc1_decrypt(kc1_key.encode("ascii"), raw))
    return decoded


def main(argv: list[str] | None = None) -> int:
    """Perform a KKBOX login from CLI arguments and print the session JSON.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: ``0`` on success, ``1`` on failure.
    """
    parser = argparse.ArgumentParser(
        prog="remote-login",
        description="Perform a KKBOX login on a device in a supported region.",
    )
    parser.add_argument("email", help="Account email / user id")
    parser.add_argument("pswd_hash", help="MD5-hashed password")
    parser.add_argument("kkid", help="Device identifier (kkid)")
    parser.add_argument("kc1_key", help="KC1 key (32-char hex)")
    parser.add_argument("secret_key", help="Secret key (32-char hex)")
    args = parser.parse_args(argv)

    try:
        resp = _post_login(
            args.email, args.pswd_hash, args.kkid, args.kc1_key, args.secret_key
        )
    except urllib.error.URLError as exc:
        print(f"Network error contacting KKBOX: {exc}", file=sys.stderr)
        return 1
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"Could not decode response (check keys): {exc}", file=sys.stderr)
        return 1

    status = login_status(resp)
    if status == REGION_BLOCKED_STATUS:
        print(
            "This device is also in an unsupported region (status -4).",
            file=sys.stderr,
        )
        return 1
    if not is_login_success(status):
        print(
            f"Login failed (status={status}). Check email/password.",
            file=sys.stderr,
        )
        return 1

    print("Login successful. Paste the line below into the host:", file=sys.stderr)
    print(json.dumps(extract_session_data(resp)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
