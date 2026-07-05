"""KKBOX API client for authentication and data retrieval.

This module provides an async KKBOX API client using aiohttp,
handling authentication, content retrieval, and DRM decryption.
"""

import logging
import re
from pathlib import Path
from time import time
from typing import Any

import anyio
import msgspec
from anyio.to_thread import run_sync
from Cryptodome.Cipher import ARC4
from mutagen.flac import FLAC
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from haberlea.utils.auth_prompter import AuthPrompter
from haberlea.utils.exceptions import ModuleAPIError, ModuleAuthError, ModuleError
from haberlea.utils.models import TemporarySettingsController
from haberlea.utils.utils import DownloadConfig, create_aiohttp_session, download_file

from .protocol import (
    REGION_BLOCKED_STATUS,
    api_url,
    build_request_params,
    extract_session_data,
    generate_kkid,
    hash_password,
    kc1_decrypt,
)

logger = logging.getLogger(__name__)

# Maximum number of retries for get_ticket
MAX_RETRIES = 5

_REMOTE_LOGIN_PROMPT = (
    "KKBOX login: this IP address is in an unsupported region.\n"
    "1. Run the following command on a device in a supported region:\n"
    "\n"
    "{command}\n"
    "\n"
    "2. Paste the JSON line it prints here."
)


class SessionRetryableError(ModuleError):
    """Signal that a request should be retried after session/auth recovery."""


class KkdrmDecryptor:
    """Stateful DRM decryptor — mutable by necessity (streaming cipher).

    KKDRM format: skip first 1024 bytes, then RC4 decrypt the rest.
    Chunks MUST be processed sequentially in order.
    """

    def __init__(self, key: bytes) -> None:
        self._rc4 = ARC4.new(key, drop=512)
        self._bytes_seen: int = 0
        self._skip: int = 1024

    def __call__(self, chunk: bytes, _chunk_index: int) -> bytes:
        """Process a single chunk with sequential decryption.

        Args:
            chunk: Raw encrypted chunk data.
            _chunk_index: Chunk index (unused, required by interface).

        Returns:
            Decrypted chunk data, or empty bytes if in skip region.
        """
        start = self._bytes_seen
        self._bytes_seen += len(chunk)

        # Case 1: Chunk entirely in skip region
        if start + len(chunk) <= self._skip:
            return b""
        # Case 2: Chunk spans the skip boundary
        elif start < self._skip:
            skip_count = self._skip - start
            return self._rc4.decrypt(chunk[skip_count:])
        # Case 3: Chunk entirely after skip region
        else:
            return self._rc4.decrypt(chunk)


class KkboxAPI:
    """Async KKBOX API client.

    Handles authentication and API requests to the KKBOX music service.

    Args:
        kc1_key: KC1 decryption key (32-character hex string).
        secret_key: API secret key (32-character hex string).
        tsc: Temporary settings controller for session persistence.
        auth_prompter: Channel for interactive prompts during login.
        kkid: Device identifier. Generated if not provided.
    """

    def __init__(
        self,
        kc1_key: str,
        secret_key: str,
        tsc: TemporarySettingsController,
        auth_prompter: AuthPrompter,
        kkid: str | None = None,
    ) -> None:
        """Initialize the KKBOX API client.

        Args:
            kc1_key: KC1 decryption key (32-character hex string).
            secret_key: API secret key (32-character hex string).
            tsc: Temporary settings controller for session persistence.
            auth_prompter: Channel for interactive prompts during login.
            kkid: Device identifier. Generated if not provided.

        Raises:
            ModuleAPIError: If kc1_key or secret_key is invalid.
        """
        self.tsc = tsc
        self.auth_prompter = auth_prompter
        key_pattern = re.compile("[0-9a-f]{32}")

        if not key_pattern.fullmatch(kc1_key):
            raise ModuleAPIError(
                error_code=400,
                error_message="kc1_key is invalid, change it in settings",
                api_endpoint="init",
                module_name="kkbox",
            )
        if not key_pattern.fullmatch(secret_key):
            raise ModuleAPIError(
                error_code=400,
                error_message="secret_key is invalid, change it in settings",
                api_endpoint="init",
                module_name="kkbox",
            )

        self.kc1_key = kc1_key.encode("ascii")
        self.secret_key = secret_key.encode("ascii")
        self.kkid = kkid or generate_kkid()
        self.session = create_aiohttp_session()

        self._headers = {"user-agent": "okhttp/3.14.9"}
        self.sid: str | None = None
        self.lic_content_key: bytes | None = None
        self.available_qualities: list[str] = []

    async def close(self) -> None:
        """Close the aiohttp session."""
        if not self.session.closed:
            await self.session.close()

    async def _api_call(
        self,
        host: str,
        path: str,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Make an API call to KKBOX.

        Args:
            host: API host identifier (e.g., "ds", "login", "ticket").
            path: API endpoint path.
            params: Query parameters.
            payload: POST body data.

        Returns:
            Decoded JSON response or None if empty.

        Raises:
            ModuleAPIError: If the API request fails.
        """
        if params is None:
            params = {}

        request_params = {**build_request_params(self.secret_key), **params}

        if self.sid:
            request_params["sid"] = self.sid

        url = api_url(host, path)

        try:
            if payload is not None:
                # For ticket host, use JSON encoding; for others, use form data
                if host == "ticket":
                    payload_data = msgspec.json.encode(payload)
                    async with self.session.post(
                        url,
                        params=request_params,
                        data=payload_data,
                        headers=self._headers,
                    ) as response:
                        if not response.content:
                            return None
                        content = await response.read()
                        return msgspec.json.decode(kc1_decrypt(self.kc1_key, content))
                else:
                    # Use form data for login and other endpoints
                    async with self.session.post(
                        url,
                        params=request_params,
                        data=payload,
                        headers=self._headers,
                    ) as response:
                        if not response.content:
                            return None
                        content = await response.read()
                        return msgspec.json.decode(kc1_decrypt(self.kc1_key, content))
            else:
                # GET request
                async with self.session.get(
                    url,
                    params=request_params,
                    headers=self._headers,
                ) as response:
                    if not response.content:
                        return None
                    content = await response.read()
                    return msgspec.json.decode(kc1_decrypt(self.kc1_key, content))

        except Exception as e:
            raise ModuleAPIError(
                error_code=500,
                error_message=str(e),
                api_endpoint=path,
                module_name="kkbox",
            ) from e

    def _apply_session(self, resp: dict[str, Any]) -> None:
        """Apply session data from login response.

        Args:
            resp: Login response dictionary containing at minimum:
                - sid: Session ID
                - lic_content_key: License content key for DRM decryption
                - high_quality: Optional flag for hi-fi access

        Note:
            ``lic_content_key`` may be absent from renewal responses
            (e.g. ``check.php``); in that case the previously applied
            key is retained.
        """
        self.sid = resp["sid"]
        key = resp.get("lic_content_key")
        if key:
            self.lic_content_key = key.encode("ascii")
        elif self.lic_content_key is None:
            logger.warning(
                "Session response missing lic_content_key and no prior key available"
            )
        self.available_qualities = ["128k", "192k", "320k"]
        if resp.get("high_quality"):
            self.available_qualities.extend(["hifi", "hires"])

    def restore_session(self) -> bool:
        """Restore session from saved data without verification.

        Returns:
            True if session was restored, False otherwise.
        """
        saved_resp = self.tsc.read("login_response")
        if saved_resp:
            self._apply_session(saved_resp)
            return True
        return False

    async def login(self, email: str, password: str) -> None:
        """Authenticate with KKBOX.

        Args:
            email: User email.
            password: User password.

        Raises:
            ModuleAuthError: If login fails.
        """
        # Try to restore saved session
        saved_resp = self.tsc.read("login_response")
        if saved_resp:
            self._apply_session(saved_resp)
            # Verify session is still valid
            test_resp = await self._api_call(
                "ticket",
                "v1/ticket",
                payload={
                    "sid": self.sid,
                    "song_id": "_a9RBgyQAvqjZBRKbm",
                    "ver": "06120082",
                    "os": "android",
                    "osver": "13",
                    "kkid": self.kkid,
                    "dist": "0021",
                    "dist2": "0021",
                    "timestamp": int(time()),
                    "play_mode": None,
                },
            )
            if test_resp and test_resp.get("status") != -1:
                return
            # Session expired, clear saved data
            self.tsc.set("login_response", None)

        # Perform fresh login
        pswd_hash = hash_password(password)

        resp = await self._api_call(
            "login",
            "login.php",
            payload={
                "uid": email,
                "passwd": pswd_hash,
                "kkid": self.kkid,
                "registration_id": "",
            },
        )

        if not resp:
            raise ModuleAuthError(module_name="kkbox")

        status = resp.get("status")
        if status == REGION_BLOCKED_STATUS:
            resp = await self._remote_login_fallback(email, pswd_hash)
            status = resp.get("status")

        if status not in (2, 3):
            raise ModuleAuthError(module_name="kkbox")

        # Save minimal session data and apply
        self.tsc.set("login_response", extract_session_data(resp))
        self._apply_session(resp)

    async def _remote_login_fallback(
        self, email: str, pswd_hash: str
    ) -> dict[str, Any]:
        """Recover login via a device in a supported region.

        When the host IP is region blocked (status -4), this shows a
        ready-to-run ``uvx`` command (with all credentials embedded as
        arguments) through the auth prompter. The user runs it on a device in
        a supported region; the standalone ``haberlea-kkbox`` tool performs
        the full login and KC1 decryption, verifies success, then prints a
        single short JSON line. Pasting that short JSON back avoids the
        terminal truncation that the full base64 response would cause.

        Args:
            email: User email address.
            pswd_hash: MD5-hashed password.

        Returns:
            A login response dict with ``status`` set to success and the
            ``sid``/``lic_content_key``/``high_quality`` fields populated from
            the remote tool's output.

        Raises:
            ModuleAuthError: If no or invalid session JSON is provided.
        """
        command = (
            'uvx --from "git+https://github.com/KyokoMiki/haberlea-kkbox" '
            f'remote-login "{email}" "{pswd_hash}" "{self.kkid}" '
            f'"{self.kc1_key.decode("ascii")}" "{self.secret_key.decode("ascii")}"'
        )
        raw = await self.auth_prompter.request_input(
            _REMOTE_LOGIN_PROMPT.format(command=command)
        )
        if not raw:
            raise ModuleAuthError("No session data provided for remote login")

        try:
            session: dict[str, Any] = msgspec.json.decode(raw)
        except msgspec.DecodeError as e:
            raise ModuleAuthError(f"Invalid session JSON for remote login: {e}") from e

        try:
            return {
                "status": 2,
                "sid": session["sid"],
                "lic_content_key": session["lic_content_key"],
                "high_quality": session.get("high_quality", 0),
            }
        except KeyError as e:
            raise ModuleAuthError(f"Session JSON missing required field: {e}") from e

    async def renew_session(self) -> None:
        """Renew the current session.

        Raises:
            ModuleAuthError: If session renewal fails.
        """
        resp = await self._api_call("login", "check.php")
        if not resp or resp.get("status") not in (2, 3):
            raise ModuleAuthError(module_name="kkbox")
        self._apply_session(resp)

    async def auth_device(self) -> None:
        """Authorize the current device.

        Raises:
            ModuleAPIError: If device authorization fails.
        """
        resp = await self._api_call(
            "ds",
            "active_sid.php",
            payload={
                "ui_lang": "en",
                "of": "j",
                "os": "android",
                "enc": "u",
                "sid": self.sid,
                "ver": "06120082",
                "kkid": self.kkid,
                "lang": "en",
                "oenc": "kc1",
                "osver": "13",
            },
        )
        if not resp or resp.get("status") != 1:
            raise ModuleAPIError(
                error_code=403,
                error_message="Couldn't authorize device",
                api_endpoint="active_sid.php",
                module_name="kkbox",
            )

    async def get_songs(self, ids: list[str]) -> list[dict[str, Any]]:
        """Get song metadata for multiple tracks.

        Args:
            ids: List of song IDs.

        Returns:
            List of song metadata dictionaries.

        Raises:
            ModuleAPIError: If the request fails.
        """
        resp = await self._api_call(
            "ds",
            "v2/song",
            payload={
                "ids": ",".join(ids),
                "fields": (
                    "artist_role,song_idx,album_photo_info,song_is_explicit,"
                    "song_more_url,album_more_url,artist_more_url,genre_name,"
                    "is_lyrics,audio_quality,song_lyrics_valid"
                ),
            },
        )
        if not resp or resp["status"]["type"] != "OK":
            raise ModuleAPIError(
                error_code=404,
                error_message="Track not found",
                api_endpoint="v2/song",
                module_name="kkbox",
            )
        return resp["data"]["songs"]

    async def get_song_lyrics(self, song_id: str) -> dict[str, Any]:
        """Get lyrics for a song.

        Args:
            song_id: Song identifier.

        Returns:
            Lyrics response dictionary.
        """
        resp = await self._api_call("ds", f"v1/song/{song_id}/lyrics")
        return resp or {}

    async def get_album(self, album_id: str) -> dict[str, Any]:
        """Get album metadata by encrypted ID.

        Args:
            album_id: Encrypted album identifier.

        Returns:
            Album data dictionary.

        Raises:
            ModuleAPIError: If the album is not found.
        """
        resp = await self._api_call("ds", f"v1/album/{album_id}")
        if not resp:
            raise ModuleAPIError(
                error_code=404,
                error_message="Album not found (empty response)",
                api_endpoint=f"v1/album/{album_id}",
                module_name="kkbox",
            )
        if resp.get("status", {}).get("type") != "OK":
            status_msg = resp.get("status", {}).get("message", "Unknown error")
            raise ModuleAPIError(
                error_code=404,
                error_message=f"Album not found: {status_msg}",
                api_endpoint=f"v1/album/{album_id}",
                module_name="kkbox",
            )
        return resp["data"]

    @retry(
        retry=retry_if_exception_type(SessionRetryableError),
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_fixed(0),
        reraise=True,
    )
    async def get_album_more(self, raw_id: int) -> dict[str, Any]:
        """Get detailed album metadata by raw ID.

        Args:
            raw_id: Raw album identifier.

        Returns:
            Detailed album data dictionary.

        Raises:
            SessionRetryableError: When retry is needed.
            ModuleAPIError: When request fails permanently.
        """
        resp = await self._api_call("ds", "album_more.php", params={"album": raw_id})
        if not resp:
            raise ModuleAPIError(
                error_code=500,
                error_message="Empty album_more response",
                api_endpoint="album_more.php",
                module_name="kkbox",
            )
        await self._handle_status_errors(resp, api_endpoint="album_more.php")
        return resp

    async def get_artist(self, artist_id: str) -> dict[str, Any]:
        """Get artist metadata.

        Args:
            artist_id: Artist identifier.

        Returns:
            Artist data dictionary.

        Raises:
            ModuleAPIError: If the artist is not found.
        """
        resp = await self._api_call("ds", f"v3/artist/{artist_id}")
        if not resp or resp["status"]["type"] != "OK":
            raise ModuleAPIError(
                error_code=404,
                error_message="Artist not found",
                api_endpoint=f"v3/artist/{artist_id}",
                module_name="kkbox",
            )
        return resp["data"]

    async def get_artist_albums(
        self, raw_id: int, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        """Get artist's albums with pagination.

        Args:
            raw_id: Raw artist identifier.
            limit: Maximum number of albums to return.
            offset: Offset for pagination.

        Returns:
            List of album dictionaries.

        Raises:
            ModuleAPIError: If the request fails.
        """
        resp = await self._api_call(
            "ds",
            f"v2/artist/{raw_id}/album",
            params={"limit": limit, "offset": offset},
        )
        if not resp or resp["status"]["type"] != "OK":
            raise ModuleAPIError(
                error_code=404,
                error_message="Artist not found",
                api_endpoint=f"v2/artist/{raw_id}/album",
                module_name="kkbox",
            )
        return resp["data"]["album"]

    async def get_playlists(self, ids: list[str]) -> list[dict[str, Any]]:
        """Get playlist metadata for multiple playlists.

        Args:
            ids: List of playlist IDs.

        Returns:
            List of playlist dictionaries.

        Raises:
            ModuleAPIError: If the request fails.
        """
        resp = await self._api_call(
            "ds", "v1/playlists", params={"playlist_ids": ",".join(ids)}
        )
        if not resp or resp["status"]["type"] != "OK":
            raise ModuleAPIError(
                error_code=404,
                error_message="Playlist not found",
                api_endpoint="v1/playlists",
                module_name="kkbox",
            )
        return resp["data"]["playlists"]

    async def search(self, query: str, types: list[str], limit: int) -> dict[str, Any]:
        """Search for content.

        Args:
            query: Search query string.
            types: List of content types to search (song, album, artist, playlist).
            limit: Maximum number of results per type.

        Returns:
            Search results dictionary.
        """
        resp = await self._api_call(
            "ds",
            "search_music.php",
            params={
                "sf": ",".join(types),
                "limit": limit,
                "query": query,
                "search_ranking": "sc-A",
            },
        )
        return resp or {}

    async def _handle_status_errors(
        self,
        resp: dict[str, Any],
        *,
        api_endpoint: str,
        fail_message: str = "Request failed",
        fail_error_code: int = 403,
    ) -> None:
        """Handle common KKBOX status codes with session/auth recovery.

        Args:
            resp: API response dictionary containing a ``status`` field.
            api_endpoint: Endpoint name for error reporting.
            fail_message: Message to use when status indicates permanent failure.
            fail_error_code: Error code to use when status indicates permanent failure.

        Raises:
            SessionRetryableError: When the caller should retry after recovery.
            ModuleAPIError: When the request failed permanently.
        """
        status = resp.get("status")
        if status == 1 or status is None:
            return
        if status == -1:
            await self.renew_session()
            raise SessionRetryableError("Session expired, renewed and retrying")
        if status == -4:
            await self.auth_device()
            raise SessionRetryableError("Device unauthorized, authorized and retrying")
        if status == 2:
            # Rate limiting, wait before retry
            await anyio.sleep(0.5)
            raise SessionRetryableError("Rate limited, retrying after delay")
        raise ModuleAPIError(
            error_code=fail_error_code,
            error_message=fail_message,
            api_endpoint=api_endpoint,
            module_name="kkbox",
        )

    @retry(
        retry=retry_if_exception_type(SessionRetryableError),
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_fixed(0),
        reraise=True,
    )
    async def _get_ticket_with_retry(
        self, song_id: str, play_mode: str | None
    ) -> dict[str, Any]:
        """Get ticket with automatic retry on specific errors.

        Args:
            song_id: Song identifier.
            play_mode: Optional play mode.

        Returns:
            Response dictionary from ticket API.

        Raises:
            SessionRetryableError: When retry is needed.
            ModuleAPIError: When request fails permanently.
        """
        resp = await self._api_call(
            "ticket",
            "v1/ticket",
            payload={
                "sid": self.sid,
                "song_id": song_id,
                "ver": "06120082",
                "os": "android",
                "osver": "13",
                "kkid": self.kkid,
                "dist": "0021",
                "dist2": "0021",
                "timestamp": int(time()),
                "play_mode": play_mode,
            },
        )

        if not resp:
            raise ModuleAPIError(
                error_code=500,
                error_message="Empty ticket response",
                api_endpoint="v1/ticket",
                module_name="kkbox",
            )

        await self._handle_status_errors(
            resp,
            api_endpoint="v1/ticket",
            fail_message="Couldn't get track URLs",
        )
        return resp

    async def get_ticket(
        self, song_id: str, play_mode: str | None = None
    ) -> list[dict[str, Any]]:
        """Get streaming ticket (URLs) for a song.

        Args:
            song_id: Song identifier.
            play_mode: Optional play mode (e.g., "chromecast").

        Returns:
            List of available format URLs.

        Raises:
            ModuleAPIError: If the ticket cannot be obtained or max retries exceeded.
        """
        try:
            resp = await self._get_ticket_with_retry(song_id, play_mode)
            return resp["uris"]
        except RetryError as e:
            # Max retries exceeded
            raise ModuleAPIError(
                error_code=403,
                error_message=f"Max retries ({MAX_RETRIES}) exceeded for get_ticket",
                api_endpoint="v1/ticket",
                module_name="kkbox",
            ) from e

    def _create_kkdrm_decryptor(self) -> KkdrmDecryptor:
        """Create a chunk processor for KKDRM RC4 decryption.

        Returns:
            KkdrmDecryptor instance for use with download_file.

        Raises:
            ModuleAPIError: If not authenticated (no license key).
        """
        if self.lic_content_key is None:
            raise ModuleAPIError(
                error_code=401,
                error_message="Not authenticated, no license key available",
                api_endpoint="download",
                module_name="kkbox",
            )
        return KkdrmDecryptor(self.lic_content_key)

    async def download_kkdrm(
        self,
        url: str,
        target_path: Path,
    ) -> None:
        """Download and decrypt a KKDRM protected file with streaming decryption.

        Decrypts during download: skips first 1024 bytes, then RC4 decrypts.

        Args:
            url: URL of the encrypted file.
            target_path: Path to save the decrypted file.
        """
        chunk_processor = self._create_kkdrm_decryptor()

        await download_file(
            url,
            target_path,
            config=DownloadConfig(chunk_processor=chunk_processor),
            session=self.session,
        )

        # Clean FLAC metadata if applicable
        if target_path.suffix.lower() == ".flac":
            await run_sync(self._clean_flac_metadata, target_path)

    def _clean_flac_metadata(self, file_path: Path) -> None:
        """Remove all metadata tags from a FLAC file.

        Args:
            file_path: Path to the FLAC file.
        """
        try:
            audio = FLAC(str(file_path))
            audio.clear()
            audio.save()
        except Exception as e:
            # Log the error but don't fail the download
            logger.exception("Failed to clean FLAC metadata for %s: %s", file_path, e)
