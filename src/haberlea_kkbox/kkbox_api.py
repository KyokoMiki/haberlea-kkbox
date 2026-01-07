"""KKBOX API client for authentication and data retrieval.

This module provides an async KKBOX API client using aiohttp,
handling authentication, content retrieval, and DRM decryption.
"""

import asyncio
import logging
import os
import re
from random import randrange
from time import time
from typing import Any

import msgspec
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import MD5
from mutagen.flac import FLAC
from tenacity import (
    RetryError,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_fixed,
)

from haberlea.utils.exceptions import ModuleAPIError, ModuleAuthError, ModuleError
from haberlea.utils.models import TemporarySettingsController
from haberlea.utils.utils import create_aiohttp_session, download_file

logger = logging.getLogger(__name__)

# Maximum number of retries for get_ticket
MAX_RETRIES = 5


class TicketRetryableError(ModuleError):
    """Exception to signal that ticket request should be retried."""


class KkboxAPI:
    """Async KKBOX API client.

    Handles authentication and API requests to the KKBOX music service.

    Args:
        kc1_key: KC1 decryption key (32-character hex string).
        secret_key: API secret key (32-character hex string).
        tsc: Temporary settings controller for session persistence.
        kkid: Device identifier. Generated if not provided.
    """

    def __init__(
        self,
        kc1_key: str,
        secret_key: str,
        tsc: TemporarySettingsController,
        kkid: str | None = None,
    ) -> None:
        """Initialize the KKBOX API client.

        Args:
            kc1_key: KC1 decryption key (32-character hex string).
            secret_key: API secret key (32-character hex string).
            tsc: Temporary settings controller for session persistence.
            kkid: Device identifier. Generated if not provided.

        Raises:
            ModuleAPIError: If kc1_key or secret_key is invalid.
        """
        self.tsc = tsc
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
        self.kkid = kkid or f"{randrange(16**32):032X}"
        self.session = create_aiohttp_session()

        self._headers = {"user-agent": "okhttp/3.14.9"}
        self.sid: str | None = None
        self.lic_content_key: bytes | None = None
        self.available_qualities: list[str] = []

        self._base_params: dict[str, str] = {
            "enc": "u",
            "ver": "06120082",
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

    async def close(self) -> None:
        """Close the aiohttp session."""
        if not self.session.closed:
            await self.session.close()

    def _kc1_decrypt(self, data: bytes) -> str:
        """Decrypt KC1 encrypted data.

        Args:
            data: Encrypted bytes.

        Returns:
            Decrypted string.
        """
        cipher = ARC4.new(self.kc1_key)
        return cipher.decrypt(data).decode("utf-8")

    def _create_secret(self) -> str:
        """Create API request secret hash.

        Returns:
            MD5 hash string for API authentication.
        """
        timestamp = int(time())
        md5 = MD5.new()
        md5.update(self._base_params["ver"].encode("ascii"))
        md5.update(str(timestamp).encode("ascii"))
        md5.update(self.secret_key)
        return md5.hexdigest()

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

        timestamp = int(time())
        request_params = {**self._base_params, **params}
        request_params["secret"] = self._create_secret()
        request_params["timestamp"] = str(timestamp)

        if self.sid:
            request_params["sid"] = self.sid

        url = f"https://api-{host}.kkbox.com.tw/{path}"

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
                        return msgspec.json.decode(self._kc1_decrypt(content))
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
                        return msgspec.json.decode(self._kc1_decrypt(content))
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
                    return msgspec.json.decode(self._kc1_decrypt(content))

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
        """
        self.sid = resp["sid"]
        self.lic_content_key = resp["lic_content_key"].encode("ascii")
        self.available_qualities = ["128k", "192k", "320k"]
        if resp.get("high_quality"):
            self.available_qualities.extend(["hifi", "hires"])

    def _extract_session_data(self, resp: dict[str, Any]) -> dict[str, Any]:
        """Extract minimal session data needed for restoration.

        Args:
            resp: Full login response dictionary.

        Returns:
            Dictionary containing only the fields needed for session restoration.
        """
        return {
            "sid": resp["sid"],
            "lic_content_key": resp["lic_content_key"],
            "high_quality": resp.get("high_quality", 0),
        }

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
        md5 = MD5.new()
        md5.update(password.encode("utf-8"))
        pswd_hash = md5.hexdigest()

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
        if status not in (2, 3):
            raise ModuleAuthError(module_name="kkbox")

        # Save minimal session data and apply
        self.tsc.set("login_response", self._extract_session_data(resp))
        self._apply_session(resp)

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

    async def get_album_more(self, raw_id: int) -> dict[str, Any]:
        """Get detailed album metadata by raw ID.

        Args:
            raw_id: Raw album identifier.

        Returns:
            Detailed album data dictionary.
        """
        resp = await self._api_call("ds", "album_more.php", params={"album": raw_id})
        return resp or {}

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

    @retry(
        retry=retry_if_exception_type(TicketRetryableError),
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
            TicketRetryableError: When retry is needed.
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

        status = resp.get("status")
        if status == -1:
            await self.renew_session()
            raise TicketRetryableError("Session expired, renewed and retrying")
        elif status == -4:
            await self.auth_device()
            raise TicketRetryableError("Device unauthorized, authorized and retrying")
        elif status == 2:
            # Rate limiting, wait before retry
            await asyncio.sleep(0.5)
            raise TicketRetryableError("Rate limited, retrying after delay")
        elif status != 1:
            raise ModuleAPIError(
                error_code=403,
                error_message="Couldn't get track URLs",
                api_endpoint="v1/ticket",
                module_name="kkbox",
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

    async def download_kkdrm(
        self,
        url: str,
        target_path: str,
    ) -> None:
        """Download and decrypt a KKDRM protected file.

        Downloads the encrypted file using download_file for progress reporting,
        then decrypts it in place.

        Args:
            url: URL of the encrypted file.
            target_path: Path to save the decrypted file.
        """
        if self.lic_content_key is None:
            raise ModuleAPIError(
                error_code=401,
                error_message="Not authenticated, no license key available",
                api_endpoint="download",
                module_name="kkbox",
            )

        # Download encrypted file with progress reporting
        temp_path = target_path + ".kkdrm"
        try:
            await download_file(url, temp_path, session=self.session)

            # Decrypt in thread pool (read, decrypt, write)
            await asyncio.to_thread(self._decrypt_kkdrm_file, temp_path, target_path)
        finally:
            # Always remove temp file if it exists
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # Clean FLAC metadata if applicable
        if target_path.lower().endswith(".flac"):
            await asyncio.to_thread(self._clean_flac_metadata, target_path)

    def _decrypt_kkdrm_file(self, input_path: str, output_path: str) -> None:
        """Decrypt a KKDRM file.

        Args:
            input_path: Path to encrypted file.
            output_path: Path to save decrypted file.
        """
        if self.lic_content_key is None:
            raise ValueError("License content key is not set")

        with open(input_path, "rb") as f_in:
            # Skip first 1024 bytes
            f_in.seek(1024)
            encrypted_data = f_in.read()

        rc4 = ARC4.new(self.lic_content_key, drop=512)
        decrypted_data = rc4.decrypt(encrypted_data)

        with open(output_path, "wb") as f_out:
            f_out.write(decrypted_data)

    def _decrypt_kkdrm(self, encrypted_data: bytes) -> bytes:
        """Decrypt KKDRM data.

        Args:
            encrypted_data: The encrypted bytes to decrypt (already skipped 1024).

        Returns:
            Decrypted bytes.

        Note:
            This method is kept for backward compatibility.
        """
        if self.lic_content_key is None:
            raise ValueError("License content key is not set")

        rc4 = ARC4.new(self.lic_content_key, drop=512)
        return rc4.decrypt(encrypted_data)

    def _clean_flac_metadata(self, file_path: str) -> None:
        """Remove all metadata tags from a FLAC file.

        Args:
            file_path: Path to the FLAC file.
        """
        try:
            audio = FLAC(file_path)
            audio.clear()
            audio.save()
        except Exception as e:
            # Log the error but don't fail the download
            logger.exception("Failed to clean FLAC metadata for %s: %s", file_path, e)
