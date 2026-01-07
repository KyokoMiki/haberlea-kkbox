"""KKBOX module interface for Haberlea.

This module implements the ModuleBase interface for the KKBOX music service,
providing async methods for authentication, metadata retrieval, and downloading.
"""

import re
from typing import Any
from urllib.parse import urlparse

from rich import print

from haberlea.plugins.base import ModuleBase
from haberlea.utils.models import (
    AlbumInfo,
    ArtistInfo,
    CodecEnum,
    CodecOptions,
    CoverInfo,
    CoverOptions,
    DownloadEnum,
    DownloadTypeEnum,
    ImageFileTypeEnum,
    LyricsInfo,
    ManualEnum,
    MediaIdentification,
    ModuleController,
    ModuleInformation,
    ModuleModes,
    PlaylistInfo,
    QualityEnum,
    SearchResult,
    Tags,
    TrackDownloadInfo,
    TrackInfo,
)
from haberlea.utils.tempfile_manager import TempFileManager

from .kkbox_api import KkboxAPI

module_information = ModuleInformation(
    service_name="KKBOX",
    module_supported_modes=(
        ModuleModes.download | ModuleModes.lyrics | ModuleModes.covers
    ),
    global_settings={
        "kc1_key": "7f1a68f00b747f4ac1469c72e7ef492c",
        "secret_key": "0ff29b7c9bd8fb60a3abd6b3d402b02c",
    },
    session_settings={"email": "", "password": ""},
    session_storage_variables=["kkid", "login_response"],
    netlocation_constant="kkbox",
    url_constants={
        "track": DownloadTypeEnum.track,
        "song": DownloadTypeEnum.track,
        "album": DownloadTypeEnum.album,
        "artist": DownloadTypeEnum.artist,
        "playlist": DownloadTypeEnum.playlist,
    },
    url_decoding=ManualEnum.manual,
    test_url="https://play.kkbox.com/album/OspOC7CYqcVQY_uLAV",
)


def _clean_artist_name(name: str) -> str:
    """Clean artist name by removing parenthesized translations.

    KKBOX often includes Chinese translations in parentheses, e.g.,
    "Arcade Fire (拱廊之火樂團)" -> "Arcade Fire"

    Args:
        name: Artist name possibly containing parenthesized translation.

    Returns:
        Cleaned artist name.
    """
    # Remove trailing parenthesized content (Chinese translations)
    # Match pattern: " (中文)" at the end of the string
    cleaned = re.sub(r"\s*\([^)]*[\u4e00-\u9fff][^)]*\)\s*$", "", name)
    return cleaned.strip()


def _build_cover_url(
    url_template: str,
    size: int,
    file_type: ImageFileTypeEnum,
) -> str:
    """Build cover image URL from template.

    Args:
        url_template: URL template with placeholders.
        size: Desired image size in pixels.
        file_type: Desired image format.

    Returns:
        Formatted cover URL.
    """
    url = url_template
    if size > 2048:
        url = url.replace("fit/{width}x{height}", "original")
        url = url.replace("cropresize/{width}x{height}", "original")
    else:
        url = url.replace("{width}", str(size))
        url = url.replace("{height}", str(size))
    url = url.replace("{format}", file_type.name)
    return url


def _extract_main_artists(artist_role: dict[str, Any]) -> list[str]:
    """Extract main artist names from artist_role data.

    Args:
        artist_role: Artist role dictionary from API response.

    Returns:
        List of cleaned main artist names.
    """
    artists: list[str] = []

    # Handle mainartist_list format
    if "mainartist_list" in artist_role:
        main_artists = artist_role["mainartist_list"].get("mainartist", [])
        if isinstance(main_artists, list):
            artists.extend(_clean_artist_name(a) for a in main_artists)
        elif main_artists:
            artists.append(_clean_artist_name(main_artists))
    elif "mainartists" in artist_role:
        main_artists = artist_role["mainartists"]
        if isinstance(main_artists, list):
            artists.extend(_clean_artist_name(a) for a in main_artists)
        elif main_artists:
            artists.append(_clean_artist_name(main_artists))

    return artists


def _extract_featured_artists(artist_role: dict[str, Any]) -> list[str]:
    """Extract featured artist names from artist_role data.

    Args:
        artist_role: Artist role dictionary from API response.

    Returns:
        List of cleaned featured artist names.
    """
    artists: list[str] = []

    # Handle featuredartist_list format
    if "featuredartist_list" in artist_role:
        featured = artist_role["featuredartist_list"].get("featuredartist", [])
        if isinstance(featured, list):
            artists.extend(_clean_artist_name(a) for a in featured)
        elif featured:
            artists.append(_clean_artist_name(featured))
    elif "featuredartists" in artist_role:
        featured = artist_role["featuredartists"]
        if isinstance(featured, list):
            artists.extend(_clean_artist_name(a) for a in featured)
        elif featured:
            artists.append(_clean_artist_name(featured))

    return artists


def _extract_artists(artist_role: dict[str, Any]) -> list[str]:
    """Extract artist names from artist_role data.

    Args:
        artist_role: Artist role dictionary from API response.

    Returns:
        List of cleaned artist names.
    """
    artists: list[str] = []

    # Extract main artists
    artists.extend(_extract_main_artists(artist_role))

    # Extract featured artists
    artists.extend(_extract_featured_artists(artist_role))

    return artists


class ModuleInterface(ModuleBase):
    """KKBOX module interface implementation.

    Handles authentication, metadata retrieval, and track downloading
    from the KKBOX music streaming service.
    """

    def __init__(self, module_controller: ModuleController) -> None:
        """Initialize the KKBOX module.

        Args:
            module_controller: Controller providing access to settings and resources.
        """
        super().__init__(module_controller)
        settings = module_controller.module_settings
        tsc = module_controller.temporary_settings_controller

        self.default_cover = module_controller.haberlea_options.default_cover_options
        self.check_sub = (
            not module_controller.haberlea_options.disable_subscription_check
        )

        # KKBOX doesn't support webp covers -
        # create a copy to avoid mutating shared options
        if self.default_cover.file_type is ImageFileTypeEnum.webp:
            self.default_cover = CoverOptions(
                file_type=ImageFileTypeEnum.jpg,
                resolution=self.default_cover.resolution,
                compression=self.default_cover.compression,
            )

        self.quality_map: dict[QualityEnum, str] = {
            QualityEnum.MINIMUM: "128k",
            QualityEnum.LOW: "128k",
            QualityEnum.MEDIUM: "192k",
            QualityEnum.HIGH: "320k",
            QualityEnum.LOSSLESS: "hifi",
            QualityEnum.HIFI: "hires",
        }

        self.current_quality = self.quality_map[
            module_controller.haberlea_options.quality_tier
        ]

        # Initialize API client
        kkid = tsc.read("kkid")
        self.api = KkboxAPI(
            kc1_key=settings["kc1_key"],
            secret_key=settings["secret_key"],
            tsc=tsc,
            kkid=kkid,
        )

        # Save kkid if newly generated
        if not kkid:
            tsc.set("kkid", self.api.kkid)
        else:
            # Restore session from saved data if available
            self.api.restore_session()

        self.temp_manager = TempFileManager()

    async def close(self) -> None:
        """Close the module and release resources."""
        await self.api.close()
        await self.temp_manager.cleanup()

    def custom_url_parse(self, url: str) -> MediaIdentification | None:
        """Parse a KKBOX URL to extract media type and ID.

        Args:
            url: The URL to parse.

        Returns:
            MediaIdentification with parsed media info, or None if invalid.
        """
        parsed = urlparse(url)
        path_match = None

        if parsed.hostname == "play.kkbox.com":
            path_match = re.match(
                r"^\/(track|album|artist|playlist)\/([a-zA-Z0-9-_]+)",
                parsed.path,
            )
        elif parsed.hostname == "www.kkbox.com":
            path_match = re.match(
                r"^\/[a-z]{2}\/[a-z]{2}\/(song|album|artist|playlist)"
                r"\/([a-zA-Z0-9-_]+)",
                parsed.path,
            )

        if not path_match:
            return None

        media_type_str = path_match.group(1)
        if media_type_str == "song":
            media_type_str = "track"

        return MediaIdentification(
            media_type=DownloadTypeEnum[media_type_str],
            media_id=path_match.group(2),
            original_url=url,
        )

    async def login(self, email: str, password: str) -> None:
        """Authenticate with KKBOX.

        Args:
            email: User email.
            password: User password.
        """
        await self.api.login(email, password)

        if self.check_sub and self.current_quality not in self.api.available_qualities:
            print(
                "KKBOX: quality set in settings is not accessible "
                "by the current subscription"
            )

    async def get_track_info(
        self,
        track_id: str,
        quality_tier: QualityEnum,
        codec_options: CodecOptions,
        data: dict[str, Any] | None = None,
    ) -> TrackInfo:
        """Get track information and metadata.

        Args:
            track_id: Track identifier.
            quality_tier: Desired audio quality.
            codec_options: Codec preference options (unused).
            data: Optional pre-fetched track data.

        Returns:
            TrackInfo with metadata and download information.
        """
        quality = self.quality_map[quality_tier]

        # Get track data
        track_data: dict[str, Any]
        album_info: dict[str, Any]

        if data and track_id in data:
            track_data = data[track_id]
            album_info = data.get("_album_info", {})
        else:
            songs = await self.api.get_songs([track_id])
            track_data = songs[0]
            album_info = {}

        # Get album info if not provided
        if not album_info:
            album_id = track_data.get("raw_album_id") or int(track_data["album_id"])
            album_data = await self.api.get_album_more(album_id)
            album_info = album_data["info"]
            album_info["num_tracks"] = len(album_data["song_list"]["song"])

        # Extract artists
        artist_role = track_data.get("artist_role", {})
        artists = _extract_artists(artist_role)
        if not artists:
            raw_name = album_info.get("artist_name", "Unknown Artist")
            artists = [_clean_artist_name(raw_name)]

        # Build tags
        genre_name = track_data.get("genre_name")
        album_artist = _clean_artist_name(album_info.get("artist_name", ""))
        tags = Tags(
            album_artist=album_artist if album_artist else None,
            track_number=int(track_data.get("song_idx", 1)),
            total_tracks=album_info.get("num_tracks"),
            genres=[genre_name] if genre_name else None,
            release_date=album_info.get("album_date"),
        )

        # Determine actual quality
        available_qualities = track_data.get("audio_quality", [])
        if quality not in available_qualities and available_qualities:
            quality = available_qualities[-1]

        # Check subscription
        error = None
        if quality not in self.api.available_qualities:
            error = "Quality not available by your subscription"

        # Map quality to codec
        codec_map: dict[str, CodecEnum] = {
            "128k": CodecEnum.MP3,
            "192k": CodecEnum.MP3,
            "320k": CodecEnum.AAC,
            "hifi": CodecEnum.FLAC,
            "hires": CodecEnum.FLAC,
        }
        codec = codec_map.get(quality, CodecEnum.MP3)

        bitrate_map: dict[str, int | None] = {
            "128k": 128,
            "192k": 192,
            "320k": 320,
            "hifi": 1411,
            "hires": None,
        }
        bitrate = bitrate_map.get(quality)

        # Build cover URL
        cover_template = track_data.get("album_photo_info", {}).get("url_template", "")
        cover_url = _build_cover_url(
            cover_template,
            self.default_cover.resolution,
            self.default_cover.file_type,
        )

        # Extract IDs from URLs
        song_url = track_data.get("song_more_url", "")
        album_url = album_info.get("album_more_url", "")
        artist_url = album_info.get("artist_more_url", "")

        song_enc_id = song_url.split("/")[-1] if song_url else track_id
        album_enc_id = album_url.split("/")[-1] if album_url else ""
        artist_enc_id = artist_url.split("/")[-1] if artist_url else ""

        return TrackInfo(
            name=track_data.get("song_name") or track_data.get("text", "Unknown"),
            album_id=album_enc_id,
            album=album_info.get("album_name", "Unknown Album"),
            artists=artists,
            tags=tags,
            codec=codec,
            cover_url=cover_url,
            release_year=int(album_info.get("album_date", "2000").split("-")[0]),
            explicit=bool(track_data.get("song_is_explicit")),
            artist_id=artist_enc_id,
            bit_depth=24 if quality == "hires" else 16,
            sample_rate=44.1,
            bitrate=bitrate,
            download_data={"song_id": song_enc_id, "quality": quality},
            cover_data={"url_template": cover_template},
            lyrics_data={
                "has_lyrics": track_data.get("is_lyrics", False),
                "lyrics_valid": track_data.get("song_lyrics_valid", 0),
            },
            error=error,
        )

    async def get_track_download(
        self,
        target_path: str,
        url: str = "",
        data: dict[str, Any] | None = None,
    ) -> TrackDownloadInfo:
        """Download track file.

        Args:
            target_path: Target file path for direct download.
            url: The URL to download the track from (unused, uses data instead).
            data: Download data containing song_id and quality.

        Returns:
            TrackDownloadInfo indicating download type.
        """
        if not data:
            raise ValueError("Download data is required for KKBOX tracks")

        song_id = data["song_id"]
        quality = data["quality"]

        # Map quality to format name
        format_map: dict[str, str] = {
            "128k": "mp3_128k_chromecast",
            "192k": "mp3_192k_kkdrm1",
            "320k": "aac_320k_m4a_kkdrm1",
            "hifi": "flac_16_download_kkdrm",
            "hires": "flac_24_download_kkdrm",
        }
        target_format = format_map.get(quality, "mp3_128k_chromecast")

        # Get play mode for DRM-free MP3
        play_mode = "chromecast" if target_format == "mp3_128k_chromecast" else None

        # Get streaming URLs
        uris = await self.api.get_ticket(song_id, play_mode)

        # Find matching format URL
        download_url = None
        for fmt in uris:
            if fmt.get("name") == target_format:
                download_url = fmt.get("url")
                break

        if not download_url:
            raise ValueError(f"Format {target_format} not available for this track")

        # DRM-free MP3 can be downloaded directly
        if target_format == "mp3_128k_chromecast":
            return TrackDownloadInfo(
                download_type=DownloadEnum.URL,
                file_url=download_url,
            )

        # Download and decrypt KKDRM protected file
        await self.api.download_kkdrm(download_url, target_path)

        return TrackDownloadInfo(download_type=DownloadEnum.DIRECT)

    async def get_album_info(
        self,
        album_id: str,
        data: dict[str, Any] | None = None,
    ) -> AlbumInfo:
        """Get album information and track list.

        Args:
            album_id: Album identifier (encrypted ID).
            data: Optional pre-fetched data containing raw_ids mapping.

        Returns:
            AlbumInfo with metadata and track list.
        """
        # Get raw album ID
        raw_id: int
        if data and "raw_ids" in data:
            raw_id_val = data["raw_ids"].get(album_id)
            if raw_id_val is not None:
                raw_id = raw_id_val
            else:
                album_basic = await self.api.get_album(album_id)
                raw_id = album_basic["album"]["album_id"]
        else:
            album_basic = await self.api.get_album(album_id)
            raw_id = album_basic["album"]["album_id"]

        # Get detailed album info
        album_data = await self.api.get_album_more(raw_id)
        info = album_data["info"]

        # Build track list and data
        track_ids: list[str] = []
        track_data: dict[str, Any] = {"_album_info": info}
        total_duration = 0

        for song in album_data["song_list"]["song"]:
            song_url = song.get("song_more_url", "")
            song_id = song_url.split("/")[-1] if song_url else ""
            if song_id:
                track_ids.append(song_id)
                track_data[song_id] = song
                total_duration += song.get("duration_ms", 0)

        info["num_tracks"] = len(track_ids)

        # Build cover URL
        cover_template = info.get("album_photo_info", {}).get("url_template", "")
        cover_url = _build_cover_url(
            cover_template,
            self.default_cover.resolution,
            self.default_cover.file_type,
        )
        jpg_cover_url = _build_cover_url(
            cover_template,
            self.default_cover.resolution,
            ImageFileTypeEnum.jpg,
        )

        # Extract artist ID
        artist_url = info.get("artist_more_url", "")
        artist_id = artist_url.split("/")[-1] if artist_url else None

        return AlbumInfo(
            name=info.get("album_name", "Unknown Album"),
            artist=_clean_artist_name(info.get("artist_name", "Unknown Artist")),
            tracks=track_ids,
            duration=int(total_duration / 1000) if total_duration else None,
            release_year=int(info.get("album_date", "2000").split("-")[0]),
            explicit=bool(info.get("album_is_explicit")),
            artist_id=artist_id,
            cover_url=cover_url,
            cover_type=self.default_cover.file_type,
            all_track_cover_jpg_url=jpg_cover_url,
            description=info.get("album_descr"),
            track_data=track_data,
        )

    async def get_playlist_info(self, playlist_id: str) -> PlaylistInfo:
        """Get playlist information and track list.

        Args:
            playlist_id: Playlist identifier.

        Returns:
            PlaylistInfo with metadata and track list.
        """
        playlists = await self.api.get_playlists([playlist_id])
        playlist_data = playlists[0]

        # Build track list and data
        track_ids: list[str] = []
        track_data: dict[str, Any] = {}

        for song in playlist_data.get("songs", []):
            song_url = song.get("song_more_url", "")
            song_id = song_url.split("/")[-1] if song_url else ""
            if song_id:
                track_ids.append(song_id)
                track_data[song_id] = song

        # Build cover URL
        cover_template = playlist_data.get("cover_photo_info", {}).get(
            "url_template", ""
        )
        cover_url = _build_cover_url(
            cover_template,
            self.default_cover.resolution,
            self.default_cover.file_type,
        )

        # Extract creator info
        user = playlist_data.get("user")
        creator = user.get("name") if user else None
        creator_id = user.get("id") if user else None

        # Parse creation year
        created_at = playlist_data.get("created_at", "2000")
        release_year = int(created_at.split("-")[0])

        return PlaylistInfo(
            name=playlist_data.get("title", "Unknown Playlist"),
            creator=creator or "Unknown",
            tracks=track_ids,
            release_year=release_year,
            creator_id=creator_id,
            cover_url=cover_url,
            cover_type=self.default_cover.file_type,
            description=playlist_data.get("content"),
            track_data=track_data,
        )

    async def get_artist_info(
        self,
        artist_id: str,
        get_credited_albums: bool = False,
    ) -> ArtistInfo:
        """Get artist information and discography.

        Args:
            artist_id: Artist identifier.
            get_credited_albums: Whether to include credited albums (unused).

        Returns:
            ArtistInfo with metadata and album list.
        """
        artist_data = await self.api.get_artist(artist_id)
        profile = artist_data.get("profile", {})
        albums = artist_data.get("album", [])

        # Fetch additional albums if needed (initial response limited to 10)
        if len(albums) == 10:
            raw_artist_id = profile.get("artist_id")
            if raw_artist_id:
                more_albums = await self.api.get_artist_albums(
                    raw_artist_id, limit=8008135, offset=10
                )
                albums.extend(more_albums)

        # Build album list and raw ID mapping
        album_ids: list[str] = []
        album_data: dict[str, Any] = {"raw_ids": {}}

        for album in albums:
            enc_id = album.get("encrypted_album_id", "")
            raw_id = album.get("album_id")
            if enc_id:
                album_ids.append(enc_id)
                if raw_id:
                    album_data["raw_ids"][enc_id] = raw_id

        return ArtistInfo(
            name=profile.get("artist_name", "Unknown Artist"),
            albums=album_ids,
            album_data=album_data,
        )

    async def get_track_cover(
        self,
        track_id: str,
        cover_options: CoverOptions,
        data: dict[str, Any] | None = None,
    ) -> CoverInfo:
        """Get track cover image information.

        Args:
            track_id: Track identifier.
            cover_options: Cover image options.
            data: Optional pre-fetched data with url_template.

        Returns:
            CoverInfo with cover URL and file type.
        """
        url_template = ""
        if data:
            url_template = data.get("url_template", "")

        if not url_template:
            songs = await self.api.get_songs([track_id])
            url_template = songs[0].get("album_photo_info", {}).get("url_template", "")

        url = _build_cover_url(
            url_template,
            cover_options.resolution,
            cover_options.file_type,
        )

        return CoverInfo(url=url, file_type=cover_options.file_type)

    async def get_track_lyrics(
        self,
        track_id: str,
        data: dict[str, Any] | None = None,
    ) -> LyricsInfo:
        """Get track lyrics.

        Args:
            track_id: Track identifier.
            data: Optional pre-fetched data with lyrics availability info.

        Returns:
            LyricsInfo with embedded and/or synced lyrics.
        """
        # Check if lyrics are available
        if data and (not data.get("has_lyrics") or data.get("lyrics_valid") == 0):
            return LyricsInfo()

        resp = await self.api.get_song_lyrics(track_id)
        if resp.get("status", {}).get("type") != "OK":
            return LyricsInfo()

        lyrics_data = resp.get("data", {}).get("lyrics", [])
        if not lyrics_data:
            return LyricsInfo()

        embedded_lines: list[str] = []
        synced_lines: list[str] = []

        for line in lyrics_data:
            content = line.get("content", "")
            if not content:
                embedded_lines.append("")
                synced_lines.append("")
                continue

            # Format timestamp for synced lyrics
            start_time = line.get("start_time", 0)
            minutes = int(start_time / (1000 * 60))
            seconds = int(start_time / 1000) % 60
            centiseconds = (start_time % 1000) // 10
            time_tag = f"[{minutes:02d}:{seconds:02d}.{centiseconds:02d}]"

            embedded_lines.append(content)
            synced_lines.append(f"{time_tag}{content}")

        return LyricsInfo(
            embedded="\n".join(embedded_lines) if embedded_lines else None,
            synced="\n".join(synced_lines) if synced_lines else None,
        )

    async def search(
        self,
        query_type: DownloadTypeEnum,
        query: str,
        track_info: TrackInfo | None = None,
        limit: int = 10,
    ) -> list[SearchResult]:
        """Search for content on KKBOX.

        Args:
            query_type: Type of content to search for.
            query: Search query string.
            track_info: Optional track info (unused, KKBOX doesn't support ISRC).
            limit: Maximum number of results.

        Returns:
            List of SearchResult objects.
        """
        # Map query type to KKBOX search type
        search_type = query_type.name
        if search_type == "track":
            search_type = "song"

        results = await self.api.search(query, [search_type], limit)
        result_key = f"{search_type}_list"
        items = results.get(result_key, {}).get(search_type, [])

        search_results: list[SearchResult] = []

        if search_type == "song":
            for item in items:
                artists = _extract_artists(item.get("artist_role", {}))
                song_url = item.get("song_more_url", "")
                song_id = song_url.split("/")[-1] if song_url else ""

                search_results.append(
                    SearchResult(
                        result_id=song_id,
                        name=item.get("song_name"),
                        artists=artists if artists else None,
                        explicit=bool(item.get("song_is_explicit")),
                        additional=[item.get("album_name")]
                        if item.get("album_name")
                        else None,
                        data={song_id: item} if song_id else None,
                    )
                )

        elif search_type == "album":
            for item in items:
                album_url = item.get("album_more_url", "")
                album_id = album_url.split("/")[-1] if album_url else ""
                raw_id = item.get("album_id")

                search_results.append(
                    SearchResult(
                        result_id=album_id,
                        name=item.get("album_name"),
                        artists=[item.get("artist_name")]
                        if item.get("artist_name")
                        else None,
                        explicit=bool(item.get("album_is_explicit")),
                        data={"raw_ids": {album_id: raw_id}} if raw_id else None,
                    )
                )

        elif search_type == "artist":
            for item in items:
                artist_url = item.get("artist_more_url", "")
                artist_id = artist_url.split("/")[-1] if artist_url else ""

                search_results.append(
                    SearchResult(
                        result_id=artist_id,
                        name=item.get("artist_name"),
                        data=item,
                    )
                )

        elif search_type == "playlist":
            for item in items:
                user = item.get("user")
                creator = user.get("name") if user else None

                search_results.append(
                    SearchResult(
                        result_id=item.get("id", ""),
                        name=item.get("title"),
                        artists=[creator] if creator else None,
                        additional=[item.get("content")]
                        if item.get("content")
                        else None,
                    )
                )

        return search_results
