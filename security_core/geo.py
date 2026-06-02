from __future__ import annotations

import hashlib
from typing import Any


COUNTRY_COORDINATES = {
    "AU": (-25.2744, 133.7751),
    "BR": (-14.2350, -51.9253),
    "CA": (56.1304, -106.3468),
    "CH": (46.8182, 8.2275),
    "CN": (35.8617, 104.1954),
    "DE": (51.1657, 10.4515),
    "ES": (40.4637, -3.7492),
    "FR": (46.2276, 2.2137),
    "GB": (55.3781, -3.4360),
    "HK": (22.3193, 114.1694),
    "IN": (20.5937, 78.9629),
    "JP": (36.2048, 138.2529),
    "KR": (35.9078, 127.7669),
    "NL": (52.1326, 5.2913),
    "RU": (61.5240, 105.3188),
    "SE": (60.1282, 18.6435),
    "SG": (1.3521, 103.8198),
    "US": (39.8283, -98.5795),
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def stable_country_coordinates(country: Any) -> tuple[float, float, str]:
    normalized = _text(country).upper()
    if not normalized:
        return 0.0, 0.0, "estimated"
    if normalized in COUNTRY_COORDINATES:
        latitude, longitude = COUNTRY_COORDINATES[normalized]
        return latitude, longitude, "country"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    latitude = (int(digest[:8], 16) / 0xFFFFFFFF) * 120 - 60
    longitude = (int(digest[8:16], 16) / 0xFFFFFFFF) * 300 - 150
    return round(latitude, 4), round(longitude, 4), "estimated"
