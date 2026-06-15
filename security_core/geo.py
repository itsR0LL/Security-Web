from __future__ import annotations

import hashlib
import ipaddress
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


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _valid_coordinates(latitude: float | None, longitude: float | None) -> bool:
    if latitude is None or longitude is None:
        return False
    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
        return False
    return not (latitude == 0 and longitude == 0)


def _stable_text_coordinates(value: str) -> tuple[float, float]:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    latitude = (int(digest[:8], 16) / 0xFFFFFFFF) * 120 - 60
    longitude = (int(digest[8:16], 16) / 0xFFFFFFFF) * 300 - 150
    return round(latitude, 4), round(longitude, 4)


def stable_country_coordinates(country: Any) -> tuple[float, float, str]:
    normalized = _text(country).upper()
    if not normalized:
        return 0.0, 0.0, "estimated"
    if normalized in COUNTRY_COORDINATES:
        latitude, longitude = COUNTRY_COORDINATES[normalized]
        return latitude, longitude, "country"
    latitude, longitude = _stable_text_coordinates(normalized)
    return latitude, longitude, "estimated"


def stable_ip_coordinates(client_ip: Any) -> tuple[float, float, str]:
    text = _text(client_ip)
    if not text:
        return 0.0, 0.0, "estimated"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return stable_country_coordinates(text)
    if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return 0.0, 0.0, "estimated"
    latitude, longitude = _stable_text_coordinates(address.compressed)
    return latitude, longitude, "estimated"


def resolve_geo_coordinates(
    *,
    country: Any = "",
    latitude: Any = None,
    longitude: Any = None,
    city: Any = "",
    region: Any = "",
    client_ip: Any = "",
) -> tuple[float, float, str]:
    parsed_latitude = _float(latitude)
    parsed_longitude = _float(longitude)
    if _valid_coordinates(parsed_latitude, parsed_longitude):
        if _text(city):
            precision = "city"
        elif _text(region):
            precision = "region"
        elif _text(country):
            precision = "country"
        else:
            precision = "estimated"
        return round(parsed_latitude, 6), round(parsed_longitude, 6), precision

    if _text(country):
        return stable_country_coordinates(country)
    return stable_ip_coordinates(client_ip)
