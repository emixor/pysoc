"""
GeoIP-style helper.

PySOC ships with a deterministic, **offline** pseudo-GeoIP resolver. It maps
the first octet of an IPv4 address to a country code, which is sufficient for
demo / training data and avoids shipping a multi-megabyte MaxMind database.

For production use, replace :func:`lookup_country` with a real MaxMind
GeoLite2 lookup (see ``docs/ROADMAP.md``).
"""

from __future__ import annotations

import ipaddress
from typing import Optional


# Deterministic mapping: first octet → ISO 3166-1 alpha-2 country code.
# This is *not* real BGP/RIR data — it is a stable synthetic map used purely
# so that the impossible-travel detector has something deterministic to test
# against. The mapping is intentionally spread across continents.
_OCTET_TO_COUNTRY = {
    1: "US",
    2: "US",
    3: "US",
    4: "US",
    5: "CN",
    6: "CN",
    7: "CN",
    8: "GB",
    9: "GB",
    10: "US",  # RFC1918 starts here — treat as internal US for demo
    11: "DE",
    12: "DE",
    13: "FR",
    14: "FR",
    15: "BR",
    16: "BR",
    17: "IN",
    18: "IN",
    19: "RU",
    20: "RU",
    21: "JP",
    22: "JP",
    23: "AU",
    24: "AU",
    25: "ZA",
    26: "NG",
    27: "NL",
    28: "IT",
    29: "ES",
    30: "CA",
    31: "CA",
    32: "MX",
    33: "AR",
    34: "KR",
    35: "SG",
    36: "AE",
    37: "IL",
    38: "TR",
    39: "PL",
    40: "SE",
    41: "NO",
    42: "FI",
    43: "UA",
    44: "RO",
    45: "EG",
    46: "KE",
    47: "VN",
    48: "TH",
    49: "ID",
    50: "NZ",
}


def lookup_country(ip: Optional[str]) -> Optional[str]:
    """Return a 2-letter ISO country code for ``ip``.

    Parameters
    ----------
    ip:
        IPv4 dotted-quad string. ``None`` returns ``None``.

    Returns
    -------
    Optional[str]
        ISO 3166-1 alpha-2 country code, or ``None`` if the IP cannot be
        parsed or is RFC1918 private.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback:
        # Treat RFC1918 / loopback as "internal" — impossible-travel does not
        # apply between two internal addresses.
        return "ZZ"  # "internal" sentinel
    if isinstance(addr, ipaddress.IPv6Address):
        return "ZZ"
    # Extract first octet for our synthetic country lookup.
    first_octet = int(str(ip).split(".")[0])
    return _OCTET_TO_COUNTRY.get(first_octet, "XX")


# ---------------------------------------------------------------------------
# Haversine distance (km) — used by the impossible-travel detector
# ---------------------------------------------------------------------------
# A tiny, intentionally-rough country→(lat, lon) table so we can compute
# great-circle distance between two logins. Coarse but adequate for the
# "did the same user log in from 10 000 km apart in 30 minutes?" check.
_COUNTRY_COORDS = {
    "US": (38.0, -97.0),
    "CN": (35.0, 105.0),
    "GB": (54.0, -2.0),
    "DE": (51.0, 10.0),
    "FR": (46.0, 2.0),
    "BR": (-10.0, -55.0),
    "IN": (20.0, 77.0),
    "RU": (60.0, 100.0),
    "JP": (36.0, 138.0),
    "AU": (-27.0, 133.0),
    "ZA": (-29.0, 24.0),
    "NG": (10.0, 8.0),
    "NL": (52.0, 5.0),
    "IT": (42.0, 12.0),
    "ES": (40.0, -4.0),
    "CA": (56.0, -106.0),
    "MX": (23.0, -102.0),
    "AR": (-34.0, -64.0),
    "KR": (37.0, 127.0),
    "SG": (1.3, 103.8),
    "AE": (24.0, 54.0),
    "IL": (31.0, 35.0),
    "TR": (39.0, 35.0),
    "PL": (52.0, 19.0),
    "SE": (62.0, 15.0),
    "NO": (62.0, 10.0),
    "FI": (64.0, 26.0),
    "UA": (49.0, 32.0),
    "RO": (46.0, 25.0),
    "EG": (26.0, 30.0),
    "KE": (1.0, 38.0),
    "VN": (16.0, 106.0),
    "TH": (15.0, 100.0),
    "ID": (-5.0, 120.0),
    "NZ": (-41.0, 174.0),
    "ZZ": (0.0, 0.0),  # internal
    "XX": (0.0, 0.0),  # unknown
}


def country_coords(country_code: Optional[str]):
    """Return ``(lat, lon)`` for a country code, or ``None`` if unknown."""
    if not country_code:
        return None
    return _COUNTRY_COORDS.get(country_code.upper())
