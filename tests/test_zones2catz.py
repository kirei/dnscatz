import dns.zone

from dnscatz import zones2catz

ZONES = [
    "example.com",
    "example.net",
    "example.org",
]


def test_zones2catz():
    origin = "test.catz."
    contents = zones2catz.generate_catalog_zone(origin=origin, zones=ZONES)
    zone = dns.zone.from_text(contents, origin=origin)
    assert str(zone.origin) == origin
