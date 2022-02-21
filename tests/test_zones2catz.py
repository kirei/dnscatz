from dnscatz import zones2catz
import dns.zone

ZONES = [
    "example.com",
    "example.net",
    "example.org",
]


def test_zones2catz():
    origin = "test.catz."
    contents = zones2catz.generate_catalog_zone(origin, ZONES)
    zone = dns.zone.from_text(contents, origin=origin)
    assert str(zone.origin) == origin
