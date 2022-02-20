from dnscatz import zones2catz

ZONES = [
    "example.com",
    "example.net",
    "example.org",
]


def test_zones2catz():
    _ = zones2catz.get_catalog_zone("test.cat", ZONES)
