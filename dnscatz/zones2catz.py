"""
Create catalog zone per draft-ietf-dnsop-dns-catalog-zones from a file
containing list of zones
"""

import argparse
import sys
import time
import uuid

CATZ_VERSION = 2

DEFAULT_CATALOG = "test.catz"
DEFAULT_ZONELIST = "zones.txt"

DEFAULT_SOA_REFRESH = 3600
DEFAULT_SOA_RETRY = 600
DEFAULT_SOA_EXPIRE = 2**31 - 1
DEFAULT_SOA_MINIMUM = 0

DEFAULT_TTL = 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--zonelist",
        metavar="filename",
        default=DEFAULT_ZONELIST,
        help="Zone list file",
    )
    parser.add_argument(
        "--catalog",
        dest="catalog_zone",
        metavar="zone",
        default=DEFAULT_CATALOG,
        help="Catalog zone name",
    )
    parser.add_argument(
        "--output",
        metavar="filename",
        help="Output zone file name",
    )

    args = parser.parse_args()

    zones = set()
    for z in open(args.zonelist).readlines():
        zones.add(z.rstrip())

    serial = int(time.time())

    origin = args.catalog_zone
    if not origin.endswith("."):
        origin += "."

    if args.output:
        sys.stdout = open(args.output, "wt")

    print(
        " ".join(
            [
                origin,
                str(DEFAULT_TTL),
                "IN SOA",
                "invalid.",
                "invalid.",
                str(serial),
                str(DEFAULT_SOA_REFRESH),
                str(DEFAULT_SOA_RETRY),
                str(DEFAULT_SOA_EXPIRE),
                str(DEFAULT_SOA_MINIMUM),
            ]
        )
    )
    print(f"{origin} {DEFAULT_TTL} IN NS invalid.")
    print(f'version.{origin} {DEFAULT_TTL} IN TXT "{CATZ_VERSION}"')
    for zone in zones:
        if not zone.endswith("."):
            zone += "."
        zone_id = uuid.uuid5(uuid.NAMESPACE_DNS, zone)
        print(f"{zone_id}.zones.{origin} {DEFAULT_TTL} IN PTR {zone}")


if __name__ == "__main__":
    main()
