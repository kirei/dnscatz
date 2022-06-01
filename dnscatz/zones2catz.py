"""
Create catalog zone per draft-ietf-dnsop-dns-catalog-zones from a file
containing list of zones
"""

import argparse
import csv
import sys
import time
import uuid
from io import StringIO
from typing import List, Optional

CATZ_VERSION = 2

DEFAULT_CATALOG = "test.catz"
DEFAULT_ZONELIST = "zones.txt"

DEFAULT_SOA_REFRESH = 3600
DEFAULT_SOA_RETRY = 600
DEFAULT_SOA_EXPIRE = 2**31 - 1
DEFAULT_SOA_MINIMUM = 0

DEFAULT_TTL = 0


def generate_catalog_zone(
    origin: str, zones: List[str] = [], zonelist: Optional[str] = None
) -> str:
    buf = StringIO()
    serial = int(time.time())

    old_stdout = sys.stdout
    sys.stdout = buf

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

    if zonelist:
        with open(zonelist, mode="r") as csv_file:
            csv_reader = csv.DictReader(csv_file, fieldnames=["zone", "group"])
            for row in csv_reader:
                zone = row["zone"].strip()
                if not zone.endswith("."):
                    zone += "."
                zone_id = uuid.uuid5(uuid.NAMESPACE_DNS, zone)
                print(f"{zone_id}.zones.{origin} {DEFAULT_TTL} IN PTR {zone}")
                if row["group"]:
                    group = row["group"].strip()
                    print(
                        f'group.{zone_id}.zones.{origin} {DEFAULT_TTL} IN TXT "{group}"'
                    )

    sys.stdout = old_stdout

    return buf.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--zonelist",
        metavar="filename",
        default=DEFAULT_ZONELIST,
        help="Zone list file",
    )
    parser.add_argument(
        "--origin",
        dest="origin",
        metavar="zone",
        default=DEFAULT_CATALOG,
        help="Catalog zone name (origin)",
    )
    parser.add_argument(
        "--output",
        metavar="filename",
        help="Output zone file name",
    )

    args = parser.parse_args()

    origin = args.origin
    if not origin.endswith("."):
        origin += "."

    catalog_zone_str = generate_catalog_zone(origin=origin, zonelist=args.zonelist)

    if args.output:
        with open(args.output, "wt") as output_file:
            output_file.write(catalog_zone_str)
    else:
        print(catalog_zone_str)


if __name__ == "__main__":
    main()
