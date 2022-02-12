import argparse
import sys
import time
import uuid

CATZ_VERSION = 2

DEFAULT_CATALOG = "test.catz"
DEFAULT_ZONELIST = "zone.list"

DEFAULT_SOA_REFRESH = 3600
DEFAULT_SOA_RETRY = 600
DEFAULT_SOA_EXPIRE = 2**31
DEFAULT_SOA_MINIMUM = 0


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
        f"{origin} 0 IN SOA invalid. invalid. {serial} {DEFAULT_SOA_REFRESH} {DEFAULT_SOA_RETRY} {DEFAULT_SOA_EXPIRE} {DEFAULT_SOA_MINIMUM}"
    )
    print(f"{origin} 0 IN NS invalid.")
    print(f'version.{origin} 0 IN TXT "{CATZ_VERSION}"')
    for zone in zones:
        if not zone.endswith("."):
            zone += "."
        h = uuid.uuid5(uuid.NAMESPACE_DNS, zone)
        print(f"{h}.zones.{origin} 0 IN PTR {zone}")


if __name__ == "__main__":
    main()
