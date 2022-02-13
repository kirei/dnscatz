"""
Configure NSD using a catalog zones per draft-ietf-dnsop-dns-catalog-zones
"""
import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Set

import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.tsig
import dns.tsigkeyring
import dns.xfr
import dns.zone

DEFAULT_CONFIG = "catz2nsd.json"
DEFAULT_ZONELIST = "zone.list"


@dataclass(frozen=True)
class CatalogZone:
    zone: str
    master: str
    keyname: str
    secret: str
    pattern: str
    zones: Set[str]

    @classmethod
    def from_config(cls, config: dict) -> []:
        return [
            CatalogZone(
                zone=cz["zone"],
                master=cz["master"],
                pattern=cz.get("pattern") or cz["master"],
                keyname=cz["keyname"],
                secret=cz["secret"],
                zones=get_catz_zones(
                    zone=cz["zone"],
                    master=cz["master"],
                    keyname=cz["keyname"],
                    secret=cz["secret"],
                ),
            )
            for cz in config.get("zones", [])
        ]


def get_catz_zones(master: str, zone: str, keyname: str, secret: str) -> set:
    """Read contents (zones) from a catalog zone"""
    keyring = dns.tsigkeyring.from_text({keyname: secret})
    master_answer = dns.resolver.resolve(master, "A")
    m = dns.query.xfr(
        master_answer[0].address,
        zone,
        keyname=keyname,
        keyring=keyring,
        keyalgorithm=dns.tsig.HMAC_SHA256,
    )
    catalog_zone = dns.zone.from_xfr(m)
    zones = set()
    for k, v in catalog_zone.nodes.items():
        if str(k).endswith(".zones"):
            for zone in v.get_rdataset(dns.rdataclass.IN, dns.rdatatype.PTR):
                zones.add(str(zone).rstrip("."))

    return zones


def ensure_unique_zones(catalog_zones: List[CatalogZone]):
    """Ensure zones are not defined in multiple catalogs"""
    zone2catalogs = defaultdict(set)
    for cz in catalog_zones:
        for zone in cz.zones:
            zone2catalogs[zone].add(cz.zone)
    errors = 0
    for zone, catalogs in zone2catalogs.items():
        if len(catalogs) > 1:
            logging.error("%s defined in multiple catalogs: %s", zone, catalogs)
            errors += 1
    if errors:
        sys.exit(-1)


def get_current_zones(filename: str) -> Dict[str, str]:
    """Get dictionary of current zones and patterns"""
    res = {}
    try:
        for line in open(filename).readlines():
            if line.startswith("#"):
                continue
            if match := re.match(r"^add (\S+) (\w+)$", line.rstrip()):
                res[match.group(1).lower()] = match.group(2)
    except FileNotFoundError:
        pass
    return res


def nsd_control(command: str, dry_run: bool = True):
    print(f"{command}")
    if not dry_run:
        os.system(f"nsd-control {command}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", metavar="config", default=DEFAULT_CONFIG, help="Config file"
    )
    parser.add_argument(
        "--zonelist",
        metavar="filename",
        default=DEFAULT_ZONELIST,
        help="Zone list file",
    )
    parser.add_argument(
        "--dry-run", dest="dry_run", action="store_true", help="Do not execute commands"
    )

    args = parser.parse_args()

    config = json.load(open(args.config))

    catalog_zones = CatalogZone.from_config(config)

    ensure_unique_zones(catalog_zones)

    current_zone_patterns = get_current_zones(args.zonelist)
    current_zones = set(current_zone_patterns.keys())
    all_new_zones = set()

    for cz in catalog_zones:
        for zone in cz.zones:
            if zone not in current_zone_patterns:
                nsd_control(f"addzone {zone} {cz.pattern}", args.dry_run)
            elif cz.pattern != current_zone_patterns[zone]:
                nsd_control(f"changezone {zone} {cz.pattern}", args.dry_run)
            all_new_zones.add(zone)

    del_zones = current_zones - all_new_zones
    for zone in del_zones:
        nsd_control(f"delzone {zone}", args.dry_run)


if __name__ == "__main__":
    main()
