"""
Configure NSD using a catalog zones per draft-ietf-dnsop-dns-catalog-zones
"""

import argparse
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
import yaml

DEFAULT_CONFIG = "/etc/nsd/catz2nsd.conf"
DEFAULT_ZONELIST = "/var/lib/nsd/zone.list"
DEFAULT_TSIG_ALGORITHM = "hmac-sha256"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CatalogZone:
    zone: str
    pattern: str
    zones: Set[str]


@dataclass(frozen=True)
class TSIG:
    keyname: str
    keyalgorithm: str
    secret: str


def read_dicts(filename: str) -> List[dict]:
    """Read multiple YAML dicts from file"""
    res = []
    data = ""
    with open(filename) as input_file:
        for line in input_file.readlines():
            if not re.fullmatch(r"^\s*$", line.rstrip()):
                data += line
            elif len(data):
                doc = yaml.safe_load(data)
                if isinstance(doc, dict):
                    res.append(doc)
    if len(data):
        doc = yaml.safe_load(data)
        if isinstance(doc, dict):
            res.append(doc)
    return res


def read_config(filename: str) -> List[CatalogZone]:
    """Read configuration file and return list of catalog zones"""

    res = []
    config_dicts = read_dicts(filename)

    # read all TSIG keys
    tsigs = {}
    for config_dict in config_dicts:
        if key_dict := config_dict.get("key"):
            tsigs[key_dict["name"]] = TSIG(
                keyname=key_dict["name"],
                keyalgorithm=key_dict["algorithm"],
                secret=key_dict["secret"],
            )

    # read catalog zones
    for config_dict in config_dicts:
        if cz_dict := config_dict.get("catalog-zone"):
            name = cz_dict["name"]
            pattern = cz_dict["pattern"]
            master, keyname = cz_dict["request-xfr"].split()

            res.append(
                CatalogZone(
                    zone=name,
                    pattern=pattern,
                    zones=get_catz_zones(
                        zone=name,
                        master=master,
                        keyname=keyname,
                        keyalgorithm=tsigs[keyname].keyalgorithm,
                        secret=tsigs[keyname].secret,
                    ),
                )
            )

    return res


def get_catz_zones(
    master: str, zone: str, keyname: str, keyalgorithm: str, secret: str
) -> set:
    """Read contents (zones) from a catalog zone"""
    keyring = dns.tsigkeyring.from_text({keyname: secret})
    m = dns.query.xfr(
        master,
        zone,
        keyname=keyname,
        keyring=keyring,
        keyalgorithm=dns.name.from_text(keyalgorithm),
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
            logger.error("%s defined in multiple catalogs: %s", zone, catalogs)
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
    if dry_run:
        logger.debug("DRY-RUN: nsd-control %s", command)
    else:
        logger.debug("EXEC: nsd-control %s", command)
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
    parser.add_argument("--debug", action="store_true", help="Enable debugging")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    catalog_zones = read_config(args.config)

    ensure_unique_zones(catalog_zones)

    current_zone_patterns = get_current_zones(args.zonelist)
    current_zones = set(current_zone_patterns.keys())
    all_new_zones = set()

    for cz in catalog_zones:
        for zone in cz.zones:
            if zone not in current_zone_patterns:
                logger.info("Add zone %s (%s)", zone, cz.pattern)
                nsd_control(f"addzone {zone} {cz.pattern}", args.dry_run)
            elif cz.pattern != current_zone_patterns[zone]:
                logger.info("Update zone %s (%s)", zone, cz.pattern)
                nsd_control(f"changezone {zone} {cz.pattern}", args.dry_run)
            else:
                logger.debug("No changes to zone %s (%s)", zone, cz.pattern)
            all_new_zones.add(zone)

    del_zones = current_zones - all_new_zones
    for zone in del_zones:
        logger.info("Delete zone %s", zone)
        nsd_control(f"delzone {zone}", args.dry_run)


if __name__ == "__main__":
    main()
