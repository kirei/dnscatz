"""
Configure NSD using a catalog zones per draft-ietf-dnsop-dns-catalog-zones

Config file syntax:

catalog-zone:
  name: <string>
  request-xfr: <ip-address> <key-name | NOKEY>
  zonefile: <filename>
  pattern: <pattern-name>

key:
  name: <string>
  algorithm: <string>
  secret: <base64 blob>
"""

import argparse
import contextlib
import logging
import os
import re
import sys
from typing import Dict, List, Optional

from .catz import (
    TSIG,
    CatalogZone,
    CatalogZoneError,
    InvalidConfigurationError,
    ensure_unique_zones,
    parse_config_catalog_zone,
)
from .utils import read_multidicts

DEFAULT_CONFIG = "/etc/nsd/catz2nsd.conf"
DEFAULT_ZONELIST = "/var/lib/nsd/zone.list"


logger = logging.getLogger(__name__)


def parse_config(
    config_dicts: List[dict], cwd: Optional[str] = None
) -> List[CatalogZone]:
    """Parse configuration (list of dictionaries) and return list of catalog zones"""

    keys = {}
    zones = {}

    # read keys
    for config_dict in config_dicts:
        if key_dict := config_dict.get("key"):
            name = key_dict["name"]
            if name in keys:
                raise InvalidConfigurationError(f"Duplicate key {name} found")
            tsig = TSIG.from_dict(key_dict)
            keys[tsig.keyname] = tsig

    # read catalog zones
    for config_dict in config_dicts:
        if zone_dict := config_dict.get("catalog-zone"):
            name = zone_dict["name"]
            if name in zones:
                raise InvalidConfigurationError(f"Duplicate catalog-zone {name} found")
            catalog_zone = parse_config_catalog_zone(zone_dict, keys, cwd)
            zones[catalog_zone.origin] = catalog_zone

    return zones.values()


def get_current_zones(filename: str) -> Dict[str, str]:
    """Get dictionary of current zones and patterns"""
    res = {}
    with contextlib.suppress(FileNotFoundError):  # noqa
        with open(filename) as fp:
            for line in fp.readlines():
                if line.startswith("#"):
                    continue
                if match := re.match(r"^add (\S+) (\w+)$", line.rstrip()):
                    res[match.group(1).lower()] = match.group(2)
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
        "--config", metavar="config", default=DEFAULT_CONFIG, help="Configuration file"
    )
    parser.add_argument(
        "--zonelist",
        metavar="filename",
        default=DEFAULT_ZONELIST,
        help="NSD zone list file",
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

    try:
        config_dicts = read_multidicts(args.config)
        catalog_zones = parse_config(config_dicts)
        ensure_unique_zones(catalog_zones)
    except (InvalidConfigurationError, CatalogZoneError) as exc:
        logger.error("%s", str(exc))
        sys.exit(-1)

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
