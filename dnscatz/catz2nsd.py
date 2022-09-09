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
import logging
import os
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

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

SUPPORTED_VERSIONS = [2]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CatalogZone:
    origin: str
    pattern: str
    zones: Set[str]


@dataclass(frozen=True)
class TSIG:
    keyname: str
    keyalgorithm: str
    secret: str

    @classmethod
    def from_dict(cls, key_dict: dict):
        return cls(
            keyname=key_dict["name"],
            keyalgorithm=key_dict["algorithm"],
            secret=key_dict["secret"],
        )


class InvalidConfigurationError(ValueError):
    pass


class CatalogZoneError(ValueError):
    pass


def read_multidicts(filename: str) -> List[dict]:
    """Read multiple YAML dictionaries from file, return list of them"""
    return parse_multidicts(open(filename).read())


def parse_multidicts(config: str) -> List[dict]:
    """Parse multiple YAML dictionaries from string, return list of them"""
    data = ""
    for line in config.split("\n"):
        if line.startswith("#") or re.fullmatch(r"^\s+$", line):
            print("IGNORE", line)
            continue
        elif re.match(r"^\S", line):
            data += "\n--- \n"
        data += line + "\n"
    res = list(yaml.safe_load_all(data))
    return res


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


def parse_config_catalog_zone(
    zone_dict: dict, keys: Dict[str, TSIG], cwd: Optional[str] = None
) -> CatalogZone:
    """Parse zone configuration dictionary"""
    name = zone_dict["name"]
    pattern = zone_dict["pattern"]

    if xfr_dict := zone_dict.get("request-xfr"):
        master, keyname = xfr_dict.split()
        if keyname.upper() == "NOKEY":
            keyname = None
            keyalgorithm = None
            secret = None
        else:
            keyalgorithm = keys[keyname].keyalgorithm
            secret = keys[keyname].secret

        zone = None
        if zonefile := zone_dict.get("zonefile"):
            zonefile = os.path.join(cwd, zonefile) if cwd else zonefile
            try:
                zone = dns.zone.from_file(zonefile, origin=name)
            except FileNotFoundError:
                pass
        else:
            zonefile = None

        zone = axfr(
            origin=name,
            master=master,
            keyname=keyname,
            keyalgorithm=keyalgorithm,
            secret=secret,
            zone=zone,
        )

        if zonefile:
            zone.to_file(zonefile, want_origin=True)
    elif zonefile := zone_dict.get("zonefile"):
        zonefile = os.path.join(cwd, zonefile) if cwd else zonefile
        zone = dns.zone.from_file(zonefile, origin=name)
    else:
        raise InvalidConfigurationError(
            f"Either request-xfr or zonefile must be specified for {name}"
        )

    return CatalogZone(origin=name, pattern=pattern, zones=get_catz_zones(zone))


def axfr(
    origin: str,
    master: str,
    keyname: Optional[str],
    keyalgorithm: Optional[str],
    secret: Optional[str],
    zone: Optional[dns.zone.Zone] = None,
) -> Optional[dns.zone.Zone]:
    """Perform zone transfer"""
    if keyname and keyalgorithm and secret:
        keyring = dns.tsigkeyring.from_text({keyname: secret})
        keyalgorithm = dns.name.from_text(keyalgorithm)
    else:
        keyring = None
        keyalgorithm = None

    if zone is not None:
        serial = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)[0].serial
        (query, new_serial) = dns.xfr.make_query(
            zone,
            serial=serial,
            keyring=keyring,
            keyname=keyname,
            keyalgorithm=keyalgorithm,
        )
        if serial == new_serial:
            logger.debug("Zone %s not changed", origin)
            return zone

    m = dns.query.xfr(
        master, origin, keyname=keyname, keyring=keyring, keyalgorithm=keyalgorithm
    )

    t1 = time.perf_counter()
    zone = dns.zone.from_xfr(m)
    t2 = time.perf_counter()
    logger.debug("Zone %s transferred in %.3f seconds", origin, t2 - t1)

    return zone


def get_catz_zones(catalog_zone: dns.zone.Zone) -> Set[str]:
    """Get zones from catalog zone"""
    zones = set()
    for k, v in catalog_zone.nodes.items():
        if str(k) == "version":
            if rdataset := v.get_rdataset(dns.rdataclass.IN, dns.rdatatype.TXT):
                catz_version = get_catz_version(rdataset[0])
                if catz_version not in SUPPORTED_VERSIONS:
                    raise CatalogZoneError(
                        f"Unsupported catalog zone version ({catz_version})"
                    )
        elif str(k).startswith("group."):
            logging.info("Group property not supported: %s", str(k))
        elif str(k).startswith("coo."):
            logging.info("Change of Ownership property not supported: %s", str(k))
        elif str(k).startswith("serial."):
            logging.info("Serial property not supported: %s", str(k))
        elif str(k).endswith(".zones"):
            rdataset = v.get_rdataset(dns.rdataclass.IN, dns.rdatatype.PTR)
            if len(rdataset) != 1:
                raise CatalogZoneError("Broken catalog zone (PTR)")
            zones.add(str(rdataset[0]).rstrip("."))
    return zones


def get_catz_version(rr) -> Optional[int]:
    """Get catalog zone version from TXT RR"""
    if rr.rdtype != dns.rdatatype.TXT:
        raise ValueError("Invalid rdatatype for catalog zone version")
    if match := re.fullmatch(r"\"(\d+)\"", str(rr)):
        return int(match.group(1))


def ensure_unique_zones(catalog_zones: List[CatalogZone]):
    """Ensure zones are not defined in multiple catalogs"""
    zone2catalogs = defaultdict(set)
    for cz in catalog_zones:
        for zone in cz.zones:
            zone2catalogs[zone].add(cz.origin)
    errors = 0
    for zone, catalogs in zone2catalogs.items():
        if len(catalogs) > 1:
            logger.error("%s defined in multiple catalogs: %s", zone, catalogs)
            errors += 1
    if errors:
        raise InvalidConfigurationError("Duplicate zones found in catalogs")


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
