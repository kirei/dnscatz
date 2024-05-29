import contextlib
import logging
import os
import re
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

SUPPORTED_VERSIONS = [2]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CatalogZone:
    origin: str
    zones: Set[str]
    pattern: Optional[str] = None


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


def parse_config_catalog_zone(
    zone_dict: dict, keys: Dict[str, TSIG], cwd: Optional[str] = None
) -> CatalogZone:
    """Parse zone configuration dictionary"""
    name = zone_dict["name"]
    pattern = zone_dict.get("pattern")

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
            with contextlib.suppress(FileNotFoundError):
                zone = dns.zone.from_file(zonefile, origin=name)
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
