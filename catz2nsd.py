import argparse
import json
import os
from dataclasses import dataclass

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


def get_catz_zones(master: str, zone: str, keyname: str, keyring) -> set:
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


def get_current_zones(filename: str) -> set:
    zones = set()
    try:
        for z in open(filename).readlines():
            zones.add(z.rstrip())
    except FileNotFoundError:
        pass
    return zones


def nsd_control(command: str, dry_run: bool = True):
    if dry_run:
        print("# nsd-control", command)
    else:
        os.system(command)


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

    keyring = dns.tsigkeyring.from_text(
        {k["keyname"]: k["secret"] for k in config.get("keyring", {})}
    )

    catalog_zones = [
        CatalogZone(zone=cz["zone"], master=cz["master"], keyname=cz["keyname"])
        for cz in config.get("zones", [])
    ]

    current_zones = get_current_zones(args.zonelist)
    all_new_zones = set()
    for cz in catalog_zones:
        zones = get_catz_zones(
            master=cz.master, zone=cz.zone, keyname=cz.keyname, keyring=keyring
        )
        new_zones = zones - current_zones
        for zone in new_zones:
            nsd_control(f"addzone {zone.lower()} {cz.master}", args.dry_run)

        all_new_zones = all_new_zones & new_zones

    del_zones = current_zones - all_new_zones
    for zone in del_zones:
        nsd_control(f"delzone {zone}", args.dry_run)


if __name__ == "__main__":
    main()
