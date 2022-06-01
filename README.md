# Catalog Zones Tools

## catz2nsd

`catz2nsd` configures NSD using catalog zones. It reads a configuration file (default `/etc/nsd/catz2nsd.conf`) and updates NSD using `nsd-control`. `catz2nsd` must be able to read the list of currently configured zones in NSD (default `/var/lib/nsd/zone.list`) in order to determine which zones to add, remove, or update.

The configuration file is NSD-like as described below:

    catalog-zone:
      name: <string>
      request-xfr: <ip-address> <key-name | NOKEY>
      zonefile: <filename>
      pattern: <pattern-name>

    key:
      name: <string>
      algorithm: <string>
      secret: <base64 blob>

## zones2catz

`zones2catz` creates a catalog zone from a comma-separated text file containing one zone per line (and optionally the intended group for the zone) and writes its output to a file or _stdout_.

## References

- [draft-ietf-dnsop-dns-catalog-zones](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-dns-catalog-zones)
