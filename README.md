# Catalog Zones Tools

## catz2nsd

`catz2nsd` configure NSD using catalog zones. It reads a configuration file (default `/etc/nsd/catz2nsd.conf`) and update NSD using `nsd-control`. `catz2nsd` must be able to read the list of NSD's currently configured zones (default `/var/lib/nsd/zone.list`) in order to determine what zones to add, remove or update.

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

`zones2catz` creates a catalog zone from a text file containing one zone per line. Writes is output to a file or stdout.

## References

- [draft-ietf-dnsop-dns-catalog-zones](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-dns-catalog-zones)
