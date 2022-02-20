test:
	zones2catz --zonelist zones.txt --origin test.catz --output test.zone
	touch zone.list
	catz2nsd --config catz2nsd.conf --zonelist zone.list --dry-run

clean:
	rm -f test.zone zone.list
