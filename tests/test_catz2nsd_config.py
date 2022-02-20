import os.path
from pathlib import Path

import pytest

from dnscatz import catz2nsd
from dnscatz.catz2nsd import CatalogZoneError

DATADIR = Path(os.path.abspath(os.path.dirname(__file__))) / "data"


def test_config_good():
    config = catz2nsd.read_dicts(DATADIR / "good.conf")
    catalog_zones = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_1():
    config = catz2nsd.read_dicts(DATADIR / "bad1.conf")
    with pytest.raises(CatalogZoneError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_2():
    config = catz2nsd.read_dicts(DATADIR / "bad2.conf")
    with pytest.raises(CatalogZoneError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)
