import os.path
from pathlib import Path

import pytest

from dnscatz import catz2nsd
from dnscatz.catz2nsd import CatalogZoneError, InvalidConfigurationError
from dnscatz.utils import parse_multidicts

DATADIR = Path(os.path.abspath(os.path.dirname(__file__))) / "data"

CONFIG_GOOD = """
catalog-zone:
  name: test.catz
  zonefile: good.zone
  pattern: ns1

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="
"""

CONFIG_BAD_ZONE1 = """
catalog-zone:
  name: test.catz
  zonefile: bad_non_unique_id.zone
  pattern: ns1

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="
"""

CONFIG_BAD_ZONE2 = """
catalog-zone:
  name: test.catz
  zonefile: invalid_version.zone
  pattern: ns1

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="
"""


CONFIG_BAD_KEY_DUPE = """
catalog-zone:
  name: test.catz
  zonefile: good.zone
  pattern: ns1

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="
"""

CONFIG_BAD_ZONE_DUPE = """
catalog-zone:
  name: test.catz
  zonefile: good.zone
  pattern: ns1

catalog-zone:
  name: test.catz
  zonefile: good.zone
  pattern: ns1

key:
  name: key1
  algorithm: hmac-sha256
  secret: "b90O5awgKh8zY9Tkc3Yc9lmREgRi0S5JJGJ5JaGF3fw="
"""


def test_config_good():
    config = parse_multidicts(CONFIG_GOOD)
    _ = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_1():
    config = parse_multidicts(CONFIG_BAD_ZONE1)
    with pytest.raises(CatalogZoneError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_2():
    config = parse_multidicts(CONFIG_BAD_ZONE2)
    with pytest.raises(CatalogZoneError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_key_dup():
    config = parse_multidicts(CONFIG_BAD_KEY_DUPE)
    with pytest.raises(InvalidConfigurationError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)


def test_config_bad_zone_dup():
    config = parse_multidicts(CONFIG_BAD_ZONE_DUPE)
    with pytest.raises(InvalidConfigurationError):
        _ = catz2nsd.parse_config(config, cwd=DATADIR)
