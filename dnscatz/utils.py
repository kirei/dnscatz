import re
from typing import List

import yaml


def read_multidicts(filename: str) -> List[dict]:
    """Read multiple YAML dictionaries from file, return list of them"""
    return parse_multidicts(open(filename).read())


def parse_multidicts(config: str) -> List[dict]:
    """Parse multiple YAML dictionaries from string, return list of them"""
    data = ""
    for line in config.split("\n"):
        if line.startswith("#") or re.fullmatch(r"^\s+$", line):
            continue
        elif re.match(r"^\S", line):
            data += "\n--- \n"
        data += line + "\n"
    res = list(yaml.safe_load_all(data))
    return res
