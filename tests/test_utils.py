from dnscatz.utils import parse_multidicts

TEST_DATA = """
section:
  value: 1

section:
  value: 2

other_section:
  value: 3

other_section:
  value: 4

section:
  value: 5
"""


def test_parse_multidicts():
    res = parse_multidicts(TEST_DATA)
    assert res[0]["section"]["value"] == 1
    assert res[1]["section"]["value"] == 2
    assert res[2]["other_section"]["value"] == 3
    assert res[3]["other_section"]["value"] == 4
    assert res[4]["section"]["value"] == 5
