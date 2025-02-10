import json

import pytest
from pydantic import ValidationError

from example.v3.interface import Vlan


@pytest.mark.parametrize("vlan_id", [1, 100, 4094])
def test_vlan_to_json_parametrized(vlan_id):
    vlan = Vlan(vlan_id=vlan_id)
    json_output = vlan.to_json(by_alias=False)
    json_data = json.loads(json_output)

    assert json_data["encap"]["single_tagged"]["vlan_id"] == vlan_id


@pytest.mark.parametrize(
    "vlan_id, expected_message",
    [
        (-1, "Input should be greater than or equal to 1"),
        (4095, "Input should be less than or equal to 4094"),
    ],
)
def test_vlan_id_invalid(vlan_id, expected_message):
    with pytest.raises(ValidationError) as exc_info:
        Vlan(vlan_id=vlan_id)

    assert expected_message in str(exc_info.value)
