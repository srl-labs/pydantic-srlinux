from typing import List

from client import Action, SRLClient
from log import setup_logging

import pydantic_srlinux.models.interfaces as srl_if

setup_logging()


def create_vlans(ids: list[int]) -> List[srl_if.SubinterfaceListEntry]:
    vlans: List[srl_if.SubinterfaceListEntry] = []
    for id in ids:
        vlans.append(
            srl_if.SubinterfaceListEntry(
                index=id,
                type="bridged",
                admin_state=srl_if.EnumerationEnum.enable,
                vlan=srl_if.VlanContainer(
                    encap=srl_if.EncapContainer(
                        single_tagged=srl_if.SingleTaggedContainer(
                            vlan_id=srl_if.VlanIdType(id)
                        )
                    ),
                ),
            )
        )

    return vlans


e1_1 = srl_if.InterfaceListEntry(
    name="ethernet-1/1",
    admin_state=srl_if.EnumerationEnum.enable,
    vlan_tagging=True,
    subinterface=create_vlans([100, 200, 300]),
)

with SRLClient(host="srl") as client:
    client.add_set_command(
        action=Action.REPLACE,
        path="/interface[name=ethernet-1/1]",
        value=e1_1,
    )
    client.send_set_request()
