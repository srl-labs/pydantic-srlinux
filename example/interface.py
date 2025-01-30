from client import Action, SRLClient
from log import setup_logging

import pydantic_srlinux.models.interfaces as srl_if

setup_logging()

e1_1 = srl_if.InterfaceListEntry(
    name="ethernet-1/1",
    admin_state=srl_if.EnumerationEnum.enable,
    vlan_tagging=True,
    subinterface=[
        srl_if.SubinterfaceListEntry(
            index=100,
            type="bridged",
            admin_state=srl_if.EnumerationEnum.enable,
            vlan=srl_if.VlanContainer(
                encap=srl_if.EncapContainer(
                    single_tagged=srl_if.SingleTaggedContainer(
                        vlan_id=srl_if.VlanIdType(100)
                    )
                ),
            ),
        )
    ],
)

with SRLClient(host="srl") as client:
    client.add_command(
        action=Action.UPDATE,
        path="/interface[name=ethernet-1/1]",
        value=e1_1,
    )
    client.send_request()
