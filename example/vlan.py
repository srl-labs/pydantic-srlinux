from client import Command, SRLClient
from log import setup_logging

import pydantic_srlinux.models.interfaces as srl_if

setup_logging()

e1_1 = srl_if.InterfaceListEntry(
    name="ethernet-1/1",
    admin_state=srl_if.EnumerationEnum.enable,
    vlan_tagging=True,
    subinterface=[
        srl_if.SubinterfaceListEntry(
            index=0,
            type="bridged",
            admin_state=srl_if.EnumerationEnum.enable,
            vlan=srl_if.VlanContainer(
                encap=srl_if.EncapContainer(
                    single_tagged=srl_if.SingleTaggedContainer(
                        vlan_id=srl_if.VlanIdType(100)
                    )
                )
            ),
        )
    ],
)

cmd = Command(
    action="replace",
    path="/interface[name=ethernet-1/1]",
    value=e1_1.model_dump(
        # indent=2,
        exclude_none=True,
        exclude_unset=True,
        by_alias=True,
    ),
)

client = SRLClient(host="clab-vlan-srl1")
client.add_command(cmd)
client.send_request()

# print(
#     e1_1.model_dump_json(indent=2, exclude_none=True, exclude_unset=True, by_alias=True)
# )
