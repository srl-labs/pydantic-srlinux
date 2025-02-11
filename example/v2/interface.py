import pydantic_srlinux.models.interfaces as srl_if
from example.client import Action, SRLClient
from example.log import setup_logging

setup_logging()


# creates a single tagged vlan
def vlan(vlan_id: int) -> srl_if.VlanContainer:
    return srl_if.VlanContainer(
        encap=srl_if.EncapContainer(
            single_tagged=srl_if.SingleTaggedContainer(
                vlan_id=srl_if.VlanIdType(vlan_id)
            )
        ),
    )


def subif(index: int, type: str) -> srl_if.SubinterfaceListEntry:
    return srl_if.SubinterfaceListEntry(
        index=index,
        type=type,
        admin_state=srl_if.EnumerationEnum.enable,
        vlan=vlan(vlan_id=index),
    )


e1_1 = srl_if.InterfaceListEntry(
    name="ethernet-1/1",
    admin_state=srl_if.EnumerationEnum.enable,
    vlan_tagging=True,
    subinterface=[
        subif(index=100, type="bridged"),
    ],
)

with SRLClient(host="srl1") as client:
    client.add_set_command(
        action=Action.UPDATE,
        path="/interface[name=ethernet-1/1]",
        value=e1_1,
    )

    client.send_set_request()
