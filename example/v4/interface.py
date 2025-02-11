from typing import cast

import pydantic_srlinux.models.interfaces as srl_if
from example.v4.common import ConfigObject


class Vlan(srl_if.VlanContainer, ConfigObject):
    def __init__(self, vlan_id: int):
        super().__init__(
            encap=srl_if.EncapContainer(
                single_tagged=srl_if.SingleTaggedContainer(
                    vlan_id=srl_if.VlanIdType(vlan_id)
                )
            ),
        )


class IPv4(srl_if.Ipv4Container, ConfigObject):
    def __init__(self, address: str):
        ipv4_addr_entry = srl_if.AddressListEntry(ip_prefix=address)
        super().__init__(
            address=[ipv4_addr_entry], admin_state=srl_if.EnumerationEnum.enable
        )


class Subinterface(srl_if.SubinterfaceListEntry, ConfigObject):
    def __init__(self, index: int, type: str | None = None):
        super().__init__(index=index)
        self.admin_state = srl_if.EnumerationEnum.enable
        self.type = type
        self._parent_if_name = ""

    def set_vlan(self, vlan: Vlan) -> "Subinterface":
        if vlan is None:
            raise ValueError("vlan must not be None")
        self.vlan = vlan
        return self

    def set_ipv4(self, ipv4: IPv4) -> "Subinterface":
        if ipv4 is None:
            raise ValueError("ipv4 must not be None")
        self.ipv4 = ipv4
        return self


class Interface(srl_if.InterfaceListEntry, ConfigObject):
    def __init__(self, name: str, vlan_tagging: bool | None = None):
        super().__init__(
            name=name,
            admin_state=srl_if.EnumerationEnum.enable,
            vlan_tagging=vlan_tagging,
        )

    @property
    def path(self) -> str:
        return f"/interface[name={self.name}]"

    def add_subif(self, subif: Subinterface):
        if self.subinterface is None:
            self.subinterface = []

        subif._parent_if_name = self.name
        self.subinterface.append(subif)

    def get_subif(self, index: int) -> Subinterface:
        if self.subinterface is None:
            raise ValueError(f"no subinterfaces found for interface {self.name}")

        for subif in self.subinterface:
            if subif.index == index:
                return cast(Subinterface, subif)
        raise ValueError(
            f"no subinterface with index={index} found for interface {self.name}"
        )
