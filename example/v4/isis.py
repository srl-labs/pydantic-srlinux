import pydantic_srlinux.models.network_instance as srl_ni
from example.v4.common import ConfigObject
from example.v4.interface import Subinterface
from pydantic_srlinux.models.network_instance import InstanceListEntry5 as ISISListEntry
from pydantic_srlinux.models.network_instance import LevelListEntry


class ISISInstance(ISISListEntry, ConfigObject):
    def __init__(self, name: str, net: str):
        super().__init__(
            name=name,
            admin_state=srl_ni.EnumerationEnum.enable,
        )

        self.net = [srl_ni.NetLeafList(net)]
        self.ipv4_unicast = srl_ni.Ipv4UnicastContainer5(
            admin_state=srl_ni.EnumerationEnum.enable,
        )

    def add_interface(
        self,
        subif: Subinterface,
        circuit_type: srl_ni.EnumerationEnum143 | None = None,
        level: int = 2,
        passive: bool = False,
    ):
        if self.interface is None:
            self.interface = []
        if_entry = srl_ni.InterfaceListEntry6(
            interface_name=f"{subif._parent_if_name}.{subif.index}",
            circuit_type=circuit_type,
            admin_state=srl_ni.EnumerationEnum.enable,
            level=[LevelListEntry(level_number=level)],
            ipv4_unicast=srl_ni.Ipv4UnicastContainer6(
                admin_state=srl_ni.EnumerationEnum.enable,
            ),
        )

        if passive:
            if_entry.passive = True

        self.interface.append(if_entry)
