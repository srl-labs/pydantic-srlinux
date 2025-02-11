from typing import TYPE_CHECKING

import pydantic_srlinux.models.network_instance as srl_ni
from example.v4.common import ConfigObject
from example.v4.interface import Subinterface

if TYPE_CHECKING:
    from example.v4.isis import ISISInstance


class NetworkInstance(srl_ni.NetworkInstanceListEntry, ConfigObject):
    def __init__(self, name: str):
        super().__init__(
            name=name,
        )

    @property
    def path(self) -> str:
        return f"/network-instance[name={self.name}]"

    def add_subif(self, subif: Subinterface):
        if self.interface is None:
            self.interface = []
        if_entry = srl_ni.InterfaceListEntry(
            name=f"{subif._parent_if_name}.{subif.index}",
        )
        self.interface.append(if_entry)

    def add_isis_instance(self, isis_instance: "ISISInstance"):
        if self.protocols is None:
            self.protocols = srl_ni.ProtocolsContainer()
        if self.protocols.isis is None:
            self.protocols.isis = srl_ni.IsisContainer()
        if self.protocols.isis.instance is None:
            self.protocols.isis.instance = []

        self.protocols.isis.instance.append(isis_instance)
