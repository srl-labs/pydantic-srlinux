from pydantic import BaseModel

import pydantic_srlinux.models.interfaces as srl_if


class Common(BaseModel):
    """Class with the common methods for SR Linux models"""

    def to_json(self, by_alias: bool) -> str:
        return self.model_dump_json(
            exclude_none=True,
            exclude_unset=True,
            by_alias=by_alias,
            indent=2,
        )


class Vlan(srl_if.VlanContainer, Common):
    def __init__(self, vlan_id: int):
        super().__init__(
            encap=srl_if.EncapContainer(
                single_tagged=srl_if.SingleTaggedContainer(
                    vlan_id=srl_if.VlanIdType(vlan_id)
                )
            ),
        )


class Subinterface(srl_if.SubinterfaceListEntry, Common):
    def __init__(self, index: int, type: str):
        super().__init__(
            index=index,
            type=type,
            admin_state=srl_if.EnumerationEnum.enable,
        )

    def set_vlan(self, vlan: Vlan) -> "Subinterface":
        if vlan is None:
            raise ValueError("vlan must not be None")
        self.vlan = vlan
        return self


class Interface(srl_if.InterfaceListEntry, Common):
    def __init__(self, name: str):
        super().__init__(
            name=name,
            admin_state=srl_if.EnumerationEnum.enable,
            vlan_tagging=True,
        )

    @property
    def path(self) -> str:
        return f"/interface[name={self.name}]"

    def add_subif(self, subif: Subinterface):
        if self.subinterface is None:
            self.subinterface = []
        self.subinterface.append(subif)
