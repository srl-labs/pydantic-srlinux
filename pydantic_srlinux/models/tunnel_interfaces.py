from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class FailedSlotsLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=16)]
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class FailedSlotsLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=16)]
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class MulticastLimitContainer(BaseModel):
    """
    Multicast limits per vxlan interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    maximum_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:maximum-entries',
            ge=-2147483648,
            le=2147483647,
        ),
    ] = None
    """
    Maximum number of multicast vxlan-destinations allowed on a vxlan-interface.
    """
    current_usage: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:current-usage',
            ge=-2147483648,
            le=2147483647,
        ),
    ] = None
    """
    Maximum number of multicast vxlan-destinations in use on this vxlan-interface.
    """


class EnumerationEnum(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum10(Enum):
    no_destination_index = 'no-destination-index'
    multicast_limit = 'multicast-limit'


class EnumerationEnum2(Enum):
    mac_failed = 'mac-failed'
    ingress_hash_failed = 'ingress-hash-failed'
    egress_hash_failed = 'egress-hash-failed'
    other = 'other'


class EnumerationEnum3(Enum):
    use_system_ipv4_address = 'use-system-ipv4-address'


class EnumerationEnum4(Enum):
    use_system_mac = 'use-system-mac'


class EnumerationEnum5(Enum):
    enable = 'enable'
    disable = 'disable'


class EnumerationEnum6(Enum):
    static = 'static'
    duplicate = 'duplicate'
    learnt = 'learnt'
    irb_interface = 'irb-interface'
    evpn = 'evpn'
    evpn_static = 'evpn-static'
    irb_interface_anycast = 'irb-interface-anycast'
    proxy_anti_spoof = 'proxy-anti-spoof'
    reserved = 'reserved'
    eth_cfm = 'eth-cfm'
    irb_interface_vrrp = 'irb-interface-vrrp'


class EnumerationEnum7(Enum):
    mac_limit = 'mac-limit'
    failed_on_slots = 'failed-on-slots'
    no_destination_index = 'no-destination-index'
    reserved = 'reserved'


class EnumerationEnum8(Enum):
    mac_limit = 'mac-limit'
    failed_on_slots = 'failed-on-slots'
    no_destination_index = 'no-destination-index'
    reserved = 'reserved'


class EnumerationEnum9(Enum):
    none = 'none'
    bum = 'BUM'
    unknown_unicast = 'unknown-unicast'
    broadcast_mcast = 'broadcast-mcast'


class IngressContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vni: Annotated[
        int, Field(alias='srl_nokia-tunnel-interfaces:vni', ge=1, le=16777215)
    ]
    """
    Ingress VXLAN Network Identifier of the VXLAN subinterface.

    The egress VNI is determined by the static egress-vni configured in the associated destination
    or by the dynamic egress-vni learned from the control plane.
    """


class InnerEthernetHeaderContainer2(BaseModel):
    """
    Parameters of the inner VXLAN ethernet payload when the VXLAN tunnel is used in an ip-vrf.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    destination_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-tunnel-interfaces:destination-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    VXLAN inner ethernet destination mac-address.

    Configured when the VXLAN tunnel is associated with a ip-vrf network-instance and the egress-vtep
    and egress-vni are statically configured. If not configured, the destination mac-address is obtained from one
    of the EVPN IP Prefix routes for the destination, out of the Router's MAC extended community.
    """


class Ipv4AddressType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$'
        ),
    ]
    """
    An IPv4 address in dotted quad notation.
    """


class Ipv6AddressType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$'
        ),
    ]
    """
    An IPv6 address represented as either a full address; shortened
    or mixed-shortened formats.
    """


class DestinationListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-tunnel-interfaces:index', ge=0, le=65535)
    ]
    """
    Numerical index of the destination member
    """
    admin_state: Annotated[
        Optional[EnumerationEnum5],
        Field(alias='srl_nokia-tunnel-interfaces:admin-state'),
    ] = 'enable'
    """
    Used to enable or disable a particular destination.
    """
    vni: Annotated[
        Optional[int], Field(alias='srl_nokia-tunnel-interfaces:vni', ge=1, le=16777215)
    ] = None
    """
    Egress VXLAN Network Identifier of the vxlan-interface.

    The egress VNI is statically configured or dynamically learned from the control plane.
    """
    inner_ethernet_header: Annotated[
        Optional[InnerEthernetHeaderContainer2],
        Field(alias='srl_nokia-tunnel-interfaces:inner-ethernet-header'),
    ] = None


class GroupListEntry(BaseModel):
    """
    Specifies the destination group.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-tunnel-interfaces:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Specifies the destination group name
    """
    admin_state: Annotated[
        Optional[EnumerationEnum5],
        Field(alias='srl_nokia-tunnel-interfaces:admin-state'),
    ] = 'enable'
    """
    Used to enable or disable a destination group
    """
    esi: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-tunnel-interfaces:esi',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){9}$).*$',
        ),
    ] = None
    """
    The 10-byte Ethernet Segment Identifier of the ethernet segment.
    ESI-0 or MAX-ESI values are not allowed.
    """
    destination: Annotated[
        Optional[List[DestinationListEntry]],
        Field(alias='srl_nokia-tunnel-interfaces:destination'),
    ] = None


class InnerEthernetHeaderContainer(BaseModel):
    """
    Parameters of the inner VXLAN ethernet payload when the VXLAN tunnel is used in an ip-vrf.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    source_mac: Annotated[
        Optional[EnumerationEnum4],
        Field(alias='srl_nokia-tunnel-interfaces:source-mac'),
    ] = 'use-system-mac'
    """
    VXLAN inner ethernet source mac-address. Present when the VXLAN tunnel is associated
    with a ip-vrf network-instance.
    """
    used_source_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-tunnel-interfaces:used-source-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    VXLAN inner ethernet source mac-address in use. Present when the VXLAN tunnel is associated
    with a ip-vrf network-instance.
    """


class MacTypeListEntry(BaseModel):
    """
    the type of the mac on the sub-interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        EnumerationEnum6,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:type'
        ),
    ]
    """
    type of mac addresses in the system
    """
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries of this type on the sub-interface
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type , active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type, which have not been programmed on atleast one slot
    """


class MacTypeListEntry2(BaseModel):
    """
    the type of the mac on the sub-interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        EnumerationEnum6,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:type'
        ),
    ]
    """
    type of mac addresses in the system
    """
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries of this type on the sub-interface
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type , active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type, which have not been programmed on atleast one slot
    """


class MacTypeListEntry3(BaseModel):
    """
    The type of the mac on the sub-interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        EnumerationEnum6,
        Field(alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:type'),
    ]
    """
    type of mac addresses in the system
    """
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries of this type on the sub-interface
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type, active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type, which have not been programmed on at least one slot
    """


class MacListEntry(BaseModel):
    """
    macs learnt on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        str,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The mac-address type represents an IEEE 802 MAC address.
    The canonical representation uses lowercase characters.

    In the value set and its semantics, this type is equivalent
    to the MacAddress textual convention of the SMIv2.
    """
    type: Annotated[
        Optional[EnumerationEnum6],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:type'
        ),
    ] = None
    """
    the type of the mac installed in the fib.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of this mac
    """
    not_programmed_reason: Annotated[
        Optional[EnumerationEnum7],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:not-programmed-reason'
        ),
    ] = None
    """
    The reason why the mac is not programmed
    """
    failed_slots: Annotated[
        Optional[List[FailedSlotsLeafList]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-slots'
        ),
    ] = []
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class MacListEntry2(BaseModel):
    """
    macs learnt on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        str,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The mac-address type represents an IEEE 802 MAC address.
    The canonical representation uses lowercase characters.

    In the value set and its semantics, this type is equivalent
    to the MacAddress textual convention of the SMIv2.
    """
    type: Annotated[
        Optional[EnumerationEnum6],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:type'
        ),
    ] = None
    """
    the type of the mac installed in the fib.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of this mac
    """
    not_programmed_reason: Annotated[
        Optional[EnumerationEnum8],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:not-programmed-reason'
        ),
    ] = None
    """
    The reason why the mac is not programmed
    """
    failed_slots: Annotated[
        Optional[List[FailedSlotsLeafList2]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-slots'
        ),
    ] = []
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class StatisticsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries that are active on the sub-interface.
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, which have not been programmed on atleast one slot
    """
    mac_type: Annotated[
        Optional[List[MacTypeListEntry]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac-type'
        ),
    ] = None


class StatisticsContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries that are active on the sub-interface.
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, which have not been programmed on atleast one slot
    """
    mac_type: Annotated[
        Optional[List[MacTypeListEntry2]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac-type'
        ),
    ] = None


class StatisticsContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:active-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of entries that are active on the sub-interface.
    """
    total_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:total-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, active and inactive, on the sub-interface.
    """
    failed_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, which have not been programmed on at least one slot
    """
    mac_type: Annotated[
        Optional[List[MacTypeListEntry3]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:mac-type'
        ),
    ] = None


class DestinationGroupsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    group: Annotated[
        Optional[List[GroupListEntry]], Field(alias='srl_nokia-tunnel-interfaces:group')
    ] = None


class DestinationListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vtep: Annotated[
        Union[Ipv4AddressType, Ipv6AddressType],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:vtep'
        ),
    ]
    """
    The IP address that identifies the remote VXLAN Termination Endpoint (VTEP).
    """
    vni: Annotated[
        int,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:vni',
            ge=1,
            le=16777215,
        ),
    ]
    """
    VXLAN Network Identifier of the destination.
    """
    multicast_forwarding: Annotated[
        Optional[EnumerationEnum9],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:multicast-forwarding'
        ),
    ] = None
    """
    The type of multicast data forwarded by this vxlan destination.
    """
    destination_index: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:destination-index',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    A system-wide unique identifier of this vxlan destination object (system allocated).
    """
    not_programmed_reason: Annotated[
        Optional[EnumerationEnum10],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:not-programmed-reason'
        ),
    ] = None
    """
    The reason why the destination is not programmed in the floodlist
    """


class EgressContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    source_ip: Annotated[
        Optional[EnumerationEnum3], Field(alias='srl_nokia-tunnel-interfaces:source-ip')
    ] = 'use-system-ipv4-address'
    """
    The ip-address that will be used as the source-ip for all vxlan traffic egressing this vxlan-interface.
    """
    inner_ethernet_header: Annotated[
        Optional[InnerEthernetHeaderContainer],
        Field(alias='srl_nokia-tunnel-interfaces:inner-ethernet-header'),
    ] = None
    destination_groups: Annotated[
        Optional[DestinationGroupsContainer],
        Field(alias='srl_nokia-tunnel-interfaces:destination-groups'),
    ] = None


class MacTableContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[List[MacListEntry]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac'
        ),
    ] = None


class MacTableContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[List[MacListEntry2]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac'
        ),
    ] = None


class MulticastDestinationsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    multicast_limit: Annotated[
        Optional[MulticastLimitContainer],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:multicast-limit'
        ),
    ] = None
    destination: Annotated[
        Optional[List[DestinationListEntry3]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:destination'
        ),
    ] = None


class VtepListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Union[Ipv4AddressType, Ipv6AddressType],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-es-destination-vteps:address'
        ),
    ]
    """
    The IP address that identifies the remote VXLAN Termination Endpoint (VTEP).
    """
    vni: Annotated[
        int,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-es-destination-vteps:vni',
            ge=1,
            le=16777215,
        ),
    ]
    """
    VXLAN Network Identifier of the destination.
    """


class DestinationListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vtep: Annotated[
        Union[Ipv4AddressType, Ipv6AddressType],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:vtep'
        ),
    ]
    """
    The IP address that identifies the remote VXLAN Termination Endpoint (VTEP).
    """
    vni: Annotated[
        int,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:vni',
            ge=1,
            le=16777215,
        ),
    ]
    """
    VXLAN Network Identifier of the destination.
    """
    destination_index: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:destination-index',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    A system-wide unique identifier of this vxlan destination object (system allocated).
    """
    statistics: Annotated[
        Optional[StatisticsContainer],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:statistics'
        ),
    ] = None
    mac_table: Annotated[
        Optional[MacTableContainer],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac-table'
        ),
    ] = None


class EsDestinationListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    esi: Annotated[
        str,
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:esi',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){9}$).*$',
        ),
    ]
    """
    The 10-byte Ethernet Segment Identifier of the ethernet segment.
    ESI-0 or MAX-ESI values are not allowed.
    """
    destination_index: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:destination-index',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    A system-wide unique identifier of this vxlan destination object (system allocated).
    """
    statistics: Annotated[
        Optional[StatisticsContainer2],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:statistics'
        ),
    ] = None
    mac_table: Annotated[
        Optional[MacTableContainer2],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:mac-table'
        ),
    ] = None
    vtep: Annotated[
        Optional[List[VtepListEntry]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-es-destination-vteps:vtep'
        ),
    ] = None


class UnicastDestinationsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    destination: Annotated[
        Optional[List[DestinationListEntry2]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:destination'
        ),
    ] = None
    es_destination: Annotated[
        Optional[List[EsDestinationListEntry]],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:es-destination'
        ),
    ] = None


class BridgeTableContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    unicast_destinations: Annotated[
        Optional[UnicastDestinationsContainer],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-unicast-destinations:unicast-destinations'
        ),
    ] = None
    multicast_destinations: Annotated[
        Optional[MulticastDestinationsContainer],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table-multicast-destinations:multicast-destinations'
        ),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer3],
        Field(
            alias='srl_nokia-tunnel-interfaces-vxlan-interface-bridge-table:statistics'
        ),
    ] = None


class VxlanInterfaceListEntry(BaseModel):
    """
    The list of vxlan-interfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-tunnel-interfaces:index', ge=0, le=99999999)
    ]
    """
    The index of the vxlan-tunnel.
    """
    type: Annotated[str, Field(alias='srl_nokia-tunnel-interfaces:type')]
    """
    The value of this leaf indicates the context in which the
    vxlan-interface will be used in.
    """
    oper_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-tunnel-interfaces:oper-state')
    ] = None
    """
    The operational state of the vxlan-interface
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum2],
        Field(alias='srl_nokia-tunnel-interfaces:oper-down-reason'),
    ] = None
    """
    The reason why the vxlan-interface is oper-down
    """
    ingress: Annotated[
        Optional[IngressContainer], Field(alias='srl_nokia-tunnel-interfaces:ingress')
    ] = None
    egress: Annotated[
        Optional[EgressContainer], Field(alias='srl_nokia-tunnel-interfaces:egress')
    ] = None
    bridge_table: Annotated[
        Optional[BridgeTableContainer],
        Field(alias='srl_nokia-tunnel-interfaces:bridge-table'),
    ] = None


class TunnelInterfaceListEntry(BaseModel):
    """
    In the case that the interface is logical tunnel
    interface, the parameters for the tunnel are
    specified within this subtree. Tunnel interfaces
    have only a single logical subinterface associated
    with them.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-tunnel-interfaces:name',
            pattern='^(?=^(vxlan(0|1[0-9][0-9]|2([0-4][0-9]|5[0-5])|[1-9][0-9]|[1-9]))$).*$',
        ),
    ]
    """
    The name of the tunnel-interface.

    Valid options are:
    vxlan<N>, N=0..255
    """
    vxlan_interface: Annotated[
        Optional[List[VxlanInterfaceListEntry]],
        Field(alias='srl_nokia-tunnel-interfaces:vxlan-interface'),
    ] = None


class Model(BaseModel):
    """
    Initialize an instance of this class and serialize it to JSON; this results in a RESTCONF payload.

    ## Tips
    Initialization:
    - all values have to be set via keyword arguments
    - if a class contains only a `root` field, it can be initialized as follows:
        - `member=MyNode(root=<value>)`
        - `member=<value>`

    Serialziation:
    - `exclude_defaults=True` omits fields set to their default value (recommended)
    - `by_alias=True` ensures qualified names are used (necessary)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel_interface: Annotated[
        Optional[List[TunnelInterfaceListEntry]],
        Field(alias='srl_nokia-tunnel-interfaces:tunnel-interface'),
    ] = None


if __name__ == "__main__":
    model = Model(
        # <Initialize model here>
    )

    restconf_payload = model.model_dump_json(
        exclude_defaults=True, by_alias=True, indent=2
    )

    print(f"Generated output: {restconf_payload}")

    # Send config to network device:
    # from pydantify.utility import restconf_patch_request
    # restconf_patch_request(url='...', user_pw_auth=('usr', 'pw'), data=restconf_payload)