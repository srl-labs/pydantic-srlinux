from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class EnumerationEnum(Enum):
    enable = 'enable'
    disable = 'disable'


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


class StatisticsContainer(BaseModel):
    """
    Container for vxlan-tunnel per VTEP (Vxlan Termination EndPoint) statistics.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-octets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of octets encapsulated in ingress VXLAN packets.
    """
    in_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets encapsulated in ingress VXLAN packets.

    A packet in this context is an inner frame.
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of discarded ingress VXLAN packets.

    Ingress VXLAN packets can be discarded due to one of the following reasons:
    - The outer destination IP address matches a local loopback in the default network-instance,
      but the sub-interface is operationally down.
    - The outer destination IP address matches a local interface in the default network-instance,
      but the sub-interface is not a loopback.
    - The VNI is not a local one.
    - The VXLAN packet is malformed.
    """
    out_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:out-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets encapsulated in egress VXLAN packets.
    """
    out_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:out-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets encapsulated in egress VXLAN packets.

    A packet in this context is an inner frame.
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of discarded egress VXLAN packets.

    Egress VXLAN packets can be discarded due to one of the following reasons:
    - The packet size exceeds the outgoing sub-interface MTU or interface MTU.
    - The packet is discarded due to existing ACLs or QoS policies.
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the vxlan tunnel counters were cleared.
    """


class Ipv4AddressUnicastType(RootModel[str]):
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
    A unicast IPv4 address in dotted quad notation
    """


class StatisticsContainer2(BaseModel):
    """
    Container for vxlan-tunnel global statistics.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:admin-state'),
    ] = 'disable'
    """
    The configured state of the VXLAN statistics on the router

    The default value is disable. No statistics are collected on VXLAN when the admin-state is disable. When enabled,
    the router starts collecting VXLAN statistics at both, global and VTEP level, however, the total number of layer-2
    subinterfaces is decreased. A change in the configuration of this command also resets the statistic counters on
    layer-2 subinterfaces as a side effect, before resuming the collection of statistics (on these layer-2
    subinterfaces).
    """
    in_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-octets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The total sum of ingress VXLAN octets.
    """
    in_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total sum of ingress VXLAN packets.

    A packet in this context is an inner frame.
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of discarded ingress VXLAN packets.

    Ingress VXLAN packets can be discarded due to one of the following reasons:
    - The tunnel source IP address is not found on the list of discovered remote VTEPs.
    - The VNI is not a local one.
    """
    out_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:out-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total sum of egress VXLAN octets
    """
    out_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:out-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total sum of egress VXLAN packets. .

    A packet in this context is an inner frame.
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the vxlan tunnel counters were cleared.
    """


class Ipv6AddressUnicastWithoutLocalType(RootModel[str]):
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
    A unicast IPv6 address represented as either a full address, shortened or mixed-shortened formats. Link-local addresses are not allowed.
    """


class VtepListEntry(BaseModel):
    """
    The IP address that identifies the remote VXLAN Termination Endpoint (VTEP).
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Union[Ipv4AddressType, Ipv6AddressType],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:address'),
    ]
    """
    The IP address that identifies the remote VXLAN Termination Endpoint (VTEP).
    """
    index: Annotated[
        Optional[int],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:index', ge=0, le=18446744073709551615),
    ] = None
    """
    the next-hop-group-id (system allocated) for resolving the VXLAN termination endpoint
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-vxlan-tunnel-vtep:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the most recent change to the tunnel state
    """
    statistics: Annotated[
        Optional[StatisticsContainer],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:statistics'),
    ] = None


class VxlanTunnelContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vtep: Annotated[
        Optional[List[VtepListEntry]], Field(alias='srl_nokia-vxlan-tunnel-vtep:vtep')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer2],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:statistics'),
    ] = None


class TunnelListEntry(BaseModel):
    """
    The name that identifies the remote system of the tunnel
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-pw-tunnel:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The name that identifies the remote system
    """
    remote_system: Annotated[
        Union[Ipv4AddressUnicastType, Ipv6AddressUnicastWithoutLocalType],
        Field(alias='srl_nokia-pw-tunnel:remote-system'),
    ]
    """
    The ip-address of the remote system that hosts the remote pseudowire-tunnel
    """
    index: Annotated[
        Optional[int],
        Field(alias='srl_nokia-pw-tunnel:index', ge=0, le=18446744073709551615),
    ] = None
    """
    The system allocated ID of the pw tunnel
    """
    allowed_tunnel_types: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-pw-tunnel:allowed-tunnel-types')
    ] = []
    """
    List of allowed transport tunnel types for the pseudowire

    If multiple tunnel types are allowed and there are multiple
    tunnel types available to the remote system, the router
    selects the lowest preference tunnel in the tunnel-table.
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-pw-tunnel:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the most recent change to the tunnel state
    """
    operational_tunnel_type: Annotated[
        Optional[str], Field(alias='srl_nokia-pw-tunnel:operational-tunnel-type')
    ] = None
    operational_tunnel_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-pw-tunnel:operational-tunnel-id', ge=0, le=4294967295),
    ] = None
    """
    The owner-assigned tunnel table index value that identifies
    the tunnel used by the pseudowire .
    """


class PseudowireTunnelContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[List[TunnelListEntry]], Field(alias='srl_nokia-pw-tunnel:tunnel')
    ] = None


class TunnelContainer(BaseModel):
    """
    This model collects all config and state aspects of the tunnel table
    in SRLinux.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pseudowire_tunnel: Annotated[
        Optional[PseudowireTunnelContainer],
        Field(alias='srl_nokia-pw-tunnel:pseudowire-tunnel'),
    ] = None
    vxlan_tunnel: Annotated[
        Optional[VxlanTunnelContainer],
        Field(alias='srl_nokia-vxlan-tunnel-vtep:vxlan-tunnel'),
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
    tunnel: Annotated[
        Optional[TunnelContainer], Field(alias='srl_nokia-tunnel:tunnel')
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