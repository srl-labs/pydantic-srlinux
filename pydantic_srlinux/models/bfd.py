from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class EnumerationEnum(Enum):
    enable = 'enable'
    disable = 'disable'


class EnumerationEnum2(Enum):
    up = 'up'
    down = 'down'
    empty = 'empty'
    downloading = 'downloading'
    booting = 'booting'
    starting = 'starting'
    failed = 'failed'
    synchronizing = 'synchronizing'
    upgrading = 'upgrading'
    low_power = 'low-power'
    degraded = 'degraded'
    warm_reboot = 'warm-reboot'
    waiting = 'waiting'


class EnumerationEnum3(Enum):
    admin_down = 'ADMIN_DOWN'
    down = 'DOWN'
    init = 'INIT'
    up = 'UP'


class EnumerationEnum4(Enum):
    no_diagnostic = 'NO_DIAGNOSTIC'
    detection_timeout = 'DETECTION_TIMEOUT'
    echo_failed = 'ECHO_FAILED'
    neighbor_signaled_down = 'NEIGHBOR_SIGNALED_DOWN'
    forwarding_reset = 'FORWARDING_RESET'
    path_down = 'PATH_DOWN'
    concatenated_path_down = 'CONCATENATED_PATH_DOWN'
    admin_down = 'ADMIN_DOWN'
    reverse_concatenated_path_down = 'REVERSE_CONCATENATED_PATH_DOWN'


class EnumerationEnum5(Enum):
    sr_mpls_colored = 'sr-mpls-colored'
    sr_mpls_uncolored = 'sr-mpls-uncolored'


class EnumerationEnum6(Enum):
    local = 'LOCAL'
    pcep = 'PCEP'


class EnumerationEnum7(Enum):
    admin_down = 'ADMIN_DOWN'
    down = 'DOWN'
    init = 'INIT'
    up = 'UP'


class EnumerationEnum8(Enum):
    no_diagnostic = 'NO_DIAGNOSTIC'
    detection_timeout = 'DETECTION_TIMEOUT'
    echo_failed = 'ECHO_FAILED'
    neighbor_signaled_down = 'NEIGHBOR_SIGNALED_DOWN'
    forwarding_reset = 'FORWARDING_RESET'
    path_down = 'PATH_DOWN'
    concatenated_path_down = 'CONCATENATED_PATH_DOWN'
    admin_down = 'ADMIN_DOWN'
    reverse_concatenated_path_down = 'REVERSE_CONCATENATED_PATH_DOWN'


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


class AsyncContainer(BaseModel):
    """
    Container for async BFD operational state parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_packet_transmitted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-bfd:last-packet-transmitted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp for when the last BFD packet was transmitted for this session
    """
    last_packet_received: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-bfd:last-packet-received',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp for when the last BFD packet was received for this session
    """
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Counter for the number of BFD packets transmitted for this session
    """
    received_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:received-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Counter for the number of BFD packets received for this session
    """
    up_transitions: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:up-transitions', ge=0, le=18446744073709551615),
    ] = 0
    """
    Counter for the number of UP transitions for this BFD session
    """
    received_errored_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-bfd:received-errored-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the number of BFD packets received with BFD level errors
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-bfd:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the session counters were cleared.
    """


class AsyncContainer2(BaseModel):
    """
    Container for async BFD operational state parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_packet_transmitted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-micro-bfd:last-packet-transmitted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp for when the last BFD packet was transmitted for this session
    """
    last_packet_received: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-micro-bfd:last-packet-received',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp for when the last BFD packet was received for this session
    """
    transmitted_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:transmitted-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the number of BFD packets transmitted for this session
    """
    received_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:received-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Counter for the number of BFD packets received for this session
    """
    up_transitions: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:up-transitions', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Counter for the number of UP transitions for this BFD session
    """
    received_errored_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:received-errored-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the number of BFD packets received with BFD level errors
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-micro-bfd:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the session counters were cleared.
    """


class MemberInterfaceListEntry(BaseModel):
    """
    List of interface references to associate a micro-BFD session config and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-micro-bfd:name')]
    """
    Reference ID for associated interface
    Example: ethernet-2/1 (Reference Interface ethernet-2/1).
    """
    session_state: Annotated[
        Optional[EnumerationEnum7], Field(alias='srl_nokia-micro-bfd:session-state')
    ] = None
    """
    The state of the BFD session perceived by the local system
    """
    remote_session_state: Annotated[
        Optional[EnumerationEnum7],
        Field(alias='srl_nokia-micro-bfd:remote-session-state'),
    ] = None
    """
    The reported state of the BFD session according to the remote system

    This state reflects the last state reported in a BFD control packet.
    """
    last_state_transition: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-micro-bfd:last-state-transition',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last micro-BFD session transition from any state to any state
    Time of the session in the current state can be calculated from this value.
    """
    last_failure_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-micro-bfd:last-failure-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last BFD session transition out of the up state to down state
    """
    failure_transitions: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:failure-transitions',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of times that the BFD session has transitioned out of the up state
    """
    local_discriminator: Annotated[
        Optional[int],
        Field(alias='srl_nokia-micro-bfd:local-discriminator', ge=0, le=4294967295),
    ] = None
    """
    BFD session local discriminator
    """
    remote_discriminator: Annotated[
        Optional[int],
        Field(alias='srl_nokia-micro-bfd:remote-discriminator', ge=0, le=4294967295),
    ] = None
    """
    A unique identifier used by the remote system to identify this BFD session
    """
    local_diagnostic_code: Annotated[
        Optional[EnumerationEnum8],
        Field(alias='srl_nokia-micro-bfd:local-diagnostic-code'),
    ] = None
    """
    The local BFD diagnostic code indicating the most recent reason for failure of this BFD session
    """
    remote_diagnostic_code: Annotated[
        Optional[EnumerationEnum8],
        Field(alias='srl_nokia-micro-bfd:remote-diagnostic-code'),
    ] = None
    """
    The remote BFD diagnostic code indicating the remote system's reason for failure of the BFD session
    """
    remote_minimum_receive_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:remote-minimum-receive-interval',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The value of the minimum receive interval that was specified by the peer

    This value references the value in the most recent BFD control packet
    received from the peer.
    """
    remote_control_plane_independent: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-micro-bfd:remote-control-plane-independent'),
    ] = None
    """
    Indicates if the remote neighbor has set the control independent flag
    """
    active_transmit_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:active-transmit-interval', ge=0, le=4294967295
        ),
    ] = None
    """
    The transmit interval currently being used by this BFD session

    This is the amount of time the local BFD agent will wait between the
    sending of BFD messages to the remote peer
    """
    active_receive_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-micro-bfd:active-receive-interval', ge=0, le=4294967295),
    ] = None
    """
    The receive interval currently being used by this BFD session

    This is the amount of time the BFD state machine expects between
    receiving BFD messages from the remote peer.
    """
    remote_multiplier: Annotated[
        Optional[int],
        Field(alias='srl_nokia-micro-bfd:remote-multiplier', ge=0, le=255),
    ] = None
    """
    The current number of packets that must be missed to declare the session as down

    The detection interval for the BFD session is calculated by multiplying the
    value of the negotiated transmission interval by this value.
    """
    async_: Annotated[
        Optional[AsyncContainer2], Field(alias='srl_nokia-micro-bfd:async')
    ] = None


class SubinterfaceListEntry(BaseModel):
    """
    List of subinterface references to associating BFD config and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[str, Field(alias='srl_nokia-bfd:id')]
    """
    Reference ID for associated subinterface
    Example: ethernet-2/1.100 (Reference Interface ethernet-2/1, subinterface 100).
    """
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-bfd:admin-state')
    ] = 'disable'
    """
    Administratively enable or disable BFD for this subinterface
    """
    desired_minimum_transmit_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-bfd:desired-minimum-transmit-interval',
            ge=10000,
            le=100000000,
        ),
    ] = 1000000
    """
    The minimum interval between transmission of BFD control packets

    This value is advertised to the peer, however the actual interval used is specified
    by taking the maximum of desired-minimum-transmit-interval and the value of the remote
    required-minimum-receive interval value.
    This value is specified as an integer number of microseconds.
    """
    required_minimum_receive: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:required-minimum-receive', ge=10000, le=100000000),
    ] = 1000000
    """
    The minimum interval between received BFD control packets that this system should support

    This value is advertised to the remote peer to indicate the maximum frequency (i.e., minimum
    inter-packet interval) between BFD control packets that is acceptable to the local system.
    This value is specified as an integer number of microseconds.
    """
    detection_multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-bfd:detection-multiplier', ge=3, le=20)
    ] = 3
    """
    The number of packets that must be missed to declare this session as down

    The detection interval for the BFD session is calculated by multiplying the
    value of the negotiated transmission interval by this value.
    """
    minimum_echo_receive_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:minimum-echo-receive-interval', ge=0, le=100000000),
    ] = 0
    """
    The minimum interval between echo packets the local node can receive

    Implicitly enabled echo mode on the associated interface.
    """
    max_hop_count: Annotated[
        Optional[int], Field(alias='srl_nokia-bfd:max-hop-count', ge=2, le=255)
    ] = 255
    """
    TTL to be used in the BFD IP header for multihop BFD.
    """


class LagInterfaceListEntry(BaseModel):
    """
    List of interface references to associate a micro-BFD session config and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-micro-bfd:name')]
    """
    Reference ID for associated lag interface
    Example: lag1 (Reference Interface lag1).
    """
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-micro-bfd:admin-state')
    ] = 'disable'
    """
    Administratively enable or disable BFD for this subinterface
    """
    local_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-micro-bfd:local-address'),
    ] = None
    """
    IP address to be used as source address in BFD packets
    """
    remote_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-micro-bfd:remote-address'),
    ] = None
    """
    The remote IP address for the far-end of the BFD session

    This must be the same IP version as the local-address.
    """
    desired_minimum_transmit_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:desired-minimum-transmit-interval',
            ge=10000,
            le=100000000,
        ),
    ] = 1000000
    """
    The minimum interval between transmission of BFD control packets

    This value is advertised to the peer, however the actual interval used is specified
    by taking the maximum of desired-minimum-transmit-interval and the value of the remote
    required-minimum-receive interval value.
    This value is specified as an integer number of microseconds.
    """
    required_minimum_receive: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-micro-bfd:required-minimum-receive', ge=10000, le=100000000
        ),
    ] = 1000000
    """
    The minimum interval between received BFD control packets that this system should support

    This value is advertised to the remote peer to indicate the maximum frequency (i.e., minimum
    inter-packet interval) between BFD control packets that is acceptable to the local system.
    This value is specified as an integer number of microseconds.
    """
    detection_multiplier: Annotated[
        Optional[int],
        Field(alias='srl_nokia-micro-bfd:detection-multiplier', ge=3, le=20),
    ] = 3
    """
    The number of packets that must be missed to declare this session as down

    The detection interval for the BFD session is calculated by multiplying the
    value of the negotiated transmission interval by this value.
    """
    member_interface: Annotated[
        Optional[List[MemberInterfaceListEntry]],
        Field(alias='srl_nokia-micro-bfd:member-interface'),
    ] = None


class MicroBfdSessionsContainer(BaseModel):
    """
    Context to configure micro-BFD session parameters and report sessions state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    lag_interface: Annotated[
        Optional[List[LagInterfaceListEntry]],
        Field(alias='srl_nokia-micro-bfd:lag-interface'),
    ] = None


class PeerListEntry(BaseModel):
    """
    BFD session state related to this peer
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    local_discriminator: Annotated[
        int, Field(alias='srl_nokia-bfd:local-discriminator', ge=0, le=4294967295)
    ]
    """
    BFD session local discriminator
    """
    oper_state: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-bfd:oper-state')
    ] = None
    """
    Details the operational state of the session
    """
    ipv6_link_local_interface: Annotated[
        Optional[str], Field(alias='srl_nokia-bfd:ipv6-link-local-interface')
    ] = None
    """
    For IPv6 link local sessions only, indicates the local interface with which the session is associated.
    """
    ipv4_unnumbered_interface: Annotated[
        Optional[str], Field(alias='srl_nokia-bfd:ipv4-unnumbered-interface')
    ] = None
    """
    For IPv4 unnumbered sessions only, indicates the local interface with which the session is associated.
    """
    local_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-bfd:local-address'),
    ] = None
    """
    IP address to be used as source address in BFD packets
    """
    remote_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-bfd:remote-address'),
    ] = None
    """
    The remote IP address for the far-end of the BFD session

    This must be the same IP version as the local-address.
    """
    remote_discriminator: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:remote-discriminator', ge=0, le=4294967295),
    ] = None
    """
    A unique identifier used by the remote system to identify this BFD session
    """
    subscribed_protocols: Annotated[
        Optional[str], Field(alias='srl_nokia-bfd:subscribed-protocols')
    ] = None
    """
    Indicates the set of protocols that currently use this BFD session for liveliness detection
    """
    session_state: Annotated[
        Optional[EnumerationEnum3], Field(alias='srl_nokia-bfd:session-state')
    ] = None
    """
    The state of the BFD session perceived by the local system
    """
    remote_session_state: Annotated[
        Optional[EnumerationEnum3], Field(alias='srl_nokia-bfd:remote-session-state')
    ] = None
    """
    The reported state of the BFD session according to the remote system

    This state reflects the last state reported in a BFD control packet.
    """
    last_state_transition: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-bfd:last-state-transition',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last BFD session transition from any state to any state
    Time of the session in the current state can be calculated from this value.
    """
    last_failure_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-bfd:last-failure-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last BFD session transition out of the up state to down state
    """
    failure_transitions: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:failure-transitions', ge=0, le=18446744073709551615),
    ] = None
    """
    The number of times that the BFD session has transitioned out of the up state
    """
    local_diagnostic_code: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-bfd:local-diagnostic-code')
    ] = None
    """
    The local BFD diagnostic code indicating the most recent reason for failure of this BFD session
    """
    remote_diagnostic_code: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-bfd:remote-diagnostic-code')
    ] = None
    """
    The remote BFD diagnostic code indicating the remote system's reason for failure of the BFD session
    """
    remote_minimum_receive_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-bfd:remote-minimum-receive-interval', ge=0, le=4294967295
        ),
    ] = None
    """
    The value of the minimum receive interval that was specified by the peer

    This value references the value in the most recent BFD control packet
    received from the peer.
    """
    remote_control_plane_independent: Annotated[
        Optional[bool], Field(alias='srl_nokia-bfd:remote-control-plane-independent')
    ] = None
    """
    Indicates if the remote neighbor has set the control independent flag
    """
    active_transmit_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:active-transmit-interval', ge=0, le=4294967295),
    ] = None
    """
    The transmit interval currently being used by this BFD session

    This is the amount of time the local BFD agent will wait between the
    sending of BFD messages to the remote peer
    """
    active_receive_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:active-receive-interval', ge=0, le=4294967295),
    ] = None
    """
    The receive interval currently being used by this BFD session

    This is the amount of time the BFD state machine expects between
    receiving BFD messages from the remote peer.
    """
    remote_multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-bfd:remote-multiplier', ge=0, le=255)
    ] = None
    """
    The current number of packets that must be missed to declare the session as down

    The detection interval for the BFD session is calculated by multiplying the
    value of the negotiated transmission interval by this value.
    """
    te_policy_name: Annotated[
        Optional[str], Field(alias='srl_nokia-bfd:te-policy-name')
    ] = None
    """
    Name of the TE-Policy associated with this seamless BFD session
    """
    te_policy_type: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-bfd:te-policy-type')
    ] = None
    """
    Type of TE-Policy associated with this seamless BFD session
    """
    te_policy_segment_list_index: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:te-policy-segment-list-index', ge=0, le=4294967295),
    ] = None
    """
    Indicates the segment list index of the TE-Policy associated with this seamless BFD session
    """
    te_policy_protocol_origin: Annotated[
        Optional[EnumerationEnum6],
        Field(alias='srl_nokia-bfd:te-policy-protocol-origin'),
    ] = None
    """
    Indicates the protocol type used to originate the TE-Policy associated with this seamless BFD session
    """
    te_policy_segment_list_lsp_index: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-bfd:te-policy-segment-list-lsp-index', ge=0, le=4294967295
        ),
    ] = None
    """
    Indicates the lsp index for the segement list of the TE-Policy associated with this seamless BFD session
    """
    sr_policy_endpoint: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-bfd:sr-policy-endpoint'),
    ] = None
    """
    SR-Policy endpoint IP address associated with this seamless BFD session
    """
    async_: Annotated[Optional[AsyncContainer], Field(alias='srl_nokia-bfd:async')] = (
        None
    )


class NetworkInstanceListEntry(BaseModel):
    """
    network-instance context for BFD session.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-bfd:name')]
    """
    A unique name identifying the network instance
    """
    peer: Annotated[
        Optional[List[PeerListEntry]], Field(alias='srl_nokia-bfd:peer')
    ] = None


class BfdContainer(BaseModel):
    """
    Context to configure BFD parameters and report BFD sessions state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    subinterface: Annotated[
        Optional[List[SubinterfaceListEntry]], Field(alias='srl_nokia-bfd:subinterface')
    ] = None
    network_instance: Annotated[
        Optional[List[NetworkInstanceListEntry]],
        Field(alias='srl_nokia-bfd:network-instance'),
    ] = None
    total_bfd_sessions: Annotated[
        Optional[int],
        Field(alias='srl_nokia-bfd:total-bfd-sessions', ge=0, le=4294967295),
    ] = 0
    """
    Counter for the total number of BFD sessions
    """
    total_unmatched_bfd_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-bfd:total-unmatched-bfd-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total number of BFD packets received not matching a BFD session
    """
    micro_bfd_sessions: Annotated[
        Optional[MicroBfdSessionsContainer],
        Field(alias='srl_nokia-micro-bfd:micro-bfd-sessions'),
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
    bfd: Annotated[Optional[BfdContainer], Field(alias='srl_nokia-bfd:bfd')] = None


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