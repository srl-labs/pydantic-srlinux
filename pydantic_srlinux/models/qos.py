from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class CommittedBurstSizeTableContainer(BaseModel):
    """
    Defines possible committed-burst sizes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    alt_0: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:alt-0', ge=0, le=4294967295)
    ] = 0
    """
    ALT-0 committed-burst-size
    """
    alt_1: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:alt-1', ge=0, le=4294967295)
    ] = 0
    """
    ALT-1 committed-burst-size
    """
    alt_2: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:alt-2', ge=0, le=4294967295)
    ] = 0
    """
    ALT-2 committed-burst-size
    """
    alt_3: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:alt-3', ge=0, le=4294967295)
    ] = 0
    """
    ALT-3 committed-burst-size
    """


class Dot1pLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=7)]
    """
    List of dot1p values of the packets which will be assigned to a given pfc-queue
    """


class DropLeaf2(BaseModel):
    """
    Violating packets should be dropped immediately
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class DscpValueType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=63)]
    """
    A DiffServ Code Point represented numerically.
    """


class MidPoolMemberListEntry(BaseModel):
    """
    Mid-pool member
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=7)]
    """
    Mid-pool index
    """


class MidPoolMembersContainer(BaseModel):
    """
    List of mid-pool members participating in this given root-pool
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mid_pool_member: Annotated[
        Optional[List[MidPoolMemberListEntry]],
        Field(alias='srl_nokia-qos:mid-pool-member'),
    ] = None


class PacketLengthAdjustmentContainer2(BaseModel):
    """
    The definition on how packet-length should be adjusted for the scheduling-algorithm calculation
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    add: Annotated[Optional[int], Field(alias='srl_nokia-qos:add', ge=0, le=32)] = 0
    """
    Number of bytes to be added to the packet-length for the scheduling-algorithm calculation
    """


class PfcPauseFramePriorityLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=7)]
    """
    PFC priorities indicated in generated pfc-pause-frame if congestion occurs in a given pfc-queue
    """


class PfcPauseFramePriorityLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=7)]
    """
    The pfc-priority received in pfc-pause-frame
    """


class PirThresholdSeparationContainer(BaseModel):
    """
    Container defining selection of one from pre-defined policer-threshold-separation policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    inplus_separated: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:inplus-separated')
    ] = False
    """
    Selecting a separate pir-bucket threshold for in-plus profile
    """


class PolicerTemplatesContainer(BaseModel):
    """
    acl policers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class RootPoolListEntry(BaseModel):
    """
    List of root-tier pools
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=4)]
    """
    Root-pool index
    """
    allocation_weight: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:allocation-weight', ge=0, le=100)
    ] = None
    """
    The amount of the egress buffer space allocated to this root-pool. The weight expresses the relative amount of buffer space taking into account the weight of other root-pools.

    The buffer divided between individual root-pools is after reserved portion has been substracted from the total buffer size
    """
    mid_pool_members: Annotated[
        Optional[MidPoolMembersContainer], Field(alias='srl_nokia-qos:mid-pool-members')
    ] = None


class SchedClassInputsLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]
    """
    List of scheduling-classes feeding the tier-0 sched-class-scheduler
    """


class SchedulerInputsLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    List of tier-0 queue-schedulers feeding the tier-1 queue-scheduler
    """


class SchedulerInputsLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    List of tier-0 sched-class-schedulers feeding the tier-1 sched-class-scheduler
    """


class SchedulingClassLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=6)]
    """
    List of scheduling-classes which are input to this tier-0 scheduler
    """


class SchedulingResourcesPoolsContainer(BaseModel):
    """
    Lists the scheduling resources pools that the given interface is using
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource_set_pool: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:resource-set-pool', ge=0, le=1)
    ] = None
    """
    Resource-set-pool from which the interface obtains scheduling resources
    """
    interface_group_resource_pool: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:interface-group-resource-pool', ge=0, le=15),
    ] = None
    """
    Interface-group-resource-pool from which the interface obtains scheduling resources
    """


class UnicastPriorityListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource_priority: Annotated[
        int, Field(alias='srl_nokia-qos:resource-priority', ge=0, le=3)
    ]
    """
    Resource-priority for unicast packets
    """
    buffer_segment_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:buffer-segment-drop-zone', ge=0, le=3)
    ] = None
    """
    Defines drop-zone for buffer-segments at which packets with a given resource-priority will be disarded
    """
    packet_id_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:packet-id-drop-zone', ge=0, le=3)
    ] = None
    """
    Defines drop-zone for packet-id at which packets with a given resource-priority will be discarded
    """
    header_buffer_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:header-buffer-drop-zone', ge=0, le=15)
    ] = None
    """
    Defines drop-zone for header-buffer at which packets with a given resource-priority will be discarded
    """


class EnumerationEnum(Enum):
    enable = 'enable'
    disable = 'disable'


class EnumerationEnum10(Enum):
    in_ = 'in'
    out = 'out'
    exceed = 'exceed'
    in_plus = 'in-plus'


class EnumerationEnum11(Enum):
    strict = 'strict'


class EnumerationEnum12(Enum):
    queue = 'queue'


class EnumerationEnum13(Enum):
    auto_input = 'auto-input'


class EnumerationEnum14(Enum):
    auto_input = 'auto-input'


class EnumerationEnum15(Enum):
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


class EnumerationEnum16(Enum):
    inner = 'inner'
    outer = 'outer'


class EnumerationEnum17(Enum):
    trusted = 'trusted'
    untrusted = 'untrusted'


class EnumerationEnum18(Enum):
    unicast = 'unicast'
    unknown_unicast = 'unknown-unicast'
    multicast = 'multicast'
    unknown_multicast = 'unknown-multicast'
    broadcast = 'broadcast'


class EnumerationEnum19(Enum):
    field_0 = '0'
    field_1 = '1'


class EnumerationEnum2(Enum):
    in_ = 'in'
    out = 'out'
    exceed = 'exceed'
    in_plus = 'in-plus'
    in_low = 'in-low'
    out_low = 'out-low'


class EnumerationEnum20(Enum):
    local = 'local'
    interface_queue = 'interface-queue'


class EnumerationEnum21(Enum):
    tcp = 'tcp'
    non_tcp = 'non-tcp'
    all = 'all'


class EnumerationEnum22(Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'
    all = 'all'


class EnumerationEnum23(Enum):
    in_ = 'in'
    out = 'out'
    exceed = 'exceed'


class EnumerationEnum24(Enum):
    field_0 = '0'
    field_1 = '1'


class EnumerationEnum25(Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'


class EnumerationEnum26(Enum):
    violating_focus = 'violating-focus'
    forwarding_focus = 'forwarding-focus'


class EnumerationEnum3(Enum):
    cs0 = 'CS0'
    le = 'LE'
    cs1 = 'CS1'
    af11 = 'AF11'
    af12 = 'AF12'
    af13 = 'AF13'
    cs2 = 'CS2'
    af21 = 'AF21'
    af22 = 'AF22'
    af23 = 'AF23'
    cs3 = 'CS3'
    af31 = 'AF31'
    af32 = 'AF32'
    af33 = 'AF33'
    cs4 = 'CS4'
    af41 = 'AF41'
    af42 = 'AF42'
    af43 = 'AF43'
    cs5 = 'CS5'
    ef = 'EF'
    cs6 = 'CS6'
    cs7 = 'CS7'


class EnumerationEnum4(Enum):
    remote = 'remote'


class EnumerationEnum5(Enum):
    trtcm1 = 'trtcm1'
    trtcm2 = 'trtcm2'


class EnumerationEnum6(Enum):
    closest = 'closest'
    lower = 'lower'
    higher = 'higher'


class EnumerationEnum7(Enum):
    drop = 'drop'
    mark_exceed = 'mark-exceed'


class EnumerationEnum8(Enum):
    extended = 'extended'


class EnumerationEnum9(Enum):
    low = 'low'
    medium = 'medium'
    high = 'high'


class AddCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    add: Annotated[Optional[int], Field(alias='srl_nokia-qos:add', ge=0, le=32)] = None
    """
    Number of bytes to be added to the packet-length for the policer-algorithm calculation
    """


class BufferSegmentContainer(BaseModel):
    """
    Utilization thresholds for buffer segments
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    rising_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:rising-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The rising-threshold-value definining the transition from higher-congestion zone to lower-congestion zone
    """
    falling_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:falling-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The falling-threshold-value defining the transition from lower-congestion zone to higher-congestion zone
    """


class BwProportionalContainer(BaseModel):
    """
    Defines how the mid-pool size is shared between individual interface-pools taking into account interface-speed
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    over_subscription_factor: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:over-subscription-factor', ge=0.0, le=10.0),
    ] = 125
    """
    Factor defining how much of the over-subscription for the given interface-pool is allowed, when its size is calculated as a proportion of the corresponding interface-speed.

    This parameter is ignored whenever 'explicit-percentage' is set to non-zero value
    """


class DeadlockContainer(BaseModel):
    """
    Parameters related to avoid a deadlock related to pfc on outgoing interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    enable: Annotated[Optional[bool], Field(alias='srl_nokia-qos:enable')] = False
    """
    Enables/disables deadlock mechanism
    """
    detection_timer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:detection-timer', ge=10, le=1500)
    ] = 750
    """
    Number of milliseconds during which outgoing interface is receiving pfc-pause-frames before triggering recovery-timer
    """
    recovery_timer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:recovery-timer', ge=100, le=1500)
    ] = 750
    """
    Number of milliseconds during which the pfc-pause-frames will be ignored
    """


class DropCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop: Annotated[Optional[DropLeaf2], Field(alias='srl_nokia-acl-policers:drop')] = (
        None
    )


class DscpRewriteContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    force_rewrite_trusted: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:force-rewrite-trusted')
    ] = False
    """
    Enables remarking packets incomming on trusted interfaces
    """


class ExceedActionContainer(BaseModel):
    """
    Container with options that specify the handling of packets that the policer has determined are exceeding (yellow)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop_probability: Annotated[
        Optional[EnumerationEnum25],
        Field(alias='srl_nokia-acl-policers:drop-probability'),
    ] = 'medium'
    """
    Recolor exceeding packets to the specified drop-probability level
    """


class HeaderBufferContainer(BaseModel):
    """
    Utilization thresholds for packet header buffers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    rising_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:rising-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The rising-threshold-value definining the transition from higher-congestion zone to lower-congestion zone
    """
    falling_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:falling-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The falling-threshold-value defining the transition from lower-congestion zone to higher-congestion zone
    """


class InputProfileListEntry(BaseModel):
    """
    Profile of the packet
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    input_profile: Annotated[
        EnumerationEnum2, Field(alias='srl_nokia-qos:input-profile')
    ]
    """
    The profile the input packet was classified to, based on applicable classification criteria
    """
    threshold_factor: Annotated[
        Optional[float], Field(alias='srl_nokia-qos:threshold-factor', ge=0.0, le=2.0)
    ] = None
    """
    Threshold-factor for the policer bucket indicating fraction of mbs
    """


class InputContainer2(BaseModel):
    """
    QoS input parmeters ar forwarding-complex level
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_buffer_reservation: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:pfc-buffer-reservation', ge=0, le=100)
    ] = 1
    """
    Percentage of the buffer reserved for accomodating incoming traffic while upstream node reacts to generated PFC-pause frames
    """
    pfc_reserved_buffer_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-reserved-buffer-size', ge=0, le=4294967295),
    ] = None
    """
    Displays the actual size of pfc-reserved buffer in bytes
    """


class InterfacePoolListEntry(BaseModel):
    """
    List of interface-pools associated with the base interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=255)]
    """
    Interface-pool index
    """
    operational_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:operational-size', ge=0, le=4294967295),
    ] = None
    """
    Operational size of the interface-pool
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:used', ge=0, le=4294967295)
    ] = None
    """
    Actual usage of the interface-pool
    """


class MulticastPriorityListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource_priority: Annotated[
        int, Field(alias='srl_nokia-qos:resource-priority', ge=0, le=3)
    ]
    """
    Resource-priority for multicast and broadcast packets
    """
    buffer_segment_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:buffer-segment-drop-zone', ge=0, le=3)
    ] = None
    """
    Defines drop-zone for buffer-segments at which packets with a given resource-priority will be disarded
    """
    packet_id_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:packet-id-drop-zone', ge=0, le=3)
    ] = None
    """
    Defines drop-zone for packet-id at which packets with a given resource-priority will be discarded
    """
    header_buffer_drop_zone: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:header-buffer-drop-zone', ge=0, le=15)
    ] = None
    """
    Defines drop-zone for header-buffer at which packets with a given resource-priority will be discarded
    """


class OperationalSeparationThresholdsListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    input_profile: Annotated[
        EnumerationEnum2, Field(alias='srl_nokia-qos:input-profile')
    ]
    """
    The profile the input packet was classified to, based on applicable classification criteria
    """
    eir_operational_separation_threshold: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:eir-operational-separation-threshold',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The operational-threshold level for the policer eir bucket
    """
    pir_operational_separation_threshold: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:pir-operational-separation-threshold',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The operational-threshold level for the policer pir bucket
    """
    cir_operational_separation_threshold: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:cir-operational-separation-threshold',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The operational-threshold level for the policer cir bucket
    """


class PacketIdContainer(BaseModel):
    """
    Utilization thresholds for packet re-ordering contexts
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    rising_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:rising-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The rising-threshold-value definining the transition from higher-congestion zone to lower-congestion zone
    """
    falling_threshold_value: Annotated[
        Optional[float],
        Field(alias='srl_nokia-qos:falling-threshold-value', ge=0.0, le=100.0),
    ] = None
    """
    The falling-threshold-value defining the transition from lower-congestion zone to higher-congestion zone
    """


class ParentPolicerThresholdPolicyListEntry(BaseModel):
    """
    List of policies defining parent-policer-thresholds and related parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The name assigned to the parent-policer-threshold-policy
    """
    threshold_separation: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:threshold-separation', ge=3000, le=65536),
    ] = 18000
    """
    Defines the threshold-separation for parent-policer
    """


class ParentPolicerContainer2(BaseModel):
    """
    Parent-policer operational parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    rate_kbps: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:rate-kbps', ge=0, le=4294967295)
    ] = None
    """
    Operational rate of the parent policer
    """
    burst_allowance: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:burst-allowance', ge=0, le=4294967295)
    ] = None
    """
    Operational value of the burst-allowance for the parent-policer
    """
    threshold_separation: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:threshold-separation', ge=0, le=4294967295),
    ] = None
    """
    Operational value of the threshold-separation for the parent-policer
    """


class PeakRateKbpsCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:peak-rate-kbps', ge=0, le=18446744073709551615),
    ] = None
    """
    Scheduler peak-rate in kilobits-per-second
    """


class PeakRateKbpsCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:peak-rate-kbps', ge=0, le=18446744073709551615),
    ] = None
    """
    Scheduler peak-rate in kilobits-per-second
    """


class PeakRatePercentageCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_percentage: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-percentage', ge=1, le=100)
    ] = 100
    """
    Scheduler peak-rate as the percentage of the output rate
    """


class PeakRatePercentageCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_percentage: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-percentage', ge=1, le=100)
    ] = 100
    """
    Scheduler peak-rate as the percentage of the output rate
    """


class PfcPriorityListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=7)]
    """
    PFC-priority index
    """
    pfc_pause_frames_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:pfc-pause-frames-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of pfc-pause-frames received on the interface and given pfc-priority
    """
    pfc_pause_frames_generated: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:pfc-pause-frames-generated',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of pfc-pause-frames generated on the interface for a given pfc-priority
    """
    pfc_transitions: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-transitions', ge=0, le=18446744073709551615),
    ] = None
    """
    Number of transitions PFC-ON --> PFC-OFF on the interface for a given pfc-priority
    """
    deadlock_recovery_occurrences: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:deadlock-recovery-occurrences',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of deadlock recovery events
    """


class PfcQueueListEntry(BaseModel):
    """
    List of pfc-queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:pfc-queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-defined name of the pfc-queue
    """
    queue_index: Annotated[int, Field(alias='srl_nokia-qos:queue-index', ge=0, le=7)]
    """
    The queue index (offset) of the pfc-queue
    """


class PfcQueueListEntry4(BaseModel):
    """
    List of pfc-queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:pfc-queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The pfc-queue name
    """
    maximum_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:maximum-burst-size', ge=0, le=4294967295),
    ] = 51200
    """
    Maximum amount of shared buffer memory available for the given pfc-queue
    """
    committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-burst-size', ge=1536, le=262144),
    ] = 102400
    """
    Reserved amount of buffer memory available for the given pfc-queue
    """
    maximum_pfc_reserved_share_percentage: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:maximum-pfc-reserved-share-percentage', ge=0, le=100
        ),
    ] = 10
    """
    Maximum level the pfc-queue can take from pfc-reserved buffer configured per given forwarding-complex
    """
    maximum_pfc_reserved_share_bytes: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:maximum-pfc-reserved-share-bytes', ge=0, le=104857600
        ),
    ] = None
    """
    Maximum level the pfc-queue can take from pfc-reserved buffer configured per given forwarding-complex expressed as bytes. If this value is configured, maximum-pfc-reserved-share-percentage value is ignored
    """
    pfc_on_threshold: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:pfc-on-threshold', ge=0, le=100)
    ] = 100
    """
    Defines the pfc-queue depth at which pfc-pause-frames genaration will start. It is expressed as percentage of maximum-burst-size or committed-burst-size, respectively
    """
    pfc_off_threshold: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:pfc-off-threshold', ge=0, le=100)
    ] = 80
    """
    Defines the pfc-queue depth at which pfc-pause-frames will stop be generated. It is expressed as percentage of maximum-burst-size or committed-burst-size, respectively
    """
    use_dynamic_allocation: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:use-dynamic-allocation')
    ] = None
    """
    Enables dynamic allocation of the buffer space

    MBS statement is ignored, if enabled
    """


class PolicerListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer_id: Annotated[int, Field(alias='srl_nokia-qos:policer-id', ge=0, le=31)]
    """
    Input policer-id
    """
    priority_level: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:priority-level', ge=0, le=5)
    ] = 0
    """
    Priority level of the input policer. Priority-level 0 corresponds to the lowest priority
    """


class PolicersContainer(BaseModel):
    """
    Container containing the assignment of the policers to respective forwarding types
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    unicast_policer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:unicast-policer', ge=0, le=31)
    ] = None
    """
    Policer for the unicast traffic
    """
    multicast_policer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:multicast-policer', ge=0, le=31)
    ] = None
    """
    Policer for the multicast traffic
    """
    broadcast_policer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:broadcast-policer', ge=0, le=31)
    ] = None
    """
    Policer for the broadcast traffic
    """
    unknown_unicast_policer: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:unknown-unicast-policer', ge=0, le=31)
    ] = None
    """
    Policer for the unknown-unicast traffic
    """


class PrecedenceCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    precedence: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:precedence', ge=0, le=7)
    ] = None
    """
    The ip-precedence marking to be used for this specific profile
    """


class PrecedenceCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    precedence: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:precedence', ge=0, le=7)
    ] = None
    """
    The ip-precedence marking to be used for this specific profile
    """


class PrecedenceCase3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    precedence: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:precedence', ge=0, le=7)
    ] = None
    """
    The ip-precedence marking to be used for this specific profile
    """


class PrecedenceCase4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    precedence: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:precedence', ge=0, le=7)
    ] = None
    """
    The ip-precedence marking to be used for this specific profile
    """


class ProfileListEntry(BaseModel):
    """
    User defined forwarding class
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    profile_name: Annotated[EnumerationEnum2, Field(alias='srl_nokia-qos:profile-name')]
    """
    Profile-names for different profiles used during classification
    """
    unicast_resource_priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:unicast-resource-priority', ge=0, le=3),
    ] = None
    """
    Defines priority unicast packets will be assigned to shared chipset resources for a specific forwarding-class and profile combination
    """
    multicast_resource_priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:multicast-resource-priority', ge=0, le=3),
    ] = None
    """
    Defines priority multicast and broadcast packets will be assigned to shared chipset resources for a specific forwarding-class and profile combination
    """


class QueueDepthContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    maximum_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:maximum-burst-size', ge=0, le=4294967295),
    ] = None
    """
    Maximum queue depth in bytes
    """
    committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-burst-size', ge=0, le=4294967295),
    ] = None
    """
    Committed queue length in bytes
    """
    last_high_threshold_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:last-high-threshold-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The last time the queue depth exceeded the high-threshold in a rising direction
    """
    high_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:high-threshold-bytes', ge=0, le=4294967295),
    ] = None
    """
    The operational hardware value of the high threshold in bytes
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:average-1', ge=0, le=4294967295)
    ] = None
    """
    The average queue depth in the last 1 minutes using samples taken every polling-interval milliseconds
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:average-5', ge=0, le=4294967295)
    ] = None
    """
    The average queue depth in the last 5 minutes using samples taken every polling-interval milliseconds
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:average-15', ge=0, le=4294967295)
    ] = None
    """
    The average queue depth in the last 15 minutes using samples taken every polling-interval milliseconds
    """
    high_watermark_1: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:high-watermark-1', ge=0, le=4294967295),
    ] = None
    """
    The highest queue depth in the last 1 minutes using samples taken every polling-interval milliseconds
    """
    high_watermark_5: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:high-watermark-5', ge=0, le=4294967295),
    ] = None
    """
    The highest queue depth in the last 5 minutes using samples taken every polling-interval milliseconds
    """
    high_watermark_15: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:high-watermark-15', ge=0, le=4294967295),
    ] = None
    """
    The highest queue depth in the last 15 minutes using samples taken every polling-interval milliseconds
    """
    missed_polling_intervals: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:missed-polling-intervals', ge=0, le=4294967295),
    ] = None
    """
    The number of samples that were expected, but did not arrive fast enough to be included in the average and high-watermark calculations
    """


class QueueLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$'
        ),
    ]
    """
    List of queues which are input to the scheduler
    """


class QueueListEntry(BaseModel):
    """
    List of user-defined queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-defined name of the queue

    The following queue names are the system-reserved default queue names on 7250 IXR systems:
    unicast-0
    unicast-1
    unicast-2
    unicast-3
    unicast-4
    unicast-5
    unicast-6
    unicast-7

    The following queue names are the system-reserved default queue names on FPcx chipset based systems:
    queue-0
    queue-1
    queue-2
    queue-3
    queue-4
    queue-5
    queue-6
    queue-7
    queue-8
    queue-9
    queue-10
    queue-11
    """
    queue_index: Annotated[int, Field(alias='srl_nokia-qos:queue-index', ge=0, le=11)]
    """
    The queue index (offset) of the queue within the set of queues allocated to a given interface or subinterface
    """


class QueueListEntry2(BaseModel):
    """
    List of egress-queue which should react to PFC-pause-frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Egress-queue name
    """
    pfc_pause_frame_priority: Annotated[
        Optional[List[PfcPauseFramePriorityLeafList2]],
        Field(alias='srl_nokia-qos:pfc-pause-frame-priority'),
    ] = []
    """
    The pfc-priority received in pfc-pause-frame
    """
    enable_pfc: Annotated[Optional[bool], Field(alias='srl_nokia-qos:enable-pfc')] = (
        False
    )
    """
    Enables/disables reaction to received pfc-frames for a given pfc-priority
    """


class QueueListEntry5(BaseModel):
    """
    List of queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The queue name
    """
    maximum_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:maximum-burst-size', ge=0, le=4294967295),
    ] = 0
    """
    Maximum amount of shared buffer memory available to the queue.

    On IXR-6/10 this parameter applies to a set of VOQs. If the configured value is 0 or no value is configured the limit is 256 MB (268435456 bytes), however the use of 'alpha' may limit the effective value to less than 256 MB. A configured non-zero value sets a static limit without 'alpha'.

    On 7220-D2/D3/D5/H2/H3 this parameter applies to an egress queue and the default value of zero instructs the forwarding chip to apply its own limit based on 'alpha'. A non-zero value disables 'alpha'. The alpha value  is 5 (0.25 multiplier of shared buffer space) for unicast queues and 4 (0.125 multiplier of shared buffer space) for multicast queues.

    On 7730 this parameter applies to egress-queue and setting value to 0 means default value (still need to determine that)

    Must be non-zero/non-default in order to add the active-queue-management presence container
    """
    mbs_adaptation_rule: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:mbs-adaptation-rule')
    ] = 'closest'
    """
    Defines how the user-configured values will be adjusted to available hardware values
    """
    committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-burst-size', ge=0, le=4294967295),
    ] = None
    """
    Committed queue length expressed in bytes
    """
    cbs_adaptation_rule: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:cbs-adaptation-rule')
    ] = 'closest'
    """
    Defines how the user-configured values will be adjusted to values defined by committed-burst-size-table
    """
    high_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:high-threshold-bytes', ge=0, le=4294967295),
    ] = 0
    """
    The queue depth that, when crossed in a rising direction, triggers a hardware interrupt and a recording of the current system time.

    The default value of 0 disables the functionality.

    On IXR-6/10 this parameter applies to a set of VOQs (and therefore to unicast traffic only). On 7220-D2/D3/H2/H3 this parameter applies to a unicast queue only; the configuration of this leaf is ignored when the queue-template is attached to a queue with queue-type other than unicast.

    On 7220-D2/D3 the threshold is rounded up the nearest multiple of 2048 bytes. On IXR-6/10 the threshold is rounded up to the nearest multiple of 4096 bytes. On 7220-H2/H3 the threshold is rounded up to the nearest multiple of 254 bytes
    """
    interface_pool: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:interface-pool', ge=0, le=7)
    ] = None
    """
    Interface-pool the queue is assigned to at subinterface level
    """


class QueuesContainer3(BaseModel):
    """
    Buffer allocation parameters for individual queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue: Annotated[
        Optional[List[QueueListEntry5]], Field(alias='srl_nokia-qos:queue')
    ] = None
    pfc_queue: Annotated[
        Optional[List[PfcQueueListEntry4]], Field(alias='srl_nokia-qos:pfc-queue')
    ] = None


class RateContainer2(BaseModel):
    """
    Defines the scheduler rate
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    kbps_or_percentage: Annotated[
        Optional[Union[PeakRateKbpsCase, PeakRatePercentageCase]],
        Field(alias='srl_nokia-qos:kbps-or-percentage'),
    ] = None
    pir_adaptation_rule: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:pir-adaptation-rule')
    ] = 'closest'
    """
    Defines how the user-configured values will be adjusted to available hardware values
    """


class RateContainer3(BaseModel):
    """
    Defines the scheduler rate
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    kbps_or_percentage: Annotated[
        Optional[Union[PeakRateKbpsCase2, PeakRatePercentageCase2]],
        Field(alias='srl_nokia-qos:kbps-or-percentage'),
    ] = None
    pir_adaptation_rule: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:pir-adaptation-rule')
    ] = 'closest'
    """
    Defines how the user-configured values will be adjusted to available hardware values
    """


class ReColorCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop_probability: Annotated[
        Optional[EnumerationEnum25],
        Field(alias='srl_nokia-acl-policers:drop-probability'),
    ] = 'high'
    """
    Recolor violating packets to the specified drop-probability level
    """


class ReceivedPfcPauseFramesContainer(BaseModel):
    """
    Parameters describing the behaviour when pfc-pause-frames are received on outgoing interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    deadlock: Annotated[
        Optional[DeadlockContainer], Field(alias='srl_nokia-qos:deadlock')
    ] = None
    queue: Annotated[
        Optional[List[QueueListEntry2]], Field(alias='srl_nokia-qos:queue')
    ] = None


class SchedulingClassCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    scheduling_class: Annotated[
        Optional[List[SchedulingClassLeafList]],
        Field(alias='srl_nokia-qos:scheduling-class'),
    ] = []
    """
    List of scheduling-classes which are input to this tier-0 scheduler
    """


class SchedulingClassListEntry(BaseModel):
    """
    List of scheduling-classes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=6)]
    """
    Scheduling-class index
    """
    scheduling_priority: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:scheduling-priority', ge=0, le=2)
    ] = None
    """
    Scheduling-priority assigned to the scheduling-class
    """


class SchedulingPriorityMappingTableContainer(BaseModel):
    """
    This table maps individual scheduling-classes into scheduling-priority.

    This table is global for the whole system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    scheduling_class: Annotated[
        Optional[List[SchedulingClassListEntry]],
        Field(alias='srl_nokia-qos:scheduling-class'),
    ] = None


class SchedulingContainer(BaseModel):
    """
    Definition of scheduling related for the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    scheduling_class: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:scheduling-class', ge=0, le=6)
    ] = 0
    """
    Scheduling-class of the queue
    """
    weight: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:weight', ge=1, le=127)
    ] = 1
    """
    The scheduling weight of the given queue
    """
    packet_length_adjustment: Annotated[
        Optional[PacketLengthAdjustmentContainer2],
        Field(alias='srl_nokia-qos:packet-length-adjustment'),
    ] = None


class SchedulingContainer2(BaseModel):
    """
    Container for queue scheduling parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-percent', ge=1, le=100)
    ] = None
    """
    The maximum percentage of port bandwidth that is available to the traffic in this queue during the PIR scheduling loop. The default is 100
    """
    peak_rate_bps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:peak-rate-bps', ge=0, le=18446744073709551615),
    ] = None
    """
    The actual/operational peak rate in bits per second
    """
    strict_priority: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:strict-priority')
    ] = None
    """
    When set to true the queue is serviced as a strict priority queue, regardless of whether a weight is configured or its value. When set to false the queue is serviced using WRR, even if the queue does not have a configured weight; in this case the default weight value of 1 is used
    """
    weight: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:weight', ge=1, le=255)
    ] = None
    """
    Configures the relative weight of a queue.

    For DWRR, this is determined by the scheduler policy
    For Strict Priority the weight is as follows

    J2:
    unicast-0..unicast-7 -> weight 9..16
    multicast-0..multicast-7 -> weight 1..8

    TD3 (D2/D3/D5):
    unicast-0..unicast-7 -> weight 1..8
    multicast-0..multicast-7 -> weight 1..8

    TH3:
    unicast-0 -> weight 2
    unicast-1 -> weight 3
    unicast-2 -> weight 5
    unicast-3 -> weight 6
    unicast-4 -> weight 8
    unicast-5 -> weight 9
    unicast-6 -> weight 11
    unicast-7 -> weight 12
    multicast-0 -> weight 1
    multicast-1 -> weight 4
    multicast-2 -> weight 7
    multicast-3 -> weight 10

    """
    scheduling_class: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:scheduling-class', ge=0, le=6)
    ] = None
    """
    The scheduling-class for output-queue
    """


class StatisticsContainer(BaseModel):
    """
    Statistics related to PFC functionality
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the statistics associated with this queue were cleared
    """
    total_pfc_pause_frames_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:total-pfc-pause-frames-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Total number of pfc-pause-frames received on the interface
    """
    total_pfc_pause_frames_generated: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:total-pfc-pause-frames-generated',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Total number of pfc-pause-frames generated on the interface
    """
    total_packet_pfc_discards: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:total-packet-pfc-discards',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Total number of packets discarded becuase pfc-buffer-allocation was depleted. Under normal condition this counter should not be incremented
    """
    pfc_priority: Annotated[
        Optional[List[PfcPriorityListEntry]], Field(alias='srl_nokia-qos:pfc-priority')
    ] = None


class SubtractCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    subtract: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:subtract', ge=0, le=64)
    ] = None
    """
    Number of bytes to be subtracted from the packet-length for the policer-algorithm calculation
    """


class ThresholdSeparationPolicyListEntry(BaseModel):
    """
    Lists configuration of pre-defined threshold-separation policy
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    System wide pre-defined threshold-separation-policy name
    """
    input_profile: Annotated[
        Optional[List[InputProfileListEntry]],
        Field(alias='srl_nokia-qos:input-profile'),
    ] = None


class ThresholdListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=1, le=3)]
    """
    Threshold index
    """
    buffer_segment: Annotated[
        Optional[BufferSegmentContainer], Field(alias='srl_nokia-qos:buffer-segment')
    ] = None
    packet_id: Annotated[
        Optional[PacketIdContainer], Field(alias='srl_nokia-qos:packet-id')
    ] = None
    header_buffer: Annotated[
        Optional[HeaderBufferContainer], Field(alias='srl_nokia-qos:header-buffer')
    ] = None


class ViolateActionContainer(BaseModel):
    """
    Container with options that specify the handling of packets that the policer has determined are violating (red)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    violate_handling: Annotated[
        Optional[Union[DropCase, ReColorCase]],
        Field(alias='srl_nokia-acl-policers:violate-handling'),
    ] = None


class AdaptationRulesContainer(BaseModel):
    """
    Container defining adaptation rules for individual policer parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:peak-rate')
    ] = 'closest'
    """
    Adaptation rule for peak-rate-kbps parameter
    """
    committed_rate: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:committed-rate')
    ] = 'closest'
    """
    Adaptation rule for committed-rate-kbps parameter
    """
    excess_rate: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:excess-rate')
    ] = 'closest'
    """
    Adaptation rule for excess-rate-kbs parameter
    """
    maximum_burst_size: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:maximum-burst-size')
    ] = 'closest'
    """
    Adaptation rule for maximum-burst-size parameter
    """
    committed_burst_size: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:committed-burst-size')
    ] = 'closest'
    """
    Adaptation rule for committed-burst-size parameter
    """
    excess_burst_size: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:excess-burst-size')
    ] = 'closest'
    """
    Adaptation rule for excess-burst-size parameter
    """


class AggregateStatisticsContainer(BaseModel):
    """
    The aggregate statistics per subinterface policers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the statistics associated with this policer were cleared
    """
    accepted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were accepted by the policer, counting all input profiles.

    Not available in extended statistics-mode
    """
    accepted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were accepted by the policer, counting all input profiles.

    Not available in extended statistics-mode
    """
    accepted_inplus_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-inplus-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of packets that were considered as Green by the policer and their input profile was 'inplus'.

    Not available in minimal statistics-mode
    """
    accepted_inplus_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-inplus-octets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of octets in packets that were considered as Green by the policer and their input profile was 'inplus'.

    Not available in minimal statistics-mode
    """
    accepted_in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were considered as Green by the policer and their input profile was 'in'.

    Not available in minimal statistics-mode
    """
    accepted_in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were considered as Green by the policer and their input profile was 'in'.

    Not available in minimal statistics-mode
    """
    accepted_out_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-out-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of packets that were considered Yellow having input profile 'inplus' or 'in', and packets that were considered Green and Yellow having input profile 'out'.

    Not available in minimal statistics-mode
    """
    accepted_out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were considered Yellow having input profile 'inplus' or 'in', and packets that were considered Green and Yellow having input profile 'out'.

    Not available in minimal statistics-mode
    """
    exceed_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:exceed-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were accepted having input profile 'exceed'.

    Available in boths statistics-modes
    """
    exceed_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:exceed-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were accepted having input profile 'exceed'.

    Available in both statistics-modes
    """


class AllocationSizeContainer(BaseModel):
    """
    Interface-pool size definition
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    explicit_percentage: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:explicit-percentage', ge=0, le=100)
    ] = 0
    """
    Interface-pool size as percentage of mid-pool. The value equal '0' means that bw-proportinal distribution is used
    """
    bw_proportional: Annotated[
        Optional[BwProportionalContainer], Field(alias='srl_nokia-qos:bw-proportional')
    ] = None


class AutoInputCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    inputs: Annotated[
        Optional[EnumerationEnum13], Field(alias='srl_nokia-qos:inputs')
    ] = None
    """
    This options defines that all queues defined in this queue-scheduling-policy are input to this tier-0 scheduler or all tier-0 schedulers are input to tier-1 scheduler
    """


class AutoInputCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    inputs: Annotated[
        Optional[EnumerationEnum14], Field(alias='srl_nokia-qos:inputs')
    ] = None
    """
    This options defines that all scheduling-classes are input to this tier-0 scheduler or all tier-0 schedulers are input to tier-1 scheduler
    """


class BufferAllocationProfileListEntry(BaseModel):
    """
    The name of a buffer-allocation-profile
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Unique string name used for the buffer-allocation-profile
    """
    queues: Annotated[
        Optional[QueuesContainer3], Field(alias='srl_nokia-qos:queues')
    ] = None


class DropProbabilityListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop_probability: Annotated[
        EnumerationEnum9, Field(alias='srl_nokia-qos:drop-probability')
    ]
    """
    A drop probability level within the FC for which a different remarking is desired
    """
    traffic_class: Annotated[
        int, Field(alias='srl_nokia-qos:traffic-class', ge=0, le=7)
    ]
    """
    The MPLS traffic class marking to be used for this specific drop-probability
    """


class DropProbabilityListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop_probability: Annotated[
        EnumerationEnum9, Field(alias='srl_nokia-qos:drop-probability')
    ]
    """
    A drop probability level within the FC for which a different remarking is desired
    """
    dot1p: Annotated[int, Field(alias='srl_nokia-qos:dot1p', ge=0, le=7)]
    """
    The dot1p marking to be used for this specific drop-probability
    """


class DropZonesContainer(BaseModel):
    """
    Defines drop-zones per shared-resource on per resource-priority and per packet-type basis
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    unicast_priority: Annotated[
        Optional[List[UnicastPriorityListEntry]],
        Field(alias='srl_nokia-qos:unicast-priority'),
    ] = None
    multicast_priority: Annotated[
        Optional[List[MulticastPriorityListEntry]],
        Field(alias='srl_nokia-qos:multicast-priority'),
    ] = None


class ExceedProfileContainer(BaseModel):
    """
    Stats for packets marked with Exceed profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class ExceedProfileContainer2(BaseModel):
    """
    Stats for packets marked with Exceed profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class ExplicitCongestionNotificationContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ecn_dscp_policy: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:ecn-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Reference to the DSCP rewrite policy to use when DSCP rewrite is required as a side effect of ECN remarking.

    This is required configuration in order to globally enable ECN on J2 platforms
    """


class ForwardingClassLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$'
        ),
    ]
    """
    List of forwarding-classes which packets are assigned to a given pfc-queue for untagged routed-interfaces
    """


class ForwardingClassLeafList2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$'
        ),
    ]
    """
    The forwarding class mapped in the given pfc-queue
    """


class ForwardingClassListEntry2(BaseModel):
    """
    User defined forwarding class
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    profile: Annotated[
        Optional[List[ProfileListEntry]], Field(alias='srl_nokia-qos:profile')
    ] = None


class ForwardingClassListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    policers: Annotated[
        Optional[PolicersContainer], Field(alias='srl_nokia-qos:policers')
    ] = None


class ForwardingComplexListEntry(BaseModel):
    """
    Forwarding complex on the card
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[EnumerationEnum19, Field(alias='srl_nokia-qos:name')]
    """
    Forwarding-complex name
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the statistics associated with this policer were cleared
    """
    accepted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were accepted by the policer, counting all input profiles.

    Not available in extended statistics-mode
    """
    accepted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were accepted by the policer, counting all input profiles.

    Not available in extended statistics-mode
    """
    accepted_inplus_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-inplus-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of packets that were considered as Green by the policer and their input profile was 'inplus'.

    Not available in minimal statistics-mode
    """
    accepted_inplus_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-inplus-octets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of octets in packets that were considered as Green by the policer and their input profile was 'inplus'.

    Not available in minimal statistics-mode
    """
    accepted_in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were considered as Green by the policer and their input profile was 'in'.

    Not available in minimal statistics-mode
    """
    accepted_in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were considered as Green by the policer and their input profile was 'in'.

    Not available in minimal statistics-mode
    """
    accepted_out_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:accepted-out-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of packets that were considered Yellow having input profile 'inplus' or 'in', and packets that were considered Green and Yellow having input profile 'out'.

    Not available in minimal statistics-mode
    """
    accepted_out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:accepted-out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were considered Yellow having input profile 'inplus' or 'in', and packets that were considered Green and Yellow having input profile 'out'.

    Not available in minimal statistics-mode
    """
    exceed_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:exceed-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets that were accepted having input profile 'exceed'.

    Available in boths statistics-modes
    """
    exceed_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:exceed-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets in packets that were accepted having input profile 'exceed'.

    Available in both statistics-modes
    """


class InPlusProfileContainer(BaseModel):
    """
    Stats for packets marked with In-Plus profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class InPlusProfileContainer2(BaseModel):
    """
    Stats for packets marked with In-Plus profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class InProfileContainer(BaseModel):
    """
    Stats for packets marked with In profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class InProfileContainer2(BaseModel):
    """
    Stats for packets marked with In profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class InputClassMapListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User defined input-class-map name
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry3]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = None


class InputListEntry(BaseModel):
    """
    List of input sources for the scheduler
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[str, Field(alias='srl_nokia-qos:id')]
    """
    User-defined identifier for the scheduler input
    """
    input_type: Annotated[
        Optional[EnumerationEnum12], Field(alias='srl_nokia-qos:input-type')
    ] = 'queue'
    queue_name: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The queue name
    """
    peak_rate_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-percent', ge=1, le=100)
    ] = 100
    """
    The maximum percentage of port bandwidth that is available to the traffic in this queue during the PIR scheduling loop. The default is 100
    """
    weight: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:weight', ge=1, le=255)
    ] = None
    """
    For weighted round-robin schedulers, this leaf indicates the weight of the corresponding input
    """


class InputsContainer(BaseModel):
    """
    Container defining input policers to parent-policer
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer: Annotated[
        Optional[List[PolicerListEntry2]], Field(alias='srl_nokia-qos:policer')
    ] = None


class InputsContainer3(BaseModel):
    """
    List of scheduler inputs
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    auto_or_explicit_list: Annotated[
        Optional[Union[SchedulingClassCase, AutoInputCase2]],
        Field(alias='srl_nokia-qos:auto-or-explicit-list'),
    ] = None


class InterfaceInstanceListEntry(BaseModel):
    """
    List of interface instances
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface_name: Annotated[str, Field(alias='srl_nokia-qos:interface-name')]
    peak_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:peak-rate-kbps', ge=0, le=18446744073709551615),
    ] = None


class InterfaceInstanceListEntry2(BaseModel):
    """
    List of interface instances
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface_name: Annotated[str, Field(alias='srl_nokia-qos:interface-name')]
    peak_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:peak-rate-kbps', ge=0, le=18446744073709551615),
    ] = None


class InterfacePoolListEntry2(BaseModel):
    """
    List of interface-pools.
    The interface-pools are directly mapped to mid-pools in 1:1 fashion
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=7)]
    slope_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:slope-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = 'default'
    """
    Slope policy associated with the given interface-pool
    """
    allocation_size: Annotated[
        Optional[AllocationSizeContainer], Field(alias='srl_nokia-qos:allocation-size')
    ] = None


class LinecardListEntry(BaseModel):
    """
    Line-card within the system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[int, Field(alias='srl_nokia-qos:slot', ge=1, le=16)]
    """
    Numeric identifier for the linecard
    """
    forwarding_complex: Annotated[
        Optional[List[ForwardingComplexListEntry]],
        Field(alias='srl_nokia-qos:forwarding-complex'),
    ] = None


class MidPoolListEntry(BaseModel):
    """
    Mid-pool definition
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-qos:index', ge=0, le=7)]
    """
    Mid-pool index
    """
    allocation_percentage_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:allocation-percentage-size', ge=0, le=100),
    ] = None
    """
    The size of the mid-pool as a percentage of root-pool
    """
    slope_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:slope-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = 'default'
    """
    The slope-policy attached to the given mid-pool
    """


class MidTierContainer(BaseModel):
    """
    Mid-pool parameters definition
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mid_pool: Annotated[
        Optional[List[MidPoolListEntry]], Field(alias='srl_nokia-qos:mid-pool')
    ] = None


class OutProfileContainer(BaseModel):
    """
    Stats for packets marked with Out profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class OutProfileContainer2(BaseModel):
    """
    Stats for packets marked with Out profile transmitted by the queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    transmitted_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue, including transit traffic and locally originated traffic
    """
    transmitted_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:transmitted-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue, including transit traffic and locally originated traffic
    """
    dropped_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of packets transmitted by the queue dropped by the queue
    """
    dropped_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:dropped-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of octets transmitted by the queue dropped by the queue
    """


class OutputContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slope_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:slope-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Assigns slope policy to interface-level forwarding-class
    """
    queue: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:queue',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Output queue for this forwarding class
    """
    unicast_queue: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:unicast-queue',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Output queue for unicast packets within this forwarding class

    For the system-reserved default forwarding classes:
    fc0 -> unicast-queue = unicast-queue0
    fc1 -> unicast-queue = unicast-queue1
    fc2 -> unicast-queue = unicast-queue2
    fc3 -> unicast-queue = unicast-queue3
    fc4 -> unicast-queue = unicast-queue4
    fc5 -> unicast-queue = unicast-queue5
    fc6 -> unicast-queue = unicast-queue6
    fc7 -> unicast-queue = unicast-queue7
    """
    multicast_queue: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:multicast-queue',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Output queue for multicast packets within this forwarding class
    """


class OutputContainer3(BaseModel):
    """
    QoS ouput parameters at forwarding-complex level
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    fp_pool_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:fp-pool-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = 'default'
    """
    FP-pool-policy assigned to the forwarding-complex
    """


class PacketLengthAdjustmentContainer(BaseModel):
    """
    The definition on how packet-length should be adjusted for the policer-algorithm calculation
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    add_or_subtract: Annotated[
        Optional[Union[AddCase, SubtractCase]],
        Field(alias='srl_nokia-qos:add-or-subtract'),
    ] = None


class PerLagMemberStatisticsContainer(BaseModel):
    """
    The subinterface policer stats per member-fp
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    linecard: Annotated[
        Optional[List[LinecardListEntry]], Field(alias='srl_nokia-qos:linecard')
    ] = None


class PfcQueueListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:pfc-queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    PFC-queue the packets should be mapped to
    """
    dot1p: Annotated[
        Optional[List[Dot1pLeafList]], Field(alias='srl_nokia-qos:dot1p')
    ] = []
    """
    List of dot1p values of the packets which will be assigned to a given pfc-queue
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassLeafList]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = []
    """
    List of forwarding-classes which packets are assigned to a given pfc-queue for untagged routed-interfaces
    """
    pfc_pause_frame_priority: Annotated[
        Optional[List[PfcPauseFramePriorityLeafList]],
        Field(alias='srl_nokia-qos:pfc-pause-frame-priority'),
    ] = []
    """
    PFC priorities indicated in generated pfc-pause-frame if congestion occurs in a given pfc-queue
    """
    enable_pfc: Annotated[Optional[bool], Field(alias='srl_nokia-qos:enable-pfc')] = (
        False
    )
    """
    Enables/disables pfc-frame generation for a given pfc-queue
    """


class PfcQueueListEntry3(BaseModel):
    """
    List of pfc-queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:pfc-queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The pfc-queue name
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassLeafList2]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = []
    """
    The forwarding class mapped in the given pfc-queue
    """
    pfc_on_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-on-threshold-bytes', ge=0, le=4294967295),
    ] = None
    """
    Displays the actual on-threshold of the pfc-queue
    """
    pfc_off_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-off-threshold-bytes', ge=0, le=4294967295),
    ] = None
    """
    Displays the actual off-threshold of the pfc-queue
    """
    pfc_committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-committed-burst-size', ge=0, le=4294967295),
    ] = None
    """
    Displays the actual committed-burst-size of the pfc-queue
    """
    pfc_maximum_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:pfc-maximum-burst-size', ge=0, le=4294967295),
    ] = None
    """
    Displays the actual maximum-burst-size of the pfc-queue
    """
    pfc_maximum_pfc_reserved_share: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-qos:pfc-maximum-pfc-reserved-share', ge=0, le=4294967295
        ),
    ] = None
    """
    Displays the actual maximum share the pfc-queue can take from pfc-reserved buffer configured per given forwarding-complex
    """


class PfcContainer(BaseModel):
    """
    Parameters and information related to PFC on the interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_mapping_profile: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:pfc-mapping-profile',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Assigns a pfc-mapping-profile to the interface. There is always default pfc-mapping-profile assigned named 'default'
    """
    pfc_enable: Annotated[Optional[bool], Field(alias='srl_nokia-qos:pfc-enable')] = (
        False
    )
    """
    Enables/disables reaction to received pfc-frames for a given interface
    """
    statistics: Annotated[
        Optional[StatisticsContainer], Field(alias='srl_nokia-qos:statistics')
    ] = None
    source_pfc_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:source-pfc-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    MAC address used as source-mac address used in generated pfc-pause-frames on the interface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum15], Field(alias='srl_nokia-qos:oper-state')
    ] = None
    """
    Details if the PFC feature is operationally available
    """
    deadlock_detection_timer: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:deadlock-detection-timer', ge=0, le=65535),
    ] = None
    """
    The actual value of deadlock-detection-timer
    """
    pfc_queue: Annotated[
        Optional[List[PfcQueueListEntry3]], Field(alias='srl_nokia-qos:pfc-queue')
    ] = None


class PolicerStatisticsContainer(BaseModel):
    """
    The statistics per subinterface policers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    aggregate_statistics: Annotated[
        Optional[AggregateStatisticsContainer],
        Field(alias='srl_nokia-qos:aggregate-statistics'),
    ] = None
    per_lag_member_statistics: Annotated[
        Optional[PerLagMemberStatisticsContainer],
        Field(alias='srl_nokia-qos:per-lag-member-statistics'),
    ] = None


class ProfileListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    profile: Annotated[EnumerationEnum10, Field(alias='srl_nokia-qos:profile')]
    """
    A packet profile within the FC for which a different remarking is desired
    """
    dscp: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:dscp')
    ]
    """
    The DSCP marking to be used for this specific profile
    """


class ProfileListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    profile: Annotated[EnumerationEnum10, Field(alias='srl_nokia-qos:profile')]
    """
    A packet profile within the FC for which a different remarking is desired
    """
    traffic_class: Annotated[
        int, Field(alias='srl_nokia-qos:traffic-class', ge=0, le=7)
    ]
    """
    The MPLS traffic class marking to be used for this specific profile
    """


class ProfileListEntry4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    profile: Annotated[EnumerationEnum10, Field(alias='srl_nokia-qos:profile')]
    """
    A packet profile within the FC for which a different remarking is desired
    """
    inner_dot1p: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:inner-dot1p', ge=0, le=7)
    ] = None
    """
    The inner-dot1p marking to be used for this specific forwarding-class and profile
    """
    outer_dot1p: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:outer-dot1p', ge=0, le=7)
    ] = None
    """
    The outer-dot1p marking to be used for this specific forwarding-class and profile
    """
    inner_de: Annotated[Optional[bool], Field(alias='srl_nokia-qos:inner-de')] = False
    """
    Re-marking inner-vlan discard-eligibility bit for this speciific forwarding-class and profile
    """
    outer_de: Annotated[Optional[bool], Field(alias='srl_nokia-qos:outer-de')] = False
    """
    Re-marking outer-vlan discard-eligibility bit for this specific forwarding-class and profile
    """


class QueueDepthSamplingContainer(BaseModel):
    """
    System level configuration for queue-depth sampling
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-qos:admin-state')
    ] = 'disable'
    """
    Set to enable to activate queue-depth sampling on all ports
    """
    polling_interval: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:polling-interval', ge=30, le=1000)
    ] = 1000
    """
    The interval of time between each sample of queue depth
    """


class QueueListCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue: Annotated[
        Optional[List[QueueLeafList]], Field(alias='srl_nokia-qos:queue')
    ] = []
    """
    List of queues which are input to the scheduler
    """


class QueueSchedulerListEntry(BaseModel):
    """
    List of queue-schedulers created at the interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[int, Field(alias='srl_nokia-qos:sequence-id', ge=0, le=255)]
    """
    Sequence-id of the scheduler as configured in the respective queue-scheduling-policy
    """
    queue_inputs: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-qos:queue-inputs')
    ] = []
    """
    List of queues feeding the tier-0 queue-scheduler
    """
    scheduler_inputs: Annotated[
        Optional[List[SchedulerInputsLeafList]],
        Field(alias='srl_nokia-qos:scheduler-inputs'),
    ] = []
    """
    List of tier-0 queue-schedulers feeding the tier-1 queue-scheduler
    """
    interface_instance: Annotated[
        Optional[List[InterfaceInstanceListEntry]],
        Field(alias='srl_nokia-qos:interface-instance'),
    ] = None


class QueueContainer(BaseModel):
    """
    Container used to define whether local subinterface should be created or re-direction to remote queue at interface level should be used
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The queue name
    """
    re_direct_to: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-qos:re-direct-to')
    ] = None
    """
    The re-direction to interface level queue
    """


class QueueListEntry3(BaseModel):
    """
    The queue parameters that is the input to the scheduler
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The queue name
    """
    scheduling: Annotated[
        Optional[SchedulingContainer], Field(alias='srl_nokia-qos:scheduling')
    ] = None


class QueuesContainer(BaseModel):
    """
    Enclosing container for the list of user-defined queue names
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue: Annotated[
        Optional[List[QueueListEntry]], Field(alias='srl_nokia-qos:queue')
    ] = None
    pfc_queue: Annotated[
        Optional[List[PfcQueueListEntry]], Field(alias='srl_nokia-qos:pfc-queue')
    ] = None
    queue_depth_sampling: Annotated[
        Optional[QueueDepthSamplingContainer],
        Field(alias='srl_nokia-qos:queue-depth-sampling'),
    ] = None


class RateContainer(BaseModel):
    """
    Container with options defining parent-policer rate
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    peak_rate_kbps: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-kbps', ge=64, le=800000000)
    ] = None
    """
    Defines peak-rate of the parent-policer
    """
    adaptation_rule: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-qos:adaptation-rule')
    ] = 'closest'
    """
    Defines adaptation-rule for peak-rate of the parent-policer
    """
    burst_allowance: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:burst-allowance', ge=0, le=16383936)
    ] = 40000
    """
    Defines burst-allowance for the parent-policer
    """


class ResourceUtilizationThresholdsContainer(BaseModel):
    """
    Defines thresholds monitoring used resorces which divide individual shared chipset resources into 4 utilization-zones
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    threshold: Annotated[
        Optional[List[ThresholdListEntry]], Field(alias='srl_nokia-qos:threshold')
    ] = None


class RewriteRulesContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4_dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ipv4-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP rewrite-rule policy that applies only to IPv4 traffic
    """
    ipv6_dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ipv6-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP rewrite-rule policy that applies only to IPv6 traffic
    """
    dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP rewrite-rule policy that applies to both IPv4 and IPv6 traffic
    """
    dot1p_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:dot1p-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a dot1p rewrite policy
    """
    mpls_traffic_class_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:mpls-traffic-class-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of an MPLS traffic-class rewrite-rule policy
    """
    dscp_rewrite: Annotated[
        Optional[DscpRewriteContainer], Field(alias='srl_nokia-qos:dscp-rewrite')
    ] = None
    qinq_rewrite_outer_only: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:qinq-rewrite-outer-only')
    ] = True
    """
    Enables remarking only outer-dot1p bits
    """


class RootTierContainer(BaseModel):
    """
    Parameters related to root-tier buffers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    default_slope_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:default-slope-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = 'default'
    """
    Slope-policy associated with all root-tier buffer pools
    """
    root_pool: Annotated[
        Optional[List[RootPoolListEntry]], Field(alias='srl_nokia-qos:root-pool')
    ] = None


class SchedClassSchedulerListEntry(BaseModel):
    """
    List of scheduling-class-schedulers created at the interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[int, Field(alias='srl_nokia-qos:sequence-id', ge=0, le=255)]
    """
    Sequence-id of the scheduler as configured in the respective sched-class-scheduling-policy
    """
    sched_class_inputs: Annotated[
        Optional[List[SchedClassInputsLeafList]],
        Field(alias='srl_nokia-qos:sched-class-inputs'),
    ] = []
    """
    List of scheduling-classes feeding the tier-0 sched-class-scheduler
    """
    scheduler_inputs: Annotated[
        Optional[List[SchedulerInputsLeafList2]],
        Field(alias='srl_nokia-qos:scheduler-inputs'),
    ] = []
    """
    List of tier-0 sched-class-schedulers feeding the tier-1 sched-class-scheduler
    """
    interface_instance: Annotated[
        Optional[List[InterfaceInstanceListEntry2]],
        Field(alias='srl_nokia-qos:interface-instance'),
    ] = None


class SchedulerContainer(BaseModel):
    """
    Output traffic scheduler options
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    scheduling_resources_pools: Annotated[
        Optional[SchedulingResourcesPoolsContainer],
        Field(alias='srl_nokia-qos:scheduling-resources-pools'),
    ] = None
    queue_scheduling_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:queue-scheduling-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Queue level scheduling policy
    """
    queue_scheduler: Annotated[
        Optional[List[QueueSchedulerListEntry]],
        Field(alias='srl_nokia-qos:queue-scheduler'),
    ] = None
    sched_class_scheduling_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:sched-class-scheduling-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Interface level scheduling policy
    """
    sched_class_scheduler: Annotated[
        Optional[List[SchedClassSchedulerListEntry]],
        Field(alias='srl_nokia-qos:sched-class-scheduler'),
    ] = None
    scheduler_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:scheduler-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The scheduler policy to be applied to traffic on this interface
    """


class SchedulerListEntry(BaseModel):
    """
    List of defined QoS traffic schedulers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence: Annotated[int, Field(alias='srl_nokia-qos:sequence', ge=0, le=1)]
    """
    Sequence number for the scheduler within the scheduler policy. Schedulers are processed from lowest sequence to highest
    """
    priority: Annotated[
        Optional[EnumerationEnum11], Field(alias='srl_nokia-qos:priority')
    ] = None
    """
    Priority of the scheduler within the scheduler policy
    """
    input: Annotated[
        Optional[List[InputListEntry]], Field(alias='srl_nokia-qos:input')
    ] = None


class SchedulerListEntry3(BaseModel):
    """
    Scheduling options for output traffic
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[int, Field(alias='srl_nokia-qos:sequence-id', ge=0, le=8)]
    """
    Identifier of the scheduler
    """
    tier: Annotated[Optional[int], Field(alias='srl_nokia-qos:tier', ge=0, le=1)] = 0
    """
    Scheduling-hierarchy level
    """
    burst_allowance: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:burst-allowance', ge=0, le=18446744073709551615),
    ] = 9000
    """
    Burst allowance for the scheduler in bytes
    """
    threshold_separation: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:threshold-separation', ge=0, le=4294967295),
    ] = 28672
    """
    Separation between thresholds in scheduling bucket in bytes
    """
    rate: Annotated[Optional[RateContainer3], Field(alias='srl_nokia-qos:rate')] = None
    inputs: Annotated[
        Optional[InputsContainer3], Field(alias='srl_nokia-qos:inputs')
    ] = None


class ThresholdSeparationPoliciesContainer(BaseModel):
    """
    This container lists pre-defined threshold-separation-policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    threshold_separation_policy: Annotated[
        Optional[List[ThresholdSeparationPolicyListEntry]],
        Field(alias='srl_nokia-qos:threshold-separation-policy'),
    ] = None


class TrafficClassListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[int, Field(alias='srl_nokia-qos:value', ge=0, le=7)]
    """
    A single traffic-class value
    """
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-qos:drop-probability')
    ] = None
    """
    The drop probability to which the traffic-class value is mapped
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = None
    """
    The profile to which the traffic-class value is mapped
    """
    de_out_profile: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:de-out-profile')
    ] = True
    """
    The discard-eligibility to which the traffic-class value is mapped
    """
    ip_rewrite_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ip-rewrite-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The ip-rewrite-policy to be used for this traffic-class value
    """


class UnicastMappingContainer(BaseModel):
    """
    Parameters defing mapping of incoming unicast traffic into a pfc-queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pfc_queue: Annotated[
        Optional[List[PfcQueueListEntry2]], Field(alias='srl_nokia-qos:pfc-queue')
    ] = None


class WredSlopeListEntry(BaseModel):
    """
    List of WRED slopes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    traffic_type: Annotated[
        EnumerationEnum21, Field(alias='srl_nokia-qos:traffic-type')
    ]
    """
    The traffic type to which the WRED slope applies
    """
    drop_probability: Annotated[
        EnumerationEnum22, Field(alias='srl_nokia-qos:drop-probability')
    ]
    """
    The drop probability to which the WRED slope applies
    """
    drop: Annotated[Optional[bool], Field(alias='srl_nokia-qos:drop')] = None
    """
    Indicates that packets will be dropped based on WRED slope policy
    """
    enable_ecn: Annotated[bool, Field(alias='srl_nokia-qos:enable-ecn')]
    """
    Indicates that packets should be marked with ecn-bit when the result of wred-slope would discard the packet. It is mutually exclusive with 'drop' flag
    """
    min_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:min-threshold-bytes', ge=0, le=4294967295),
    ] = None
    """
    The queue depth in bytes that corresponds to the WRED mininum threshold parameter
    """
    max_threshold_bytes: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:max-threshold-bytes', ge=0, le=4294967295),
    ] = None
    """
    The queue depth in bytes that corresponds to the WRED maximum threshold parameter
    """
    max_probability: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:max-probability', ge=0, le=100)
    ] = None
    """
    The maximum probability of dropping a packet (at or above the max-threshold).

    On 7250 IXR-6/10 there can be a significant difference between the configured value and the operational value
    """


class WredSlopeListEntry2(BaseModel):
    """
    List of WRED slopes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    traffic_type: Annotated[
        EnumerationEnum21, Field(alias='srl_nokia-qos:traffic-type')
    ]
    """
    The traffic type to which the WRED slope applies
    """
    drop_probability: Annotated[
        EnumerationEnum22, Field(alias='srl_nokia-qos:drop-probability')
    ]
    """
    The drop probability to which the WRED slope applies
    """
    enable_ecn: Annotated[bool, Field(alias='srl_nokia-qos:enable-ecn')]
    """
    When this leaf is true and the number of packets in the queue is between the minimum threshold and the maximum threshold, if the ECN field on the packet indicates that the endpoints are ECN capable and the WRED algorithm determines that the packet should have been dropped based on the drop probability, the CE bits for the packet are changed to 1, and the packet is transmitted.
    When set to false, the such packets will be discarded based on wred-slope
    """
    min_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:min-threshold', ge=0, le=18446744073709551615),
    ] = None
    """
    The mininum threshold parameter for a RED-managed queue. When the average queue length is less than min-threshold, the packets are admitted to the queue (without any ECN marking change)
    """
    max_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:max-threshold', ge=0, le=18446744073709551615),
    ] = None
    """
    The maximum threshold parameter for a RED-managed queue. When the average queue length exceeds the max-threshold, the packets are dropped (or marked if ECN is enabled).

    When both, 'drop' and 'ecn-enable' flags are set to false, packets will be drop only if the mbs of the queue is reached
    """
    min_threshold_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:min-threshold-percent', ge=0, le=100)
    ] = None
    """
    The percentage of the MBS that corresponds to the WRED mininum threshold parameter
    """
    max_threshold_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:max-threshold-percent', ge=0, le=100)
    ] = None
    """
    The percentage of the MBS that corresponds to the WRED maximum threshold parameter
    """
    slope_enabled: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:slope-enabled')
    ] = None
    """
    Reads true if traffic is dropped by WRED
    """
    max_drop_probability_percent: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:max-drop-probability-percent', ge=0, le=100),
    ] = None
    """
    The probability with which packets are dropped or marked at max-threshold
    """
    weight_factor: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:weight-factor', ge=0, le=15)
    ] = None
    """
    Actual Weight factor used in the calculation of the current (average weighted) queue depth
    """


class WredSlopeListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    wred_profile: Annotated[
        EnumerationEnum23, Field(alias='srl_nokia-qos:wred-profile')
    ]
    """
    The key for individual wred-slopes 
    """
    slope_enabled: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:slope-enabled')
    ] = False
    """
    Enables/disables the corresponding wred-slope
    """
    min_threshold_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:min-threshold-percent', ge=0, le=100)
    ] = 85
    """
    The buffer threshold defining when the drop-probability starts rising from zero for the corresponding wred-slope
    """
    max_threshold_percent: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:max-threshold-percent', ge=0, le=100)
    ] = 100
    """
    The buffer threshold defining when the drop-probability reaches its max-probabilty value for the corresponding wred-slope
    """
    max_probability: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:max-probability', ge=0, le=100)
    ] = 80
    """
    The drop probability at max-threshold level for the corresponding wred-slope
    """


class WredContainer(BaseModel):
    """
    Configuration and operational state parameters relating to Weighted Random Early Detection (WRED)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    wred_slope: Annotated[
        Optional[List[WredSlopeListEntry2]], Field(alias='srl_nokia-qos:wred-slope')
    ] = None


class ActiveQueueManagementContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    wred_slope: Annotated[
        Optional[List[WredSlopeListEntry]], Field(alias='srl_nokia-qos:wred-slope')
    ] = None


class AggregateStatisticsContainer2(BaseModel):
    """
    Aggregate queue statistics per interface-queue or subinterface-queue
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the statistics associated with this queue were cleared
    """
    in_profile: Annotated[
        Optional[InProfileContainer], Field(alias='srl_nokia-qos:in-profile')
    ] = None
    in_plus_profile: Annotated[
        Optional[InPlusProfileContainer], Field(alias='srl_nokia-qos:in-plus-profile')
    ] = None
    out_profile: Annotated[
        Optional[OutProfileContainer], Field(alias='srl_nokia-qos:out-profile')
    ] = None
    exceed_profile: Annotated[
        Optional[ExceedProfileContainer], Field(alias='srl_nokia-qos:exceed-profile')
    ] = None


class DefaultContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-qos:drop-probability')
    ] = None
    """
    The default drop-probability for packets arriving on this subinterface that do not match any classification rule
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = 'out'
    """
    The default profile for packets arriving on this subinterface that do not match any classification rule
    """


class Dot1pListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[int, Field(alias='srl_nokia-qos:value', ge=0, le=7)]
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-qos:drop-probability')
    ] = None
    """
    The drop probability to which the dot1p value is mapped
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = None
    """
    The profile to which the dot1p value is mapped
    """
    de_out_profile: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:de-out-profile')
    ] = True
    """
    The discard-eligibility to which dot1p value is mapped 
    """
    ip_rewrite_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ip-rewrite-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The ip-rewrite-policy to be used for this dot1p value
    """


class DropProbabilityListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop_probability: Annotated[
        EnumerationEnum9, Field(alias='srl_nokia-qos:drop-probability')
    ]
    """
    A drop probability level within the FC for which a different remarking is desired
    """
    dscp: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:dscp')
    ]
    """
    The DSCP marking to be used for this specific drop-probability
    """


class DscpCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp: Annotated[
        Optional[Union[DscpValueType, EnumerationEnum3]],
        Field(alias='srl_nokia-qos:dscp'),
    ] = None
    """
    The DSCP marking to be used for this specific profile
    """


class DscpCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp: Annotated[
        Optional[Union[DscpValueType, EnumerationEnum3]],
        Field(alias='srl_nokia-qos:dscp'),
    ] = None
    """
    The DSCP marking to be used for this specific profile
    """


class DscpCase3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp: Annotated[
        Optional[Union[DscpValueType, EnumerationEnum3]],
        Field(alias='srl_nokia-qos:dscp'),
    ] = None
    """
    The DSCP marking to be used for this specific profile
    """


class DscpCase4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp: Annotated[
        Optional[Union[DscpValueType, EnumerationEnum3]],
        Field(alias='srl_nokia-qos:dscp'),
    ] = None
    """
    The DSCP marking to be used for this specific profile
    """


class DscpListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:value')
    ]
    """
    A DiffServ Code Point represented numerically or by a PHB name.
    """
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = None
    """
    The profile to which the DSCP value is mapped
    """


class DscpListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:value')
    ]
    """
    A DiffServ Code Point represented numerically or by a PHB name.
    """
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-qos:drop-probability')
    ] = None
    """
    The drop probability to which the DSCP value is mapped
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = None
    """
    The profile to which the DSCP value is mapped
    """
    de_out_profile: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:de-out-profile')
    ] = True
    """
    The discard-eligibility to which the DSCP value is mapped
    """
    ip_rewrite_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ip-rewrite-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The ip-rewrite-policy to be used for this dscp-value
    """


class DscpListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:value')
    ]
    """
    A DiffServ Code Point represented numerically or by a PHB name.
    """
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The forwarding class
    """
    profile: Annotated[
        Optional[EnumerationEnum2], Field(alias='srl_nokia-qos:profile')
    ] = None
    """
    The profile to which the DSCP value is mapped
    """


class ExceedContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp_or_precedence: Annotated[
        Optional[Union[DscpCase4, PrecedenceCase4]],
        Field(alias='srl_nokia-qos:dscp-or-precedence'),
    ] = None


class ForwardingClassResourcePriorityContainer(BaseModel):
    """
    Defines priority per forwarding-class and per profile to be used for access to shared chipset resources
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry2]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = None


class ForwardingClassListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-defined name of the forwarding class

    The following forwarding-class names are the system-reserved default FC names on 7250 IXR systems:
    fc0
    fc1
    fc2
    fc3
    fc4
    fc5
    fc6
    fc7

    In addition to fc0-fc7, the following forwarding-class names are also system-reserved default FC names on FPcx based platforms
    fc8
    fc9
    fc10
    fc11
    fc12
    fc13
    fc14
    fc15
    """
    forwarding_class_index: Annotated[
        int, Field(alias='srl_nokia-qos:forwarding-class-index', ge=0, le=15)
    ]
    """
    Associates the forwarding class name with an index representing the forwarding-class-index. Forwarding classes with a higher forwarding-class-index are generally (subject to scheduler configuration) serviced more preferentially than forwarding classes with a lower forwarding-class-index.

    For the system-reserved default forwarding classes:
    fc0 -> forwarding-class-index = 0
    fc1 -> forwarding-class-index = 1
    fc2 -> forwarding-class-index = 2
    fc3 -> forwarding-class-index = 3
    fc4 -> forwarding-class-index = 4
    fc5 -> forwarding-class-index = 5
    fc6 -> forwarding-class-index = 6
    fc7 -> forwarding-class-index = 7
    fc8 -> forwarding-class-index = 8
    fc9 -> forwarding-class-index = 9
    fc10 -> forwarding-class-index = 10
    fc11 -> forwarding-class-index = 11
    fc12 -> forwarding-class-index = 12
    fc13 -> forwarding-class-index = 13
    fc14 -> forwarding-class-index = 14
    fc15 -> forwarding-class-index = 15
    """
    output: Annotated[
        Optional[OutputContainer], Field(alias='srl_nokia-qos:output')
    ] = None


class ForwardingClassListEntry4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    slope_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:slope-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Slope-policy assigned to the forwarding-class
    """
    queue: Annotated[Optional[QueueContainer], Field(alias='srl_nokia-qos:queue')] = (
        None
    )


class ForwardingClassListEntry5(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    forwarding_type: Annotated[
        Optional[List[EnumerationEnum18]], Field(alias='srl_nokia-qos:forwarding-type')
    ] = []
    """
    The list of forwarding types, belonging to this forwarding-class, to match to the policer
    """


class ForwardingClassListEntry6(BaseModel):
    """
    The list of forwarding classes with traffic to be sent to the policer. If this list is not configured then all subinterface traffic is matched.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    fc: Annotated[
        str,
        Field(
            alias='srl_nokia-acl-policers:fc',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A forwarding class that has traffic to match to the policer
    """
    forwarding_type: Annotated[
        Optional[List[EnumerationEnum18]],
        Field(alias='srl_nokia-acl-policers:forwarding-type'),
    ] = []
    """
    The list of forwarding types, belonging to this forwarding-class, to match to the policer. If none are specified, this implies ALL forwarding types.
    """


class ForwardingClassesContainer(BaseModel):
    """
    Enclosing container for list of user-defined forwarding class names
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = None


class ForwardingComplexListEntry2(BaseModel):
    """
    List of forwarding complexes on the card
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[EnumerationEnum24, Field(alias='srl_nokia-qos:name')]
    """
    Forwarding-complex name
    """
    input: Annotated[Optional[InputContainer2], Field(alias='srl_nokia-qos:input')] = (
        None
    )
    output: Annotated[
        Optional[OutputContainer3], Field(alias='srl_nokia-qos:output')
    ] = None


class FpPoolPolicyListEntry(BaseModel):
    """
    List of fp-pool-policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Unique string name used for the fp-pool-policy. There is a default fp-pool-policy named 'default', as a reserved name not usable for user-defined fp-pool-policies
    """
    system_reserve_percentage: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:system-reserve-percentage', ge=0, le=100),
    ] = 10
    """
    The ammount of the global buffer-pool reserved for system generated traffic expressed as percentage of total available buffer space. The sum of all root-pools and system-reserved has to be 100%
    """
    root_tier: Annotated[
        Optional[RootTierContainer], Field(alias='srl_nokia-qos:root-tier')
    ] = None
    mid_tier: Annotated[
        Optional[MidTierContainer], Field(alias='srl_nokia-qos:mid-tier')
    ] = None


class InPlusContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp_or_precedence: Annotated[
        Optional[Union[DscpCase, PrecedenceCase]],
        Field(alias='srl_nokia-qos:dscp-or-precedence'),
    ] = None


class InContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp_or_precedence: Annotated[
        Optional[Union[DscpCase2, PrecedenceCase2]],
        Field(alias='srl_nokia-qos:dscp-or-precedence'),
    ] = None


class InputsContainer2(BaseModel):
    """
    List of scheduler inputs
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    auto_or_explicit_input: Annotated[
        Optional[Union[QueueListCase, AutoInputCase]],
        Field(alias='srl_nokia-qos:auto-or-explicit-input'),
    ] = None


class InterfacePoolPolicyListEntry(BaseModel):
    """
    List of interface-pool policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Unique string name used for the interface-pool-policy
    """
    interface_pool: Annotated[
        Optional[List[InterfacePoolListEntry2]],
        Field(alias='srl_nokia-qos:interface-pool'),
    ] = None


class InterfaceRefContainer(BaseModel):
    """
    Reference to an interface or subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface: Annotated[Optional[str], Field(alias='srl_nokia-qos:interface')] = None
    """
    Reference to a base interface, for example a port or LAG
    """
    subinterface: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:subinterface', ge=0, le=9999)
    ] = None
    """
    Reference to a subinterface

    This requires the base interface to be specified using the interface leaf in this container
    """


class LinecardListEntry2(BaseModel):
    """
    Container for QoS linecard configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[int, Field(alias='srl_nokia-qos:slot', ge=1, le=16)]
    """
    Numeric identifier for the linecard
    """
    forwarding_complex: Annotated[
        Optional[List[ForwardingComplexListEntry2]],
        Field(alias='srl_nokia-qos:forwarding-complex'),
    ] = None


class MapListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[List[DropProbabilityListEntry]],
        Field(alias='srl_nokia-qos:drop-probability'),
    ] = None
    profile: Annotated[
        Optional[List[ProfileListEntry2]], Field(alias='srl_nokia-qos:profile')
    ] = None
    dscp: Annotated[
        Union[DscpValueType, EnumerationEnum3], Field(alias='srl_nokia-qos:dscp')
    ]
    """
    The DSCP marking to be used for all packets associated with the FC, except those with a drop-probability-specific or profile-specific override
    """


class MapListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[List[DropProbabilityListEntry2]],
        Field(alias='srl_nokia-qos:drop-probability'),
    ] = None
    profile: Annotated[
        Optional[List[ProfileListEntry3]], Field(alias='srl_nokia-qos:profile')
    ] = None
    traffic_class: Annotated[
        int, Field(alias='srl_nokia-qos:traffic-class', ge=0, le=7)
    ]
    """
    The MPLS traffic class marking to be used for all packets associated with the FC, except those with a drop-probability-specific or profile-specific override
    """


class MapListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The forwarding class
    """
    drop_probability: Annotated[
        Optional[List[DropProbabilityListEntry3]],
        Field(alias='srl_nokia-qos:drop-probability'),
    ] = None
    profile: Annotated[
        Optional[List[ProfileListEntry4]], Field(alias='srl_nokia-qos:profile')
    ] = None
    dot1p: Annotated[int, Field(alias='srl_nokia-qos:dot1p', ge=0, le=7)]
    """
    The dot1p marking to be used for all packets associated with the FC, except those with a drop-probability-specific or profile-specific override
    """
    inner_dot1p: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:inner-dot1p', ge=0, le=7)
    ] = None
    """
    The inner-dot1p marking to be used for all packets associated with the FC, except those with a profile-specific override
    """
    outer_dot1p: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:outer-dot1p', ge=0, le=7)
    ] = None
    """
    The outer-dot1p marking to be used for all packets associated with the FC, except those with a profile-specific override
    """
    inner_de: Annotated[Optional[bool], Field(alias='srl_nokia-qos:inner-de')] = False
    """
    Re-marking inner-vlan discard-eligibility bit for the respecitve forwarding-class
    """
    outer_de: Annotated[Optional[bool], Field(alias='srl_nokia-qos:outer-de')] = False
    """
    Re-marking outer-vlan discard-eligibility bit for the respecitve forwarding-class
    """


class MemberInterfaceListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    member_interface_name: Annotated[
        str, Field(alias='srl_nokia-qos:member-interface-name')
    ]
    in_profile: Annotated[
        Optional[InProfileContainer2], Field(alias='srl_nokia-qos:in-profile')
    ] = None
    in_plus_profile: Annotated[
        Optional[InPlusProfileContainer2], Field(alias='srl_nokia-qos:in-plus-profile')
    ] = None
    out_profile: Annotated[
        Optional[OutProfileContainer2], Field(alias='srl_nokia-qos:out-profile')
    ] = None
    exceed_profile: Annotated[
        Optional[ExceedProfileContainer2], Field(alias='srl_nokia-qos:exceed-profile')
    ] = None


class MplsTrafficClassPolicyListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for an MPLS traffic-class mapping policy

    The name 'default' is reserved for the system default MPLS TC mapping policy
    """
    traffic_class: Annotated[
        Optional[List[TrafficClassListEntry]],
        Field(alias='srl_nokia-qos:traffic-class'),
    ] = None


class MplsTrafficClassPolicyListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for an MPLS traffic-class rewrite policy
    """
    map: Annotated[Optional[List[MapListEntry2]], Field(alias='srl_nokia-qos:map')] = (
        None
    )


class OutContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp_or_precedence: Annotated[
        Optional[Union[DscpCase3, PrecedenceCase3]],
        Field(alias='srl_nokia-qos:dscp-or-precedence'),
    ] = None


class OutputClassMapListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User defined output-class-map name
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry4]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = None


class ParentPolicerContainer(BaseModel):
    """
    Container with options to define aggeregate parent-policer parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    parent_policer_threshold_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:parent-policer-threshold-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Assigns parent-policer-threshold-policy to the parent-policer
    """
    rate: Annotated[Optional[RateContainer], Field(alias='srl_nokia-qos:rate')] = None
    inputs: Annotated[
        Optional[InputsContainer], Field(alias='srl_nokia-qos:inputs')
    ] = None


class PerLagMemberStatisticsContainer2(BaseModel):
    """
    Queue statistics per-LAG member. These statistics are relevant only for LAG
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    member_interface: Annotated[
        Optional[List[MemberInterfaceListEntry]],
        Field(alias='srl_nokia-qos:member-interface'),
    ] = None


class PolicerListEntry(BaseModel):
    """
    The list of policer belonging to the policer-policy
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer_id: Annotated[int, Field(alias='srl_nokia-qos:policer-id', ge=0, le=31)]
    """
    A number to identify given policer within policer-policy
    """
    algorithm_type: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-qos:algorithm-type')
    ] = 'trtcm2'
    """
    Defines the algorithm-type used for the given policer
    """
    adaptation_rules: Annotated[
        Optional[AdaptationRulesContainer],
        Field(alias='srl_nokia-qos:adaptation-rules'),
    ] = None
    pir_threshold_separation: Annotated[
        Optional[PirThresholdSeparationContainer],
        Field(alias='srl_nokia-qos:pir-threshold-separation'),
    ] = None
    packet_length_adjustment: Annotated[
        Optional[PacketLengthAdjustmentContainer],
        Field(alias='srl_nokia-qos:packet-length-adjustment'),
    ] = None
    peak_rate_kbps: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-kbps', ge=64, le=800000000)
    ] = 64
    """
    The peak information rate (PIR) of the policer, defined in kilobits (1024 bits) per second.

    This parameter is ignored if 'algorithm-type' is set to 'trtcm2'
    """
    committed_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-rate-kbps', ge=0, le=800000000),
    ] = 64
    """
    The committed information rate (CIR) of the policer, defined in kilobits (1024 bits) per second
    """
    excess_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:excess-rate-kbps', ge=64, le=800000000),
    ] = 64
    """
    The excess information rate (EIR) of the policer, defined in kilobits (1024 bits) per second.

    This parameter is ignored if 'algorithm-type' is set to 'trtcm1'
    """
    maximum_burst_size: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:maximum-burst-size', ge=64, le=253952)
    ] = 40000
    """
    Maximum PIR bucket depth in bytes.

    This parameter is ignored if 'algorithm-type' is set to 'trtcm2'
    """
    committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-burst-size', ge=64, le=190941),
    ] = 40000
    """
    Maximum CIR bucket depth in bytes
    """
    excess_burst_size: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:excess-burst-size', ge=64, le=253952)
    ] = 40000
    """
    Maximum EIR bucket depth in bytes.

    This parameter is ignored if 'algorithm-type' is set to 'trtcm1'
    """
    violate_action: Annotated[
        Optional[EnumerationEnum7], Field(alias='srl_nokia-qos:violate-action')
    ] = 'drop'
    """
    Defines action when policer will evaluate the packet as violating
    """
    statistics_mode: Annotated[
        Optional[EnumerationEnum8], Field(alias='srl_nokia-qos:statistics-mode')
    ] = 'extended'
    """
    Defines the number and type of the counters collected for the policer. The modes are mutually exclusive
    """


class PolicerListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer_id: Annotated[int, Field(alias='srl_nokia-qos:policer-id', ge=0, le=31)]
    """
    A number to identify given policer within policer-policy
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry5]],
        Field(alias='srl_nokia-qos:forwarding-class'),
    ] = None
    eir_policer_threshold_separation_policy: Annotated[
        Optional[str],
        Field(alias='srl_nokia-qos:eir-policer-threshold-separation-policy'),
    ] = None
    """
    The name of eir-policer-threshold-separation policy assigned to the policer
    """
    pir_policer_threshold_separation_policy: Annotated[
        Optional[str],
        Field(alias='srl_nokia-qos:pir-policer-threshold-separation-policy'),
    ] = None
    """
    The name of pir-policer-threshold-separation policy assigned to the policer
    """
    cir_policer_threshold_separation_policy: Annotated[
        Optional[str],
        Field(alias='srl_nokia-qos:cir-policer-threshold-separation-policy'),
    ] = None
    """
    The name of cir-policer-threshold-separation policy assigned to the policer
    """
    operational_separation_thresholds: Annotated[
        Optional[List[OperationalSeparationThresholdsListEntry]],
        Field(alias='srl_nokia-qos:operational-separation-thresholds'),
    ] = None
    peak_rate_kbps: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:peak-rate-kbps', ge=0, le=4294967295)
    ] = None
    """
    The actual/operational peak information rate (PIR) of the policer as it is programmed into hardware
    """
    excess_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:excess-rate-kbps', ge=0, le=4294967295),
    ] = None
    """
    The actual/operational excess information rate (EIR) of the policer as it is programmed into hardware
    """
    committed_rate_kbps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-rate-kbps', ge=0, le=4294967295),
    ] = None
    """
    The actual/operational committed information rate (CIR) of the policer as it is programmed into hardware
    """
    maximum_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:maximum-burst-size', ge=0, le=4294967295),
    ] = None
    """
    The actual/operational maximum PIR bucket depth in bytes as it is programmed into hardware
    """
    committed_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:committed-burst-size', ge=0, le=4294967295),
    ] = None
    """
    The actual/operational maximum CIR bucket depth in bytes as it is programmed into hardware
    """
    excess_burst_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:excess-burst-size', ge=0, le=4294967295),
    ] = None
    """
    The actual/operational maximum EIR bucket depth in bytes as it is programmed into hardware
    """
    policer_statistics: Annotated[
        Optional[PolicerStatisticsContainer],
        Field(alias='srl_nokia-qos:policer-statistics'),
    ] = None


class PolicerListEntry4(BaseModel):
    """
    The list of policer instances belonging to the template definition.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[
        int, Field(alias='srl_nokia-acl-policers:sequence-id', ge=1, le=65535)
    ]
    """
    A number to indicate the relative evaluation order of the different policers in a template; policers with lower sequence-id numbers are evaluated before policers with higher sequence-id numbers
    """
    forwarding_class: Annotated[
        Optional[List[ForwardingClassListEntry6]],
        Field(alias='srl_nokia-acl-policers:forwarding-class'),
    ] = None
    peak_rate_kbps: Annotated[
        int, Field(alias='srl_nokia-acl-policers:peak-rate-kbps', ge=0, le=4294967295)
    ]
    """
    The peak information rate (PIR) of the policer, defined in kilobits (1024 bits) per second.
    On 7220-D2/D3 the minimum rate is 8 Kbps
    """
    committed_rate_kbps: Annotated[
        int,
        Field(alias='srl_nokia-acl-policers:committed-rate-kbps', ge=0, le=4294967295),
    ]
    """
    The committed information rate (CIR) of the policer, defined in kilobits (1024 bits) per second
    On 7220-D2/D3 the minimum rate  is 8 Kbps
    """
    maximum_burst_size: Annotated[
        int,
        Field(alias='srl_nokia-acl-policers:maximum-burst-size', ge=0, le=4294967295),
    ]
    """
    Maximum PIR bucket depth in bytes

    On 7220-D2/D3 the lower limit is 512 Bytes and higher limit is 268 MB
    """
    committed_burst_size: Annotated[
        int,
        Field(alias='srl_nokia-acl-policers:committed-burst-size', ge=0, le=4294967295),
    ]
    """
    Maximum CIR bucket depth in bytes

    On 7220-D2/D3 the lower limit is 512 Bytes and higher limit is 268 MB
    """
    exceed_action: Annotated[
        Optional[ExceedActionContainer],
        Field(alias='srl_nokia-acl-policers:exceed-action'),
    ] = None
    violate_action: Annotated[
        Optional[ViolateActionContainer],
        Field(alias='srl_nokia-acl-policers:violate-action'),
    ] = None


class QueueManagementProfileListEntry(BaseModel):
    """
    The name of a queue management profile
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Unique string name used for the queue management profile
    """
    weight_factor: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:weight-factor', ge=0, le=15)
    ] = 0
    """
    Weight factor to use in the calculation of the current (average weighted) queue depth
    """
    wred: Annotated[Optional[WredContainer], Field(alias='srl_nokia-qos:wred')] = None


class QueueStatisticsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    aggregate_statistics: Annotated[
        Optional[AggregateStatisticsContainer2],
        Field(alias='srl_nokia-qos:aggregate-statistics'),
    ] = None
    per_lag_member_statistics: Annotated[
        Optional[PerLagMemberStatisticsContainer2],
        Field(alias='srl_nokia-qos:per-lag-member-statistics'),
    ] = None


class QueueListEntry4(BaseModel):
    """
    List of queues
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue_name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:queue-name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The queue name
    """
    queue_management_profile: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:queue-management-profile',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The queue management profile that is to be used for the queue on the interface.

    For example, the system may use a profile which specifies that WRED curves are used for setting an ECN mark in the IP header instead of dropping a packet in order to signal impending congestion and for determining when there is sufficient congestion to tail drop packets
    """
    forwarding_class: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-qos:forwarding-class')
    ] = []
    """
    The list of forwarding classes that map to this queue
    """
    queue_type: Annotated[
        Optional[EnumerationEnum20], Field(alias='srl_nokia-qos:queue-type')
    ] = None
    """
    Indicates whether given queue is local to subinterface or interface-queue
    """
    active_queue_management: Annotated[
        Optional[ActiveQueueManagementContainer],
        Field(alias='srl_nokia-qos:active-queue-management'),
    ] = None
    queue_depth: Annotated[
        Optional[QueueDepthContainer], Field(alias='srl_nokia-qos:queue-depth')
    ] = None
    scheduling: Annotated[
        Optional[SchedulingContainer2], Field(alias='srl_nokia-qos:scheduling')
    ] = None
    queue_statistics: Annotated[
        Optional[QueueStatisticsContainer],
        Field(alias='srl_nokia-qos:queue-statistics'),
    ] = None


class QueuesContainer2(BaseModel):
    """
    Container for a list of queues that are instantiated on an interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queue: Annotated[
        Optional[List[QueueListEntry4]], Field(alias='srl_nokia-qos:queue')
    ] = None


class ReceivedTrafficContainer(BaseModel):
    """
    Parameters related to receiving traffic for pfc-generation
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    unicast_mapping: Annotated[
        Optional[UnicastMappingContainer], Field(alias='srl_nokia-qos:unicast-mapping')
    ] = None


class ResourceManagementContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class_resource_priority: Annotated[
        Optional[ForwardingClassResourcePriorityContainer],
        Field(alias='srl_nokia-qos:forwarding-class-resource-priority'),
    ] = None
    drop_zones: Annotated[
        Optional[DropZonesContainer], Field(alias='srl_nokia-qos:drop-zones')
    ] = None
    resource_utilization_thresholds: Annotated[
        Optional[ResourceUtilizationThresholdsContainer],
        Field(alias='srl_nokia-qos:resource-utilization-thresholds'),
    ] = None


class SchedClassSchedulingPolicyListEntry(BaseModel):
    """
    Scheduling-policy defining scheduling at scheduling-class level
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Name for the sched-class-scheduling-policy
    """
    scheduler: Annotated[
        Optional[List[SchedulerListEntry3]], Field(alias='srl_nokia-qos:scheduler')
    ] = None


class SchedulerPolicyListEntry(BaseModel):
    """
    List of scheduler policies. A scheduler policy is a set of schedulers that are to be applied together. Each scheduler within a scheduler policy takes an input, and outputs it according to a scheduling discipline that is specified within it
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Name for the scheduler policy
    """
    scheduler: Annotated[
        Optional[List[SchedulerListEntry]], Field(alias='srl_nokia-qos:scheduler')
    ] = None


class SchedulerListEntry2(BaseModel):
    """
    Scheduling options for output traffic
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[int, Field(alias='srl_nokia-qos:sequence-id', ge=0, le=16)]
    """
    Identifier of the scheduler
    """
    tier: Annotated[Optional[int], Field(alias='srl_nokia-qos:tier', ge=0, le=1)] = 0
    """
    Scheduling-hierarchy level
    """
    output_weight: Annotated[
        Optional[int], Field(alias='srl_nokia-qos:output-weight', ge=1, le=127)
    ] = 1
    """
    Output weight of the scheduler
    """
    burst_allowance: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:burst-allowance', ge=0, le=18446744073709551615),
    ] = 9000
    """
    Burst allowance for the scheduler in bytes
    """
    threshold_separation: Annotated[
        Optional[int],
        Field(alias='srl_nokia-qos:threshold-separation', ge=0, le=4294967295),
    ] = 28672
    """
    Separation between thresholds in scheduling bucket in bytes
    """
    rate: Annotated[Optional[RateContainer2], Field(alias='srl_nokia-qos:rate')] = None
    inputs: Annotated[
        Optional[InputsContainer2], Field(alias='srl_nokia-qos:inputs')
    ] = None


class SlopePolicyListEntry(BaseModel):
    """
    List of slope-policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Unique string name used for the slope-policy
    """
    wred_slope: Annotated[
        Optional[List[WredSlopeListEntry3]], Field(alias='srl_nokia-qos:wred-slope')
    ] = None


class SystemGeneratedTrafficContainer(BaseModel):
    """
    Defines mapping of dscp values into forwarding-class and profile for system generated traffic
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    dscp: Annotated[
        Optional[List[DscpListEntry]], Field(alias='srl_nokia-qos:dscp')
    ] = None


class BufferManagementContainer(BaseModel):
    """
    Container for the list of configured queue management profiles
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    committed_burst_size_table: Annotated[
        Optional[CommittedBurstSizeTableContainer],
        Field(alias='srl_nokia-qos:committed-burst-size-table'),
    ] = None
    queue_management_profile: Annotated[
        Optional[List[QueueManagementProfileListEntry]],
        Field(alias='srl_nokia-qos:queue-management-profile'),
    ] = None
    buffer_allocation_profile: Annotated[
        Optional[List[BufferAllocationProfileListEntry]],
        Field(alias='srl_nokia-qos:buffer-allocation-profile'),
    ] = None
    slope_policy: Annotated[
        Optional[List[SlopePolicyListEntry]], Field(alias='srl_nokia-qos:slope-policy')
    ] = None
    fp_pool_policy: Annotated[
        Optional[List[FpPoolPolicyListEntry]],
        Field(alias='srl_nokia-qos:fp-pool-policy'),
    ] = None
    interface_pool_policy: Annotated[
        Optional[List[InterfacePoolPolicyListEntry]],
        Field(alias='srl_nokia-qos:interface-pool-policy'),
    ] = None


class ClassifiersContainer2(BaseModel):
    """
    Classifiers to be applied to the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    default: Annotated[
        Optional[DefaultContainer], Field(alias='srl_nokia-qos:default')
    ] = None
    ipv4_dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ipv4-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP mapping policy that applies only to IPv4 traffic
    """
    ipv6_dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:ipv6-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP mapping policy that applies only to IPv6 traffic
    """
    dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP mapping policy that applies to both IPv4 and IPv6 traffic
    """
    dot1p_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:dot1p-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a dot1p mapping policy
    """
    mpls_traffic_class_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:mpls-traffic-class-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of an MPLS traffic-class mapping policy
    """
    ler_use_dscp: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:ler-use-dscp')
    ] = False
    """
    Enables short-pipe model for all lsp-bindings terminated on the subinterface
    """
    match_qinq_dot1p: Annotated[
        Optional[EnumerationEnum16], Field(alias='srl_nokia-qos:match-qinq-dot1p')
    ] = 'outer'
    """
    Defines which dot1p bits will be used for dot1p-classification in case of QinQ encapsulation
    """
    tos_rewrite_state: Annotated[
        Optional[EnumerationEnum17], Field(alias='srl_nokia-qos:tos-rewrite-state')
    ] = 'trusted'
    """
    Defines whether given subinterface is considered as trusted/untrusted for ToS rewrite purpose
    """


class Dot1pPolicyListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for a 802.1p prioriy code point mapping policy

    The name 'default' is reserved for the system default dot1p mapping policy
    """
    dot1p: Annotated[
        Optional[List[Dot1pListEntry]], Field(alias='srl_nokia-qos:dot1p')
    ] = None


class Dot1pPolicyListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for an 802.1p priorty code point rewrite policy
    """
    map: Annotated[Optional[List[MapListEntry3]], Field(alias='srl_nokia-qos:map')] = (
        None
    )


class DscpPolicyListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for a DSCP mapping policy

    The name 'default' is reserved for the system default DSCP mapping policy
    """
    dscp: Annotated[
        Optional[List[DscpListEntry2]], Field(alias='srl_nokia-qos:dscp')
    ] = None


class DscpPolicyListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-configured name for a DSCP rewrite policy
    """
    map: Annotated[Optional[List[MapListEntry]], Field(alias='srl_nokia-qos:map')] = (
        None
    )


class DscpReclassifyPolicyListEntry(BaseModel):
    """
    Egress DSCP reclassification policy
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Name of egress dscp-reclassifier policy
    """
    dscp: Annotated[
        Optional[List[DscpListEntry3]], Field(alias='srl_nokia-qos:dscp')
    ] = None


class IpRewritePolicyListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User defined ip-rewrite-policy name
    """
    in_plus: Annotated[
        Optional[InPlusContainer], Field(alias='srl_nokia-qos:in-plus')
    ] = None
    in_: Annotated[Optional[InContainer], Field(alias='srl_nokia-qos:in')] = None
    out: Annotated[Optional[OutContainer], Field(alias='srl_nokia-qos:out')] = None
    exceed: Annotated[
        Optional[ExceedContainer], Field(alias='srl_nokia-qos:exceed')
    ] = None


class OutputContainer2(BaseModel):
    """
    Top-level container for QoS configuration and state relating to egress traffic on the interface or subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface_pool_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:interface-pool-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Interface-pool-policy assigned to the interface
    """
    queues: Annotated[
        Optional[QueuesContainer2], Field(alias='srl_nokia-qos:queues')
    ] = None
    scheduler: Annotated[
        Optional[SchedulerContainer], Field(alias='srl_nokia-qos:scheduler')
    ] = None
    dscp_reclassify_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:dscp-reclassify-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to egress dscp-reclassification policy
    """
    output_class_map: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:output-class-map',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of output-class-map that applies to subinterface
    """
    rewrite_rules: Annotated[
        Optional[RewriteRulesContainer2], Field(alias='srl_nokia-qos:rewrite-rules')
    ] = None
    output_class_map_pending: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-qos:output-class-map-pending')
    ] = []
    """
    List of interfaces, related to this subinterface, where the configured output-class-map is not yet operational
    """
    buffer_allocation_profile: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:buffer-allocation-profile',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Buffer-allocation-profile for interface output queues
    """
    interface_pool: Annotated[
        Optional[List[InterfacePoolListEntry]],
        Field(alias='srl_nokia-qos:interface-pool'),
    ] = None


class PfcMappingProfileListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User defined pfc-mapping-profile name. The name 'default' is reserved for system use
    """
    received_traffic: Annotated[
        Optional[ReceivedTrafficContainer],
        Field(alias='srl_nokia-qos:received-traffic'),
    ] = None
    received_pfc_pause_frames: Annotated[
        Optional[ReceivedPfcPauseFramesContainer],
        Field(alias='srl_nokia-qos:received-pfc-pause-frames'),
    ] = None


class PolicerPoliciesContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:policer-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Policer-policy assigned to this subinterface
    """
    parent_policer: Annotated[
        Optional[ParentPolicerContainer2], Field(alias='srl_nokia-qos:parent-policer')
    ] = None
    policer: Annotated[
        Optional[List[PolicerListEntry3]], Field(alias='srl_nokia-qos:policer')
    ] = None


class PolicerPolicyListEntry(BaseModel):
    """
    List of policer policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The name assigned to the policer policy
    """
    policer: Annotated[
        Optional[List[PolicerListEntry]], Field(alias='srl_nokia-qos:policer')
    ] = None
    parent_policer: Annotated[
        Optional[ParentPolicerContainer], Field(alias='srl_nokia-qos:parent-policer')
    ] = None


class PolicerTemplateListEntry(BaseModel):
    """
    List of policer templates.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-acl-policers:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    The name assigned to the policer template.
    """
    policer: Annotated[
        Optional[List[PolicerListEntry4]], Field(alias='srl_nokia-acl-policers:policer')
    ] = None
    statistics_mode: Annotated[
        Optional[EnumerationEnum26],
        Field(alias='srl_nokia-acl-policers:statistics-mode'),
    ] = 'violating-focus'
    """
    The statistics mode of all policers belonging to this template
    """


class PolicerTemplatesContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policer_template: Annotated[
        Optional[List[PolicerTemplateListEntry]],
        Field(alias='srl_nokia-acl-policers:policer-template'),
    ] = None


class QueueSchedulingPolicyListEntry(BaseModel):
    """
    Scheduling-policy defining scheduling at queue level
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-qos:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Name for the queue-scheduling-policy
    """
    queue: Annotated[
        Optional[List[QueueListEntry3]], Field(alias='srl_nokia-qos:queue')
    ] = None
    scheduler: Annotated[
        Optional[List[SchedulerListEntry2]], Field(alias='srl_nokia-qos:scheduler')
    ] = None


class RewriteRulesContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vxlan_outer_header_dscp_policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:vxlan-outer-header-dscp-policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP rewrite policy that applies to the outer IP header of originating VXLAN packets
    """
    dscp_policy: Annotated[
        Optional[List[DscpPolicyListEntry2]], Field(alias='srl_nokia-qos:dscp-policy')
    ] = None
    mpls_traffic_class_policy: Annotated[
        Optional[List[MplsTrafficClassPolicyListEntry2]],
        Field(alias='srl_nokia-qos:mpls-traffic-class-policy'),
    ] = None
    dot1p_policy: Annotated[
        Optional[List[Dot1pPolicyListEntry2]], Field(alias='srl_nokia-qos:dot1p-policy')
    ] = None
    ip_rewrite_policy: Annotated[
        Optional[List[IpRewritePolicyListEntry]],
        Field(alias='srl_nokia-qos:ip-rewrite-policy'),
    ] = None


class SchedulerPoliciesContainer(BaseModel):
    """
    Container for the list of configured scheduler policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    scheduler_policy: Annotated[
        Optional[List[SchedulerPolicyListEntry]],
        Field(alias='srl_nokia-qos:scheduler-policy'),
    ] = None
    scheduling_priority_mapping_table: Annotated[
        Optional[SchedulingPriorityMappingTableContainer],
        Field(alias='srl_nokia-qos:scheduling-priority-mapping-table'),
    ] = None
    queue_scheduling_policy: Annotated[
        Optional[List[QueueSchedulingPolicyListEntry]],
        Field(alias='srl_nokia-qos:queue-scheduling-policy'),
    ] = None
    sched_class_scheduling_policy: Annotated[
        Optional[List[SchedClassSchedulingPolicyListEntry]],
        Field(alias='srl_nokia-qos:sched-class-scheduling-policy'),
    ] = None


class ClassifiersContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vxlan_default: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:vxlan-default',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of a DSCP mapping policy that applies to terminating VXLAN packets
    """
    dscp_policy: Annotated[
        Optional[List[DscpPolicyListEntry]], Field(alias='srl_nokia-qos:dscp-policy')
    ] = None
    mpls_traffic_class_policy: Annotated[
        Optional[List[MplsTrafficClassPolicyListEntry]],
        Field(alias='srl_nokia-qos:mpls-traffic-class-policy'),
    ] = None
    dot1p_policy: Annotated[
        Optional[List[Dot1pPolicyListEntry]], Field(alias='srl_nokia-qos:dot1p-policy')
    ] = None
    dscp_reclassify_policy: Annotated[
        Optional[List[DscpReclassifyPolicyListEntry]],
        Field(alias='srl_nokia-qos:dscp-reclassify-policy'),
    ] = None


class InputContainer(BaseModel):
    """
    Top-level container for QoS configuration and state relating to ingress traffic on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    classifiers: Annotated[
        Optional[ClassifiersContainer2], Field(alias='srl_nokia-qos:classifiers')
    ] = None
    input_class_map: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:input-class-map',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to the name of input-class-map that applies to subinterface
    """
    policer_policies: Annotated[
        Optional[PolicerPoliciesContainer2],
        Field(alias='srl_nokia-qos:policer-policies'),
    ] = None
    pfc_buffer_allocation_profile: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-qos:pfc-buffer-allocation-profile',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Buffer-allocation-profile for pfc queues
    """
    policer_templates: Annotated[
        Optional[PolicerTemplatesContainer],
        Field(alias='srl_nokia-acl-policers:policer-templates'),
    ] = None


class InterfaceListEntry(BaseModel):
    """
    List of interfaces and subinterfaces referenced by QoS policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface_id: Annotated[str, Field(alias='srl_nokia-qos:interface-id')]
    """
    Identifier for the interface or subinterface
    """
    interface_ref: Annotated[
        Optional[InterfaceRefContainer], Field(alias='srl_nokia-qos:interface-ref')
    ] = None
    pfc: Annotated[Optional[PfcContainer], Field(alias='srl_nokia-qos:pfc')] = None
    input: Annotated[Optional[InputContainer], Field(alias='srl_nokia-qos:input')] = (
        None
    )
    output: Annotated[
        Optional[OutputContainer2], Field(alias='srl_nokia-qos:output')
    ] = None


class InterfacesContainer(BaseModel):
    """
    Interfaces and subinterfaces with QoS configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface: Annotated[
        Optional[List[InterfaceListEntry]], Field(alias='srl_nokia-qos:interface')
    ] = None


class PolicerPoliciesContainer(BaseModel):
    """
    Policer-policies for subinterface level traffic metering
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    threshold_separation_policies: Annotated[
        Optional[ThresholdSeparationPoliciesContainer],
        Field(alias='srl_nokia-qos:threshold-separation-policies'),
    ] = None
    parent_policer_threshold_policy: Annotated[
        Optional[List[ParentPolicerThresholdPolicyListEntry]],
        Field(alias='srl_nokia-qos:parent-policer-threshold-policy'),
    ] = None
    policer_policy: Annotated[
        Optional[List[PolicerPolicyListEntry]],
        Field(alias='srl_nokia-qos:policer-policy'),
    ] = None


class QosContainer(BaseModel):
    """
    Top-level container for QoS data
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    explicit_congestion_notification: Annotated[
        Optional[ExplicitCongestionNotificationContainer],
        Field(alias='srl_nokia-qos:explicit-congestion-notification'),
    ] = None
    queues: Annotated[
        Optional[QueuesContainer], Field(alias='srl_nokia-qos:queues')
    ] = None
    forwarding_classes: Annotated[
        Optional[ForwardingClassesContainer],
        Field(alias='srl_nokia-qos:forwarding-classes'),
    ] = None
    resource_management: Annotated[
        Optional[ResourceManagementContainer],
        Field(alias='srl_nokia-qos:resource-management'),
    ] = None
    system_generated_traffic: Annotated[
        Optional[SystemGeneratedTrafficContainer],
        Field(alias='srl_nokia-qos:system-generated-traffic'),
    ] = None
    input_class_map: Annotated[
        Optional[List[InputClassMapListEntry]],
        Field(alias='srl_nokia-qos:input-class-map'),
    ] = None
    output_class_map: Annotated[
        Optional[List[OutputClassMapListEntry]],
        Field(alias='srl_nokia-qos:output-class-map'),
    ] = None
    pfc_mapping_profile: Annotated[
        Optional[List[PfcMappingProfileListEntry]],
        Field(alias='srl_nokia-qos:pfc-mapping-profile'),
    ] = None
    policer_policies: Annotated[
        Optional[PolicerPoliciesContainer],
        Field(alias='srl_nokia-qos:policer-policies'),
    ] = None
    classifiers: Annotated[
        Optional[ClassifiersContainer], Field(alias='srl_nokia-qos:classifiers')
    ] = None
    rewrite_rules: Annotated[
        Optional[RewriteRulesContainer], Field(alias='srl_nokia-qos:rewrite-rules')
    ] = None
    scheduler_policies: Annotated[
        Optional[SchedulerPoliciesContainer],
        Field(alias='srl_nokia-qos:scheduler-policies'),
    ] = None
    preserve_dscp: Annotated[
        Optional[bool], Field(alias='srl_nokia-qos:preserve-dscp')
    ] = None
    """
    When forwarding an untunneled IP packet or decapsulating an IP-in-IP packet, preserve the received DSCP and use it in the transmitted packet.

    This should not be enabled unless all IP packets have been classified by a multi-field classifier policy
    """
    interfaces: Annotated[
        Optional[InterfacesContainer], Field(alias='srl_nokia-qos:interfaces')
    ] = None
    buffer_management: Annotated[
        Optional[BufferManagementContainer],
        Field(alias='srl_nokia-qos:buffer-management'),
    ] = None
    linecard: Annotated[
        Optional[List[LinecardListEntry2]], Field(alias='srl_nokia-qos:linecard')
    ] = None
    policer_templates: Annotated[
        Optional[PolicerTemplatesContainer2],
        Field(alias='srl_nokia-acl-policers:policer-templates'),
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
    qos: Annotated[Optional[QosContainer], Field(alias='srl_nokia-qos:qos')] = None


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