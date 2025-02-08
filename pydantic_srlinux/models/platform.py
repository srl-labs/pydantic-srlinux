from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class CpuSetLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=1024)]
    """
    The list of CPUs used for vXDP PMD threads

    These CPUs should be isolated out-of-band of SR Linux, and are used for forwarder and NIC threads for vhost-user, physical, and lif interfaces.
    It is expected that the sibling of a CPU is always passed to vXDP, and in order to enforce this if a single CPU of a core is passed, vXDP will derive and bind to the undefined sibling. vXDP supports the passing of both single and both siblings together, and will perform a merge to ensure all siblings are consumed.
    """


class IndexLeaf121(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    CPU index for each processor core on the system

    On a single-core system, the index should be zero.  The 'all' index signifies an aggregation of the CPU utilization statistics over all cores in the system.
    """


class IndexLeaf51(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=7)]
    """
    The pipeline number (TH3 systems) or direction (J2 and J2C+ systems).
    """


class P4rtContainer(BaseModel):
    """
    Top-level container for P4Runtime forwarding complex configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[
        int, Field(alias='srl_nokia-platform-p4rt:id', ge=1, le=18446744073709551615)
    ]
    """
    The numeric ID used by the controller to address the forwarding complex

    This ID may be referred to as a 'device', 'node' or 'target' by the P4RT specification.

    Each ASIC is addressed by the client based on this numeric identifier.
    """


class Sha1HashListEntry(BaseModel):
    """
    List of SHA-1 hash digests
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-platform-secure-boot:index', ge=0, le=4294967295)
    ]
    """
    The index of the hash
    """
    digest_value: Annotated[
        Optional[bytes],
        Field(
            alias='srl_nokia-platform-secure-boot:digest-value',
            max_length=18446744073709551615,
        ),
    ] = None
    """
    SHA-1 digest
    """


class Sha256HashCertListEntry(BaseModel):
    """
    List of SHA-256 hash digests of X.509 certificates
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-platform-secure-boot:index', ge=0, le=4294967295)
    ]
    """
    The index of the hash
    """
    digest_value: Annotated[
        Optional[bytes],
        Field(
            alias='srl_nokia-platform-secure-boot:digest-value',
            max_length=18446744073709551615,
        ),
    ] = None
    """
    SHA-256 digest of an X.509 certificate
    """
    revocation_time: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-secure-boot:revocation-time')
    ] = None
    """
    Certificate revocation start time
    """


class Sha256HashListEntry(BaseModel):
    """
    List of SHA-256 hash digests
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-platform-secure-boot:index', ge=0, le=4294967295)
    ]
    """
    The index of the hash
    """
    digest_value: Annotated[
        Optional[bytes],
        Field(
            alias='srl_nokia-platform-secure-boot:digest-value',
            max_length=18446744073709551615,
        ),
    ] = None
    """
    SHA-256 digest
    """


class SystemReservedPoolContainer(BaseModel):
    """
    Operational size and the current usage of system-reserved-pool
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operational_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:operational-size', ge=0, le=4294967295),
    ] = None
    """
    Operational size of the system-reserved-pool
    """


class TcamContainer(BaseModel):
    """
    Container for managing the allocation of TCAM banks to different applications.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class EnumerationEnum(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum10(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum11(Enum):
    active = 'active'
    standby = 'standby'


class EnumerationEnum12(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum13(Enum):
    all = 'all'


class EnumerationEnum14(Enum):
    x86_64 = 'x86_64'
    aarch64 = 'aarch64'


class EnumerationEnum15(Enum):
    compactflash = 'compactflash'
    ssd = 'ssd'
    hdd = 'hdd'
    usb = 'usb'
    mmc = 'mmc'


class EnumerationEnum16(Enum):
    ro = 'ro'
    rw = 'rw'


class EnumerationEnum17(Enum):
    a = 'A'
    b = 'B'


class EnumerationEnum18(Enum):
    synchronized = 'synchronized'
    synchronizing = 'synchronizing'
    not_ready = 'not-ready'


class EnumerationEnum19(Enum):
    disabled = 'disabled'
    enabled = 'enabled'
    high_scale = 'high-scale'


class EnumerationEnum2(Enum):
    firmware = 'firmware'
    hardware = 'hardware'


class EnumerationEnum20(Enum):
    feed = 'feed'
    module = 'module'
    none = 'none'


class EnumerationEnum21(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum22(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum23(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum24(Enum):
    fault = 'fault'
    eeprom_invalid = 'eeprom-invalid'
    airflow_mismatch = 'airflow-mismatch'


class EnumerationEnum25(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum26(Enum):
    no_input_fault = 'no-input/fault'
    eeprom_invalid = 'eeprom-invalid'
    airflow_mismatch = 'airflow-mismatch'


class EnumerationEnum27(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum28(Enum):
    not_isolated = 'not-isolated'
    no_hugepages = 'no-hugepages'
    irq_not_masked = 'irq-not-masked'
    sibling_not_isolated = 'sibling-not-isolated'
    invalid_cpu_id = 'invalid-cpu-id'


class EnumerationEnum3(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum4(Enum):
    enable = 'enable'
    disable = 'disable'


class EnumerationEnum5(Enum):
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


class EnumerationEnum6(Enum):
    field_0 = '0'
    field_1 = '1'


class EnumerationEnum7(Enum):
    egress = 'egress'
    ingress = 'ingress'


class EnumerationEnum8(Enum):
    up = 'up'
    down = 'down'
    failed = 'failed'
    up_unused = 'up-unused'


class EnumerationEnum9(Enum):
    active = 'active'
    inactive = 'inactive'


class CertificateListEntry(BaseModel):
    """
    List of X.509 certificates
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int, Field(alias='srl_nokia-platform-secure-boot:index', ge=0, le=4294967295)
    ]
    """
    The index of the certificate
    """
    data: Annotated[
        Optional[bytes],
        Field(
            alias='srl_nokia-platform-secure-boot:data', max_length=18446744073709551615
        ),
    ] = None
    """
    DER encoded X.509 certificate
    """


class CertificatesListEntry(BaseModel):
    """
    List of TPM certificates
    Three main types of certificates can be accessed via this statement, including Endorsement Key Certificate (EK), Attestation Key Certificate (AK), Device ID key Certificate (DevID)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-tpm:name')]
    """
    An arbitrary name uniquely identifying a certificate associated to a key within a TPM
    Endorsement Key Certificate (EK): endorsement-certificate
    Initial Device ID Certificate (IDevID): initial-device-id-certificate
    Initial Attestation Key Certificate (IAK): initial-attestation-certificate
    """
    nv_index: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-tpm:nv-index', ge=0, le=4294967295),
    ] = None
    """
    NV index for the certificate
    """
    data: Annotated[
        Optional[bytes],
        Field(alias='srl_nokia-platform-tpm:data', max_length=18446744073709551615),
    ] = None
    """
    DER encoded X.509 certificate
    """


class ContentsContainer(BaseModel):
    """
    Content Secure Boot database variable
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    certificate: Annotated[
        Optional[List[CertificateListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:certificate'),
    ] = None
    sha1_hash: Annotated[
        Optional[List[Sha1HashListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:sha1-hash'),
    ] = None
    sha256_hash: Annotated[
        Optional[List[Sha256HashListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:sha256-hash'),
    ] = None
    sha256_hash_cert: Annotated[
        Optional[List[Sha256HashCertListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:sha256-hash-cert'),
    ] = None


class CpuacctStatisticsContainer(BaseModel):
    """
    Top-level container for cgroup cpuacct statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    user: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:user', ge=0, le=18446744073709551615),
    ] = None
    """
    CPU usage user mode
    """
    system: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:system', ge=0, le=18446744073709551615),
    ] = None
    """
    CPU usage user system
    """


class DramContainer(BaseModel):
    """
    Container for utilization statistics of the DRAM memory.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=100)
    ] = None
    """
    Used DRAM memory
    """


class ExtractionReasonListEntry(BaseModel):
    """
    List of extraction reasons that are possible for the pipeline
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    reason: Annotated[str, Field(alias='srl_nokia-platform-lc:reason')]
    """
    A reason for extracting the packet towards the host CPU
    """
    extracted_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:extracted-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of Ethernet frames extracted towards the CPU from the pipeline; this includes packets that might be dropped (due to congestion or rate limiting) before reaching the final consuming application on the CPM
    """
    extracted_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:extracted-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in Ethernet frames extracted towards the CPU from the pipeline; this includes packets that might be dropped (due to congestion or rate limiting) before reaching the final consuming application on the CPM
    """


class FabricContainer(BaseModel):
    """
    Top-level container for fabric configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    availability: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-lc:availability', ge=0, le=100)
    ] = None
    """
    Details the percentage bandwidth available to the fabric for the line card
    """
    total_capacity: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:total-capacity', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Total backplane-facing capacity that is available in the presence of no link failures or degradation
    """
    operational_capacity: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:operational-capacity',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Total backplane-facing capacity that is currently available based on the active links
    """
    consumed_capacity: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:consumed-capacity',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Backplane-facing capacity that is consumed by front-panel ports that are connected to the integrated circuit and are operationally up
    """
    utilization_ingress: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:utilization-ingress',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Provides the linecard bandwidth utilization into the switch fabric
    """
    utilization_egress: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:utilization-egress',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Provides the linecard bandwidth utilization from the switch fabric
    """


class FanContainer(BaseModel):
    """
    Top-level container for state relating to fans
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    speed: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-psu:speed', ge=0, le=100)
    ] = None
    """
    The current speed of the fan
    """
    speed_rpm: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-psu:speed-rpm', ge=0, le=65535)
    ] = None
    """
    The current RPM of the fan
    """


class FeedListEntry(BaseModel):
    """
    List of feeds on this power-supply
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[int, Field(alias='srl_nokia-platform-psu:id', ge=0, le=255)]
    """
    ID of the feed
    """
    voltage: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:voltage',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current input voltage for this feed
    """
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current input amperage of this feed
    """


class InputContainer(BaseModel):
    """
    Top-level container for power-supply input state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    voltage: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:voltage',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current voltage input/output for the power-supply
    """
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current amperage input/output for the power-supply
    """
    power: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:power',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current power input/output for the power-supply
    """


class IowaitContainer(BaseModel):
    """
    Time spent idle, waiting for an outstanding disk I/O request
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class LastSwitchoverReasonContainer(BaseModel):
    """
    State information relating to the last control module switchover
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trigger: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:trigger')
    ] = None
    """
    Indicates the trigger of the last switchover

    This field is not populated if the system has not performed a switchover since initial startup.
    """
    details: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:details')
    ] = None
    """
    Any additional details relating to the last switchover

    This field is not populated if the system has not performed a switchover since initial startup.
    """


class MemoryEventsContainer(BaseModel):
    """
    Top-level container for cgroup memory events
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    low: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:low', ge=0, le=18446744073709551615),
    ] = None
    """
    The number of times the cgroup is reclaimed due to high memory pressure
    even though its usage is under the low boundary.
    """
    high: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:high', ge=0, le=18446744073709551615),
    ] = None
    """
    The number of times processes of the cgroup are throttled and routed to perform direct memory reclaim
    because the high memory boundary was exceeded.
    """
    max: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:max', ge=0, le=18446744073709551615),
    ] = None
    """
    The number of times the cgroup’s memory usage was about to go over the max boundary
    """
    oom: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:oom', ge=0, le=18446744073709551615),
    ] = None
    """
    The number of time the cgroup’s memory usage had reached the limit and allocation was about to fail
    """
    oom_kill: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:oom-kill', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    The number of processes belonging to this cgroup killed by any kind of out-of-memory killer
    """


class MemoryStatisticsContainer(BaseModel):
    """
    Top-level container for cgroup memory statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:current', ge=0, le=18446744073709551615),
    ] = None
    """
    The total amount of memory currently being used by the cgroup and its descendants. Read from memory.current
    """
    current_swap: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:current-swap',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The total amount of swap currently being used by the cgroup and its descendants. Read from memory.swap.current
    """
    anon: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:anon', ge=0, le=18446744073709551615),
    ] = None
    """
    Amount of memory used in anonymous mappings such as brk(), sbrk(), and mmap(MAP_ANONYMOUS)
    """
    kernel_stack: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:kernel-stack',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Amount of memory allocated to kernel stacks
    """
    slab: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:slab', ge=0, le=18446744073709551615),
    ] = None
    """
    Amount of memory used for storing in-kernel data structures
    """
    sock: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:sock', ge=0, le=18446744073709551615),
    ] = None
    """
    Amount of memory used in network transmission buffers
    """
    anon_thp: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:anon-thp', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Amount of memory used in anonymous mappings backed by transparent hugepages
    """
    file: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cgroup:file', ge=0, le=18446744073709551615),
    ] = None
    """
    Amount of memory used to cache filesystem data, including tmpfs and shared memory
    """
    file_writeback: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:file-writeback',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Amount of cached filesystem data that was modified and is currently being written back to disk
    """
    file_dirty: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cgroup:file-dirty', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Amount of cached filesystem data that was modified but not yet written back to disk
    """
    memory_events: Annotated[
        Optional[MemoryEventsContainer],
        Field(alias='srl_nokia-platform-cgroup:memory-events'),
    ] = None


class MemoryContainer(BaseModel):
    """
    Top-level container for system memory state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    physical: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-memory:physical', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Total physical memory available on this component
    """
    reserved: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-memory:reserved', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Memory reserved for system use
    """
    free: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-memory:free', ge=0, le=18446744073709551615),
    ] = None
    """
    Memory available for system use
    """
    utilization: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-memory:utilization', ge=0, le=100),
    ] = None
    """
    Total memory utilized
    """


class MidPoolListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-platform-qos:index', ge=0, le=255)]
    """
    Mid-pool index
    """
    operational_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:operational-size', ge=0, le=4294967295),
    ] = None
    """
    Operational size of the mid-pool
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=4294967295)
    ] = None
    """
    Actual usage of the mid-pool
    """


class NextHopGroupsContainer(BaseModel):
    """
    Container for the FIB programming state of next-hop-group (NHG) entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    entries_remaining_to_add: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-add',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be created in order to reach synchronization with the CPM
    """
    entries_remaining_to_modify: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-modify',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be modified in order to reach synchronization with the CPM
    """
    last_sync_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ip-route-tables:last-sync-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The time when the forwarding complex last reached sync with the control plane

    A linecard reaches sync when both entries-remaining-to-add and entries-remaining-to-modify reach zero
    """


class NextHopGroupsContainer2(BaseModel):
    """
    Container for the FIB programming state of next-hop-group (NHG) entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    entries_remaining_to_add: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-add',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be created in order to reach synchronization with the CPM
    """
    entries_remaining_to_modify: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-modify',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be modified in order to reach synchronization with the CPM
    """
    last_sync_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ip-route-tables:last-sync-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The time when the forwarding complex last reached sync with the control plane

    A linecard reaches sync when both entries-remaining-to-add and entries-remaining-to-modify reach zero
    """


class NicContainer(BaseModel):
    """
    Top-level container for NIC thread statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    idle: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:idle', ge=0, le=100)
    ] = None
    """
    The aggregate idle percentage of threads
    """
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class NiceContainer(BaseModel):
    """
    Time spent running low-priority (niced) user processes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class OutputContainer(BaseModel):
    """
    Top-level container for power-supply output state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    voltage: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:voltage',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current voltage input/output for the power-supply
    """
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current amperage input/output for the power-supply
    """
    power: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-psu:power',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current power input/output for the power-supply
    """


class OverlayContainer(BaseModel):
    """
    Top-level container for overlay synchronization
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    synchronization_frequency: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-redundancy:synchronization-frequency',
            ge=30,
            le=65535,
        ),
    ] = 60
    """
    Sets the frequency of overlay synchronizations

    This has no effect if overlay is not a configured synchronization mode. Changing this value results in the timer to the next synchronization being reset.
    """
    last_synchronization: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-redundancy:last-synchronization',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last date and time a synchronization of the overlay occurred
    """
    next_synchronization: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-redundancy:next-synchronization',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Next date and time a synchronization of the overlay will occur
    """


class PacketExtractionContainer(BaseModel):
    """
    Packet extraction from the NPU towards the CPU
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    extracted_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:extracted-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of Ethernet frames extracted towards the CPU from the pipeline; this includes packets that might be dropped (due to congestion or rate limiting) before reaching the final consuming application on the CPM
    """
    extracted_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:extracted-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in Ethernet frames extracted towards the CPU from the pipeline; this includes packets that might be dropped (due to congestion or rate limiting) before reaching the final consuming application on the CPM
    """
    extraction_reason: Annotated[
        Optional[List[ExtractionReasonListEntry]],
        Field(alias='srl_nokia-platform-lc:extraction-reason'),
    ] = None


class PcrIndexLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=31)]
    """
    List the TPM2.0 PCRs available to be extracted
    """


class PowerContainer(BaseModel):
    """
    State related to power consumption and allocation for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-lc:allocated', ge=0, le=4294967295),
    ] = None
    """
    The power budget allocated to this component
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-lc:used', ge=0, le=4294967295)
    ] = None
    """
    The power in use by this component
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-lc:required', ge=0, le=4294967295),
    ] = None
    """
    The power budget required to enable this component
    """


class PowerContainer2(BaseModel):
    """
    State related to power consumption and allocation for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:allocated', ge=0, le=4294967295),
    ] = None
    """
    The power budget allocated to this component
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:used', ge=0, le=4294967295),
    ] = None
    """
    The power in use by this component
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:required', ge=0, le=4294967295),
    ] = None
    """
    The power budget required to enable this component
    """


class PowerContainer4(BaseModel):
    """
    State related to power consumption and allocation for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:allocated', ge=0, le=4294967295),
    ] = None
    """
    The power budget allocated to this component
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:used', ge=0, le=4294967295),
    ] = None
    """
    The power in use by this component
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:required', ge=0, le=4294967295),
    ] = None
    """
    The power budget required to enable this component
    """


class PowerContainer5(BaseModel):
    """
    State related to power consumption and allocation for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fan:allocated', ge=0, le=4294967295),
    ] = None
    """
    The power budget allocated to this component
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-fan:used', ge=0, le=4294967295)
    ] = None
    """
    The power in use by this component
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fan:required', ge=0, le=4294967295),
    ] = None
    """
    The power budget required to enable this component
    """


class ResourceGroupsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=4294967295)
    ] = None
    """
    The number of resource-groups that are in use
    """
    free: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:free', ge=0, le=4294967295)
    ] = None
    """
    The number of resource-groups that are unused and available
    """


class ResourceSetsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=4294967295)
    ] = None
    """
    The number of resource-sets that are in use
    """
    free: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:free', ge=0, le=4294967295)
    ] = None
    """
    The number of resource-sets that are unused and available
    """


class ResourceListEntry(BaseModel):
    """
    List of generic datapath resources.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-datapath-resources:name')]
    """
    The name of the XDP datapath resource
    """
    used_percent: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-datapath-resources:used-percent', ge=0, le=100),
    ] = None
    """
    The percentage of the resource that is currently used
    """
    used_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently used
    """
    free_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:free-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently free
    """


class ResourceListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-qos:name')]
    """
    The name of the QoS resource
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=4294967295)
    ] = None
    """
    The number of resources that are in use
    """
    free: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:free', ge=0, le=4294967295)
    ] = None
    """
    The number of resources that are unused and available
    """


class ResourceListEntry3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-mtu:name')]
    """
    The name of the MTU resource
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-mtu:used', ge=0, le=255)
    ] = None
    """
    The number of resources that are in use
    """
    free: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-mtu:free', ge=0, le=255)
    ] = None
    """
    The number of resources that are unused and available
    """


class ResourceListEntry6(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-qos:name')]
    """
    The name of the QoS resource
    """
    rising_threshold_log: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:rising-threshold-log', ge=0, le=100),
    ] = 90
    """
    Sets the threshold that triggers the generation of a WARNING log whenever the utilization of the QoS resource in any linecard/complex/core reaches this value in a rising direction
    """
    falling_threshold_log: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:falling-threshold-log', ge=0, le=100),
    ] = 70
    """
    Sets the threshold that triggers the generation of a NOTICE log whenever the utilization of the QoS resource in any linecard/complex/core falls reaches this value in a falling direction
    """


class ResourceListEntry7(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-mtu:name')]
    """
    The name of the MTU resource
    """
    rising_threshold_log: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-mtu:rising-threshold-log', ge=0, le=100),
    ] = 90
    """
    Sets the threshold that triggers the generation of a WARNING log whenever the utilization of the MTU resource in any linecard/complex/core reaches this value in a rising direction and this is the first trigger since the last restart or since the last falling-threshold-log was triggered.
    """
    falling_threshold_log: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-mtu:falling-threshold-log', ge=0, le=100),
    ] = 70
    """
    Sets the threshold that triggers the generation of a NOTICE log whenever the utilization of the MTU resource in any linecard/complex/core reaches this value in a falling direction and this is the first trigger since the last rising-threshold-log was triggered.
    """


class ResourceListEntry8(BaseModel):
    """
    List of generic datapath resources
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-datapath-resources:name')]
    """
    The name of the XDP datapath resource.

    Some of these resources may be software only (i.e. no correspondence to a hardware table).

    Some of these resources may depend on multiple HW tables and when the utilization is reported it represents an aggregated or summarized view.
    """
    upper_threshold_set: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:upper-threshold-set',
            ge=0,
            le=100,
        ),
    ] = 90
    """
    Sets the threshold that triggers the generation of a WARNING log and the setting of 'used-upper-threshold-exceeded' to 'true' whenever the utilization of the datapath resource in any linecard (if applicable) or forwarding complex or pipeline (if applicable) reaches this value in a rising direction
    """
    upper_threshold_clear: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:upper-threshold-clear',
            ge=0,
            le=100,
        ),
    ] = 70
    """
    Sets the threshold that triggers the generation of a NOTICE log and the setting of 'used-upper-threshold-exceeded' to 'false' whenever the utilization of the datapath resource in any linecard (if applicable) or forwarding complex or pipeline (if applicable) reaches this value in a falling direction
    """


class ResourceListEntry9(BaseModel):
    """
    List of ASIC-specific datapath resources
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-datapath-resources:name')]
    """
    The name of the ASIC-specific datapath resource.
    """
    upper_threshold_set: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:upper-threshold-set',
            ge=0,
            le=100,
        ),
    ] = 90
    """
    Sets the threshold that triggers the generation of a WARNING log and the setting of 'used-upper-threshold-exceeded' to 'true' whenever the utilization of the datapath resource in any linecard (if applicable) or forwarding complex or pipeline (if applicable) reaches this value in a rising direction
    """
    upper_threshold_clear: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:upper-threshold-clear',
            ge=0,
            le=100,
        ),
    ] = 70
    """
    Sets the threshold that triggers the generation of a NOTICE log and the setting of 'used-upper-threshold-exceeded' to 'false' whenever the utilization of the datapath resource in any linecard (if applicable) or forwarding complex or pipeline (if applicable) reaches this value in a falling direction
    """


class RootPoolListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-platform-qos:index', ge=0, le=255)]
    """
    Root-pool index
    """
    operational_size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:operational-size', ge=0, le=4294967295),
    ] = None
    """
    Operational size of the root-pool
    """
    used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-qos:used', ge=0, le=4294967295)
    ] = None
    """
    Actual usage of the root-pool
    """
    mid_pool: Annotated[
        Optional[List[MidPoolListEntry]], Field(alias='srl_nokia-platform-qos:mid-pool')
    ] = None


class SoftwareInterruptContainer(BaseModel):
    """
    Time spent servicing software interrupts
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class SramContainer(BaseModel):
    """
    Container for utilization statistics of the on-chip SRAM memory.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:used', ge=0, le=18446744073709551615),
    ] = None
    """
    Used SRAM memory
    """
    free: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:free', ge=0, le=18446744073709551615),
    ] = None
    """
    Available SRAM memory
    """


class StatisticsContainer(BaseModel):
    """
    Top-level container for disk statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    utilization: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-disk:utilization', ge=0, le=100)
    ] = None
    """
    The current tps utilization of the disk, expressed as a percentage
    """
    transfers_per_second: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-disk:transfers-per-second',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the number of transfers per second that were issued to the device
    A transfer is an I/O request to the device. Multiple logical requests can be combined into a single I/O request to the device. A transfer is of indeterminate size.
    """
    read_per_second: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-disk:read-per-second',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the amount of data read from the device per second
    """
    written_per_second: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-disk:written-per-second',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the amount of data written to the device per second
    """
    io_errors: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-disk:io-errors', ge=0, le=18446744073709551615),
    ] = None
    max_erase_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-disk:max-erase-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None


class SystemContainer(BaseModel):
    """
    Time spent executing at the system level

    This can otherwise be known as kernel time, and does not include time spent servicing hardware and software interrupts.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class TemperatureContainer(BaseModel):
    """
    State related to temperature for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-lc:instant', ge=-32768, le=32767)
    ] = None
    """
    Represents the highest current temperature of any sensor on this component

    Note that as multiple sensors may feed in, that this field and the margin field may be referencing different sensors.
    """
    maximum: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-lc:maximum', ge=-32768, le=32767)
    ] = None
    """
    Represents the highest temperature any sensor on this component has reached since it booted
    """
    maximum_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:maximum-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the time this component reached the temperature referenced in the maximum field
    """
    alarm_status: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-lc:alarm-status')
    ] = None
    """
    Indicates if a temperature sensor of this component is currently in an alarm state

    An alarm state is triggered if the margin is <=2 degrees, indicating that a thermal protection shut down is imminent unless adequate system cooling is provided to bring the temperature sensor back into safe operating ranges.
    """
    margin: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-lc:margin', ge=-32768, le=32767)
    ] = None
    """
    Indicates the lowest alarm margin of any sensor on this component

    The margin is the delta between the current sensor temperature and the thermal protection threshold for that sensor. Note that as multiple sensors may feed in, that this field and the instant field may be referencing different sensors.
    """


class TemperatureContainer2(BaseModel):
    """
    State related to temperature for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:instant', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest current temperature of any sensor on this component

    Note that as multiple sensors may feed in, that this field and the margin field may be referencing different sensors.
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:maximum', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest temperature any sensor on this component has reached since it booted
    """
    maximum_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-control:maximum-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the time this component reached the temperature referenced in the maximum field
    """
    alarm_status: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-control:alarm-status')
    ] = None
    """
    Indicates if a temperature sensor of this component is currently in an alarm state

    An alarm state is triggered if the margin is <=2 degrees, indicating that a thermal protection shut down is imminent unless adequate system cooling is provided to bring the temperature sensor back into safe operating ranges.
    """
    margin: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-control:margin', ge=-32768, le=32767),
    ] = None
    """
    Indicates the lowest alarm margin of any sensor on this component

    The margin is the delta between the current sensor temperature and the thermal protection threshold for that sensor. Note that as multiple sensors may feed in, that this field and the instant field may be referencing different sensors.
    """


class TemperatureContainer3(BaseModel):
    """
    State related to temperature for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:instant', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest current temperature of any sensor on this component

    Note that as multiple sensors may feed in, that this field and the margin field may be referencing different sensors.
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:maximum', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest temperature any sensor on this component has reached since it booted
    """
    maximum_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fabric:maximum-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the time this component reached the temperature referenced in the maximum field
    """
    alarm_status: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-fabric:alarm-status')
    ] = None
    """
    Indicates if a temperature sensor of this component is currently in an alarm state

    An alarm state is triggered if the margin is <=2 degrees, indicating that a thermal protection shut down is imminent unless adequate system cooling is provided to bring the temperature sensor back into safe operating ranges.
    """
    margin: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-fabric:margin', ge=-32768, le=32767),
    ] = None
    """
    Indicates the lowest alarm margin of any sensor on this component

    The margin is the delta between the current sensor temperature and the thermal protection threshold for that sensor. Note that as multiple sensors may feed in, that this field and the instant field may be referencing different sensors.
    """


class TemperatureContainer4(BaseModel):
    """
    State related to temperature for this component
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-psu:instant', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest current temperature of any sensor on this component

    Note that as multiple sensors may feed in, that this field and the margin field may be referencing different sensors.
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-psu:maximum', ge=-32768, le=32767),
    ] = None
    """
    Represents the highest temperature any sensor on this component has reached since it booted
    """
    maximum_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-psu:maximum-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the time this component reached the temperature referenced in the maximum field
    """
    alarm_status: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-psu:alarm-status')
    ] = None
    """
    Indicates if a temperature sensor of this component is currently in an alarm state

    An alarm state is triggered if the margin is <=2 degrees, indicating that a thermal protection shut down is imminent unless adequate system cooling is provided to bring the temperature sensor back into safe operating ranges.
    """


class TotalContainer(BaseModel):
    """
    Total CPU utilization
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class Tpm20PcrBankListEntry(BaseModel):
    """
    Specifies the list of PCRs that may be extracted for a specific Hash Algorithm
    A TPM2.0 bank is a set of PCRs which are extended using a particular hash algorithm
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tpm20_hash_algo: Annotated[
        str,
        Field(
            alias='srl_nokia-platform-tpm:tpm20-hash-algo',
            pattern='^(?=^sha1|sha256$).*$',
        ),
    ]
    """
    The hash algorithm that is used to hash TPM2.0 PCRs
    """
    pcr_index: Annotated[
        Optional[List[PcrIndexLeafList]],
        Field(alias='srl_nokia-platform-tpm:pcr-index'),
    ] = []
    """
    List the TPM2.0 PCRs available to be extracted
    """


class UefiVariablesUpdateContainer(BaseModel):
    """
    Update status of the UEFI Secure Boot variables PK, KEK, DB and DBx programmed in the control module compared to the UEFI variables update in the modification dataset
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    modification_dataset_present: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:modification-dataset-present'),
    ] = None
    """
    The modification dataset is present
    """
    modification_dataset_valid: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:modification-dataset-valid'),
    ] = None
    """
    The status of the modification dataset
    true = the modification dataset is valid
    false = the modification dataset is invalid
    """
    up_to_date: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-secure-boot:up-to-date')
    ] = None
    """
    Status of the Secure Boot variables programmed in the control module compared to the current modification dataset
    true = UEFI variables are up to date
    false = UEFI variable update required
    """
    dbx_update_required: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:dbx-update-required'),
    ] = None
    """
    The forbidden database (dbx) update status compared to the modification dataset
    true = the forbidden database (dbx) is not up to date, update required
    false = the forbidden database (dbx) is up to date
    """
    db_update_required: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-secure-boot:db-update-required')
    ] = None
    """
    The authorized database (db) update status compared to the modification dataset
    true = the authorized database (db) is not up to date, update required
    false = the authorized database (db) is up to date
    """
    pk_update_required: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-secure-boot:pk-update-required')
    ] = None
    """
    The Platform Key (PK) update status compared to the modification dataset
    true = the Platform Key is not up to date, update required
    false = the Platform Key is up to date
    """
    kek_update_required: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:kek-update-required'),
    ] = None
    """
    The Key Exchange Key database (KEK) update status compared to the modification dataset
    true = the Key Exchange Key database (KEK) is not up to date, update required
    false = the Key Exchange Key database (KEK) is up to date
    """
    modification_dataset_db_conflict: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:modification-dataset-db-conflict'),
    ] = None
    """
    The authorized database (db) conflict status between the modification dataset and the current running image
    true = conflict
    false = no conflict
    """
    modification_dataset_dbx_conflict: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-secure-boot:modification-dataset-dbx-conflict'),
    ] = None
    """
    The forbidden database (dbx) conflict status between the modification dataset and the current running image
    true = conflict
    false = no conflict
    """
    modification_dataset_digest: Annotated[
        Optional[bytes],
        Field(
            alias='srl_nokia-platform-secure-boot:modification-dataset-digest',
            max_length=18446744073709551615,
        ),
    ] = None
    """
    The SHA256 digest of the modification dataset file
    """


class UefiVariablesListEntry(BaseModel):
    """
    Content of the UEFI Secure Boot variables programmed in the control module
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    variable: Annotated[str, Field(alias='srl_nokia-platform-secure-boot:variable')]
    """
    UEFI Secure Boot database variable name
    """
    contents: Annotated[
        Optional[ContentsContainer],
        Field(alias='srl_nokia-platform-secure-boot:contents'),
    ] = None


class UnifiedForwardingResourcesContainer(BaseModel):
    """
    Container for managing Broadcom-specific UFT resources.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    xdp_restart_required: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-platform-resource-mgmt:xdp-restart-required'),
    ] = None
    """
    Reads true if the user has committed a change to one or more of the configurable values in the uft container but has not yet restarted XDP so the operational values are still the values initialized at the last XDP restart.
    """
    alpm: Annotated[
        Optional[EnumerationEnum19],
        Field(alias='srl_nokia-platform-resource-mgmt:alpm'),
    ] = None
    """
    Controls the ALPM mode.

    If this is set to disabled then no UFT banks are allocated to ALPM.  This mode is not supported by 7220 IXR-D4 or 7220 IXR-D5.

    If this is set to enabled then 4 UFT shared banks are allocated to ALPM.  This mode is not supported by 7220 IXR-D2 or 7220 IXR-D3.

    If this is set to high-scale then 8 UFT shared banks are allocated to ALPM. This mode is not supported by 7220 IXR-D1.
    """
    requested_extra_ip_host_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-resource-mgmt:requested-extra-ip-host-entries',
            ge=0,
            le=262144,
        ),
    ] = None
    """
    The extra number of host entries that are desired.

    The number of UFT shared banks that are reserved for IPv4 and IPv6 host entries is given by:
    min(N//X,P-A)

    where:
    N = configured value of requested-extra-ip-host-entries
    X = the size of each shared bank, which is platform specific
    P-A = platform-specific number of shared banks, subtracting the ALPM banks

    requested-extra-ip-host-entries is interpreted in terms of IPv4 hosts (single-wide entries). IPv6 host entries are double-wide so 1 IPv4 host entry + 1 IPv6 host-entry counts as 3 entries.

    All UFT shared banks that are not reserved by ALPM and not reserved for extra IP host entries are used for extra MAC entries.

    On D1 the default value is 48K entries, which provides 3 shared banks, max is 96K.
    On D2/D3 the default value is 128K entries, which provides 4 shared banks, max is 256K.
    """
    allocated_extra_ip_host_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-resource-mgmt:allocated-extra-ip-host-entries',
            ge=0,
            le=262144,
        ),
    ] = None
    """
    The extra number of host entries that have been allocated from UFT shared banks.
    """
    allocated_extra_mac_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-resource-mgmt:allocated-extra-mac-entries',
            ge=0,
            le=262144,
        ),
    ] = None
    """
    The extra number of MAC address entries that have been allocated from UFT shared banks.
    """
    ipv6_128bit_lpm_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-resource-mgmt:ipv6-128bit-lpm-entries',
            ge=0,
            le=8192,
        ),
    ] = None
    """
    Sets the value for num_ipv6_lpm_128b_entries, which affects IP FIB scale.

    H2/H3 range: 0-1024
    D1 range: 0-4096
    D2/D3 range: 0-8192
    """


class UserContainer(BaseModel):
    """
    Time spent executing at the user level

    This can otherwise be known as application or user space time.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class XdpContainer(BaseModel):
    """
    Container for monitoring datapath resources that are generic in concept.

    At the pipeline level only one XDP resource is currently reported:
    - subinterfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry]],
        Field(alias='srl_nokia-platform-datapath-resources:resource'),
    ] = None


class XdpContainer3(BaseModel):
    """
    Container for monitoring datapath resources that are generic in concept.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry8]],
        Field(alias='srl_nokia-platform-datapath-resources:resource'),
    ] = None


class AsicContainer2(BaseModel):
    """
    Container for monitoring datapath resources that are specific to a subset of the chipsets supported by SRLinux.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry9]],
        Field(alias='srl_nokia-platform-datapath-resources:resource'),
    ] = None


class BufferMemoryContainer(BaseModel):
    """
    Container for utilization statistics of the packet buffer memory
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:used', ge=0, le=18446744073709551615),
    ] = None
    """
    Used buffer memory, excluding reserved memory.
    """
    free: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:free', ge=0, le=18446744073709551615),
    ] = None
    """
    Available buffer memory, which equals the total memory less the used memory and the reserved memory.
    """
    reserved: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-qos:reserved', ge=0, le=18446744073709551615),
    ] = None
    """
    Buffer memory reserved for proper system operation and by the user (due to assignment of non-zero CBS for certain queues, on platforms that support CBS).
    """
    sram: Annotated[
        Optional[SramContainer], Field(alias='srl_nokia-platform-qos:sram')
    ] = None
    dram: Annotated[
        Optional[DramContainer], Field(alias='srl_nokia-platform-qos:dram')
    ] = None
    system_reserved_pool: Annotated[
        Optional[SystemReservedPoolContainer],
        Field(alias='srl_nokia-platform-qos:system-reserved-pool'),
    ] = None
    root_pool: Annotated[
        Optional[List[RootPoolListEntry]],
        Field(alias='srl_nokia-platform-qos:root-pool'),
    ] = None


class CgroupListEntry(BaseModel):
    """
    List of cgroups present in the system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-cgroup:name')]
    """
    Name of the cgroup, as defined by its directory location in the filesystem
    """
    memory_statistics: Annotated[
        Optional[MemoryStatisticsContainer],
        Field(alias='srl_nokia-platform-cgroup:memory-statistics'),
    ] = None
    cpuacct_statistics: Annotated[
        Optional[CpuacctStatisticsContainer],
        Field(alias='srl_nokia-platform-cgroup:cpuacct-statistics'),
    ] = None


class ControlPlaneTrafficContainer(BaseModel):
    """
    Counters related to traffic destined to the control-plane
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    queued_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:queued-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The aggregation of all counters where the switch has enqueued traffic related to the control plane
    """
    queued_bytes_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:queued-bytes-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The aggregation of all counters in bytes where the switch has enqueued traffic related to the control plane
    """
    dropped_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:dropped-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The aggregation of all counters where the switch has dropped traffic related to the control plane
    """
    dropped_bytes_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:dropped-bytes-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Te aggregation of all counters in bytes where the switch has dropped traffic related to the control plane
    """


class ControlContainer(BaseModel):
    """
    Top-level container for power usage of control modules
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:allocated', ge=0, le=4294967295),
    ] = None
    """
    Power allocated to components as part of power management
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:required', ge=0, le=4294967295),
    ] = None
    """
    Power required to power on all present admin enabled components as part of power management
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:used', ge=0, le=4294967295),
    ] = None
    """
    Used power
    """
    peak: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:peak', ge=0, le=4294967295),
    ] = None
    """
    Peak power used
    """


class ControlListEntry(BaseModel):
    """
    Secure Boot states related to control modules
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[
        str, Field(alias='srl_nokia-platform-secure-boot:slot', pattern='^(?=^A|B$).*$')
    ]
    """
    Slot identifier for the control module
    """
    oper_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-platform-secure-boot:oper-state'),
    ] = None
    """
    Secure Boot operational state
    """
    root_of_trust: Annotated[
        Optional[EnumerationEnum2],
        Field(alias='srl_nokia-platform-secure-boot:root-of-trust'),
    ] = None
    """
    Root of Trust for Secure Boot execution
    """
    uefi_variables_update: Annotated[
        Optional[UefiVariablesUpdateContainer],
        Field(alias='srl_nokia-platform-secure-boot:uefi-variables-update'),
    ] = None
    uefi_variables: Annotated[
        Optional[List[UefiVariablesListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:uefi-variables'),
    ] = None


class ControlListEntry2(BaseModel):
    """
    TPM status, PCR indexes and certificates per control module
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[
        str, Field(alias='srl_nokia-platform-tpm:slot', pattern='^(?=^A|B$).*$')
    ]
    """
    Slot identifier for the control module.
    The slot identifier is the system wide unique name for the module's TPM
    """
    oper_state: Annotated[
        Optional[EnumerationEnum3], Field(alias='srl_nokia-platform-tpm:oper-state')
    ] = None
    """
    TPM chip self-test status
    """
    tpm20_pcr_bank: Annotated[
        Optional[List[Tpm20PcrBankListEntry]],
        Field(alias='srl_nokia-platform-tpm:tpm20-pcr-bank'),
    ] = None
    certificates: Annotated[
        Optional[List[CertificatesListEntry]],
        Field(alias='srl_nokia-platform-tpm:certificates'),
    ] = None


class DatapathContainer(BaseModel):
    """
    Container for monitoring datapath resources of a particular pipeline
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    xdp: Annotated[
        Optional[XdpContainer], Field(alias='srl_nokia-platform-datapath-resources:xdp')
    ] = None


class DatapathContainer3(BaseModel):
    """
    Container for monitoring datapath resources system-wide
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    xdp: Annotated[
        Optional[XdpContainer3],
        Field(alias='srl_nokia-platform-datapath-resources:xdp'),
    ] = None
    asic: Annotated[
        Optional[AsicContainer2],
        Field(alias='srl_nokia-platform-datapath-resources:asic'),
    ] = None


class DropCountersContainer(BaseModel):
    """
    State container for forwarding-complex drop counters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    adverse_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:adverse-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Aggregation of all counters incremented when packets are dropped unexpectedly

    This leaf counts packet discarded as result of corrupted programming state or data structures in the forwarding-complex integrated circuit.

    Note: corrupted packets received on ingress interfaces are not counted in this leaf. This is because incoming corrupted packets are not a signal of adverse state within the integrated circuit, but rather of an adjacent entity, such as a cable or transceiver.
    """
    congestion_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:congestion-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Aggregation of all counters incremeneted when packets are dropped because the aggregate ingress traffic rate exceeds internal performance limits of the integrated circuit
    """
    packet_processing_aggregate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-lc:packet-processing-aggregate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Aggregation of all counters incremented when packets are dropped due to legitimate programming decisions

    This is derived by summing:
    * subinterface-level in-discarded counters (counts FIB lookup failures, packets dropped due to ACL drop action, packets dropped due to TTL expiry)
    * subinterface-level out-error counters (packets dropped due to IP MTU exceeded)
    * port-level out-error counters (packets dropped due to port MTU exceeded)
    * port-level in-error counters (packets dropped due to MRU exceeded oe packet CRC error)
    """
    no_route: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-lc:no-route', ge=0, le=18446744073709551615),
    ] = 0
    """
    Aggregation of all counters incremented when packets are dropped due to no FIB entry for an IPv4 or IPv6 packet

    This counter and the packet-processing-aggregate counter should be incremented for each no-route packet drop.
    """


class FabricContainer2(BaseModel):
    """
    Top-level container for power usage of fabric modules
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:allocated', ge=0, le=4294967295),
    ] = None
    """
    Power allocated to components as part of power management
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:required', ge=0, le=4294967295),
    ] = None
    """
    Power required to power on all present admin enabled components as part of power management
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:used', ge=0, le=4294967295),
    ] = None
    """
    Used power
    """
    peak: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:peak', ge=0, le=4294967295),
    ] = None
    """
    Peak power used
    """


class FanTrayContainer(BaseModel):
    """
    Top-level container for power usage of fan-trays
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:allocated', ge=0, le=4294967295),
    ] = None
    """
    Power allocated to components as part of power management
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:required', ge=0, le=4294967295),
    ] = None
    """
    Power required to power on all present admin enabled components as part of power management
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:used', ge=0, le=4294967295),
    ] = None
    """
    Used power
    """
    peak: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:peak', ge=0, le=4294967295),
    ] = None
    """
    Peak power used
    """


class ForwarderContainer(BaseModel):
    """
    Top-level container for forwarder thread statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    idle: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:idle', ge=0, le=100)
    ] = None
    """
    The aggregate idle percentage of threads
    """
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class HardwareInterruptContainer(BaseModel):
    """
    Time spent servicing hardware interrupts
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class HealthzContainer(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum10], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HealthzContainer2(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum12], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HealthzContainer3(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum22], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HealthzContainer4(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum23], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HealthzContainer5(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum25], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HealthzContainer6(BaseModel):
    """
    The health of the component

    The paramaters within this
    container indicate the status of the component beyond whether
    it is operationally up or down. When a signal is received
    that a component is in an unhealthy state the gNOI.Healthz
    service can be used to retrieve further diagnostic information
    relating to the component.
    The contents of this directory relate only to the specific
    component that it is associated with.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum27], Field(alias='srl_nokia-platform-healthz:status')
    ] = None
    """
    Health status

    The status of the component, indicating its current health.
    """
    last_unhealthy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-healthz:last-unhealthy',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """
    unhealthy_count: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-healthz:unhealthy-count',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class HostInterfaceBlockContainer(BaseModel):
    """
    The ASIC host interface block subsystem that connects the NPU to the host CPU (on the CPM)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    packet_extraction: Annotated[
        Optional[PacketExtractionContainer],
        Field(alias='srl_nokia-platform-lc:packet-extraction'),
    ] = None


class IdleContainer(BaseModel):
    """
    Time spent idle
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    instant: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:instant', ge=0, le=100)
    ] = None
    """
    The instantaneous percentage value
    """
    average_1: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-1', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last minute
    """
    average_5: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-5', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last five minutes
    """
    average_15: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-cpu:average-15', ge=0, le=100)
    ] = None
    """
    The arithmetic mean value of this statistic over the last fifteen minutes
    """


class IpRoutesContainer(BaseModel):
    """
    Container for the FIB programming state of IP route entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    entries_remaining_to_add: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-add',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be created in order to reach synchronization with the CPM
    """
    entries_remaining_to_modify: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-modify',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be modified in order to reach synchronization with the CPM
    """
    last_sync_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ip-route-tables:last-sync-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The time when the forwarding complex last reached sync with the control plane

    A linecard reaches sync when both entries-remaining-to-add and entries-remaining-to-modify reach zero
    """


class IpRoutesContainer2(BaseModel):
    """
    Container for the FIB programming state of IP route entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    entries_remaining_to_add: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-add',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be created in order to reach synchronization with the CPM
    """
    entries_remaining_to_modify: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ip-route-tables:entries-remaining-to-modify',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The number of entries that need to be modified in order to reach synchronization with the CPM
    """
    last_sync_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ip-route-tables:last-sync-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The time when the forwarding complex last reached sync with the control plane

    A linecard reaches sync when both entries-remaining-to-add and entries-remaining-to-modify reach zero
    """


class LinecardContainer(BaseModel):
    """
    Top-level container for power usage of linecard modules
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:allocated', ge=0, le=4294967295),
    ] = None
    """
    Power allocated to components as part of power management
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:required', ge=0, le=4294967295),
    ] = None
    """
    Power required to power on all present admin enabled components as part of power management
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:used', ge=0, le=4294967295),
    ] = None
    """
    Used power
    """
    peak: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:peak', ge=0, le=4294967295),
    ] = None
    """
    Peak power used
    """


class MtuContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry3]],
        Field(alias='srl_nokia-platform-mtu:resource'),
    ] = None


class MtuContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry7]],
        Field(alias='srl_nokia-platform-mtu:resource'),
    ] = None


class NextHopListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[int, Field(alias='srl_nokia-platform-linecard-fib:id', ge=0, le=1023)]
    """
    Index of the next-hop within the NHG
    """
    next_hop: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-linecard-fib:next-hop',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The system-wide unique identifier of the next-hop object
    """
    oper_state: Annotated[
        Optional[EnumerationEnum8],
        Field(alias='srl_nokia-platform-linecard-fib:oper-state'),
    ] = None
    """
    Operational state of the next-hop member
    """
    normalized_weight: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-linecard-fib:normalized-weight', ge=0, le=255),
    ] = None
    """
    The normalized weight assigned to the next-hop within the group

    This represents the number of ECMP hash buckets assigned to the next-hop based on the currently-active set of next-hops in the NHG
    """


class PartitionListEntry(BaseModel):
    """
    List of partitions available on this disk
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-disk:name')]
    """
    Name of the partition
    """
    uuid: Annotated[Optional[str], Field(alias='srl_nokia-platform-disk:uuid')] = None
    """
    UUID of the partition
    """
    mount_point: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-disk:mount-point')
    ] = None
    """
    Path to where this partition is mounted
    """
    mount_status: Annotated[
        Optional[EnumerationEnum16], Field(alias='srl_nokia-platform-disk:mount-status')
    ] = None
    """
    Current mount status of this partition
    """
    size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-disk:size', ge=0, le=18446744073709551615),
    ] = None
    """
    Size of the partition
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-disk:used', ge=0, le=18446744073709551615),
    ] = None
    """
    Space used on the partition
    """
    free: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-disk:free', ge=0, le=18446744073709551615),
    ] = None
    """
    Space free on the partition
    """
    percent_used: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-disk:percent-used', ge=0, le=100)
    ] = None
    """
    Percentage of the partition in use
    """
    encrypted: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-disk:encrypted')
    ] = None
    """
    Indicates if the partition is encrypted using disk encryption
    """


class PipelineCountersContainer(BaseModel):
    """
    Top-level container for the packet counters associated with the different NPU sub-blocks.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    host_interface_block: Annotated[
        Optional[HostInterfaceBlockContainer],
        Field(alias='srl_nokia-platform-lc:host-interface-block'),
    ] = None


class PipelineListEntry(BaseModel):
    """
    List of pipelines that make up one forwarding complex.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        Union[IndexLeaf51, EnumerationEnum7], Field(alias='srl_nokia-platform-lc:index')
    ]
    """
    The pipeline number (TH3 systems) or direction (J2 and J2C+ systems).
    """
    pipeline_counters: Annotated[
        Optional[PipelineCountersContainer],
        Field(alias='srl_nokia-platform-lc:pipeline-counters'),
    ] = None
    datapath: Annotated[
        Optional[DatapathContainer],
        Field(alias='srl_nokia-platform-datapath-resources:datapath'),
    ] = None


class PowerSupplyListEntry(BaseModel):
    """
    Top-level container for power supply module configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[int, Field(alias='srl_nokia-platform-psu:id', ge=1, le=255)]
    """
    Numeric identifier for the power supply module
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-psu:type')] = None
    """
    Power-supply type, as translated from the components EEPROM
    """
    capacity: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-psu:capacity', ge=0, le=4294967295),
    ] = None
    """
    The total capacity the power supply module can provide
    """
    fan: Annotated[
        Optional[FanContainer], Field(alias='srl_nokia-platform-psu:fan')
    ] = None
    input: Annotated[
        Optional[InputContainer], Field(alias='srl_nokia-platform-psu:input')
    ] = None
    output: Annotated[
        Optional[OutputContainer], Field(alias='srl_nokia-platform-psu:output')
    ] = None
    feed: Annotated[
        Optional[List[FeedListEntry]], Field(alias='srl_nokia-platform-psu:feed')
    ] = None
    oper_reason: Annotated[
        Optional[EnumerationEnum26], Field(alias='srl_nokia-platform-psu:oper-reason')
    ] = None
    """
    Indicates the reason for the current state of the component
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-psu:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-psu:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-psu:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-psu:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-psu:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-psu:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-psu:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-psu:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-psu:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-psu:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    temperature: Annotated[
        Optional[TemperatureContainer4],
        Field(alias='srl_nokia-platform-psu:temperature'),
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer6], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None


class ProcessListEntry(BaseModel):
    """
    List of system processes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    pid: Annotated[
        int, Field(alias='srl_nokia-platform-cpu:pid', ge=0, le=18446744073709551615)
    ]
    """
    The process ID
    """
    name: Annotated[Optional[str], Field(alias='srl_nokia-platform-cpu:name')] = None
    """
    The process name
    """
    args: Annotated[Optional[List[str]], Field(alias='srl_nokia-platform-cpu:args')] = (
        []
    )
    """
    Current process command line arguments
    Arguments with a parameter (e.g., --option 10  or -option=10) should be represented as a single element of the list with the argument name and parameter together.  Flag arguments, i.e., those without a parameter should also be in their own list element.
    """
    start_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-cpu:start-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The time at which this process started
    """
    cpu_utilization: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cpu:cpu-utilization', ge=0, le=100),
    ] = None
    """
    The percentage of CPU that is being used by the process
    """
    memory_usage: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-cpu:memory-usage', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    Bytes allocated and in use by the process
    """
    memory_utilization: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-cpu:memory-utilization', ge=0, le=100),
    ] = None
    """
    The percentage of RAM that is being used by the process
    """


class ProgrammingProgressContainer(BaseModel):
    """
    State that shows the FIB programming progress of the forwarding complex
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ip_routes: Annotated[
        Optional[IpRoutesContainer], Field(alias='srl_nokia-ip-route-tables:ip-routes')
    ] = None
    next_hop_groups: Annotated[
        Optional[NextHopGroupsContainer],
        Field(alias='srl_nokia-ip-route-tables:next-hop-groups'),
    ] = None


class ProgrammingProgressContainer2(BaseModel):
    """
    State that shows the FIB programming progress of the forwarding complex
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ip_routes: Annotated[
        Optional[IpRoutesContainer2], Field(alias='srl_nokia-ip-route-tables:ip-routes')
    ] = None
    next_hop_groups: Annotated[
        Optional[NextHopGroupsContainer2],
        Field(alias='srl_nokia-ip-route-tables:next-hop-groups'),
    ] = None


class QosContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry6]],
        Field(alias='srl_nokia-platform-qos:resource'),
    ] = None


class RedundancyContainer2(BaseModel):
    """
    Top-level container for power redundancy configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mode: Annotated[
        Optional[EnumerationEnum20], Field(alias='srl_nokia-platform-chassis:mode')
    ] = 'none'
    """
    Set the power redundancy mode in use

    This only sets the level at which power redundancy will be assumed unavailable, and will not result in the powering down of components unless there is insufficient non-redundant power available.
    """
    status: Annotated[
        Optional[EnumerationEnum21], Field(alias='srl_nokia-platform-chassis:status')
    ] = None
    """
    Current status of the selected power redundancy mode
    """


class ResourceGroupListEntry(BaseModel):
    """
    Resource-group resources for the given interface-group-resource-pool

    Describes the number of resource-sets used and free within the resource-group.
    A resource-set consists of 16 output-queues, 16 tier-0 queue-schedulers and 1 tier-1 queue-scheduler, which is allocated to every configured subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-platform-qos:index', ge=0, le=61)]
    resource_sets: Annotated[
        Optional[ResourceSetsContainer],
        Field(alias='srl_nokia-platform-qos:resource-sets'),
    ] = None


class ResourceManagementContainer(BaseModel):
    """
    Container for managing resources in a system-wide context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tcam: Annotated[
        Optional[TcamContainer], Field(alias='srl_nokia-platform-resource-mgmt:tcam')
    ] = None
    unified_forwarding_resources: Annotated[
        Optional[UnifiedForwardingResourcesContainer],
        Field(alias='srl_nokia-platform-resource-mgmt:unified-forwarding-resources'),
    ] = None


class ResourceMonitoringContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    qos: Annotated[
        Optional[QosContainer2], Field(alias='srl_nokia-platform-qos:qos')
    ] = None
    mtu: Annotated[
        Optional[MtuContainer2], Field(alias='srl_nokia-platform-mtu:mtu')
    ] = None
    datapath: Annotated[
        Optional[DatapathContainer3],
        Field(alias='srl_nokia-platform-datapath-resources:datapath'),
    ] = None


class ResourceListEntry4(BaseModel):
    """
    List of generic datapath resources.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-datapath-resources:name')]
    """
    The name of the XDP datapath resource
    """
    used_percent: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-datapath-resources:used-percent', ge=0, le=100),
    ] = None
    """
    The percentage of the resource that is currently used
    """
    used_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently used
    """
    free_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:free-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently free
    """
    used_high_watermark: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-high-watermark',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    A watermark of highest number of entries used for this resource
    """
    used_last_high_watermark_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-last-high-watermark-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The timestamp when the high-watermark was last updated
    """
    used_upper_threshold_exceeded: Annotated[
        Optional[bool],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-upper-threshold-exceeded'
        ),
    ] = None
    """
    This value is set to true when the used percentage value (used / (used + free) * 100) has reached (in a rising direction) the configured upper-threshold-set for this resource and false when the used percentage value has reached (in a falling direction) the configured upper-threshold-clear for this resource
    """


class ResourceListEntry5(BaseModel):
    """
    List of ASIC-specific datapath resources.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-datapath-resources:name')]
    """
    The name of the ASIC-specific datapath resource
    """
    used_percent: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-datapath-resources:used-percent', ge=0, le=100),
    ] = None
    """
    The percentage of the resource that is currently used
    """
    used_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently used
    """
    free_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:free-entries',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The number of entries that are currently free
    """
    used_high_watermark: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-high-watermark',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    A watermark of highest number of entries used for this resource
    """
    used_last_high_watermark_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-last-high-watermark-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The timestamp when the high-watermark was last updated
    """
    used_upper_threshold_exceeded: Annotated[
        Optional[bool],
        Field(
            alias='srl_nokia-platform-datapath-resources:used-upper-threshold-exceeded'
        ),
    ] = None
    """
    This value is set to true when the used percentage value (used / (used + free) * 100) has reached (in a rising direction) the configured upper-threshold-set for this resource and false when the used percentage value has reached (in a falling direction) the configured upper-threshold-clear for this resource
    """


class SecureBootContainer(BaseModel):
    """
    State information related to Secure Boot
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    control: Annotated[
        Optional[List[ControlListEntry]],
        Field(alias='srl_nokia-platform-secure-boot:control'),
    ] = None


class StatisticsContainer2(BaseModel):
    """
    Top-level container for statistics relating to vXDP thread utilization
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    nic: Annotated[
        Optional[NicContainer], Field(alias='srl_nokia-platform-vxdp:nic')
    ] = None
    forwarder: Annotated[
        Optional[ForwarderContainer], Field(alias='srl_nokia-platform-vxdp:forwarder')
    ] = None


class SynchronizationContainer(BaseModel):
    """
    Top-level container for redundancy synchronization
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    state: Annotated[
        Optional[EnumerationEnum18], Field(alias='srl_nokia-platform-redundancy:state')
    ] = None
    """
    Current synchronization status
    """
    state_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-redundancy:state-reason')
    ] = None
    """
    One or more reasons separated by semicolons for the current synchronization state

    This field is not populated when synchronized.
    """
    last_synchronization: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-redundancy:last-synchronization',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Last date and time a synchronization of system files occurred
    """
    overlay: Annotated[
        Optional[OverlayContainer], Field(alias='srl_nokia-platform-redundancy:overlay')
    ] = None


class TotalContainer2(BaseModel):
    """
    Top-level container for total power usage and capacity
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    capacity: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:capacity', ge=0, le=4294967295),
    ] = None
    """
    Total power capacity provided by all power supplies
    """
    allocated: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:allocated', ge=0, le=4294967295),
    ] = None
    """
    Power allocated to components as part of power management
    """
    required: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:required', ge=0, le=4294967295),
    ] = None
    """
    Power required to power on all present admin enabled components as part of power management
    """
    used: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:used', ge=0, le=4294967295),
    ] = None
    """
    Used power
    """
    peak: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-chassis:peak', ge=0, le=4294967295),
    ] = None
    """
    Peak power used
    """


class TpmContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    control: Annotated[
        Optional[List[ControlListEntry2]], Field(alias='srl_nokia-platform-tpm:control')
    ] = None


class TrustContainer(BaseModel):
    """
    State information related to Platform Trust
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    secure_boot: Annotated[
        Optional[SecureBootContainer],
        Field(alias='srl_nokia-platform-secure-boot:secure-boot'),
    ] = None
    tpm: Annotated[
        Optional[TpmContainer], Field(alias='srl_nokia-platform-tpm:tpm')
    ] = None


class XdpContainer2(BaseModel):
    """
    Container for monitoring datapath resources that are generic in concept.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry4]],
        Field(alias='srl_nokia-platform-datapath-resources:resource'),
    ] = None


class AsicContainer(BaseModel):
    """
    Container for monitoring ASIC-specific datapath resources
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry5]],
        Field(alias='srl_nokia-platform-datapath-resources:resource'),
    ] = None


class CpuListEntry(BaseModel):
    """
    List of all CPUs in the system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        Union[EnumerationEnum13, IndexLeaf121],
        Field(alias='srl_nokia-platform-cpu:index'),
    ]
    """
    CPU index for each processor core on the system

    On a single-core system, the index should be zero.  The 'all' index signifies an aggregation of the CPU utilization statistics over all cores in the system.
    """
    architecture: Annotated[
        Optional[EnumerationEnum14], Field(alias='srl_nokia-platform-cpu:architecture')
    ] = None
    """
    Architecture supported by the CPU
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-cpu:type')] = None
    """
    Model name of the CPU
    """
    speed: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-platform-cpu:speed',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Capable speed of the CPU
    """
    total: Annotated[
        Optional[TotalContainer], Field(alias='srl_nokia-platform-cpu:total')
    ] = None
    user: Annotated[
        Optional[UserContainer], Field(alias='srl_nokia-platform-cpu:user')
    ] = None
    system: Annotated[
        Optional[SystemContainer], Field(alias='srl_nokia-platform-cpu:system')
    ] = None
    nice: Annotated[
        Optional[NiceContainer], Field(alias='srl_nokia-platform-cpu:nice')
    ] = None
    idle: Annotated[
        Optional[IdleContainer], Field(alias='srl_nokia-platform-cpu:idle')
    ] = None
    iowait: Annotated[
        Optional[IowaitContainer], Field(alias='srl_nokia-platform-cpu:iowait')
    ] = None
    hardware_interrupt: Annotated[
        Optional[HardwareInterruptContainer],
        Field(alias='srl_nokia-platform-cpu:hardware-interrupt'),
    ] = None
    software_interrupt: Annotated[
        Optional[SoftwareInterruptContainer],
        Field(alias='srl_nokia-platform-cpu:software-interrupt'),
    ] = None


class CpuListEntry2(BaseModel):
    """
    State information relating to the list of CPUs pinned to vXDP threads
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[int, Field(alias='srl_nokia-platform-vxdp:id', ge=0, le=65535)]
    """
    Reference to a CPU within the configured cpu-set
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-vxdp:oper-state')
    ] = None
    """
    The operational state of the CPU
    """
    oper_reason: Annotated[
        Optional[EnumerationEnum28], Field(alias='srl_nokia-platform-vxdp:oper-reason')
    ] = None
    """
    The reason (if any) that this CPU is in its current operational state
    """
    socket_id: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:socket-id', ge=0, le=255)
    ] = None
    """
    The socket this CPU resides on
    """
    core_id: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:core-id', ge=0, le=255)
    ] = None
    """
    The physical core this CPU resides on
    """
    sibling_id: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-vxdp:sibling-id', ge=0, le=65535)
    ] = None
    """
    The sibling CPU (if any) residing on the same core
    """


class DatapathContainer2(BaseModel):
    """
    Container for monitoring datapath resources of a particular forwarding complex
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    xdp: Annotated[
        Optional[XdpContainer2],
        Field(alias='srl_nokia-platform-datapath-resources:xdp'),
    ] = None
    asic: Annotated[
        Optional[AsicContainer],
        Field(alias='srl_nokia-platform-datapath-resources:asic'),
    ] = None


class DiskListEntry(BaseModel):
    """
    List of disks present in the system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-disk:name')]
    """
    Name of the disk, as defined by its physical location in the system
    """
    model_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-disk:model-number')
    ] = None
    """
    Model name of the disk
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-disk:serial-number')
    ] = None
    """
    Serial number of the disk
    """
    size: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-disk:size', ge=0, le=18446744073709551615),
    ] = None
    """
    Total size of the disk
    """
    type: Annotated[
        Optional[EnumerationEnum15], Field(alias='srl_nokia-platform-disk:type')
    ] = None
    """
    Type of disk
    """
    encrypted: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-disk:encrypted')
    ] = None
    """
    Indicates if the disk is encrypted
    """
    partition: Annotated[
        Optional[List[PartitionListEntry]],
        Field(alias='srl_nokia-platform-disk:partition'),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer], Field(alias='srl_nokia-platform-disk:statistics')
    ] = None


class FabricListEntry(BaseModel):
    """
    Top-level container for fabric configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[int, Field(alias='srl_nokia-platform-fabric:slot', ge=1, le=255)]
    """
    Numeric identifier for the fabric module
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-fabric:type')] = None
    """
    Fabric module type, as translated from the components EEPROM
    """
    admin_state: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-platform-fabric:admin-state')
    ] = 'enable'
    """
    The administrative state of this component
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-fabric:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fabric:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fabric:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fabric:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fabric:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-fabric:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fabric:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fabric:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fabric:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fabric:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    rebooting_at: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fabric:rebooting-at',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the date and time this component will reboot

    If empty, no delayed reboots are queued for this component.

    A non empty value implies that a delayed reboot operation has been triggered for this component, which can be aborted using 'tools platform <component> reboot cancel'.
    """
    locator_state: Annotated[
        Optional[EnumerationEnum9],
        Field(alias='srl_nokia-platform-fabric:locator-state'),
    ] = 'inactive'
    """
    Details if the locator LED is active on this component
    """
    power: Annotated[
        Optional[PowerContainer4], Field(alias='srl_nokia-platform-fabric:power')
    ] = None
    temperature: Annotated[
        Optional[TemperatureContainer3],
        Field(alias='srl_nokia-platform-fabric:temperature'),
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer4], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None


class FanTrayListEntry(BaseModel):
    """
    Top-level container for fan module configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[int, Field(alias='srl_nokia-platform-fan:id', ge=1, le=255)]
    """
    Numeric identifier for the fan tray
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-fan:type')] = None
    """
    Fan tray type, as translated from the components EEPROM
    """
    speed: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-fan:speed', ge=0, le=100)
    ] = None
    """
    The current speed of the fan tray
    """
    speed_rpm: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-fan:speed-rpm', ge=0, le=65535)
    ] = None
    """
    The current RPM of the fan tray
    """
    oper_reason: Annotated[
        Optional[EnumerationEnum24], Field(alias='srl_nokia-platform-fan:oper-reason')
    ] = None
    """
    Indicates the reason for the current state of this fan tray
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-fan:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fan:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fan:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fan:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fan:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-fan:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fan:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fan:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-fan:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-fan:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    locator_state: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-platform-fan:locator-state')
    ] = 'inactive'
    """
    Details if the locator LED is active on this component
    """
    power: Annotated[
        Optional[PowerContainer5], Field(alias='srl_nokia-platform-fan:power')
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer5], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None


class FibTableContainer2(BaseModel):
    """
    A representation of the IP FIB table maintained by each control card
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    programming_progress: Annotated[
        Optional[ProgrammingProgressContainer2],
        Field(alias='srl_nokia-ip-route-tables:programming-progress'),
    ] = None


class ForwardingPlaneContainer(BaseModel):
    """
    Container for state related to the datapath on the control card
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    fib_table: Annotated[
        Optional[FibTableContainer2],
        Field(alias='srl_nokia-platform-control-fp:fib-table'),
    ] = None


class InterfaceGroupResourcePoolListEntry(BaseModel):
    """
    Interface-group-resource-pool resources for the given resource-set-pool

    Contains the resource-groups which have been allocated to this interface-group-resource-pool.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-platform-qos:index', ge=0, le=15)]
    resource_group: Annotated[
        Optional[List[ResourceGroupListEntry]],
        Field(alias='srl_nokia-platform-qos:resource-group'),
    ] = None


class InterfaceListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-platform-control:name')]
    """
    Name of a specific control module interface
    """
    admin_state: Annotated[
        Optional[EnumerationEnum4],
        Field(alias='srl_nokia-platform-control:admin-state'),
    ] = None
    """
    Set the administrative state of this interface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-control:oper-state')
    ] = None
    """
    Indicates the current operational state of this interface
    """


class NextHopGroupListEntry(BaseModel):
    """
    List of next hop groups (NHGs) in the FIB table
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[
        int,
        Field(
            alias='srl_nokia-platform-linecard-fib:index', ge=0, le=18446744073709551615
        ),
    ]
    """
    A system-wide unique identifier of a next-hop-group
    """
    oper_state: Annotated[
        Optional[EnumerationEnum8],
        Field(alias='srl_nokia-platform-linecard-fib:oper-state'),
    ] = None
    """
    Operational state of the next-hop group
    """
    backup_next_hop_group: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-platform-linecard-fib:backup-next-hop-group',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    The backup next-hop-group for the current group. When all entries within the next-hop group become unusable, the backup next-hop group is used if specified.
    """
    backup_active: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-linecard-fib:backup-active')
    ] = None
    """
    When true, this NHG is not being used to forward traffic and its backup NHG is being relied upon to provide reachability
    """
    next_hop: Annotated[
        Optional[List[NextHopListEntry]],
        Field(alias='srl_nokia-platform-linecard-fib:next-hop'),
    ] = None


class PowerContainer3(BaseModel):
    """
    Top-level container for chassis-wide power state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    total: Annotated[
        Optional[TotalContainer2], Field(alias='srl_nokia-platform-chassis:total')
    ] = None
    fan_tray: Annotated[
        Optional[FanTrayContainer], Field(alias='srl_nokia-platform-chassis:fan-tray')
    ] = None
    control: Annotated[
        Optional[ControlContainer], Field(alias='srl_nokia-platform-chassis:control')
    ] = None
    linecard: Annotated[
        Optional[LinecardContainer], Field(alias='srl_nokia-platform-chassis:linecard')
    ] = None
    fabric: Annotated[
        Optional[FabricContainer2], Field(alias='srl_nokia-platform-chassis:fabric')
    ] = None
    redundancy: Annotated[
        Optional[RedundancyContainer2],
        Field(alias='srl_nokia-platform-chassis:redundancy'),
    ] = None


class RedundancyContainer(BaseModel):
    """
    Top-level container for platform redundancy
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    active_module: Annotated[
        Optional[EnumerationEnum17],
        Field(alias='srl_nokia-platform-redundancy:active-module'),
    ] = None
    """
    Control module currently active
    """
    failover_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-redundancy:failover-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Date and time of the last control module failover
    """
    synchronization: Annotated[
        Optional[SynchronizationContainer],
        Field(alias='srl_nokia-platform-redundancy:synchronization'),
    ] = None


class ResourceSetPoolListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-platform-qos:index', ge=0, le=1)]
    """
    Resource-set-pool resources for the given forwarding-complex

    Contains resource-group resources.
    """
    resource_groups: Annotated[
        Optional[ResourceGroupsContainer],
        Field(alias='srl_nokia-platform-qos:resource-groups'),
    ] = None
    interface_group_resource_pool: Annotated[
        Optional[List[InterfaceGroupResourcePoolListEntry]],
        Field(alias='srl_nokia-platform-qos:interface-group-resource-pool'),
    ] = None


class VxdpContainer(BaseModel):
    """
    Top-level container for vXDP configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    cpu_set: Annotated[
        Optional[List[CpuSetLeafList]], Field(alias='srl_nokia-platform-vxdp:cpu-set')
    ] = []
    """
    The list of CPUs used for vXDP PMD threads

    These CPUs should be isolated out-of-band of SR Linux, and are used for forwarder and NIC threads for vhost-user, physical, and lif interfaces.
    It is expected that the sibling of a CPU is always passed to vXDP, and in order to enforce this if a single CPU of a core is passed, vXDP will derive and bind to the undefined sibling. vXDP supports the passing of both single and both siblings together, and will perform a merge to ensure all siblings are consumed.
    """
    cpu: Annotated[
        Optional[List[CpuListEntry2]], Field(alias='srl_nokia-platform-vxdp:cpu')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer2],
        Field(alias='srl_nokia-platform-vxdp:statistics'),
    ] = None


class ChassisContainer(BaseModel):
    """
    Top-level container for chassis configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    secondary_mac_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:secondary-mac-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    MAC address programmed as a secondary terminating MAC address on every IP interface, across all network instances

    If an IP packet is received on a routed subinterface and it arrives with a DMAC equal to the secondary-mac-address then it is terminated and forwarded exactly the same way it would be forwarded if it had arrived on this subinterface with a DMAC equal to the subinterface MAC address.
    """
    id: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-chassis:id', ge=0, le=4294967295)
    ] = None
    """
    A user configured chassis ID

    This value is not used by the system, but is provided for user convenience.
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-chassis:type')] = (
        None
    )
    """
    The chassis type
    """
    last_boot_type: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:last-boot-type')
    ] = None
    """
    The type of boot the chassis initialized from

    This field indicates what type of reboot occurred, whether it be warm, normal, or otherwise.
    """
    rebooting_at: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:rebooting-at',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the date and time this component will reboot

    If empty, no delayed reboots are queued for this component.

    A non empty value implies that a delayed reboot operation has been triggered for this component, which can be aborted using 'tools platform <component> reboot cancel'.
    """
    hw_mac_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:hw-mac-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    The chassis MAC address

    Read from hardware, or derived from the systems UUID
    """
    slots: Annotated[
        Optional[int], Field(alias='srl_nokia-platform-chassis:slots', ge=0, le=255)
    ] = None
    """
    The number of line card slots supported by the chassis
    """
    power: Annotated[
        Optional[PowerContainer3], Field(alias='srl_nokia-platform-chassis:power')
    ] = None
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-chassis:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-chassis:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-chassis:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-chassis:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    healthz: Annotated[
        Optional[HealthzContainer3], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None
    uuid: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-vxdp:uuid',
            pattern='^(?=^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$).*$',
        ),
    ] = None
    """
    The system-generated or user-configured UUID for the chassis
    """
    mac_address_allocation: Annotated[
        Optional[int],
        Field(alias='srl_nokia-platform-vxdp:mac-address-allocation', ge=1, le=8192),
    ] = 1024
    """
    The number of MAC addresses to generate from the chassis MAC address

    These MAC addresses are used for interfaces that need MAC addresses generated by the system.
    """
    mac_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-vxdp:mac-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    The configured or derived MAC address of the chassis

    If not configured, this is set to the hw-mac-address, which is populated depending on system type:

    - For systems with a discoverable chassis MAC address (either populated by an external system or present in hardware) the discovered value is populated.
    - For systems without a discoverable MAC address, the address is generated from a hash of the systems UUID.

    When deleted, will revert back to the value of hw-mac-address.

    This MAC address is used by the system as a base to generate MAC addresses for interfaces (when needed).
    """


class ControlListEntry3(BaseModel):
    """
    Top-level container for control module configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[
        str, Field(alias='srl_nokia-platform-control:slot', pattern='^(?=^A|B$).*$')
    ]
    """
    Slot identifier for the control module

    This is set to 'A' for systems without removable control modules.
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-control:type')] = (
        None
    )
    """
    Control module type, as translated from the components EEPROM
    """
    role: Annotated[
        Optional[EnumerationEnum11], Field(alias='srl_nokia-platform-control:role')
    ] = None
    """
    Control module role, detailing active or standby state

    This field is not present on systems without removable control modules.
    """
    disk_encrypted: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-control:disk-encrypted')
    ] = None
    """
    Indicates if the disk is encrypted on a control module
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-control:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-control:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-control:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-control:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-control:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    interface: Annotated[
        Optional[List[InterfaceListEntry]],
        Field(alias='srl_nokia-platform-control:interface'),
    ] = None
    last_switchover_reason: Annotated[
        Optional[LastSwitchoverReasonContainer],
        Field(alias='srl_nokia-platform-control:last-switchover-reason'),
    ] = None
    rebooting_at: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-control:rebooting-at',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the date and time this component will reboot

    If empty, no delayed reboots are queued for this component.

    A non empty value implies that a delayed reboot operation has been triggered for this component, which can be aborted using 'tools platform <component> reboot cancel'.
    """
    software_version: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-control:software-version')
    ] = None
    """
    Image version version running on this component

    This version is the squashfs version, and may not represent the current per-application versions if versions have been modified after the system has been installed.
    """
    locator_state: Annotated[
        Optional[EnumerationEnum9],
        Field(alias='srl_nokia-platform-control:locator-state'),
    ] = 'inactive'
    """
    Details if the locator LED is active on this component
    """
    power: Annotated[
        Optional[PowerContainer2], Field(alias='srl_nokia-platform-control:power')
    ] = None
    temperature: Annotated[
        Optional[TemperatureContainer2],
        Field(alias='srl_nokia-platform-control:temperature'),
    ] = None
    forwarding_plane: Annotated[
        Optional[ForwardingPlaneContainer],
        Field(alias='srl_nokia-platform-control-fp:forwarding-plane'),
    ] = None
    cgroup: Annotated[
        Optional[List[CgroupListEntry]], Field(alias='srl_nokia-platform-cgroup:cgroup')
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer2], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None
    cpu: Annotated[
        Optional[List[CpuListEntry]], Field(alias='srl_nokia-platform-cpu:cpu')
    ] = None
    process: Annotated[
        Optional[List[ProcessListEntry]], Field(alias='srl_nokia-platform-cpu:process')
    ] = None
    disk: Annotated[
        Optional[List[DiskListEntry]], Field(alias='srl_nokia-platform-disk:disk')
    ] = None
    memory: Annotated[
        Optional[MemoryContainer], Field(alias='srl_nokia-platform-memory:memory')
    ] = None


class FibTableContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    next_hop_group: Annotated[
        Optional[List[NextHopGroupListEntry]],
        Field(alias='srl_nokia-platform-linecard-fib:next-hop-group'),
    ] = None
    programming_progress: Annotated[
        Optional[ProgrammingProgressContainer],
        Field(alias='srl_nokia-ip-route-tables:programming-progress'),
    ] = None


class QosContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    resource: Annotated[
        Optional[List[ResourceListEntry2]],
        Field(alias='srl_nokia-platform-qos:resource'),
    ] = None
    resource_set_pool: Annotated[
        Optional[List[ResourceSetPoolListEntry]],
        Field(alias='srl_nokia-platform-qos:resource-set-pool'),
    ] = None


class ForwardingComplexListEntry(BaseModel):
    """
    List of forwarding complexes on the linecard
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[EnumerationEnum6, Field(alias='srl_nokia-platform-lc:name')]
    """
    The identifier of the forwarding complex
    """
    interfaces: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-platform-lc:interfaces')
    ] = []
    """
    List of interfaces that belong to this forwarding complex
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-lc:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-lc:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    fabric: Annotated[
        Optional[FabricContainer], Field(alias='srl_nokia-platform-lc:fabric')
    ] = None
    pipeline: Annotated[
        Optional[List[PipelineListEntry]], Field(alias='srl_nokia-platform-lc:pipeline')
    ] = None
    control_plane_traffic: Annotated[
        Optional[ControlPlaneTrafficContainer],
        Field(alias='srl_nokia-platform-lc:control-plane-traffic'),
    ] = None
    drop_counters: Annotated[
        Optional[DropCountersContainer],
        Field(alias='srl_nokia-platform-lc:drop-counters'),
    ] = None
    fib_table: Annotated[
        Optional[FibTableContainer],
        Field(alias='srl_nokia-platform-linecard-fib:fib-table'),
    ] = None
    p4rt: Annotated[
        Optional[P4rtContainer], Field(alias='srl_nokia-platform-p4rt:p4rt')
    ] = None
    qos: Annotated[
        Optional[QosContainer], Field(alias='srl_nokia-platform-qos:qos')
    ] = None
    buffer_memory: Annotated[
        Optional[BufferMemoryContainer],
        Field(alias='srl_nokia-platform-qos:buffer-memory'),
    ] = None
    mtu: Annotated[
        Optional[MtuContainer], Field(alias='srl_nokia-platform-mtu:mtu')
    ] = None
    datapath: Annotated[
        Optional[DatapathContainer2],
        Field(alias='srl_nokia-platform-datapath-resources:datapath'),
    ] = None


class LinecardListEntry(BaseModel):
    """
    Top-level container for linecard configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot: Annotated[int, Field(alias='srl_nokia-platform-lc:slot', ge=1, le=16)]
    """
    Numeric identifier for the linecard
    """
    admin_state: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-platform-lc:admin-state')
    ] = 'enable'
    """
    The administrative state of this component
    """
    oper_state: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-platform-lc:oper-state')
    ] = None
    """
    The operational state of this component
    """
    last_booted: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:last-booted',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last booted

    For components that do not boot, this is the time the component was last discovered by the active control module
    """
    last_booted_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:last-booted-reason')
    ] = None
    """
    The reason this component last booted or rebooted

    For components without the ability to 'boot' this field is never populated
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time this component last changed state
    """
    part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:part-number')
    ] = None
    """
    Part number for this component
    """
    removable: Annotated[
        Optional[bool], Field(alias='srl_nokia-platform-lc:removable')
    ] = None
    """
    Details if this component can be removed from the system
    """
    failure_reason: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:failure-reason')
    ] = None
    """
    The reason the component transitioned to a failed state

    Field is empty if the component is not currently in a failure state
    """
    clei_code: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:clei-code')
    ] = None
    """
    The Common Language Identification Code for this component
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:serial-number')
    ] = None
    """
    The serial number for this component
    """
    manufactured_date: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:manufactured-date',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date this component was manufactured
    """
    rebooting_at: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-platform-lc:rebooting-at',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the date and time this component will reboot

    If empty, no delayed reboots are queued for this component.

    A non empty value implies that a delayed reboot operation has been triggered for this component, which can be aborted using 'tools platform <component> reboot cancel'.
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-platform-lc:type')] = None
    """
    Linecard type, as translated from the components EEPROM
    """
    forwarding_complex: Annotated[
        Optional[List[ForwardingComplexListEntry]],
        Field(alias='srl_nokia-platform-lc:forwarding-complex'),
    ] = None
    software_version: Annotated[
        Optional[str], Field(alias='srl_nokia-platform-lc:software-version')
    ] = None
    """
    Image version version running on this component

    This version is the squashfs version, and may not represent the current per-application versions if versions have been modified after the system has been installed.
    """
    locator_state: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-platform-lc:locator-state')
    ] = 'inactive'
    """
    Details if the locator LED is active on this component
    """
    power: Annotated[
        Optional[PowerContainer], Field(alias='srl_nokia-platform-lc:power')
    ] = None
    temperature: Annotated[
        Optional[TemperatureContainer], Field(alias='srl_nokia-platform-lc:temperature')
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None


class PlatformContainer(BaseModel):
    """
    Enclosing container for platform components
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trust: Annotated[
        Optional[TrustContainer], Field(alias='srl_nokia-platform:trust')
    ] = None
    linecard: Annotated[
        Optional[List[LinecardListEntry]], Field(alias='srl_nokia-platform-lc:linecard')
    ] = None
    control: Annotated[
        Optional[List[ControlListEntry3]],
        Field(alias='srl_nokia-platform-control:control'),
    ] = None
    redundancy: Annotated[
        Optional[RedundancyContainer],
        Field(alias='srl_nokia-platform-redundancy:redundancy'),
    ] = None
    resource_management: Annotated[
        Optional[ResourceManagementContainer],
        Field(alias='srl_nokia-platform-resource-mgmt:resource-management'),
    ] = None
    resource_monitoring: Annotated[
        Optional[ResourceMonitoringContainer],
        Field(alias='srl_nokia-platform-resource-monitoring:resource-monitoring'),
    ] = None
    chassis: Annotated[
        Optional[ChassisContainer], Field(alias='srl_nokia-platform-chassis:chassis')
    ] = None
    fabric: Annotated[
        Optional[List[FabricListEntry]], Field(alias='srl_nokia-platform-fabric:fabric')
    ] = None
    fan_tray: Annotated[
        Optional[List[FanTrayListEntry]], Field(alias='srl_nokia-platform-fan:fan-tray')
    ] = None
    power_supply: Annotated[
        Optional[List[PowerSupplyListEntry]],
        Field(alias='srl_nokia-platform-psu:power-supply'),
    ] = None
    vxdp: Annotated[
        Optional[VxdpContainer], Field(alias='srl_nokia-platform-vxdp:vxdp')
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
    platform: Annotated[
        Optional[PlatformContainer], Field(alias='srl_nokia-platform:platform')
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