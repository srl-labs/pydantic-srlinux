from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class AgingLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]
    """
    remaining age time for learnt macs
    """


class DomainNameType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^((([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)|\\.$).*$'
        ),
    ]
    """
    The domain-name type represents a DNS domain name.  The
    name SHOULD be fully qualified whenever possible.

    Internet domain names are only loosely specified.  Section
    3.5 of RFC 1034 recommends a syntax (modified in Section
    2.1 of RFC 1123).  The pattern above is intended to allow
    for current practice in domain name use, and some possible
    future expansion.  It is designed to hold various types of
    domain names, including names used for A or AAAA records
    (host names) and other records, such as SRV records.  Note
    that Internet host names have a stricter syntax (described
    in RFC 952) than the DNS recommendations in RFCs 1034 and
    1123, and that systems that want to store host names in
    schema nodes using the domain-name type are recommended to
    adhere to this stricter standard to ensure interoperability.

    The encoding of DNS names in the DNS protocol is limited
    to 255 characters.  Since the encoding consists of labels
    prefixed by a length bytes and there is a trailing NULL
    byte, only 253 characters can appear in the textual dotted
    notation.

    The description clause of schema nodes using the domain-name
    type MUST describe when and how these names are resolved to
    IP addresses.  Note that the resolution of a domain-name value
    may require to query multiple DNS records (e.g., A for IPv4
    and AAAA for IPv6).  The order of the resolution process and
    which DNS record takes precedence can either be defined
    explicitly or may depend on the configuration of the
    resolver.

    Domain-name values use the US-ASCII encoding.  Their canonical
    format uses lowercase US-ASCII characters.  Internationalized
    domain names MUST be A-labels as per RFC 5890.
    """


class FailedSlotsLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=16)]
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class HoldDownTimeRemainingLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]
    """
    remaining hold down time for duplicate mac
    """


class LastFailedComplexesLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str, Field(pattern='^(?=^(\\(([0-9]|[1][0-9]|[2][0-4]),[0-1]\\))$).*$')
    ]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class LastFailedComplexesLeafList2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str, Field(pattern='^(?=^(\\(([0-9]|[1][0-9]|[2][0-4]),[0-1]\\))$).*$')
    ]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class LastReportedDynamicDelayLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=2147483647)]
    """
    Indicates the last delay measurement reported to the routing engine
    """


class LinuxContainer(BaseModel):
    """
    Top-level container for configuration and state related to Linux interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    device_name: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-vxdp:device-name', max_length=10, min_length=0
        ),
    ] = None
    """
    Slow path device name of this interface in Linux

    This is the interface name that can be used to look at this interface within Linux.

    If not specified it is auto-derived by the system.
    """


class OpticalSignalToNoiseRatioContainer(BaseModel):
    """
    Enter the optical-signal-to-noise-ratio context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Current SNR received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Average SNR received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Minimum SNR received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Maximum SNR received on the optical channel
    """


class PhysicalChannelLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=10)]
    """
    The list of transceiver channels associated with this port
    """


class PolarizationDependentLossContainer(BaseModel):
    """
    Enter the polarization-dependent-loss context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the current Polarization Dependent Loss received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the average Polarization Dependent Loss received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the minimum Polarization Dependent Loss received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the maximum Polarization Dependent Loss received on the optical channel
    """


class PowerContainer(BaseModel):
    """
    Enter the power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current power received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Average power received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Minimum power received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Maximum power received on the optical channel
    """


class PowerContainer2(BaseModel):
    """
    Enter the power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current power transmitted on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Average power transmitted on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Minimum power transmitted on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Maximum power transmitted on the optical channel
    """


class PreferredLifetimeLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    The length of time in seconds (relative to the time the packet is sent) that addresses generated from the prefix via stateless address autoconfiguration remain preferred.
    """


class PrimaryLeaf(BaseModel):
    """
    One of the IPv4 prefixes assigned to the subinterface can be explicitly configured as primary by setting this leaf to true. This designates the associated IPv4 address as a primary IPv4 address of the subinterface. By default, the numerically lowest value IPv4 address is selected as the primary address.

    The primary address is used as the source address for locally originated broadcast and multicast packets sent out the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class PrimaryLeaf2(BaseModel):
    """
    One of the IPv6 prefixes assigned to the subinterface can be explicitly configured as primary by setting this leaf to true. This designates the associated IPv6 address as a primary IPv6 address of the subinterface. By default, the numerically lowest value IPv6 address is selected as the primary address.

    The primary address is used as the source address for locally originated broadcast and multicast packets sent out the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class PtpTimestampingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    disable_ip_timestamping: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:disable-ip-timestamping')
    ] = None
    """
    Disables timestamping of PTP over IP messages on this port

    For platforms supporting PTP functionality, any transiting PTP over IP packets are timestamped in hardware by default, regardless of whether PTP is enabled on the system. To avoid unwanted correction-field updates of PTP transit packets on ports (ports involved in PTP packet transit only), this command can be used to disabled the timestmaping.
    """


class QualityContainer(BaseModel):
    """
    Enter the quality context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Current quality received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Average quality received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Minimum quality received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Maximum quality received on the optical channel
    """


class SignalDegradeContainer(BaseModel):
    """
    Signal-degrade parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    exponent: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:exponent', ge=1, le=9)
    ] = 5
    """
    Signal-degrade exponent
    """
    multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:multiplier', ge=1, le=9)
    ] = 1
    """
    Signal-degrade multiplier
    """


class SignalDegradeContainer2(BaseModel):
    """
    Signal-degrade parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    exponent: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:exponent', ge=1, le=9)
    ] = 5
    """
    Signal-degrade exponent
    """
    multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:multiplier', ge=1, le=9)
    ] = 1
    """
    Signal-degrade multiplier
    """


class SignalFailureContainer(BaseModel):
    """
    Signal-failure parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    exponent: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:exponent', ge=1, le=9)
    ] = 5
    """
    Signal-failure exponent
    """
    multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:multiplier', ge=1, le=9)
    ] = 1
    """
    Signal-failure multiplier
    """


class SignalFailureContainer2(BaseModel):
    """
    Signal-failure parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    exponent: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:exponent', ge=1, le=9)
    ] = 5
    """
    Signal-failure exponent
    """
    multiplier: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:multiplier', ge=1, le=9)
    ] = 1
    """
    Signal-failure multiplier
    """


class SocketCpusLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=65535)]
    """
    List of CPUs present on the socket this interface is attached to
    """


class SocketCpusLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=65535)]
    """
    List of CPUs present on the socket this interface is attached to
    """


class StateOfPolarizationRateOfChangeContainer(BaseModel):
    """
    Enter the state-of-polarization-rate-of-change context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the current SOP-ROC received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the average SOP-ROC received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the minimum SOP-ROC received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the maximum SOP-ROC received on the optical channel
    """


class StaticDelayLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=16777215)]
    """
    A statically configured unidirectional delay value that can be advertised as an interface attribute by an IGP
    """


class SweepContainer(BaseModel):
    """
    Enter the sweep context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    start: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:start', ge=-50000, le=50000),
    ] = -25500
    """
    Lower bound of the dispersion compensation range
    """
    end: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-dco:end', ge=-50000, le=50000)
    ] = 2000
    """
    Upper bound of the dispersion compensation range
    """


class TotalPowerContainer(BaseModel):
    """
    Enter the total-power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the current total power received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the average total power received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the minimum total power received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Indicates the maximum total power received on the optical channel
    """


class TrafficRateContainer(BaseModel):
    """
    Container for traffic rate statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_bps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-bps', ge=0, le=18446744073709551615),
    ] = None
    """
    The ingress bandwidth utilization of the port
    """
    out_bps: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-bps', ge=0, le=18446744073709551615),
    ] = None
    """
    The egress bandwidth utilization of the port
    """


class TransmitPowerContainer(BaseModel):
    """
    Enter the transmit-power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Minimum configurable transmit power for the equipped optical module
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Maximum configurable transmit power for the equipped optical module
    """


class TransmittedContainer(BaseModel):
    """
    Enter the transmitted context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    power: Annotated[
        Optional[PowerContainer2], Field(alias='srl_nokia-interfaces-dco:power')
    ] = None


class UntaggedContainer(BaseModel):
    """
    When present, untagged frames and VLAN ID 0 priority tagged frames are associated to the subinterface when it belongs to an interface with vlan-tagging enabled
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class ValidLifetimeLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for the purpose of on-link determination. 
    """


class VlanIdType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=4094)]
    """
    Type definition representing a single-tagged VLAN
    """


class VlanListListEntry(BaseModel):
    """
    List of VLAN IDs that the RA policy should be matched against
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vlan_id: Annotated[int, Field(alias='srl_nokia-ra_guard:vlan-id', ge=0, le=4095)]


class VoltageContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    latest_value: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:latest-value',
            ge=-922337203685477.6,
            le=922337203685477.6,
        ),
    ] = None
    """
    The current voltage reading of the transceiver module (in Volts)
    """
    high_alarm_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:high-alarm-condition')
    ] = None
    """
    High alarm threshold condition.

    Set to true whenever the module voltage is above the high-alarm-threshold and set to false whenever the module voltage is below the high-alarm-threshold
    """
    high_alarm_threshold: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:high-alarm-threshold',
            ge=-922337203685477.6,
            le=922337203685477.6,
        ),
    ] = None
    """
    High alarm threshold.

    Read from the installed transceiver
    """
    low_alarm_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:low-alarm-condition')
    ] = None
    """
    Low alarm threshold condition.

    Set to true whenever the module voltage is below the low-alarm-threshold and set to false whenever the module voltage is above the low-alarm-threshold
    """
    low_alarm_threshold: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:low-alarm-threshold',
            ge=-922337203685477.6,
            le=922337203685477.6,
        ),
    ] = None
    """
    Low alarm threshold.

    Read from the installed transceiver
    """
    high_warning_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:high-warning-condition')
    ] = None
    """
    High warning threshold condition.

    Set to true whenever the module voltage is above the high-warning-threshold and set to false whenever the module voltage is below the high-warning-threshold
    """
    high_warning_threshold: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:high-warning-threshold',
            ge=-922337203685477.6,
            le=922337203685477.6,
        ),
    ] = None
    """
    High warning threshold.

    Read from the installed transceiver
    """
    low_warning_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:low-warning-condition')
    ] = None
    """
    Low warning threshold condition.

    Set to true whenever the module voltage is below the low-warning-threshold and set to false whenever the module voltage is above the low-warning-threshold
    """
    low_warning_threshold: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:low-warning-threshold',
            ge=-922337203685477.6,
            le=922337203685477.6,
        ),
    ] = None
    """
    Low warning threshold .

    Read from the installed transceiver
    """


class EnumerationEnum(Enum):
    enable = 'enable'
    disable = 'disable'


class EnumerationEnum10(Enum):
    not_present = 'not-present'
    read_failure = 'read-failure'
    checksum_failure = 'checksum-failure'
    unknown_transceiver = 'unknown-transceiver'
    tx_laser_disabled = 'tx-laser-disabled'
    unsupported_breakout = 'unsupported-breakout'
    port_disabled = 'port-disabled'
    connector_transceiver_down = 'connector-transceiver-down'
    unsupported_operational_mode = 'unsupported-operational-mode'
    no_tunable_config = 'no-tunable-config'


class EnumerationEnum11(Enum):
    cfp2 = 'CFP2'
    cfp2_aco = 'CFP2-ACO'
    cfp4 = 'CFP4'
    qsfp = 'QSFP'
    qsf_pplus = 'QSFPplus'
    qsfp28 = 'QSFP28'
    qsfpdd = 'QSFPDD'
    sfp = 'SFP'
    sf_pplus = 'SFPplus'
    non_pluggable = 'Non-pluggable'
    other = 'Other'
    sfp28 = 'SFP28'
    sfpdd = 'SFPDD'
    qsfp56 = 'QSFP56'
    sfp56 = 'SFP56'


class EnumerationEnum12(Enum):
    sc = 'SC'
    fc_style1_copper = 'FC-STYLE1-COPPER'
    fc_style2_copper = 'FC-STYLE2-COPPER'
    bnc_or_tnc = 'BNC-OR-TNC'
    fc_coax = 'FC-COAX'
    fiber_jack = 'FIBER-JACK'
    lc = 'LC'
    mt_rj = 'MT-RJ'
    mu = 'MU'
    sg = 'SG'
    optical_pigtail = 'OPTICAL-PIGTAIL'
    mpo_1x12 = 'MPO-1x12'
    mpo_2x16 = 'MPO-2x16'
    hssdc = 'HSSDC'
    copper_pigtail = 'COPPER-PIGTAIL'
    rj45 = 'RJ45'
    no_separable_connector = 'no-separable-connector'
    mxc_2x16 = 'MXC-2x16'
    cs_optical_connector = 'CS-OPTICAL-CONNECTOR'
    sn_optical_connector = 'SN-OPTICAL-CONNECTOR'
    mpo_2x12 = 'MPO-2x12'
    mpo_1x16 = 'MPO-1x16'
    unknown = 'unknown'


class EnumerationEnum13(Enum):
    unspecified = 'unspecified'
    healthy = 'healthy'
    unhealthy = 'unhealthy'


class EnumerationEnum14(Enum):
    field_21 = '21'
    field_22 = '22'
    field_25 = '25'
    field_33 = '33'
    field_37 = '37'
    field_43 = '43'
    field_51 = '51'
    field_61 = '61'
    field_65 = '65'
    field_69 = '69'
    field_81 = '81'
    field_82 = '82'
    field_83 = '83'
    field_85 = '85'
    field_88 = '88'
    field_169 = '169'


class EnumerationEnum15(Enum):
    unequipped = 'unequipped'
    not_tunable = 'not-tunable'
    fully_tunable = 'fully-tunable'
    tunable_100g = 'tunable-100g'
    flex_tunable = 'flex-tunable'


class EnumerationEnum16(Enum):
    grid_100_ghz = 'grid-100-ghz'
    grid_75_ghz = 'grid-75-ghz'
    grid_50_ghz = 'grid-50-ghz'
    grid_33_ghz = 'grid-33-ghz'
    grid_25_ghz = 'grid-25-ghz'
    grid_12500_mhz = 'grid-12500-mhz'
    grid_6250_mhz = 'grid-6250-mhz'
    grid_3125_mhz = 'grid-3125-mhz'


class EnumerationEnum17(Enum):
    automatic = 'automatic'
    manual = 'manual'


class EnumerationEnum18(Enum):
    none = 'none'
    squelch = 'squelch'


class EnumerationEnum19(Enum):
    reset = 'reset'
    init = 'init'
    low_power = 'low-power'
    high_power_up = 'high-power-up'
    high_power_down = 'high-power-down'
    tx_off = 'tx-off'
    tx_turn_off = 'tx-turn-off'
    tx_turn_on = 'tx-turn-on'
    ready = 'ready'
    fault = 'fault'


class EnumerationEnum2(Enum):
    field_1 = '1'
    field_2 = '2'
    field_3 = '3'
    field_4 = '4'
    field_8 = '8'


class EnumerationEnum20(Enum):
    init = 'init'
    laser_turn_up = 'laser-turn-up'
    laser_ready_off = 'laser-ready-off'
    laser_ready = 'laser-ready'
    modulator_converge = 'modulator-converge'
    output_power_adjust = 'output-power-adjust'


class EnumerationEnum21(Enum):
    init = 'init'
    laser_ready = 'laser-ready'
    wait_for_input = 'wait-for-input'
    adc_signal = 'adc-signal'
    optical_lock = 'optical-lock'
    demod_lock = 'demod-lock'


class EnumerationEnum22(Enum):
    module_fault = 'module-fault'
    module_alarm = 'module-alarm'
    media_receive_alarm = 'media-receive-alarm'
    media_transmit_alarm = 'media-transmit-alarm'
    host_transmit_alarm = 'host-transmit-alarm'


class EnumerationEnum23(Enum):
    over_temp = 'over-temp'
    hw_post = 'hw-post'
    pld_flash_init = 'pld-flash-init'
    power_supply = 'power-supply'
    check_sum = 'check-sum'
    ref_clock_in = 'ref-clock-in'
    tx_jit_pll_lol = 'tx-jit-pll-lol'
    tx_cmu_lol = 'tx-cmu-lol'
    tx_loss_func = 'tx-loss-func'
    host_tx_lol = 'host-tx-lol'
    net_rx_lol = 'net-rx-lol'
    host_tx_skew_high = 'host-tx-skew-high'
    net_tx_tec = 'net-tx-tec'
    net_tx_wave_unlk = 'net-tx-wave-unlk'
    net_tx_losf = 'net-tx-losf'
    net_rx_los = 'net-rx-los'
    net_rx_fifo_err = 'net-rx-fifo-err'
    net_rx_tec = 'net-rx-tec'
    net_tx_out_of_align = 'net-tx-out-of-align'
    net_tx_cmu_lock = 'net-tx-cmu-lock'
    net_tx_ref_clk = 'net-tx-ref-clk'
    net_rx_modem_sync_det = 'net-rx-modem-sync-det'
    net_rx_modem_lock = 'net-rx-modem-lock'
    host_tx_lane_fifo_err = 'host-tx-lane-fifo-err'
    host_tx_deskew = 'host-tx-deskew'
    host_rx_corr = 'host-rx-corr'
    host_rx_uncorr = 'host-rx-uncorr'
    comm_fail = 'comm-fail'


class EnumerationEnum24(Enum):
    full = 'full'
    half = 'half'


class EnumerationEnum25(Enum):
    field_10_m = '10M'
    field_100_m = '100M'
    field_1_g = '1G'
    field_10_g = '10G'
    field_25_g = '25G'
    field_40_g = '40G'
    field_50_g = '50G'
    field_100_g = '100G'
    field_200_g = '200G'
    field_400_g = '400G'
    field_800_g = '800G'
    field_1_t = '1T'


class EnumerationEnum26(Enum):
    field_1000_base_t = '1000BASE-T'


class EnumerationEnum27(Enum):
    power_off = 'power-off'
    lacp = 'lacp'


class EnumerationEnum28(Enum):
    none = 'none'
    sd_threshold_exceeded = 'sd-threshold-exceeded'
    sf_threshold_exceeded = 'sf-threshold-exceeded'


class EnumerationEnum29(Enum):
    active = 'active'
    idle = 'idle'


class EnumerationEnum3(Enum):
    field_10_g = '10G'
    field_25_g = '25G'
    field_50_g = '50G'
    field_100_g = '100G'
    field_200_g = '200G'
    field_400_g = '400G'


class EnumerationEnum30(Enum):
    kbps = 'kbps'
    percentage = 'percentage'


class EnumerationEnum31(Enum):
    none = 'none'
    trigger_event = 'trigger-event'
    disable_interface = 'disable-interface'


class EnumerationEnum32(Enum):
    force_unauthorized = 'force-unauthorized'
    auto = 'auto'
    force_authorized = 'force-authorized'


class EnumerationEnum33(Enum):
    single_host = 'single-host'
    multi_host = 'multi-host'
    multi_domain = 'multi-domain'


class EnumerationEnum34(Enum):
    authenticated = 'AUTHENTICATED'
    authenticating = 'AUTHENTICATING'
    failed_authentication = 'FAILED_AUTHENTICATION'
    supplicant_timeout = 'SUPPLICANT_TIMEOUT'


class EnumerationEnum35(Enum):
    trap_to_cpu_untagged = 'trap-to-cpu-untagged'
    drop_tagged_and_untagged = 'drop-tagged-and-untagged'
    tunnel_tagged_and_untagged = 'tunnel-tagged-and-untagged'
    tunnel_tagged_drop_untagged = 'tunnel-tagged-drop-untagged'
    tunnel_tagged_trap_to_cpu_untagged = 'tunnel-tagged-trap-to-cpu-untagged'


class EnumerationEnum36(Enum):
    none = 'none'


class EnumerationEnum37(Enum):
    none = 'none'


class EnumerationEnum38(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum39(Enum):
    admin_disabled = 'admin-disabled'
    port_down = 'port-down'
    ip_mtu_resource_exceeded = 'ip-mtu-resource-exceeded'
    mpls_mtu_resource_exceeded = 'mpls-mtu-resource-exceeded'
    ip_mtu_too_large = 'ip-mtu-too-large'
    mpls_mtu_too_large = 'mpls-mtu-too-large'
    l2_mtu_too_large = 'l2-mtu-too-large'
    no_ip_config = 'no-ip-config'
    ip_mtu_larger_than_oper_mac_vrf_mtu = 'ip-mtu-larger-than-oper-mac-vrf-mtu'
    irb_mac_address_not_programmed = 'irb-mac-address-not-programmed'
    missing_xdp_state = 'missing-xdp-state'
    no_underlay_egress_next_hop_resources = 'no-underlay-egress-next-hop-resources'
    cfm_ccm_defect = 'cfm-ccm-defect'
    no_irb_hardware_resources = 'no-irb-hardware-resources'
    other = 'other'


class EnumerationEnum4(Enum):
    up = 'up'
    down = 'down'
    testing = 'testing'


class EnumerationEnum40(Enum):
    other = 'other'
    static = 'static'
    dhcp = 'dhcp'
    link_layer = 'link-layer'
    random = 'random'


class EnumerationEnum41(Enum):
    preferred = 'preferred'
    inaccessible = 'inaccessible'
    tentative = 'tentative'
    duplicate = 'duplicate'


class EnumerationEnum42(Enum):
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


class EnumerationEnum43(Enum):
    admin_down = 'admin-down'
    sub_intf_down = 'sub-intf-down'
    virtual_ip_mismatch = 'virtual-ip-mismatch'
    authentication_config = 'authentication-config'
    other = 'other'


class EnumerationEnum44(Enum):
    not_same_network_instance = 'not-same-network-instance'
    referenced_interface_is_down = 'referenced-interface-is-down'
    referenced_interface_ipv4_is_down = 'referenced-interface-ipv4-is-down'
    referenced_interface_has_no_ipv4_addresses = (
        'referenced-interface-has-no-ipv4-addresses'
    )


class EnumerationEnum45(Enum):
    other = 'other'
    static = 'static'
    dynamic = 'dynamic'
    evpn = 'evpn'


class EnumerationEnum46(Enum):
    success = 'success'
    failed = 'failed'
    pending = 'pending'


class EnumerationEnum47(Enum):
    static = 'static'
    dynamic = 'dynamic'
    evpn = 'evpn'


class EnumerationEnum48(Enum):
    messages = 'messages'


class EnumerationEnum49(Enum):
    static = 'static'
    dynamic = 'dynamic'


class EnumerationEnum5(Enum):
    port_admin_disabled = 'port-admin-disabled'
    mda_admin_disabled = 'mda-admin-disabled'
    transceiver_oper_down = 'transceiver-oper-down'
    port_not_present = 'port-not-present'
    mda_not_present = 'mda-not-present'
    phy_initializing = 'phy-initializing'
    lower_layer_down = 'lower-layer-down'
    auto_negotiation_mismatch = 'auto-negotiation-mismatch'
    port_mtu_resource_exceeded = 'port-mtu-resource-exceeded'
    unsupported_speed = 'unsupported-speed'
    unsupported_fec = 'unsupported-fec'
    other = 'other'
    fabric_availability = 'fabric-availability'
    no_active_links = 'no-active-links'
    min_link_threshold = 'min-link-threshold'
    port_9_12_speed_mismatch = 'port-9-12-speed-mismatch'
    lag_resource_exceeded = 'lag-resource-exceeded'
    lag_member_resource_exceeded = 'lag-member-resource-exceeded'
    standby_signaling = 'standby-signaling'
    interface_hold_time_up_active = 'interface-hold-time-up-active'
    interface_reload_timer_active = 'interface-reload-timer-active'
    connector_down = 'connector-down'
    event_handler = 'event-handler'
    unsupported_breakout_port = 'unsupported-breakout-port'
    cfm_ccm_defect = 'cfm-ccm-defect'
    crc_monitor_fail_threshold = 'crc-monitor-fail-threshold'
    symbol_monitor_fail_threshold = 'symbol-monitor-fail-threshold'
    link_loss_forwarding = 'link-loss-forwarding'
    storm_control_action = 'storm-control-action'
    unsupported_num_channels_for_speed = 'unsupported-num-channels-for-speed'


class EnumerationEnum50(Enum):
    dhcp_relay_admin_down = 'dhcp-relay-admin-down'
    sub_interface_oper_down = 'sub-interface-oper-down'
    all_dhcp_servers_unreachable_within_net_instance = (
        'all-dhcp-servers-unreachable-within-net-instance'
    )
    gi_address_not_matching_relay_sub_interface_ipv4_addresses = (
        'gi-address-not-matching-relay-sub-interface-ipv4-addresses'
    )
    no_valid_ipv4_address_on_sub_interface = 'no-valid-ipv4-address-on-sub-interface'


class EnumerationEnum51(Enum):
    circuit_id = 'circuit-id'
    remote_id = 'remote-id'


class EnumerationEnum52(Enum):
    messages = 'messages'


class EnumerationEnum53(Enum):
    messages = 'messages'


class EnumerationEnum54(Enum):
    global_unicast = 'global-unicast'
    link_local_unicast = 'link-local-unicast'


class EnumerationEnum55(Enum):
    preferred = 'preferred'
    deprecated = 'deprecated'
    invalid = 'invalid'
    inaccessible = 'inaccessible'
    unknown = 'unknown'
    tentative = 'tentative'
    duplicate = 'duplicate'
    optimistic = 'optimistic'


class EnumerationEnum56(Enum):
    none = 'none'
    global_ = 'global'
    link_local = 'link-local'
    both = 'both'


class EnumerationEnum57(Enum):
    incomplete = 'incomplete'
    reachable = 'reachable'
    stale = 'stale'
    delay = 'delay'
    probe = 'probe'


class EnumerationEnum58(Enum):
    success = 'success'
    failed = 'failed'
    pending = 'pending'


class EnumerationEnum59(Enum):
    static = 'static'
    dynamic = 'dynamic'
    evpn = 'evpn'


class EnumerationEnum6(Enum):
    field_0 = '0'
    field_1 = '1'


class EnumerationEnum60(Enum):
    messages = 'messages'


class EnumerationEnum61(Enum):
    static = 'static'
    dynamic = 'dynamic'


class EnumerationEnum62(Enum):
    dhcp_relay_admin_down = 'dhcp-relay-admin-down'
    sub_interface_oper_down = 'sub-interface-oper-down'
    all_dhcpv6_servers_unreachable_within_net_instance = (
        'all-dhcpv6-servers-unreachable-within-net-instance'
    )
    source_address_not_matching_relay_sub_interface_ipv6_addresses = (
        'source-address-not-matching-relay-sub-interface-ipv6-addresses'
    )
    no_valid_ipv6_address_on_sub_interface = 'no-valid-ipv6-address-on-sub-interface'


class EnumerationEnum63(Enum):
    interface_id = 'interface-id'
    remote_id = 'remote-id'
    client_link_layer_address = 'client-link-layer-address'


class EnumerationEnum64(Enum):
    messages = 'messages'


class EnumerationEnum65(Enum):
    infinite = 'infinite'


class EnumerationEnum66(Enum):
    infinite = 'infinite'


class EnumerationEnum67(Enum):
    messages = 'messages'


class EnumerationEnum68(Enum):
    messages = 'messages'


class EnumerationEnum69(Enum):
    configured = 'configured'
    vrid_auto_derived = 'vrid-auto-derived'


class EnumerationEnum7(Enum):
    store_and_forward = 'store-and-forward'
    cut_through = 'cut-through'


class EnumerationEnum70(Enum):
    disabled = 'disabled'


class EnumerationEnum71(Enum):
    use_net_instance_action = 'use-net-instance-action'
    stop_learning = 'stop-learning'
    blackhole = 'blackhole'
    oper_down = 'oper-down'


class EnumerationEnum72(Enum):
    indefinite = 'indefinite'


class EnumerationEnum73(Enum):
    yes = 'yes'
    no = 'no'


class EnumerationEnum74(Enum):
    yes = 'yes'
    no = 'no'


class EnumerationEnum75(Enum):
    shared = 'shared'
    pt_pt = 'pt-pt'


class EnumerationEnum76(Enum):
    yes = 'yes'
    no = 'no'


class EnumerationEnum77(Enum):
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


class EnumerationEnum78(Enum):
    mac_limit = 'mac-limit'
    failed_on_slots = 'failed-on-slots'
    no_destination_index = 'no-destination-index'
    reserved = 'reserved'


class EnumerationEnum79(Enum):
    i_pv4 = 'IPv4'
    i_pv6 = 'IPv6'
    i_pv4v6 = 'IPv4v6'


class EnumerationEnum8(Enum):
    unknown = 'unknown'
    qsfp28_to_sfp__sfp28 = 'qsfp28-to-sfp+/sfp28'
    cfp_to_qsfp28 = 'cfp-to-qsfp28'


class EnumerationEnum80(Enum):
    optional = 'optional'
    any = 'any'


class EnumerationEnum81(Enum):
    any = 'any'
    optional = 'optional'


class EnumerationEnum82(Enum):
    any = 'any'
    optional = 'optional'


class EnumerationEnum83(Enum):
    push = 'PUSH'
    pop = 'POP'
    swap = 'SWAP'
    preserve = 'PRESERVE'
    push_push = 'PUSH-PUSH'
    pop_pop = 'POP-POP'
    pop_swap = 'POP-SWAP'
    swap_swap = 'SWAP-SWAP'


class EnumerationEnum84(Enum):
    unspecified = 'unspecified'
    error = 'error'
    idle = 'idle'
    setup = 'setup'
    running = 'running'
    teardown = 'teardown'
    completed = 'completed'


class EnumerationEnum85(Enum):
    not_found = 'not-found'
    invalid_argument = 'invalid-argument'
    canceled = 'canceled'
    deadline_exceeded = 'deadline-exceeded'
    failed_precondition = 'failed-precondition'
    internal = 'internal'


class EnumerationEnum86(Enum):
    lacp = 'lacp'
    static = 'static'


class EnumerationEnum87(Enum):
    field_10_m = '10M'
    field_100_m = '100M'
    field_1_g = '1G'
    field_10_g = '10G'
    field_25_g = '25G'
    field_40_g = '40G'
    field_50_g = '50G'
    field_100_g = '100G'
    field_400_g = '400G'


class EnumerationEnum88(Enum):
    static = 'static'


class EnumerationEnum89(Enum):
    port_disabled = 'port-disabled'
    port_oper_disabled = 'port-oper-disabled'
    lag_admin_disabled = 'lag-admin-disabled'
    lacp_down = 'lacp-down'
    micro_bfd_down = 'microBFD-down'
    lag_min_link_threshold = 'lag-min-link-threshold'
    lag_speed_mismatch = 'lag-speed-mismatch'
    other = 'other'


class EnumerationEnum9(Enum):
    up = 'up'
    down = 'down'


class EnumerationEnum90(Enum):
    active = 'ACTIVE'
    passive = 'PASSIVE'


class EnumerationEnum91(Enum):
    long = 'LONG'
    short = 'SHORT'


class EnumerationEnum92(Enum):
    in_sync = 'IN_SYNC'
    out_sync = 'OUT_SYNC'


class EnumerationEnum93(Enum):
    fast = 'FAST'
    slow = 'SLOW'


class EnumerationEnum94(Enum):
    server = 'server'
    client = 'client'


class AllowedMacsLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$')]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """


class AllowedMacsLeafList2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$')]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """


class BitErrorRateContainer(BaseModel):
    """
    Enter the bit-error-rate context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776,
            le=9.223372036854776,
        ),
    ] = None
    """
    Current BER received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776,
            le=9.223372036854776,
        ),
    ] = None
    """
    Average BER received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776,
            le=9.223372036854776,
        ),
    ] = None
    """
    Minimum BER received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776,
            le=9.223372036854776,
        ),
    ] = None
    """
    Maximum BER received on the optical channel
    """


class ChannelListEntry(BaseModel):
    """
    List of physical channels supported by the transceiver associated with this port
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-interfaces:index', ge=1, le=10)]
    """
    Index of the physical channel or lane
    """
    wavelength: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:wavelength',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Wavelength of the transmitting laser in nanometers
    """


class ChromaticDispersionRangeContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    minimum: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-dco:minimum', ge=-100000, le=0)
    ] = None
    """
    Chromatic dispersion sweep range minimum

    This has different defaults based on the setting of the operational-mode.  This value is usually a large negative number
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:maximum', ge=-100000, le=100000),
    ] = None
    """
    Chromatic dispersion sweep range maximum

    This has different defaults based on the setting of the operational-mode.
    """


class ChromaticDispersionContainer(BaseModel):
    """
    Enter the chromatic-dispersion context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:current', ge=-2147483648, le=2147483647),
    ] = None
    """
    Current chromatic dispersion received on the optical channel
    """
    average: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:average', ge=-2147483648, le=2147483647),
    ] = None
    """
    Average chromatic dispersion received on the optical channel
    """
    minimum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:minimum', ge=-2147483648, le=2147483647),
    ] = None
    """
    Minimum chromatic dispersion received on the optical channel
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:maximum', ge=-2147483648, le=2147483647),
    ] = None
    """
    Maximum chromatic dispersion received on the optical channel
    """


class DifferentialGroupDelayContainer(BaseModel):
    """
    Enter the differential-group-delay context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Current differential group delay received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Average differential group delay received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Minimum differential group delay received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Maximum differential group delay received on the optical channel
    """


class ElectricalSignalToNoiseRatioContainer(BaseModel):
    """
    Enter the electrical-signal-to-noise-ratio context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:current',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Current SNR received on the optical channel
    """
    average: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:average',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Average SNR received on the optical channel
    """
    minimum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:minimum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Minimum SNR received on the optical channel
    """
    maximum: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:maximum',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Maximum SNR received on the optical channel
    """


class FineTuningContainer(BaseModel):
    """
    State related to fine-tuning
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    range: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:range', ge=0, le=4294967295),
    ] = None
    """
    The positive or negative offset that can be applied when using frequency fine tuning

    The offset is from a frequency of one of the grids supported by the equipped optical module.
    """
    resolution: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:resolution', ge=0, le=4294967295),
    ] = None
    """
    The resolution that can be used for frequency fine tuning.
    """


class FirmwareVersionContainer(BaseModel):
    """
    Active firmware version

    This is the information as read from the EEPROM of the part.
    This is only available for digital coherent optic transceivers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    major_revision: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:major-revision', ge=0, le=255)
    ] = None
    """
    Major revision number
    """
    minor_revision: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:minor-revision', ge=0, le=255)
    ] = None
    """
    Minor revision number
    """


class FlowControlContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    receive: Annotated[Optional[bool], Field(alias='srl_nokia-interfaces:receive')] = (
        None
    )
    """
    When this is true PAUSE frames received on this interface are accepted and processed, and, if auto-negotiation is enabled it also causes the capability to receive PAUSE frames to be signaled to the peer (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports).

    When this is false PAUSE frames received on this interface are ignored, and, if auto-negotiation is enabled it causes the capability to receive PAUSE frames to be signaled to the peer as non-support (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports)
    """
    transmit: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:transmit')
    ] = None
    """
    Enables/disables the sending of PAUSE frames.

    If auto-negotiation is enabled (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports) PAUSE frames are sent to the peer only if the peer advertised support for PAUSE frames.
    """


class FrequencyOffsetContainer(BaseModel):
    """
    Enter the frequency-offset context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:current', ge=-2147483648, le=2147483647),
    ] = None
    """
    Current frequency offset received on the optical channel
    """
    average: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:average', ge=-2147483648, le=2147483647),
    ] = None
    """
    Average frequency offset received on the optical channel
    """
    minimum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:minimum', ge=-2147483648, le=2147483647),
    ] = None
    """
    Minimum frequency offset received on the optical channel
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:maximum', ge=-2147483648, le=2147483647),
    ] = None
    """
    Maximum frequency offset received on the optical channel
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


class LimitContainer(BaseModel):
    """
    Container for the configuration of Neighbor-Discovery limit
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    max_entries: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-nbr:max-entries', ge=0, le=4294967295),
    ] = None
    """
    The maximum number of neighbor entries allowed on the subinterface

    If not configured, the amount of neighbor entries on the subinterface
    is only limited by the total amount of entries supported by the router.
    """
    log_only: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:log-only')
    ] = False
    """
    Generate only a log message when limit is reached

    When set to true, neighbor entries are still being learned after
    exceeding the max-entries limit.
    """
    warning_threshold_pct: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-nbr:warning-threshold-pct', ge=1, le=100),
    ] = 90
    """
    Threshold percentage of the configured maximum number of entries

    When exceeded, an event is triggered.
    """


class MacAddressListEntry(BaseModel):
    """
    Add a list entry for source mac-address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        str,
        Field(
            alias='srl_nokia-dot1x:mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    Source MAC address of a host that is authorized to use this interface
    """


class MacLimitContainer(BaseModel):
    """
    Bridge Table size and thresholds.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    maximum_entries: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:maximum-entries', ge=1, le=8192),
    ] = 250
    """
    Maximum number of mac addresses allowed in the bridge-table.
    """
    warning_threshold_pct: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:warning-threshold-pct', ge=6, le=100),
    ] = 95
    """
    Percentage of the configured max-number-macs over which a warning is triggered.
    The warning message is cleared when the percentage drops below the configured
    percentage minus 5%
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
            alias='srl_nokia-interfaces-bridge-table-mac-learning-entries:address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The mac-address type represents an IEEE 802 MAC address.
    The canonical representation uses lowercase characters.

    In the value set and its semantics, this type is equivalent
    to the MacAddress textual convention of the SMIv2.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-learning-entries:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of this learnt mac
    """
    aging: Annotated[
        Optional[Union[AgingLeaf1, EnumerationEnum70]],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-learning-entries:aging'),
    ] = None
    """
    remaining age time for learnt macs
    """


class MacListEntry2(BaseModel):
    """
    macs duplicate on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-duplication-entries:address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The mac-address type represents an IEEE 802 MAC address.
    The canonical representation uses lowercase characters.

    In the value set and its semantics, this type is equivalent
    to the MacAddress textual convention of the SMIv2.
    """
    dup_detect_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-duplication-entries:dup-detect-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time when the mac was declared duplicate
    """
    hold_down_time_remaining: Annotated[
        Optional[Union[EnumerationEnum72, HoldDownTimeRemainingLeaf1]],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-duplication-entries:hold-down-time-remaining'
        ),
    ] = None
    """
    remaining hold down time for duplicate mac
    """


class MediaFrameErrorCountContainer(BaseModel):
    """
    Enter the media-frame-error-count context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    current: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:current', ge=0, le=18446744073709551615),
    ] = None
    """
    Indicates the current Media Frame Rate Error Count received on the optical channel
    """
    average: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:average', ge=0, le=18446744073709551615),
    ] = None
    """
    Indicates the average Media Frame Rate Error Count received on the optical channel
    """
    minimum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:minimum', ge=0, le=18446744073709551615),
    ] = None
    """
    Indicates the minimum Media Frame Rate Error Count received on the optical channel
    """
    maximum: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:maximum', ge=0, le=18446744073709551615),
    ] = None
    """
    Indicates the maximum Media Frame Rate Error Count received on the optical channel
    """


class MultiDomainAllowedSourceMacsContainer(BaseModel):
    """
    Enter the allowed-source-macs context for per-host multi-domain mode

    This command is only relevant only to per-host mode of multi-domain mode.
    The source mac under this list will be allowed in any port state,
    even if the port is forced unauthorized or port is set to auto
    and the host with this source mac address is not authorized.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac_address: Annotated[
        Optional[List[MacAddressListEntry]], Field(alias='srl_nokia-dot1x:mac-address')
    ] = None


class P4rtContainer(BaseModel):
    """
    Top-level container for P4Runtime interface configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-p4rt:id', ge=1, le=4294967295)
    ] = None
    """
    The numeric identifier used by the controller to address the interface

    This ID is the interface ifIndex by default, or is assigned by an
    external-to-the-device entity (e.g., an SDN management system) to
    establish an externally deterministic numeric reference for the interface.

    The programming entity must ensure that the ID is unique within the
    required context.

    Note that this identifier is used only when a numeric reference to the
    interface is required, it does not replace the unique name assigned to
    the interface.
    """
    parent_id: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-p4rt:parent-id', ge=0, le=18446744073709551615
        ),
    ] = None
    """
    The numeric ID used by the controller to address the ASIC this interface resides on

    This is the ID configured at /platform/linecard/forwarding-complex/p4rt/id.

    This ID may be referred to as a 'device', 'node' or 'target' by the P4RT
    specification.

    Each switching ASIC (i.e., node) is addressed by the external entity
    based on its numeric identifier.
    """


class PtpContainer(BaseModel):
    """
    Container for the configuration of Precision Time Protocol Peer-Delay frames.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming ptp frames are tunneled.

    ptp frames are identified by MAC DA 01-80-c2-00-00-0e and Ethertype 0x88f7.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress ptp frames.
    """


class RaGuardContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policy: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ra_guard:policy',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to RA Guard Policy to apply to the associated subinterface
    """
    vlan_list: Annotated[
        Optional[List[VlanListListEntry]], Field(alias='srl_nokia-ra_guard:vlan-list')
    ] = None


class ReceivedContainer(BaseModel):
    """
    Enter the received context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    bit_error_rate: Annotated[
        Optional[BitErrorRateContainer],
        Field(alias='srl_nokia-interfaces-dco:bit-error-rate'),
    ] = None
    electrical_signal_to_noise_ratio: Annotated[
        Optional[ElectricalSignalToNoiseRatioContainer],
        Field(alias='srl_nokia-interfaces-dco:electrical-signal-to-noise-ratio'),
    ] = None
    optical_signal_to_noise_ratio: Annotated[
        Optional[OpticalSignalToNoiseRatioContainer],
        Field(alias='srl_nokia-interfaces-dco:optical-signal-to-noise-ratio'),
    ] = None
    chromatic_dispersion: Annotated[
        Optional[ChromaticDispersionContainer],
        Field(alias='srl_nokia-interfaces-dco:chromatic-dispersion'),
    ] = None
    differential_group_delay: Annotated[
        Optional[DifferentialGroupDelayContainer],
        Field(alias='srl_nokia-interfaces-dco:differential-group-delay'),
    ] = None
    frequency_offset: Annotated[
        Optional[FrequencyOffsetContainer],
        Field(alias='srl_nokia-interfaces-dco:frequency-offset'),
    ] = None
    quality: Annotated[
        Optional[QualityContainer], Field(alias='srl_nokia-interfaces-dco:quality')
    ] = None
    power: Annotated[
        Optional[PowerContainer], Field(alias='srl_nokia-interfaces-dco:power')
    ] = None
    total_power: Annotated[
        Optional[TotalPowerContainer],
        Field(alias='srl_nokia-interfaces-dco:total-power'),
    ] = None
    polarization_dependent_loss: Annotated[
        Optional[PolarizationDependentLossContainer],
        Field(alias='srl_nokia-interfaces-dco:polarization-dependent-loss'),
    ] = None
    state_of_polarization_rate_of_change: Annotated[
        Optional[StateOfPolarizationRateOfChangeContainer],
        Field(alias='srl_nokia-interfaces-dco:state-of-polarization-rate-of-change'),
    ] = None
    media_frame_error_count: Annotated[
        Optional[MediaFrameErrorCountContainer],
        Field(alias='srl_nokia-interfaces-dco:media-frame-error-count'),
    ] = None


class SetTagSetLeafList(RootModel[str]):
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
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList2(RootModel[str]):
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
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList3(RootModel[str]):
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
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList4(RootModel[str]):
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
    Reference to a tag-set defined under routing-policy
    """


class StatisticsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Sum of all received packets, independent of protocol and forwarding type and before discards and errors
    """
    in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Corresponds to ifHCInOctets from the IFMIB
    """
    in_unicast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-unicast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCInUcastPkts from the IF-MIB
    """
    in_broadcast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-broadcast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCInBroadcastPkts from the IF-MIB
    """
    in_multicast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-multicast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCInMulticastPkts from the IF-MIB
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifInDiscards from the IFMIB.

    This counts the number of IP packets discarded due to VLAN mismatch, unknown dest MAC or drop by system-filter drop action. On 7250 IXR/IXRe systems this counter is not expected to increment above zero.
    """
    in_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Corresponds to ifInErrors from the IF-MIB
    """
    in_fcs_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-fcs-error-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Ingress FCS errors
    """
    out_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Sum of all transmitted packets, independent of protocol and forwarding type and before discards and errors
    """
    out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    Corresponds to ifHCOutOctets from the IF-MIB
    """
    out_mirror_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-mirror-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    This counts the number of outgoing mirrored octets
    """
    out_unicast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-unicast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCOutUcastPkts from the IF-MIB
    """
    out_broadcast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-broadcast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCOutBroadcastPkts from the IF-MIB
    """
    out_multicast_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-multicast-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifHCOutMulticastPkts from the IF-MIB
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifOutDiscards from the IF-MIB.

    On Jericho2 systems this counts packets dropped by an egress IP ACL of any of the port's subinterfaces.
    """
    out_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-error-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Corresponds to ifOutErrors from the IF-MIB
    """
    out_mirror_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-mirror-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    This counts the number of outgoing mirrored packets
    """
    carrier_transitions: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:carrier-transitions',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of times the interface state has transitioned from down to up.

    This is reset to zero when the device is started or reset or the counters are cleared.
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the interface counters were cleared
    """


class StatisticsContainer10(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    advertisements_sent: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-sent',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total number fo VRRP advertisement messages sent
    """
    advertisements_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages received
    """
    advertisements_discarded_version_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-version-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to version mismatch
    """
    advertisements_discarded_authfail: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authfail',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication failure
    """
    advertisements_discarded_authtype_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authtype-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication type mismatch
    """
    advertisements_discarded_address_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-address-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to address mismatch
    """
    priority_zero_packets_sent: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:priority-zero-packets-sent',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages sent out with priority 0
    """
    priority_zero_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:priority-zero-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages received with priority 0
    """
    advertisements_discarded_ttl: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-ttl',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to ttl error
    """
    advertisements_discarded_length: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-length',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to length of the packet
    """
    advertisements_discarded_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-interval',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to interval mismatch
    """
    advertisements_interval_error: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-interval-error',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages with interval mismatch
    """
    advertisements_discarded_total: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-total',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages dicarded
    """


class StatisticsContainer11(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """
    in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """
    in_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The total number of input packets discarded due to errors, counting transit and terminating traffic

    In an IP context, the sum of the following RFC 4293 counters:
    ipIfStatsInHdrErrors
    ipIfStatsInNoRoutes
    ipIfStatsInAddrErrors
    ipIfStatsInUnknownProtos
    ipIfStatsInTruncatedPkts

    In an MPLS context, the total number of MPLS packets that were dropped because:
    - forwarded top label had an MPLS TTL value of 0
    - terminating top label had an MPLS TTL value of 0
    - the top label was unknown (no matching forwarding entry)
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were dropped due to explicit programming

    The discards can be due to any of the following reasons
    - ingress interface ACL drop action
    - CPM filter drop action
    - VOQ congestion discards (7250 IXR only)
    - unicast destination MAC address is not the MAC address of the subinterface
    - packet matched a route with a blackhole next-hop
    - packet was non-terminating and its TTL expired
    - packet matched a route with a next-hop via another subinterface but the next-hop address was not resolvable by ARP/ND
    - packet is a host address on another subinterface but the host address was not resolvable by ARP/ND

    In an MPLS context, this includes the total number of MPLS packets that were dropped because they were received with forwarded top label having an MPLS TTL value of 1
    """
    in_terminated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """
    in_terminated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """
    in_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """
    in_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """
    in_matched_ra_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-matched-ra-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """
    out_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """
    out_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """
    out_originated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_originated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-error-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """
    out_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """
    out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class StatisticsContainer12(BaseModel):
    """
    Statistics for the Virtual IP address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    out_probe_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:out-probe-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of probe packets transmitted for the Virtual IP discovery.
    """


class StatisticsContainer13(BaseModel):
    """
    Global statistics for Virtual IP discovery
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    out_total_probe_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:out-total-probe-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of total probe packets transmitted for Virtual discovery.
    """


class StatisticsContainer14(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    client_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total received dhcp packets from dhcp client(s) for DHCP Relay
    """
    client_packets_relayed: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-relayed',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total relayed dhcp packets from dhcp client(s) towards DHCP server(s)
    """
    client_packets_discarded: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-discarded',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total discarded dhcp packets from dhcp client(s) towards DHCP server(s)
    """
    server_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total received dhcp packets from DHCP server(s) for DHCP Relay
    """
    server_packets_relayed: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-relayed',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total relayed dhcp packets from DHCP server(s) towards dhcp client(s)
    """
    server_packets_discarded: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-discarded',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total discarded dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class StatisticsContainer15(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """
    in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """
    in_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The total number of input packets discarded due to errors, counting transit and terminating traffic

    In an IP context, the sum of the following RFC 4293 counters:
    ipIfStatsInHdrErrors
    ipIfStatsInNoRoutes
    ipIfStatsInAddrErrors
    ipIfStatsInUnknownProtos
    ipIfStatsInTruncatedPkts

    In an MPLS context, the total number of MPLS packets that were dropped because:
    - forwarded top label had an MPLS TTL value of 0
    - terminating top label had an MPLS TTL value of 0
    - the top label was unknown (no matching forwarding entry)
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were dropped due to explicit programming

    The discards can be due to any of the following reasons
    - ingress interface ACL drop action
    - CPM filter drop action
    - VOQ congestion discards (7250 IXR only)
    - unicast destination MAC address is not the MAC address of the subinterface
    - packet matched a route with a blackhole next-hop
    - packet was non-terminating and its TTL expired
    - packet matched a route with a next-hop via another subinterface but the next-hop address was not resolvable by ARP/ND
    - packet is a host address on another subinterface but the host address was not resolvable by ARP/ND

    In an MPLS context, this includes the total number of MPLS packets that were dropped because they were received with forwarded top label having an MPLS TTL value of 1
    """
    in_terminated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """
    in_terminated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """
    in_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """
    in_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """
    in_matched_ra_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-matched-ra-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """
    out_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """
    out_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """
    out_originated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_originated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-error-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """
    out_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """
    out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class StatisticsContainer17(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-ethcfm:discarded-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The count of ETH-CFM packets discarded on the subinterface because of ingress squelching
    """


class StatisticsContainer18(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-if-mpls:in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """
    in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-if-mpls:in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """
    in_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The total number of input packets discarded due to errors, counting transit and terminating traffic

    In an IP context, the sum of the following RFC 4293 counters:
    ipIfStatsInHdrErrors
    ipIfStatsInNoRoutes
    ipIfStatsInAddrErrors
    ipIfStatsInUnknownProtos
    ipIfStatsInTruncatedPkts

    In an MPLS context, the total number of MPLS packets that were dropped because:
    - forwarded top label had an MPLS TTL value of 0
    - terminating top label had an MPLS TTL value of 0
    - the top label was unknown (no matching forwarding entry)
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were dropped due to explicit programming

    The discards can be due to any of the following reasons
    - ingress interface ACL drop action
    - CPM filter drop action
    - VOQ congestion discards (7250 IXR only)
    - unicast destination MAC address is not the MAC address of the subinterface
    - packet matched a route with a blackhole next-hop
    - packet was non-terminating and its TTL expired
    - packet matched a route with a next-hop via another subinterface but the next-hop address was not resolvable by ARP/ND
    - packet is a host address on another subinterface but the host address was not resolvable by ARP/ND

    In an MPLS context, this includes the total number of MPLS packets that were dropped because they were received with forwarded top label having an MPLS TTL value of 1
    """
    in_terminated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-terminated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """
    in_terminated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-terminated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """
    in_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """
    in_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-forwarded-octets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """
    in_matched_ra_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:in-matched-ra-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """
    out_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """
    out_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """
    out_originated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-originated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_originated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-originated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-if-mpls:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """
    out_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-if-mpls:out-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """
    out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-if-mpls:out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-if-mpls:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class StatisticsContainer19(BaseModel):
    """
    LACP protocol counters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    lacp_in_pkts: Annotated[
        Optional[int],
        Field(alias='srl_nokia-lacp:lacp-in-pkts', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of LACPDUs received
    """
    lacp_out_pkts: Annotated[
        Optional[int],
        Field(alias='srl_nokia-lacp:lacp-out-pkts', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of LACPDUs transmitted
    """
    lacp_rx_errors: Annotated[
        Optional[int],
        Field(alias='srl_nokia-lacp:lacp-rx-errors', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of LACPDU receive packet errors
    """
    lacp_tx_errors: Annotated[
        Optional[int],
        Field(alias='srl_nokia-lacp:lacp-tx-errors', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of LACPDU transmit packet errors
    """
    lacp_unknown_errors: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-lacp:lacp-unknown-errors', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Number of LACPDU unknown packet errors
    """
    lacp_errors: Annotated[
        Optional[int],
        Field(alias='srl_nokia-lacp:lacp-errors', ge=0, le=18446744073709551615),
    ] = 0
    """
    Number of LACPDU illegal packet errors
    """


class StatisticsContainer2(BaseModel):
    """
    Enter the statistics context

    interface/statistics/last-clear indicates when these statistics were last cleared.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    received: Annotated[
        Optional[ReceivedContainer], Field(alias='srl_nokia-interfaces-dco:received')
    ] = None
    transmitted: Annotated[
        Optional[TransmittedContainer],
        Field(alias='srl_nokia-interfaces-dco:transmitted'),
    ] = None


class StatisticsContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_mac_pause_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-mac-pause-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of MAC layer PAUSE frames received on the interface.
    """
    in_oversize_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-oversize-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of oversize frames received on the interface (i.e. frames that exceed the operational port MTU)
    """
    in_jabber_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-jabber-frames', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Number of jabber frames received on the interface. Jabber frames are typically defined as oversize frames which also have a bad CRC
    """
    in_fragment_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-fragment-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of fragment frames received on the interface
    """
    in_crc_error_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-crc-error-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of receive error events due to FCS/CRC check failure
    """
    out_mac_pause_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-mac-pause-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of MAC layer PAUSE frames sent on the interface
    """
    in_64b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-64b-frames', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Number of received Ethernet frames that are exactly 64 bytes in length
    """
    in_65b_to_127b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-65b-to-127b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 65-127 bytes in length
    """
    in_128b_to_255b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-128b-to-255b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 128-255 bytes in length
    """
    in_256b_to_511b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-256b-to-511b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 256-511 bytes in length
    """
    in_512b_to_1023b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-512b-to-1023b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 512-1023 bytes in length
    """
    in_1024b_to_1518b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-1024b-to-1518b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 1024-1518 bytes in length
    """
    in_1519b_or_longer_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-1519b-or-longer-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of received Ethernet frames that are 1519 bytes or longer
    """
    out_64b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-64b-frames', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are exactly 64 bytes in length
    """
    out_65b_to_127b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-65b-to-127b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 65-127 bytes in length
    """
    out_128b_to_255b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-128b-to-255b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 128-255 bytes in length
    """
    out_256b_to_511b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-256b-to-511b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 256-511 bytes in length
    """
    out_512b_to_1023b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-512b-to-1023b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 512-1023 bytes in length
    """
    out_1024b_to_1518b_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-1024b-to-1518b-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 1024-1518 bytes in length
    """
    out_1519b_or_longer_frames: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-1519b-or-longer-frames',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Number of transmitted Ethernet frames that are 1519 bytes or longer
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the MAC counters were cleared
    """


class StatisticsContainer5(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    advertisements_sent: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-sent',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total number fo VRRP advertisement messages sent
    """
    advertisements_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages received
    """
    advertisements_discarded_version_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-version-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to version mismatch
    """
    advertisements_discarded_authfail: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authfail',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication failure
    """
    advertisements_discarded_authtype_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authtype-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication type mismatch
    """
    advertisements_discarded_address_mismatch: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-address-mismatch',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to address mismatch
    """
    priority_zero_packets_sent: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:priority-zero-packets-sent',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages sent out with priority 0
    """
    priority_zero_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:priority-zero-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages received with priority 0
    """
    advertisements_discarded_ttl: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-ttl',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to ttl error
    """
    advertisements_discarded_length: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-length',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to length of the packet
    """
    advertisements_discarded_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-interval',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to interval mismatch
    """
    advertisements_interval_error: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-interval-error',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages with interval mismatch
    """
    advertisements_discarded_total: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertisements-discarded-total',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Counter for the total numebr fo VRRP advertisement messages dicarded
    """


class StatisticsContainer6(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """
    in_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:in-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """
    in_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-error-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    The total number of input packets discarded due to errors, counting transit and terminating traffic

    In an IP context, the sum of the following RFC 4293 counters:
    ipIfStatsInHdrErrors
    ipIfStatsInNoRoutes
    ipIfStatsInAddrErrors
    ipIfStatsInUnknownProtos
    ipIfStatsInTruncatedPkts

    In an MPLS context, the total number of MPLS packets that were dropped because:
    - forwarded top label had an MPLS TTL value of 0
    - terminating top label had an MPLS TTL value of 0
    - the top label was unknown (no matching forwarding entry)
    """
    in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were dropped due to explicit programming

    The discards can be due to any of the following reasons
    - ingress interface ACL drop action
    - CPM filter drop action
    - VOQ congestion discards (7250 IXR only)
    - unicast destination MAC address is not the MAC address of the subinterface
    - packet matched a route with a blackhole next-hop
    - packet was non-terminating and its TTL expired
    - packet matched a route with a next-hop via another subinterface but the next-hop address was not resolvable by ARP/ND
    - packet is a host address on another subinterface but the host address was not resolvable by ARP/ND

    In an MPLS context, this includes the total number of MPLS packets that were dropped because they were received with forwarded top label having an MPLS TTL value of 1
    """
    in_terminated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """
    in_terminated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-terminated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """
    in_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """
    in_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """
    in_matched_ra_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:in-matched-ra-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """
    out_forwarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """
    out_forwarded_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-forwarded-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """
    out_originated_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_originated_octets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-originated-octets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """
    out_error_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-error-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """
    out_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:out-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """
    out_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """
    out_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:out-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class StatisticsContainer7(BaseModel):
    """
    Statistics for the Virtual IP address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    out_probe_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:out-probe-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of probe packets transmitted for the Virtual IP discovery.
    """


class StatisticsContainer8(BaseModel):
    """
    Global statistics for Virtual IP discovery
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    out_total_probe_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:out-total-probe-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The number of total probe packets transmitted for Virtual discovery.
    """


class StatisticsContainer9(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    client_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total received dhcp packets from dhcp client(s) for DHCP Relay
    """
    client_packets_relayed: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-relayed',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total relayed dhcp packets from dhcp client(s) towards DHCP server(s)
    """
    client_packets_discarded: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:client-packets-discarded',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total discarded dhcp packets from dhcp client(s) towards DHCP server(s)
    """
    server_packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total received dhcp packets from DHCP server(s) for DHCP Relay
    """
    server_packets_relayed: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-relayed',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total relayed dhcp packets from DHCP server(s) towards dhcp client(s)
    """
    server_packets_discarded: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:server-packets-discarded',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Total discarded dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class SubsystemContainer(BaseModel):
    """
    Top-level container for PCI subsystem state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vendor_name: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:vendor-name')
    ] = None
    """
    PCI device vendor
    """
    vendor_id: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:vendor-id')
    ] = None
    """
    PCI device vendor ID

    This field is the two byte vendor ID reported over PCI.
    """
    device_name: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:device-name')
    ] = None
    """
    PCI device name
    """
    device_id: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:device-id')
    ] = None
    """
    PCI device ID

    This field is the two byte device ID reported over PCI.
    """


class TemperatureContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    latest_value: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:latest-value', ge=-32768, le=32767),
    ] = None
    """
    The current temperature of the transceiver module in degrees Celsius
    """
    maximum: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:maximum', ge=-32768, le=32767)
    ] = None
    """
    Represents the highest temperature the transceiver has reached since it booted
    """
    maximum_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:maximum-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Indicates the time this transceiver reached the temperature referenced in maximum
    """
    high_alarm_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:high-alarm-condition')
    ] = None
    """
    High alarm threshold condition

    Set to true whenever the temperature is above the high-alarm-threshold and set to false whenever the temperature is below the high-alarm-threshold
    """
    high_alarm_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:high-alarm-threshold', ge=-32768, le=32767),
    ] = None
    """
    High alarm threshold

    Read from the installed transceiver
    """
    low_alarm_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:low-alarm-condition')
    ] = None
    """
    Low alarm threshold condition.

    Set to true whenever the temperature is below the low-alarm-threshold and set to false whenever the temperature is above the low-alarm-threshold
    """
    low_alarm_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:low-alarm-threshold', ge=-32768, le=32767),
    ] = None
    """
    Low alarm threshold.

    Read from the installed transceiver
    """
    high_warning_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:high-warning-condition')
    ] = None
    """
    High warning threshold condition.

    Set to true whenever the temperature is above the high-warning-threshold and set to false whenever the temperature is below the high-warning-threshold
    """
    high_warning_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:high-warning-threshold', ge=-32768, le=32767),
    ] = None
    """
    High warning threshold.

    Read from the installed transceiver
    """
    low_warning_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:low-warning-condition')
    ] = None
    """
    Low warning threshold condition.

    Set to true whenever the temperature is below the low-warning-threshold and set to false whenever the temperature is above the low-warning-threshold
    """
    low_warning_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:low-warning-threshold', ge=-32768, le=32767),
    ] = None
    """
    Low warning threshold.

    Read from the installed transceiver
    """


class UnidirectionalLinkDelayContainer(BaseModel):
    """
    Unidirectional link delay configuration and state related to subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    static_delay: Annotated[
        Optional[Union[StaticDelayLeaf1, EnumerationEnum36]],
        Field(alias='srl_nokia-interfaces:static-delay'),
    ] = 'none'
    """
    A statically configured unidirectional delay value that can be advertised as an interface attribute by an IGP
    """
    last_reported_dynamic_delay: Annotated[
        Optional[Union[LastReportedDynamicDelayLeaf1, EnumerationEnum37]],
        Field(alias='srl_nokia-interfaces:last-reported-dynamic-delay'),
    ] = None
    """
    Indicates the last delay measurement reported to the routing engine
    """


class VhostContainer(BaseModel):
    """
    Top-level container for vhost-user interface configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vhost_socket_path: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-vxdp:vhost-socket-path',
            pattern='^(?=^(/[0-9A-Za-z_\\-\\.]+)+$).*$',
        ),
    ]
    """
    Filesystem path to the vhost-user socket
    """
    vhost_socket_mode: Annotated[
        Optional[EnumerationEnum94],
        Field(alias='srl_nokia-interfaces-vxdp:vhost-socket-mode'),
    ] = 'client'
    """
    The vhost-user socket mode

    If set to server, the socket is created by SR Linux, if set to client SR Linux will connect to a pre-existing socket.
    """
    vhost_socket_queues: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-vxdp:vhost-socket-queues', ge=1, le=1024),
    ] = None
    """
    The number of vhost-user queues

    The number of queues are retrieved from the vhost-user socket if not configured. This should be set equivalent to the number of vCPUs allocated to the other end of the vhost-user interface. This value must not exceed the count of vCPUs provided as the vXDP cpu-set.
    """
    socket_id: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-vxdp:socket-id', ge=0, le=255)
    ] = None
    """
    Socket this interface is physically or logically attached to

    This field is not populated for interfaces that have no socket preference - e.g. veth, tap.
    """
    socket_cpus: Annotated[
        Optional[List[SocketCpusLeafList]],
        Field(alias='srl_nokia-interfaces-vxdp:socket-cpus'),
    ] = []
    """
    List of CPUs present on the socket this interface is attached to
    """


class VirtualAddressLeafList2(RootModel[str]):
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
    Associated Virtual IP address.
    """


class XstpContainer(BaseModel):
    """
    Container for the configuration of all the Spanning Tree Protocols.

    It includes Spanning Tree Protocol (STP), Rapid RSTP (RSTP) and Multiple STP (MSTP)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming xSTP frames are tunneled.

    xSTP frames are identified by MAC DA 01-80-c2-00-00-00 and any Ethertype.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress xSTP frames.
    """


class AdapterContainer(BaseModel):
    """
    State for adapters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    model_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:model-number')
    ] = None
    """
    Model information for the adapter

    This is the information as read from the EEPROM of the part.  The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """
    type: Annotated[
        Optional[EnumerationEnum8], Field(alias='srl_nokia-interfaces:type')
    ] = None
    """
    Type of adapter for the port
    """
    vendor_manufacture_date: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-manufacture-date')
    ] = None
    """
    Vendor's date code.

    This is the information as read from the EEPROM of the part.  
    """
    vendor_oui: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-oui')
    ] = None
    """
    Vendor's OUI which contains the IEEE company identifier for the vendor

    This is the information as read from the EEPROM of the part.  A value of all zero indicates that the vendor OUI is unspecified.
    """
    vendor_part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-part-number')
    ] = None
    """
    Vendor's part number or product name of the adapter

    This is the information as read from the EEPROM of the part.  An empty string indicates the vendor part number is unspecified. The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """
    vendor_serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-serial-number')
    ] = None
    """
    Vendor's serial number of the adapter

    This is the information as read from the EEPROM of the part.  An empty string indicates the vendor serial number is unspecified. The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """


class AgingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'enable'
    """
    Configurable state of the aging for the dynamic mac entries in the bridge table.
    If disabled, dynamically learned mac entries will be programmed in the bridge table
    until the network instance is disabled.
    """


class AnycastGwContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    virtual_router_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:virtual-router-id', ge=1, le=255),
    ] = 1
    """
    The Virtual Router Identifier (VRID) value used to auto-derive the anycast-gw-mac in the format 00:00:5E:00:01:VRID.
    """
    anycast_gw_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:anycast-gw-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    The MAC address of associated to the anycast-gw IP address.

    If the anycast-gw MAC address is not configured, it will be auto-derived from the virtual-router-id value
    as per draft-ietf-bess-evpn-inter-subnet-forwarding following the format 00:00:5E:00:01:VRID.
    """
    anycast_gw_mac_origin: Annotated[
        Optional[EnumerationEnum69],
        Field(alias='srl_nokia-interfaces:anycast-gw-mac-origin'),
    ] = None
    """
    Origin of the active anycast-gateway MAC address.

    If not configured, the anycast-gateway-mac will be auto-derived out of 00:00:5E:00:01:VRID, where VRID is the
    Virtual Router Identifier of the subinterface anycast-gw.
    """


class BreakoutModeContainer(BaseModel):
    """
    Configuration of breakout options.

    7220 D3 ports 3-33: 4x10G and 4x25G
    7220 D3L ports 1-31: 2x50G, 4x10G and 4x25G
    7220 H3 ports 3-34: 4x10G, 2x100G/4x100G, and 2x200G
    7220 H4 ports 1-64: 4x100G and 2x200G
    7220 D4 ports 29-32: 4x100G, 4x25G, and 4x10G
    7220 D4 ports 9, 23-27: 4x25G and 4x10G
    7220 D5 ports 1-32: 4x10G, 4x25G, 2x100G/4x100G, and 2x200G
    7730 SXR-1d-32D QSFP28 ports 1-16, 21-32: 4x10G and 4x25G (Note 3)
    7730 SXR-1d-32D QSFPDD ports 17-20: 4x100G, 3x100G (Note 1), 4x25G, and 4x10G
    7730 SXR-1x-44S SFPDD ports 1-20, 23-42: No breakouts
    7730 SXR-1x-44S QSFPDD ports 21,22,43,44: 4x100G, 3x100G (Note 1), 4x25G, and 4x10G
    7250 IXR-6e/10e 60p QSFP28 IMM 9,12,15,18,21,24,26,27,29,30,32,35,38,39,41,42,45,48: 4x25G and 4x10G (Note 2)
    7250 IXR-6e/10e 36p QSFPDD IMM all ports: 4x100G, 2x100G, 4x25G, and 4x10G
    7250 IXR-X1b QSFP28 ports 1-24: 4x25G, and 4x10G (Note 4)
    7250 IXR-X1b QSFPDD ports 25-36: 4x100G, 3x100G (Note 1), 2x100G, 4x25G, and 4x10G
    7250 IXR-X3b QSFPDD all ports: 4x100G, 3x100G (Note 1), 2x100G, 4x25G, and 4x10G
    Note 1: 3x100G is only supported for Digital Coherent Optic transceivers

    Note 2: For the following port groupings only the higher numbered port supports breakout-mode.
            If the higher numbered port is to be configured for breakout-mode, then the lower numbered port should not be configured.
            If both ports are configured, then the lower numbered port takes precedence and the higher numbered port shall be operationally down with reason unsupported-breakout-port.
            Groupings are (8,9), (11,12), (14,15), (17,18), (20,21), (23,24), (44, 45), (47,48).

    Note 3: Breakout and 40G is only supported on odd numbered ports.
            For the QSFP28 four port groupings [1-4], [5-8], [9-12], [13-16], [21-24], [25-28], and [29-32] if either of the odd numbered ports within a group is configured for 40G, 4x10G, or 4x25G,
            then the other odd numbered port in the same group may only be configured if it is configured for one of 40G, 4x10G, or 4x25G (can differ between the odd ports) and neither of
            the two even numbered ports within the same group can be configured.

    Note 4: For the QSFP28 ports, the following port groups exist [n, n+1, n+2, n+3] for n = 1, 5, 9, 13, 17, 21.  Breakout for 4x25G or 4x10G is only supported on ports n+1 and n+3.
            When initially configuring a port with a breakout configuration or port speed that does not already exist on another configured port within the same group, then a link flap and traffic hit may occur on other ports within the same group.
            When the breakout configuration or port speed is changed for a port in a group, then a link flap and traffic hit may occur on other ports within the same group.
            If port n+1 within the group is configured for breakout, then port n cannot be configured.
            In addition if port n+1 is configured for breakout and port n+3 is configured without breakout, then port n+2 may only be configured with the same speed as port n+3.
            If port n+3 within the group is configured for breakout, then port n+2 cannot be configured.
            In addition if port n+3 is configured for breakout and port n+1 is configured without breakout, then port n may only be configured with the same speed as port n+1.

    Port Groups and auto-configuration of port speed:
     Manually configured breakout-mode takes precedence over the auto-configured port-speed.  This means that configuring a port within a port-group can have a side effect to take down an operational port that had its speed set based on the auto configuration feature.  If there is risk of mixing transceiver types within a port group, then it is recommended to always manually configure the ports
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    num_breakout_ports: Annotated[
        EnumerationEnum2, Field(alias='srl_nokia-interfaces:num-breakout-ports')
    ]
    """
    The number of breakout ports supported by this connector
    """
    breakout_port_speed: Annotated[
        EnumerationEnum3, Field(alias='srl_nokia-interfaces:breakout-port-speed')
    ]
    """
    The speed of each breakout port
    """


class DatapathProgrammingContainer(BaseModel):
    """
    Container for state related to the datapath programming of the ARP or neighbor entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum46], Field(alias='srl_nokia-interfaces-nbr:status')
    ] = None
    """
    The status of the ARP or neighbor entry with respect to datapath programming
    """
    last_failed_complexes: Annotated[
        Optional[List[LastFailedComplexesLeafList]],
        Field(alias='srl_nokia-interfaces-nbr:last-failed-complexes'),
    ] = []
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class DatapathProgrammingContainer2(BaseModel):
    """
    Container for state related to the datapath programming of the ARP or neighbor entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    status: Annotated[
        Optional[EnumerationEnum58], Field(alias='srl_nokia-interfaces-nbr:status')
    ] = None
    """
    The status of the ARP or neighbor entry with respect to datapath programming
    """
    last_failed_complexes: Annotated[
        Optional[List[LastFailedComplexesLeafList2]],
        Field(alias='srl_nokia-interfaces-nbr:last-failed-complexes'),
    ] = []
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class Dot1xContainer2(BaseModel):
    """
    Container for the configuration of 802.1x Port based Network Access Control.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming dot1x frames are tunneled.

    Dot1x frames are identified by MAC DA 01-80-c2-00-00-03 and Ethertype 0x888e.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress dot1x frames.
    """


class DoubleTaggedContainer(BaseModel):
    """
    When present, double-tagged frames with a specific, non-zero, outer and inner VLAN ID values are associated to the subinterface

    By default, the specific configured vlan-id tags are stripped at ingress and pushed on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    inner_vlan_id: Annotated[
        Union[VlanIdType, EnumerationEnum81],
        Field(alias='srl_nokia-interfaces-vlans:inner-vlan-id'),
    ]
    """
    Inner VLAN tag identifier for double-tagged packets
    """
    outer_vlan_id: Annotated[
        Union[VlanIdType, EnumerationEnum82],
        Field(alias='srl_nokia-interfaces-vlans:outer-vlan-id'),
    ]
    """
    Outer VLAN tag identifier for double-tagged packets
    """


class DuplicateEntriesContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[List[MacListEntry2]],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-duplication-entries:mac'),
    ] = None


class EfmOamContainer(BaseModel):
    """
    Container for the configuration of Ethernet in the First Mile OAM frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming EFM-OAM frames are tunneled

    EFM-OAM frames are identified by Ethertype 0x8809 and slow protocol subtype 0x03.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress EFM-OAM frames.
    """


class ElmiContainer(BaseModel):
    """
    Container for the configuration of Ethernet local management interface frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming ELMI frames are tunneled

    ELMI frames are identified by MAC DA 01-80-C2-00-00-07 and Ethertype 0x88ee.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress ELMI frames
    """


class EsmcContainer(BaseModel):
    """
    Container for the configuration of Ethernet synchronization messaging channel frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming esmc frames are tunneled

    ESMC frames are identified by Ethertype 0x8809 and slow protocol subtype 0x0A.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress ESMC frames
    """


class EthernetSegmentAssociationContainer(BaseModel):
    """
    ethernet-segment association information.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ethernet_segment: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ethernet-segment-association:ethernet-segment',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The value of this leaf indicates the ethernet-segment, the
    sub-interface is associated to.
    """
    es_managed: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-ethernet-segment-association:es-managed'),
    ] = False
    """
    The value of this leaf indicates if the interface is managed
    by the ethernet-segment on the network-instance.
    """
    designated_forwarder: Annotated[
        Optional[bool],
        Field(
            alias='srl_nokia-interfaces-ethernet-segment-association:designated-forwarder'
        ),
    ] = False
    """
    The value of this leaf indicates if the interface is the designated
    forwarder for the ethernet-segment on the network-instance.
    """


class ExponentialPortDampeningContainer(BaseModel):
    """
    Exponential port dampening parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Administrative state of exponential port dampening
    """
    half_life: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:half-life', ge=1, le=2000)
    ] = 5
    """
    Half-life decay time
    """
    max_suppress_time: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:max-suppress-time', ge=1, le=43200),
    ] = 20
    """
    Maximum suppression time
    """
    reuse_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:reuse-threshold', ge=1, le=20000),
    ] = 1000
    """
    Threshold which port-up state is no longer suppressed
    """
    suppress_threshold: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:suppress-threshold', ge=1, le=20000),
    ] = 2000
    """
    Threshold at which the port-up state is suppressed
    """
    current_penalties: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:current-penalties',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    Indicates the accumulated penalties applied to the port

    Penalties are accumulated on every port down event except a system restart.
    """
    max_penalties: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:max-penalties', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    Indicates the maximum possible value of the accumulated penalties against the port
    """
    oper_state: Annotated[
        Optional[EnumerationEnum29], Field(alias='srl_nokia-interfaces:oper-state')
    ] = None
    """
    Indicates if the port up state of the port is suppressed or not

    The port up state is 'idle' if the value of current-penalties
    exceeds the value of suppress-threshold. The port up state will
    be 'active' when current-penalties falls below the value of
    reuse-threshold.
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
        Optional[EnumerationEnum13], Field(alias='srl_nokia-platform-healthz:status')
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


class HoldTimeContainer(BaseModel):
    """
    Configure interface hold timers for Ethernet interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    up: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:up', ge=0, le=86400000)
    ] = 0
    """
    Holds link up events for the configured time

    The hold-time up behavior is triggered with any event that tries to bring up the ethernet interface
    (interface admin-state enable, a reboot, etc). While the hold-time up is running, the transceiver
    laser will be enabled, however the higher layers will not be notified that the interface is
    operationally up until the timer expires.
    """
    up_expires: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:up-expires',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The remaining time until the hold-time up expires and the interface comes up.
    """
    down: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:down', ge=0, le=86400000)
    ] = 0
    """
    Holds link down events for the configured time

    The hold-time down behavior is triggered with events that try to bring the ethernet interface
    down and can change quickly. It is not triggered with an admin-state disable event or interface
    disable due to other internal reasons (such as fabric unavailability). When running, the
    interface will not be brought down till the timer expires. The typical use of the hold-time down
    is to provide stability and avoid the protocols to advertise/withdraw messages if there are
    flapping optics. The hold-time down is aborted if the user does admin-state disable or if the
    interface is disabled due to other internal reasons that prevent the traffic to be forwarded
    on the interface.
    """
    down_expires: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:down-expires',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The remaining time until the hold-time down expires and the interface goes operationally down.
    """


class HostsContainer(BaseModel):
    """
    Top level state container for 802.1X
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-dot1x:mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    Host MAC address
    """
    status: Annotated[
        Optional[EnumerationEnum34], Field(alias='srl_nokia-dot1x:status')
    ] = None
    """
    The status of the 802.1X session for a device
    """


class IngressSquelchingContainer(BaseModel):
    """
    Ingress ETH-CFM functions independent of Maintenance Domain context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    squelch_levels: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-ethcfm:squelch-levels',
            pattern='^(?=^(0|0 1|0 1 2|0 1 2 3|0 1 2 3 4|0 1 2 3 4 5|0 1 2 3 4 5 6|0 1 2 3 4 5 6 7)$).*$',
        ),
    ] = None
    """
    Contiguous ETH-CFM Maintenance Domain levels silently discarded at ingress, matching subinterface and level

    ETH-CFM packets ingressing a subinterface that match the definition of the subinterface and have an ETH-CFM level
    that is part of the squelching configuration will be silently discarded without processing. The lookup is an exact
    match of the subinterface followed immediately by the ETH-CFM etype 0x8902 and a level equal to any configured squelch
    values.  The lookup for the ETH-CFM level cannot exceed a total of two VLAN tags.  Ingress squelching will occur
    prior to any ingress ETH-CFM MP processing.  For example, if a down MEP exists on the subinterface with a level
    covered by the configured squelch levels the packet will be dropped before the packet it reaches the down MEP.
    """
    statistics: Annotated[
        Optional[StatisticsContainer17], Field(alias='srl_nokia-ethcfm:statistics')
    ] = None


class InternalTagsContainer(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList]],
        Field(alias='srl_nokia-interfaces-nbr:set-tag-set'),
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer2(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList2]],
        Field(alias='srl_nokia-interfaces-nbr-evpn:set-tag-set'),
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer3(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList3]],
        Field(alias='srl_nokia-interfaces-nbr:set-tag-set'),
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer4(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList4]],
        Field(alias='srl_nokia-interfaces-nbr-evpn:set-tag-set'),
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """


class LacpContainer(BaseModel):
    """
    Container for L2CP transparency of the Link Aggregation Control Protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming LACP frames are tunneled.

    LACP frames are identified by MAC DA 01-80-c2-00-00-02, Ethertype 0x8809 and slow-protocol
    sub-type 0x01.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress LACP frames.
    """


class LacpContainer2(BaseModel):
    """
    Operational status data for the member interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    activity: Annotated[
        Optional[EnumerationEnum90], Field(alias='srl_nokia-lacp:activity')
    ] = None
    """
    Indicates participant is active or passive
    """
    timeout: Annotated[
        Optional[EnumerationEnum91], Field(alias='srl_nokia-lacp:timeout')
    ] = None
    """
    The timeout type (short or long) used by the
    participant
    """
    synchronization: Annotated[
        Optional[EnumerationEnum92], Field(alias='srl_nokia-lacp:synchronization')
    ] = None
    """
    Indicates whether the participant is in-sync or
    out-of-sync
    """
    aggregatable: Annotated[
        Optional[bool], Field(alias='srl_nokia-lacp:aggregatable')
    ] = None
    """
    A true value indicates that the participant will allow
    the link to be used as part of the aggregate. A false
    value indicates the link should be used as an individual
    link
    """
    collecting: Annotated[Optional[bool], Field(alias='srl_nokia-lacp:collecting')] = (
        None
    )
    """
    If true, the participant is collecting incoming frames
    on the link, otherwise false
    """
    distributing: Annotated[
        Optional[bool], Field(alias='srl_nokia-lacp:distributing')
    ] = None
    """
    When true, the participant is distributing outgoing
    frames; when false, distribution is disabled
    """
    system_id: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-lacp:system-id',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    MAC address that defines the local system ID for the
    aggregate interface
    """
    oper_key: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:oper-key', ge=0, le=65535)
    ] = None
    """
    Current operational value of the key for the aggregate
    interface
    """
    partner_id: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-lacp:partner-id',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    MAC address representing the protocol partner's interface
    system ID
    """
    partner_key: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:partner-key', ge=0, le=65535)
    ] = None
    """
    Operational value of the protocol partner's key
    """
    port_num: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:port-num', ge=0, le=65535)
    ] = None
    """
    Port number of the local (actor) aggregation member
    """
    partner_port_num: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:partner-port-num', ge=0, le=65535)
    ] = None
    """
    Port number of the partner (remote) port for this member
    port
    """
    lacp_port_priority: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:lacp-port-priority', ge=0, le=65535)
    ] = None
    """
    Configure the port priority for LACP.  This value is used to  determine which port should be activated with LACP fallback mode. Lower values are more preferred.
    """
    statistics: Annotated[
        Optional[StatisticsContainer19], Field(alias='srl_nokia-lacp:statistics')
    ] = None


class LacpContainer3(BaseModel):
    """
    LACP parameters for the associated LAG
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interval: Annotated[
        Optional[EnumerationEnum93], Field(alias='srl_nokia-lacp:interval')
    ] = 'SLOW'
    """
    Set the period between LACP messages -- uses
          the lacp-period-type enumeration.
    """
    lacp_mode: Annotated[
        Optional[EnumerationEnum90], Field(alias='srl_nokia-lacp:lacp-mode')
    ] = 'ACTIVE'
    """
    ACTIVE is to initiate the transmission of LACP packets.
    PASSIVE is to wait for peer to initiate the transmission of
    LACP packets.
    """
    admin_key: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:admin-key', ge=1, le=65535)
    ] = None
    """
    Configure the LACP admin-key to be advertised by the local system.
    If this value is not specified a value starting from 32768 is automatically
    assigned by the system.
    """
    system_id_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-lacp:system-id-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    The MAC address portion of the node's System ID. This is
    combined with the system priority to construct the 8-octet
    system-id.
    If not configured, the system-ID configured at the system/ level is used.
    """
    system_priority: Annotated[
        Optional[int], Field(alias='srl_nokia-lacp:system-priority', ge=0, le=65535)
    ] = None
    """
    System priority used by the node on this LAG interface.
    Lower value is higher priority for determining which node
    is the controlling system.
    If not configured, the system-priority configured at the system/ level is used.
    """


class LearntEntriesContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[List[MacListEntry]],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-learning-entries:mac'),
    ] = None


class LldpContainer(BaseModel):
    """
    Container for L2CP transparency of the Link Layer Discovery Protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel')
    ] = False
    """
    Configures if incoming LLDP frames are tunneled.

    LLDP frames are identified by MAC DA 01-80-c2-00-00-00 and Ethertype 0x88cc.
    """
    oper_rule: Annotated[
        Optional[EnumerationEnum35], Field(alias='srl_nokia-interfaces-l2cp:oper-rule')
    ] = None
    """
    The operational state of the TCAM rule applied to ingress LLDP frames.
    """


class LowVlanIdListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    range_low_vlan_id: Annotated[
        int, Field(alias='srl_nokia-interfaces-vlans:range-low-vlan-id', ge=1, le=4094)
    ]
    """
    The low-value VLAN identifier in a range for single-tagged packets
    The range is matched inclusively.
    """
    high_vlan_id: Annotated[
        int, Field(alias='srl_nokia-interfaces-vlans:high-vlan-id', ge=1, le=4094)
    ]
    """
    The high-value VLAN identifier in a range for single-tagged packets
    The range is matched inclusively.
    """


class MacDuplicationContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    action: Annotated[
        Optional[EnumerationEnum71], Field(alias='srl_nokia-interfaces:action')
    ] = 'use-net-instance-action'
    """
    Action to take on the subinterface upon detecting at least one mac addresses as duplicate
    on the subinterface. In particular:
    - use-net-instance-action: upon detecting a duplicate mac on the subinterface, the action on the subinterface will be
      inherited from the action configured under network-instance/bridge-table/mac-duplication/action.
    - oper-down: if configured, upon detecting a duplicate mac on the subinterface, the subinterface
      will be brought oper-down, with oper-down-reason mac-dup-detected. The duplicate macs on the interface will be kept
      in CPM though, and shown in the duplicate-entries state. In this case, arriving frames on a different subinterface with
      the duplicate mac as source mac are dropped. Arriving frames on a different subinterface with a destination mac
      matching the duplicate mac are dropped.
    - blackhole: upon detecting a duplicate mac on the subinterface, the mac will be blackholed. Any
      frame received on this or any other subinterface with source mac matching a blackhole mac will be discarded. Any frame
      received with destination mac matching the blackhole mac will be discarded, although still processed for source mac
      learning.
    - stop-learning: upon detecting a duplicate mac on the subinterface, existing macs are kept (and refreshed) but new macs
      are no longer learned on this subinterface. The duplicate mac will stay learned on the subinterface. Frames arriving to
      a different subinterface with a source mac matching the duplicate mac will be dropped. Frames arriving to a different
      subinterface with a destination mac matching the duplicate mac will be forwarded normally.
    """
    duplicate_entries: Annotated[
        Optional[DuplicateEntriesContainer],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-duplication-entries:duplicate-entries'
        ),
    ] = None


class MacLearningContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'enable'
    """
    Configurable state of the learning procedures for dynamic mac addresses.
    If disabled, the existing macs in the bridge-table will be kept (and refreshed
    if new frames arrive for them) but no new mac addresses will be learned. Frames
    with unknown mac addresses are not dropped, unless discard-unknown-src-mac is
    configured.
    """
    aging: Annotated[
        Optional[AgingContainer], Field(alias='srl_nokia-interfaces:aging')
    ] = None
    learnt_entries: Annotated[
        Optional[LearntEntriesContainer],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-learning-entries:learnt-entries'
        ),
    ] = None


class MacTypeListEntry(BaseModel):
    """
    the type of the mac on the sub-interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        EnumerationEnum77,
        Field(alias='srl_nokia-interfaces-bridge-table-statistics:type'),
    ]
    """
    type of mac addresses in the system
    """
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-bridge-table-statistics:active-entries',
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
            alias='srl_nokia-interfaces-bridge-table-statistics:total-entries',
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
            alias='srl_nokia-interfaces-bridge-table-statistics:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs of this type, which have not been programmed on atleast one slot
    """


class MacListEntry3(BaseModel):
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
            alias='srl_nokia-interfaces-bridge-table-mac-table:address',
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
        Optional[EnumerationEnum77],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-table:type'),
    ] = None
    """
    the type of the mac installed in the fib.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-table:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of this mac
    """
    not_programmed_reason: Annotated[
        Optional[EnumerationEnum78],
        Field(
            alias='srl_nokia-interfaces-bridge-table-mac-table:not-programmed-reason'
        ),
    ] = None
    """
    The reason why the mac is not programmed
    """
    failed_slots: Annotated[
        Optional[List[FailedSlotsLeafList]],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-table:failed-slots'),
    ] = []
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class MplsContainer(BaseModel):
    """
    Container for MPLS configuration and state at the subinterface level
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    statistics: Annotated[
        Optional[StatisticsContainer18], Field(alias='srl_nokia-if-mpls:statistics')
    ] = None


class MstInstanceListEntry(BaseModel):
    """
    List of subinterfaces used by this mstp-policy
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mst_instance: Annotated[
        int,
        Field(
            alias='srl_nokia-interfaces-bridge-table-stp:mst-instance',
            ge=0,
            le=4294967295,
        ),
    ]
    """
    Name of the subinterface bound to this mstp-policy
    """
    mst_port_priority: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-bridge-table-stp:mst-port-priority',
            ge=16,
            le=255,
        ),
    ] = 128
    """
    The port-priority command is used to populate the priority portion
    of the bridge ID field within outbound BPDUs (the most significant 4
    bits of the bridge ID). It is also used as part of the decision process
    when determining the best BPDU between messages received and sent.
    When running MSTP, this is the bridge priority used for the CIST.

    All values are truncated to multiples of 4096, conforming with
    IEEE 802.1t and 802.1D-2004.
    """
    mst_path_cost: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-bridge-table-stp:mst-path-cost', ge=1, le=65535
        ),
    ] = 16
    """
    The interface path-cost is used by STP to calculate the path cost
    to the root bridge. STP defined this as a function of link bandwidth
    but this configuration is static.
    """


class NeighborListEntry(BaseModel):
    """
    List of static and dynamic ARP cache entries that map an IPv4 address to a MAC address

    To configure a static ARP entry a value must be written into this leaf and the link-layer-address leaf.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr:ipv4-address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ]
    """
    IPv4 address resolved by the ARP entry

    To configure a static neighbor entry a value must be written into this leaf and the link-layer-address leaf.
    """
    link_layer_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr:link-layer-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The resolving MAC address of the ARP entry

    To configure a static ARP entry a value must be written into this leaf and the ipv4-address leaf.
    """
    origin: Annotated[
        Optional[EnumerationEnum45], Field(alias='srl_nokia-interfaces-nbr:origin')
    ] = None
    """
    The origin of the ARP entry
    """
    expiration_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-nbr:expiration-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time when the dynamic ARP entry is set to expire
    """
    datapath_programming: Annotated[
        Optional[DatapathProgrammingContainer],
        Field(alias='srl_nokia-interfaces-nbr:datapath-programming'),
    ] = None


class NeighborListEntry2(BaseModel):
    """
    List of static and dynamic ND cache entries that map an IPv6 address to a MAC address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv6_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr:ipv6-address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ]
    """
    IPv6 address resolved by the ND cache entry

    To configure a static neighbor entry a value must be written into this leaf and the link-layer-address leaf.
    """
    link_layer_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr:link-layer-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    The resolving MAC address of the ND cache entry

    To configure a static neighbor entry a value must be written into this leaf and the ipv6-address leaf.
    """
    origin: Annotated[
        Optional[EnumerationEnum45], Field(alias='srl_nokia-interfaces-nbr:origin')
    ] = None
    """
    The origin of the neighbor cache entry.
    """
    is_router: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:is-router')
    ] = None
    """
    Indicates that the neighbor node claims to be a router (R bit in the Neighbor Advertisement message)
    """
    current_state: Annotated[
        Optional[EnumerationEnum57],
        Field(alias='srl_nokia-interfaces-nbr:current-state'),
    ] = None
    """
    The Neighbor Unreachability Detection state
    """
    next_state_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-nbr:next-state-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time when the neighbor state is expected to transition to the next state
    """
    datapath_programming: Annotated[
        Optional[DatapathProgrammingContainer2],
        Field(alias='srl_nokia-interfaces-nbr:datapath-programming'),
    ] = None


class OpticalChannelListEntry(BaseModel):
    """
    List of optical channels supported by the transceiver associated with this port.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-interfaces-dco:index', ge=1, le=1)]
    """
    Index of the optical channel
    """
    frequency: Annotated[
        int,
        Field(alias='srl_nokia-interfaces-dco:frequency', ge=191100000, le=196150000),
    ]
    """
    Center frequency for tunable DWDM optical interface
    """
    operational_mode: Annotated[
        EnumerationEnum14, Field(alias='srl_nokia-interfaces-dco:operational-mode')
    ]
    """
    Operational mode for the transceiver

     This is a numeric value the defines a set of operating characteristics such as modulation, bit-rate, max power range, fec, etc.
     Refer to Nokia documentation for details by transceiver part number.
    """
    tx_filter_enable: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-dco:tx-filter-enable')
    ] = False
    """
    Controls transmit filtering
    """
    chromatic_dispersion_range: Annotated[
        Optional[ChromaticDispersionRangeContainer],
        Field(alias='srl_nokia-interfaces-dco:chromatic-dispersion-range'),
    ] = None
    target_power: Annotated[
        Optional[float],
        Field(alias='srl_nokia-interfaces-dco:target-power', ge=-20.0, le=3.0),
    ] = 100
    """
    Average output power target for the port
    """
    laser_tunability: Annotated[
        Optional[EnumerationEnum15],
        Field(alias='srl_nokia-interfaces-dco:laser-tunability'),
    ] = None
    """
    Tunability of the optical interface.

    Value 'unequipped' indicates the optical interface is not equipped with a laser.
    """
    oper_frequency: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-dco:oper-frequency', ge=191100000, le=196150000
        ),
    ] = None
    """
    The operating frequency of the optical-channel.
    """
    minimum_frequency: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-dco:minimum-frequency',
            ge=191100000,
            le=196150000,
        ),
    ] = None
    """
    The minimum frequency supported by the equipped optical module.
    """
    maximum_frequency: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-dco:maximum-frequency',
            ge=191100000,
            le=196150000,
        ),
    ] = None
    """
    The maximum frequency supported by the equipped optical module.
    """
    supported_grids: Annotated[
        Optional[List[EnumerationEnum16]],
        Field(alias='srl_nokia-interfaces-dco:supported-grids'),
    ] = []
    """
    Indicates the frequency grids supported by the equipped tunable optical port.
    """
    fine_tuning: Annotated[
        Optional[FineTuningContainer],
        Field(alias='srl_nokia-interfaces-dco:fine-tuning'),
    ] = None
    dispersion: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:dispersion', ge=-50000, le=50000),
    ] = None
    """
    Residual chromatic dispersion compensation
    """
    dispersion_control_mode: Annotated[
        Optional[EnumerationEnum17],
        Field(alias='srl_nokia-interfaces-dco:dispersion-control-mode'),
    ] = 'automatic'
    """
    Mode used to compensate for chromatic dispersion
    """
    rx_los_reaction: Annotated[
        Optional[EnumerationEnum18],
        Field(alias='srl_nokia-interfaces-dco:rx-los-reaction'),
    ] = 'squelch'
    """
    Reaction to an RX LOS
    """
    rx_los_thresh: Annotated[
        Optional[float],
        Field(alias='srl_nokia-interfaces-dco:rx-los-thresh', ge=-30.0, le=-13.0),
    ] = -2300
    """
    Average input power LOS threshold
    """
    module_state: Annotated[
        Optional[EnumerationEnum19],
        Field(alias='srl_nokia-interfaces-dco:module-state'),
    ] = None
    """
    Indicates the state of the coherent optical module.
    """
    module_tx_turn_up_states: Annotated[
        Optional[List[EnumerationEnum20]],
        Field(alias='srl_nokia-interfaces-dco:module-tx-turn-up-states'),
    ] = []
    """
    Indicates the completed transmitted turn-up states of the coherent optical module
    """
    module_rx_turn_up_states: Annotated[
        Optional[List[EnumerationEnum21]],
        Field(alias='srl_nokia-interfaces-dco:module-rx-turn-up-states'),
    ] = []
    """
    Indicates the completed received turn-up states of the coherent optical module
    """
    rx_electrical_snr_x_polarization: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:rx-electrical-snr-x-polarization',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the network received electrical SNR (Signal-to-Noise Ratio) of X polarization.
    """
    rx_electrical_snr_y_polarization: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:rx-electrical-snr-y-polarization',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the network received electrical SNR (Signal-to-Noise Ratio) of Y polarization.
    """
    rx_quality_margin: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:rx-quality-margin',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the received quality margin.
    """
    rx_optical_snr_x_polarization: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:rx-optical-snr-x-polarization',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the network received estimated optical SNR (Signal-to-Noise Ratio) of X polarization.
    """
    rx_optical_snr_y_polarization: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces-dco:rx-optical-snr-y-polarization',
            ge=-9.223372036854776e17,
            le=9.223372036854776e17,
        ),
    ] = None
    """
    Indicates the network received estimated optical SNR (Signal-to-Noise Ratio) of Y polarization.
    """
    current_alarms: Annotated[
        Optional[List[EnumerationEnum22]],
        Field(alias='srl_nokia-interfaces-dco:current-alarms'),
    ] = []
    """
    Indicates the coherent optical alarms currently active on the port.
    """
    defect_points: Annotated[
        Optional[List[EnumerationEnum23]],
        Field(alias='srl_nokia-interfaces-dco:defect-points'),
    ] = []
    """
    Indicates the coherent optical defect points currently active on the port.
    """
    sweep: Annotated[
        Optional[SweepContainer], Field(alias='srl_nokia-interfaces-dco:sweep')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer2],
        Field(alias='srl_nokia-interfaces-dco:statistics'),
    ] = None
    transmit_power: Annotated[
        Optional[TransmitPowerContainer],
        Field(alias='srl_nokia-interfaces-dco:transmit-power'),
    ] = None
    logical_channel: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-dco:logical-channel', ge=0, le=4294967295),
    ] = None
    """
    Logical channel associated to this optical channel

    This is used to assist with the openconfig management of DCO using logical channels
    """


class PciContainer(BaseModel):
    """
    Top-level container for state related to PCI interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-vxdp:address',
            pattern='^(?=^[a-zA-Z0-9]{4}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}\\.[a-zA-Z0-9]$).*$',
        ),
    ] = None
    """
    PCI address of the interface, unpopulated if interface is not present on PCI

    Unpopulated if interface is not available for PCI passthrough. This format follows the extended Domain:Bus:Device.Function (or BDF) notation. In most cases domain will be padded with four 0000's.
    """
    socket_id: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-vxdp:socket-id', ge=0, le=255)
    ] = None
    """
    Socket this interface is physically or logically attached to

    This field is not populated for interfaces that have no socket preference - e.g. veth, tap.
    """
    socket_cpus: Annotated[
        Optional[List[SocketCpusLeafList2]],
        Field(alias='srl_nokia-interfaces-vxdp:socket-cpus'),
    ] = []
    """
    List of CPUs present on the socket this interface is attached to
    """
    vendor_name: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:vendor-name')
    ] = None
    """
    PCI device vendor
    """
    vendor_id: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:vendor-id')
    ] = None
    """
    PCI device vendor ID

    This field is the two byte vendor ID reported over PCI.
    """
    device_name: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:device-name')
    ] = None
    """
    PCI device name
    """
    device_id: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vxdp:device-id')
    ] = None
    """
    PCI device ID

    This field is the two byte device ID reported over PCI.
    """
    subsystem: Annotated[
        Optional[SubsystemContainer], Field(alias='srl_nokia-interfaces-vxdp:subsystem')
    ] = None


class PopulateListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    route_type: Annotated[
        EnumerationEnum47, Field(alias='srl_nokia-interfaces-nbr:route-type')
    ]
    """
    Controls what type of ARP or ND entries generate a host route.
    """
    datapath_programming: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:datapath-programming')
    ] = None
    """
    When set to true, the host route is programmed in the datapath
    """
    internal_tags: Annotated[
        Optional[InternalTagsContainer],
        Field(alias='srl_nokia-interfaces-nbr:internal-tags'),
    ] = None


class PopulateListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    route_type: Annotated[
        EnumerationEnum59, Field(alias='srl_nokia-interfaces-nbr:route-type')
    ]
    """
    Controls what type of ARP or ND entries generate a host route.
    """
    datapath_programming: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:datapath-programming')
    ] = None
    """
    When set to true, the host route is programmed in the datapath
    """
    internal_tags: Annotated[
        Optional[InternalTagsContainer3],
        Field(alias='srl_nokia-interfaces-nbr:internal-tags'),
    ] = None


class PrefixListEntry(BaseModel):
    """
    The list of IPv6 prefixes to advertise in the router advertisement messages.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv6_prefix: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-router-adv:ipv6-prefix',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$',
        ),
    ]
    """
    An IPv6 global unicast address prefix.
    """
    autonomous_flag: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-router-adv:autonomous-flag')
    ] = True
    """
    When this is set in the prefix information option hosts can use the prefix for stateless address autoconfiguration (SLAAC). 
    """
    on_link_flag: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-router-adv:on-link-flag')
    ] = True
    """
    When this is set in the prefix information option hosts can use the prefix for on-link determination.
    """
    preferred_lifetime: Annotated[
        Optional[Union[EnumerationEnum65, PreferredLifetimeLeaf1]],
        Field(alias='srl_nokia-interfaces-router-adv:preferred-lifetime'),
    ] = '604800'
    """
    The length of time in seconds (relative to the time the packet is sent) that addresses generated from the prefix via stateless address autoconfiguration remain preferred.
    """
    valid_lifetime: Annotated[
        Optional[Union[EnumerationEnum66, ValidLifetimeLeaf1]],
        Field(alias='srl_nokia-interfaces-router-adv:valid-lifetime'),
    ] = '2592000'
    """
    The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for the purpose of on-link determination. 
    """


class ResultListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    id: Annotated[
        str,
        Field(
            alias='srl_nokia-packet-link-qual:id',
            pattern="^(?=^[<>A-Za-z0-9!@#$%^&()|+=`~.,'/_:;?-][<>A-Za-z0-9 !@#$%^&()|+=`~.,'/_:;?-]*$).*$",
        ),
    ]
    """
    Packet link qualification test ID
    """
    oper_state: Annotated[
        Optional[EnumerationEnum84],
        Field(alias='srl_nokia-packet-link-qual:oper-state'),
    ] = None
    """
    State of the qualification test
    """
    packets_sent: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:packets-sent',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of packets sent
    """
    packets_received: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:packets-received',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of packets received
    """
    packets_error: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:packets-error',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of packets transmitted that experienced corruption
    """
    packets_dropped: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:packets-dropped',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Number of packets dropped
    """
    start_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-packet-link-qual:start-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Start time of the test
    """
    end_time: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-packet-link-qual:end-time',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    End time of the test
    """
    expected_rate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:expected-rate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Expected rate of the test

    This is the computed or
    observed rate that the service expected to be maintained
    throughout the qualification duration.
    """
    qualification_rate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-packet-link-qual:qualification-rate',
            ge=0,
            le=18446744073709551615,
        ),
    ] = None
    """
    Observed rate of the test

    This is the computed or
    observed rate that the service expected to be maintained
    throughout the qualification duration.
    """
    status: Annotated[
        Optional[EnumerationEnum85], Field(alias='srl_nokia-packet-link-qual:status')
    ] = None
    """
    Status of the test

    Only set when the test is in the error state.
    """
    status_message: Annotated[
        Optional[str], Field(alias='srl_nokia-packet-link-qual:status-message')
    ] = None
    """
    Status message of the test

    Only set when the test is in the error state.
    """


class RouterRoleContainer(BaseModel):
    """
    IPv6 router advertisement options that apply when the role of the interface is a router interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-router-adv:admin-state'),
    ] = 'disable'
    """
    Administratively enable or disable the sending of router advertisements on the subinterface.
    """
    current_hop_limit: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-router-adv:current-hop-limit', ge=0, le=255),
    ] = 64
    """
    The current hop limit to advertise in the router advertisement messages.
    """
    ip_mtu: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-router-adv:ip-mtu', ge=1280, le=9486),
    ] = None
    """
    The IP MTU to advertise in the router advertisement messages and that hosts should associate with the link on which these messages are received.

    If no value is specified the option is not included.
    """
    managed_configuration_flag: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-router-adv:managed-configuration-flag'),
    ] = False
    """
    When this is set the M-bit is set in the router advertisement messages, indicating that hosts should use DHCPv6 to obtain IPv6 addresses.
    """
    other_configuration_flag: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-router-adv:other-configuration-flag'),
    ] = False
    """
    When this is set the O-bit is set in the router advertisement messages, indicating that hosts should use DHCPv6 to obtain other configuration information (besides addresses).
    """
    max_advertisement_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-router-adv:max-advertisement-interval',
            ge=4,
            le=1800,
        ),
    ] = 600
    """
    The maximum time between sending router advertisement messages to the all-nodes multicast address.

    Each subinterface has its own timer. Whenever the timer fires the message is sent and then the timer is reset to a uniformly distributed random value between min-advertisement-interval and max-advertisement-interval. The RA message can be sent before timer expiry in response to a RS message.
    """
    min_advertisement_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-router-adv:min-advertisement-interval',
            ge=3,
            le=1350,
        ),
    ] = 200
    """
    The minimum time between sending router advertisement messages to the all-nodes multicast address.

    Each subinterface has its own timer. Whenever the timer fires the message is sent and then the timer is reset to a uniformly distributed random value between min-advertisement-interval and max-advertisement-interval. The RA message can be sent before timer expiry in response to a RS message.
    """
    reachable_time: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-router-adv:reachable-time', ge=0, le=3600000),
    ] = 0
    """
    The time, in milliseconds, that is advertised as the reachable time in RA messages and that hosts use for the ICMPv6 Neighbor Unreachability Detection algorithm. A value of zero means unspecified by this router.
    """
    retransmit_time: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-router-adv:retransmit-time', ge=0, le=1800000
        ),
    ] = 0
    """
    The time, in milliseconds, that is advertised as the retrans-timer in RA messages and that hosts use for address resolution and the Neighbor Unreachability Detection algorithm. It represents the time between retransmitted NS messages. A value of zero means unspecified by this router.
    """
    router_lifetime: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-router-adv:router-lifetime', ge=0, le=9000),
    ] = 1800
    """
    The lifetime in seconds that is advertised as the router lifetime in RA messages. This indicates the time period for which the advertising router can be used as a default router/gateway. A value of 0 means the router should not be used as a default gateway.
    """
    prefix: Annotated[
        Optional[List[PrefixListEntry]],
        Field(alias='srl_nokia-interfaces-router-adv:prefix'),
    ] = None


class ServerListEntry(BaseModel):
    """
    Reports the resolved IP address for server entries using domain names
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    domain: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:domain',
            pattern='^(?=^((([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)|\\.$).*$',
        ),
    ]
    """
    The server domain name
    """
    resolved_ip_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:resolved-ip-address'),
    ] = None
    """
    The resolved IP address of the server domain name.

    An entry of 0.0.0.0 indicates the server IP cannot be resolved.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of the server IP address
    """


class ServerListEntry2(BaseModel):
    """
    Reports the resolved IP address for server entries using domain names
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    domain: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:domain',
            pattern='^(?=^((([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)|\\.$).*$',
        ),
    ]
    """
    The server domain name
    """
    resolved_ip_address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:resolved-ip-address'),
    ] = None
    """
    The resolved IP address of the server domain name.

    An entry of 0.0.0.0 indicates the server IP cannot be resolved.
    """
    last_update: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:last-update',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the last update of the server IP address
    """


class SflowContainer(BaseModel):
    """
    Context to configure sFlow parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = None
    """
    Administratively enable or disable sFlow on this interface
    """
    ingress_sampling_rate: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:ingress-sampling-rate', ge=0, le=2000000),
    ] = None
    """
    Specify sFlow Ingress packet sample rate.
    This value is the rate at which traffic will be sampled at a rate of 1:N received packets.
    """
    egress_sampling_rate: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:egress-sampling-rate', ge=0, le=2000000),
    ] = None
    """
    Specify sFlow Egress packet sample rate.
    This value is the rate at which traffic will be sampled at a rate of 1:N received packets.
    """


class SingleTaggedRangeContainer(BaseModel):
    """
    When present, tagged frames with a specific, non-zero, outer VLAN ID contained in a specified set of range are associated to the subinterface

    The outer VLAN ID tag of the frame is not stripped off on ingress, and no tag is pushed on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    low_vlan_id: Annotated[
        Optional[List[LowVlanIdListEntry]],
        Field(alias='srl_nokia-interfaces-vlans:low-vlan-id'),
    ] = None


class SingleTaggedContainer(BaseModel):
    """
    When present, tagged frames with a specific, non-zero, outer VLAN ID are associated to the subinterface

    The outer VLAN-ID tag is considered service delimiting and it is by default stripped at ingress and restored/added on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vlan_id: Annotated[
        Optional[Union[VlanIdType, EnumerationEnum80]],
        Field(alias='srl_nokia-interfaces-vlans:vlan-id'),
    ] = None
    """
    VLAN identifier for single-tagged packets
    """


class SsmContainer(BaseModel):
    """
    This struct containing all attributes for QL/SSM with SyncE in these ports.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Configure the administrative state for SyncE in line/client ports.
    When enabled, the associated transmit and receiver ports are set to
    synchronous mode and ESMC/SSM processing is enabled.
    Otherwise, all syncE functions are disabled in the port.
    """


class StatisticsContainer16(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    active_entries: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-bridge-table-statistics:active-entries',
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
            alias='srl_nokia-interfaces-bridge-table-statistics:total-entries',
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
            alias='srl_nokia-interfaces-bridge-table-statistics:failed-entries',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    The total number of macs, which have not been programmed on atleast one slot
    """
    mac_type: Annotated[
        Optional[List[MacTypeListEntry]],
        Field(alias='srl_nokia-interfaces-bridge-table-statistics:mac-type'),
    ] = None


class StatisticsContainer4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    total_in_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-dot1x:total-in-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    System or interface level total incoming dot1x frames

    Cumulative of all Ethernet interfaces or specific interface including the tunneled, discarded and copy-to-cpu dot1x frames.
    """
    total_in_discarded_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-dot1x:total-in-discarded-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    System or interface level incoming do1x discarded frames

    Cumulative of all Ethernet interfaces or specific interface including all the discarded dot1x frames.
    """
    in_tunneled_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-dot1x:in-tunneled-packets', ge=0, le=18446744073709551615
        ),
    ] = 0
    """
    System or interface level incoming 802.1x tunneled frames

    Cumulative of all Ethernet interfaces including all the tunneled 802.1x frames.
    802.1x frames are identified by a destination MAC value of 01:80:c2:00:00:03 and EtherType value of 0x888e.
    """
    in_trap_to_cpu_packets: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-dot1x:in-trap-to-cpu-packets',
            ge=0,
            le=18446744073709551615,
        ),
    ] = 0
    """
    System or interface level incoming 802.1x frames copied to CPU

    Cumulative of all Ethernet interfaces including all the copy-to-cpu 802.1x frames.
    802.1x frames are identified by a destination MAC value of 01:80:c2:00:00:03 and EtherType value of 0x888e.
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-dot1x:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Timestamp of the last time the 802.1x counters were cleared
    """


class StormControlContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    units: Annotated[
        Optional[EnumerationEnum30], Field(alias='srl_nokia-interfaces:units')
    ] = 'percentage'
    """
    Units of storm-control policer in kbps or percentage of the interface bandwidth
    """
    broadcast_rate: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:broadcast-rate', ge=0, le=132000000),
    ] = None
    """
    The maximum rate allowed for ingress broadcast frames on the interface

    The rate can be set in multiple of 64kbps. If the rate is configured to any value
    in the 1-127 kbps range, the effective rate will be 64kbps and shown in the
    operational rate. If any value in the 128-191 range, the effective rate will be
    128kbps and shown in the operational rate, and so on for higher rates. When the
    rate is set to zero, all the broadcast traffic in the interface is discarded.

    The maximum rate that can be effectively configured in 7220 D4/D5 platforms is
    132000000. When a configured percentage exceeds that value, the maximum supported
    rate is set and shown in the operational-broadcast-rate.
    """
    multicast_rate: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:multicast-rate', ge=0, le=132000000),
    ] = None
    """
    The maximum rate allowed for ingress multicast frames on the interface

    The rate can be set in multiple of 64kbps. If the rate is configured to any value
    in the 1-127 kbps range, the effective rate will be 64kbps and shown in the
    operational rate. If any value in the 128-191 range, the effective rate will be
    128kbps and shown in the operational rate, and so on for higher rates. When the
    rate is set to zero, all the multicast traffic in the interface is discarded.

    The maximum rate that can be effectively configured in 7220 D4/D5 platforms is
    132000000. When a configured percentage exceeds that value, the maximum supported
    rate is set and shown in the operational-multicast-rate.
    """
    unknown_unicast_rate: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:unknown-unicast-rate', ge=0, le=132000000),
    ] = None
    """
    The maximum rate allowed for ingress unknown unicast frames on the interface

    The rate can be set in multiple of 64kbps. If the rate is configured to any value
    in the 1-127 kbps range, the effective rate will be 64kbps and shown in the
    operational rate. If any value in the 128-191 range, the effective rate will be
    128kbps and shown in the operational rate, and so on for higher rates. When the
    rate is set to zero, all the unknown unicast traffic in the interface is discarded.

    The maximum rate that can be effectively configured in 7220 D4/D5 platforms is
    132000000. When a configured percentage exceeds that value, the maximum supported
    rate is set and shown in the operational-multicast-rate.
    """
    operational_broadcast_rate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:operational-broadcast-rate', ge=0, le=4294967295
        ),
    ] = None
    """
    The operational maximum rate for ingress broadcast frames programmed on the interface
    """
    operational_multicast_rate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:operational-multicast-rate', ge=0, le=4294967295
        ),
    ] = None
    """
    The operational maximum rate for ingress multicast frames programmed on the interface
    """
    operational_unknown_unicast_rate: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:operational-unknown-unicast-rate',
            ge=0,
            le=4294967295,
        ),
    ] = None
    """
    The operational maximum rate for ingress unknown unicast frames programmed on the interface
    """
    rising_threshold_action: Annotated[
        Optional[EnumerationEnum31],
        Field(alias='srl_nokia-interfaces:rising-threshold-action'),
    ] = 'none'
    """
    Configures the action triggered when traffic exceeds the configured storm-control rates
    """


class StpContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:admin-state'),
    ] = 'enable'
    """
    Administratively enable or disable the STP protocol for this interface
    When STP on the network instance is administratively disabled,
    any BPDUs are forwarded transparently.
    When STP on the network instance is administratively enabled,
    but the administrative state on a sub-interface is disabled,
    BPDUs received on such a subinterface are discarded.
    """
    port_number: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:port-number', ge=0, le=2047),
    ] = 0
    """
    The virtual port number uniquely identifies subinterface within
    configuration BPDUs. The internal representation is unique to a system
    and has a reference space much bigger than the 12 bits definable in a
    configuration BPDU. STP takes the internal representation value and
    identifies it with its own virtual port number that is unique to every
    other subinterface defined on the Mac-Vrf. The virtual port number is
    assigned at the time that the subinterface is added to the Mac-Vrf.
    The virtual port number can be specified explicitly

    Default port number : 0 - System generated
    Range 1 to 2047  
    """
    priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:priority', ge=16, le=255),
    ] = 128
    """
    The port-priority command is used to populate the priority portion
    of the bridge ID field within outbound BPDUs (the most significant 4
    bits of the bridge ID). It is also used as part of the decision process
    when determining the best BPDU between messages received and sent.
    When running MSTP, this is the bridge priority used for the CIST.

    All values are truncated to multiples of 4096, conforming with
    IEEE 802.1t and 802.1D-2004.
    """
    path_cost: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:path-cost', ge=1, le=65535),
    ] = 16
    """
    The interface path-cost is used by STP to calculate the path cost
    to the root bridge. STP defined this as a function of link bandwidth
    but this configuration is static.
    """
    edge_port: Annotated[
        Optional[EnumerationEnum73],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:edge-port'),
    ] = 'no'
    """
    When subInterface is participating in STP it will experience delays,
    timeouts and onboarding new devices would be difficult. Edge ports
    are connected to end devices that do not speak STP and hence the
    interfaces aren't expected to receive xSTP BPDUs. Setting edge port
    indicates the interface is access edge and STP OPER_EDGE is set to true.
    This flag dictates that STP transitions to the Forwarding state without
    waiting for Bpdu with agreement flag set. If STP bpdu is received on
    Edge port OPER_EDGE is made to false. (without changing configured valued)
    Now the interface will switch back to the normal mode of timer-based
    transitioning. User needs to do shut-no-shut manually to put it back to
    configurated value
    """
    auto_edge: Annotated[
        Optional[EnumerationEnum74],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:auto-edge'),
    ] = 'no'
    """
    When auto-edge is enabled, STP will send bpdu to determine if there
    exists a rstp peer. Upon receiving no response, the port is determined
    as edge-port. Auto-Edge is enabled by default. It dynamically sets the
    value of OPER_EDGE to true/false based on if stp bpdu is received on
    the interface. 
    """
    link_type: Annotated[
        Optional[EnumerationEnum75],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:link-type'),
    ] = 'pt-pt'
    root_guard: Annotated[
        Optional[EnumerationEnum76],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:root-guard'),
    ] = 'no'
    mst_instance: Annotated[
        Optional[List[MstInstanceListEntry]],
        Field(alias='srl_nokia-interfaces-bridge-table-stp:mst-instance'),
    ] = None


class SymbolMonitorContainer(BaseModel):
    """
    Parameters for ethernet symbol monitoring

    Both a signal degrade and signal error threshold can be defined.
    Crossing of the signal degrade threshold triggers a notification
    Crossing of the signal failure threshold changes the interface operational state to down.
    Each threshold is defined using an exponent (N) and a multiplier (M) using the formula M*10E-N.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Administrative state of symbol monitoring on the port
    """
    window_size: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:window-size', ge=5, le=60)
    ] = 10
    """
    Sliding window size over which errors are measured
    """
    signal_degrade: Annotated[
        Optional[SignalDegradeContainer2],
        Field(alias='srl_nokia-interfaces:signal-degrade'),
    ] = None
    signal_failure: Annotated[
        Optional[SignalFailureContainer2],
        Field(alias='srl_nokia-interfaces:signal-failure'),
    ] = None
    current_alarms: Annotated[
        Optional[List[EnumerationEnum28]],
        Field(alias='srl_nokia-interfaces:current-alarms'),
    ] = []
    """
    Current alarms of the Ethernet symbol monitoring, raised when corresponding threshold is exceeded
    """


class SynceContainer(BaseModel):
    """
    This struct containing all attributes for SyncE in line/client ports.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ssm: Annotated[Optional[SsmContainer], Field(alias='srl_nokia-interfaces:ssm')] = (
        None
    )


class TraceOptionsContainer(BaseModel):
    """
    Container for tracing DHCPv4 relay operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace: Annotated[
        Optional[List[EnumerationEnum52]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:trace'),
    ] = []
    """
    List of events to trace
    """


class TraceOptionsContainer2(BaseModel):
    """
    Container for tracing DHCPv4 operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace: Annotated[
        Optional[List[EnumerationEnum53]],
        Field(alias='srl_nokia-interfaces-ip-dhcp:trace'),
    ] = []
    """
    List of events to trace
    """


class TraceOptionsContainer3(BaseModel):
    """
    Container for tracing DHCPv6 relay operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace: Annotated[
        Optional[List[EnumerationEnum64]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:trace'),
    ] = []
    """
    List of events to trace
    """


class TraceOptionsContainer4(BaseModel):
    """
    Container for tracing DHCPv6 operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace: Annotated[
        Optional[List[EnumerationEnum68]],
        Field(alias='srl_nokia-interfaces-ip-dhcp:trace'),
    ] = []
    """
    List of events to trace
    """


class TrackInterfaceListEntry(BaseModel):
    """
    Interface reference for interface tracking.
    VRRP Group can track multiple interfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface: Annotated[str, Field(alias='srl_nokia-interfaces-ip-vrrp:interface')]
    """
    Interface to track
    """
    priority_decrement: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:priority-decrement', ge=0, le=255),
    ] = None
    """
    For each tracked interface that is down then the priority
    is decremented by the specific amount to a minimum value of 0
    """


class TrackInterfaceListEntry2(BaseModel):
    """
    Interface reference for interface tracking.
    VRRP Group can track multiple interfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface: Annotated[str, Field(alias='srl_nokia-interfaces-ip-vrrp:interface')]
    """
    Interface to track
    """
    priority_decrement: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:priority-decrement', ge=0, le=255),
    ] = None
    """
    For each tracked interface that is down then the priority
    is decremented by the specific amount to a minimum value of 0
    """


class TransceiverContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    functional_type: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:functional-type')
    ] = None
    """
    Indicates the module functional type which will be deployed for this interface

    This refines the set of leaves available within the transceiver configuration.
    """
    tx_laser: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:tx-laser')
    ] = None
    """
    Enable (true) or disable (false) the transmit laser of the transceiver

    When read from state this leaf always returns false (even if the configured value is true) when the Ethernet port is a copper/RJ45 port.

    Default is true (for interfaces that support transceivers).
    """
    oper_state: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-interfaces:oper-state')
    ] = None
    """
    The operational state of the transceiver

    The oper-state is always down when the Ethernet port is a copper/RJ45 port.
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum10],
        Field(alias='srl_nokia-interfaces:oper-down-reason'),
    ] = None
    """
    The reason for the transceiver being operationally down
    """
    ddm_events: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:ddm-events')
    ] = None
    """
    Controls the reporting of DDM events

    When set to true, log events related to the Digital Diagnostic Monitoring (DDM) capabilities of the transceiver are generated.

    When set to false, no DDM-related log events are generated for this port/transceiver.

    When read from state this leaf always returns false (even if the configured value is true) when the Ethernet port is a copper/RJ45 port.
    """
    form_factor: Annotated[
        Optional[EnumerationEnum11], Field(alias='srl_nokia-interfaces:form-factor')
    ] = None
    """
    Specifies the transceiver form factor associated with the port
    """
    ethernet_pmd: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:ethernet-pmd')
    ] = None
    """
    Specifies the Ethernet compliance code of the transceiver associated with the port
    """
    connector_type: Annotated[
        Optional[EnumerationEnum12], Field(alias='srl_nokia-interfaces:connector-type')
    ] = None
    """
    Specifies the fiber connector type of the transceiver associated with the port
    """
    vendor: Annotated[Optional[str], Field(alias='srl_nokia-interfaces:vendor')] = None
    """
    Name of the transceiver vendor

    This is the information as read from the EEPROM of the part.
    """
    vendor_part_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-part-number')
    ] = None
    """
    Vendor's part number for the transceiver

    This is the information as read from the EEPROM of the part.
    """
    vendor_revision: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-revision')
    ] = None
    """
    Vendor's revision number for the transceiver

    This is the information as read from the EEPROM of the part.
    """
    vendor_lot_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:vendor-lot-number')
    ] = None
    """
    Vendor's lot number for the transceiver

    This is the information as read from the EEPROM of the part.
    """
    serial_number: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:serial-number')
    ] = None
    """
    Transceiver serial number

    This is the information as read from the EEPROM of the part.
    """
    date_code: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:date-code',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Transceiver date code.
    """
    firmware_version: Annotated[
        Optional[FirmwareVersionContainer],
        Field(alias='srl_nokia-interfaces:firmware-version'),
    ] = None
    fault_condition: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:fault-condition')
    ] = None
    """
    Indicates if a fault condition exists in the transceiver.
    """
    wavelength: Annotated[
        Optional[float],
        Field(
            alias='srl_nokia-interfaces:wavelength',
            ge=-9.223372036854776e16,
            le=9.223372036854776e16,
        ),
    ] = None
    """
    Wavelength of the transmitting laser in nanometers
    """
    temperature: Annotated[
        Optional[TemperatureContainer], Field(alias='srl_nokia-interfaces:temperature')
    ] = None
    voltage: Annotated[
        Optional[VoltageContainer], Field(alias='srl_nokia-interfaces:voltage')
    ] = None
    channel: Annotated[
        Optional[List[ChannelListEntry]], Field(alias='srl_nokia-interfaces:channel')
    ] = None
    healthz: Annotated[
        Optional[HealthzContainer], Field(alias='srl_nokia-platform-healthz:healthz')
    ] = None
    optical_channel: Annotated[
        Optional[List[OpticalChannelListEntry]],
        Field(alias='srl_nokia-interfaces-dco:optical-channel'),
    ] = None
    supported_operational_mode: Annotated[
        Optional[List[EnumerationEnum14]],
        Field(alias='srl_nokia-interfaces-dco:supported-operational-mode'),
    ] = []
    """
    Operational modes supported by the installed transceiver

    Lists the operational-modes supported by the installed transceiver.  If no transceiver is installed, nothing is reported.
    """


class TunnelContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel_all: Annotated[Optional[bool], Field(alias='srl_nokia-dot1x:tunnel-all')] = (
        False
    )
    """
    tunnel all dot1x PDUs through the interface

    tunnel untagged and tagged dot1x PDUs.
    """
    untagged: Annotated[Optional[bool], Field(alias='srl_nokia-dot1x:untagged')] = False
    """
    tunnel untagged dot1x PDUs through the interface
    """
    single_tagged: Annotated[
        Optional[bool], Field(alias='srl_nokia-dot1x:single-tagged')
    ] = True
    """
    tunnel single tagged dot1x PDUs through the interface
    """
    double_tagged: Annotated[
        Optional[bool], Field(alias='srl_nokia-dot1x:double-tagged')
    ] = True
    """
    tunnel double tagged dot1x PDUs through the interface
    """
    statistics: Annotated[
        Optional[StatisticsContainer4], Field(alias='srl_nokia-dot1x:statistics')
    ] = None


class UnnumberedContainer(BaseModel):
    """
    Top-level container for configuring unnumbered interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    When enabled, the subinterface should operate in unnumbered mode for IPv4
    """
    interface: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:interface')
    ] = None
    """
    Reference to the subinterface with the IPv4 address to be borrowed
    """
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    The operational IPv4 address borrowed from the referenced subinterface
    """
    unavailable_address_reason: Annotated[
        Optional[EnumerationEnum44],
        Field(alias='srl_nokia-interfaces:unavailable-address-reason'),
    ] = None
    """
    The reason why there is no operational IPv4 address to use for this subinterface
    """


class VlanDiscoveryContainer(BaseModel):
    """
    When present the subinterface should perform vlan discovery by broadcasting dhcp message on all vlanids
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        Optional[EnumerationEnum79], Field(alias='srl_nokia-interfaces-vlans:type')
    ] = 'IPv4v6'
    """
    Types of addresses over which vlan discovery is performed
    """


class AddressListEntry2(BaseModel):
    """
    The list of virtual IPv4 addresses to be discovered on the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:ipv4-address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ]
    """
    The virtual IPv4 address.
    """
    allowed_macs: Annotated[
        Optional[List[AllowedMacsLeafList]],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:allowed-macs'),
    ] = []
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """
    probe_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-interval',
            ge=0,
            le=86400,
        ),
    ] = 0
    """
    Configure the ARP probe interval at which the system sends an ARP request for the
    virtual IPv4 address.

    The default value of zero determines that the system sends an ARP Request for the
    virtual IPv4 only when the address is configured. The creation of the ARP entry for
    the virtual IPv4 address will in this case rely on the server sending a Gratuitous ARP
    for the virtual IPv4 address. When the value is set to a non-zero interval, the system
    sends a periodic ARP Request at the configured interval and irrespective of the ARP entry
    being already created.
    """
    probe_bridged_subinterfaces: Annotated[
        Optional[List[str]],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-bridged-subinterfaces'
        ),
    ] = []
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the ARP
    probes are sent.
    """
    statistics: Annotated[
        Optional[StatisticsContainer7],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics'),
    ] = None


class AddressListEntry4(BaseModel):
    """
    The list of virtual IPv6 addresses to be discovered on the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv6_address: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:ipv6-address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ]
    """
    The virtual IPv6 address.
    """
    allowed_macs: Annotated[
        Optional[List[AllowedMacsLeafList2]],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:allowed-macs'),
    ] = []
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """
    probe_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-interval',
            ge=0,
            le=86400,
        ),
    ] = 0
    """
    Configure the probe interval at which the system sends a Neighbor Solicitation (NS) for
    the virtual IPv6 address.

    The default value of zero determines that the system sends a NS for the
    virtual IPv6 only when the address is configured. The creation of the Neighbor entry for
    the virtual IPv6 address will in this case rely on the server sending an unsolicited
    Neighbor Advertisement for the virtual IPv6 address. When the value is set to a non-zero interval, the system
    sends a periodic NS at the configured interval and irrespective of the Neighbor entry
    being already created.
    """
    probe_bridged_subinterfaces: Annotated[
        Optional[List[str]],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-bridged-subinterfaces'
        ),
    ] = []
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the NS
    probes are sent.
    """
    statistics: Annotated[
        Optional[StatisticsContainer12],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics'),
    ] = None


class AdvertiseListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    route_type: Annotated[
        EnumerationEnum49, Field(alias='srl_nokia-interfaces-nbr-evpn:route-type')
    ]
    """
    Controls what type of ARP or ND entries to advertise.
    """
    internal_tags: Annotated[
        Optional[InternalTagsContainer2],
        Field(alias='srl_nokia-interfaces-nbr-evpn:internal-tags'),
    ] = None


class AdvertiseListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    route_type: Annotated[
        EnumerationEnum61, Field(alias='srl_nokia-interfaces-nbr-evpn:route-type')
    ]
    """
    Controls what type of ARP or ND entries to advertise.
    """
    internal_tags: Annotated[
        Optional[InternalTagsContainer4],
        Field(alias='srl_nokia-interfaces-nbr-evpn:internal-tags'),
    ] = None


class AuthenticatedSessionListEntry(BaseModel):
    """
    The list of authenticated sessions on this device
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        str,
        Field(
            alias='srl_nokia-dot1x:mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ]
    """
    Authenticated device source MAC address
    """
    hosts: Annotated[Optional[HostsContainer], Field(alias='srl_nokia-dot1x:hosts')] = (
        None
    )


class AuthenticatedSessionsContainer(BaseModel):
    """
    Top level container for authenticated sessions state data
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    authenticated_session: Annotated[
        Optional[List[AuthenticatedSessionListEntry]],
        Field(alias='srl_nokia-dot1x:authenticated-session'),
    ] = None


class AuthenticationContainer(BaseModel):
    """
    Context to configure authentication keychain
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    keychain: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:keychain',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a keychain. The keychain type must be md5 or clear-text
    """


class AuthenticationContainer2(BaseModel):
    """
    Context to configure authentication keychain
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    keychain: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:keychain',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a keychain. The keychain type must be md5 or clear-text
    """


class AuthenticatorContainer(BaseModel):
    """
    configure dot1x for an authenticator
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    authenticate_port: Annotated[
        Optional[bool], Field(alias='srl_nokia-dot1x:authenticate-port')
    ] = True
    """
    Enable IEEE802.1X port control on an interface
    """
    port_control: Annotated[
        Optional[EnumerationEnum32], Field(alias='srl_nokia-dot1x:port-control')
    ] = 'force-authorized'
    """
    IEEE802.1x authentication mode
    """
    authenticator_initiated: Annotated[
        Optional[bool], Field(alias='srl_nokia-dot1x:authenticator-initiated')
    ] = True
    """
    When true the authenticator sends an EAP-Request/EAP-Identity to the Supplicant
    """
    host_mode: Annotated[
        Optional[EnumerationEnum33], Field(alias='srl_nokia-dot1x:host-mode')
    ] = None
    """
    Allow for single or multiple hosts to communicate through an IEEE802.1X controlled port
    """
    reauthenticate_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-dot1x:reauthenticate-interval', ge=0, le=65535),
    ] = None
    """
    Enable periodic re-authentication of the device connected to this port

    Send out a identity request once every unit seconds.
    Setting a value of 0 disables re-authentication on this port.
    """
    retransmit_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-dot1x:retransmit-interval', ge=0, le=65535),
    ] = None
    """
    How long the interface waits for a response before restarting authentication

    How long the interface waits for a response from an EAPoL Start before restarting 802.1X authentication on the port.
    """
    quiet_period: Annotated[
        Optional[int], Field(alias='srl_nokia-dot1x:quiet-period', ge=1, le=3600)
    ] = 60
    """
    Time to wait after a failed session when no EAPoL frames are processed
    """
    supplicant_timeout: Annotated[
        Optional[int], Field(alias='srl_nokia-dot1x:supplicant-timeout', ge=1, le=300)
    ] = 30
    """
    Time to wait for a response from the supplicant before restarting the authentication process
    """
    max_requests: Annotated[
        Optional[int], Field(alias='srl_nokia-dot1x:max-requests', ge=1, le=10)
    ] = 2
    """
    Maximum number of times an EAPoL request packet is retransmitted to the supplicant before the authentication session fails
    """
    max_authentication_requests: Annotated[
        Optional[int],
        Field(alias='srl_nokia-dot1x:max-authentication-requests', ge=1, le=10),
    ] = 2
    """
    Maximum number of RADIUS retries before the authentication fails

    In the case of challenge response, if the supplicant does not respond
    the authenticator will retransmit the challenge without going to the radius server.
    This parameter will be used toward supplicant as well when the challenge respond is
    dropped.
    """
    multi_domain_allowed_source_macs: Annotated[
        Optional[MultiDomainAllowedSourceMacsContainer],
        Field(alias='srl_nokia-dot1x:multi-domain-allowed-source-macs'),
    ] = None
    radius_policy: Annotated[
        Optional[str], Field(alias='srl_nokia-dot1x:radius-policy')
    ] = None
    """
    RADIUS policy used for 802.1x authentication
    """
    authenticated_sessions: Annotated[
        Optional[AuthenticatedSessionsContainer],
        Field(alias='srl_nokia-dot1x:authenticated-sessions'),
    ] = None


class CrcMonitorContainer(BaseModel):
    """
    Parameters for crc frame error monitoring

    Both a signal degrade and signal error threshold can be defined.
    Crossing of the signal degrade threshold triggers a notification
    Crossing of the signal failure threshold changes the interface operational state to down.
    Each threshold is defined using an exponent (N) and a multiplier (M) using the formula M*10E-N.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Administrative state of crc monitoring on the port
    """
    window_size: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:window-size', ge=5, le=60)
    ] = 10
    """
    Sliding window size over which errors are measured
    """
    signal_degrade: Annotated[
        Optional[SignalDegradeContainer],
        Field(alias='srl_nokia-interfaces:signal-degrade'),
    ] = None
    signal_failure: Annotated[
        Optional[SignalFailureContainer],
        Field(alias='srl_nokia-interfaces:signal-failure'),
    ] = None
    current_alarms: Annotated[
        Optional[List[EnumerationEnum28]],
        Field(alias='srl_nokia-interfaces:current-alarms'),
    ] = []
    """
    Current alarms of the Ethernet CRC monitoring, raised when corresponding threshold is exceeded
    """


class DhcpClientContainer(BaseModel):
    """
    Container for options related to DHCP
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace_options: Annotated[
        Optional[TraceOptionsContainer2],
        Field(alias='srl_nokia-interfaces-ip-dhcp:trace-options'),
    ] = None


class DhcpClientContainer2(BaseModel):
    """
    Container for options related to DHCPv6
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    trace_options: Annotated[
        Optional[TraceOptionsContainer4],
        Field(alias='srl_nokia-interfaces-ip-dhcp:trace-options'),
    ] = None


class DhcpServerContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:admin-state'),
    ] = 'disable'
    """
    Enables/Disables DHCP server function on subinterface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:oper-state'),
    ] = None
    """
    Details if the dhcp server is operationally available
    """


class Dhcpv6ServerContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:admin-state'),
    ] = 'disable'
    """
    Enables/Disables DHCPv6 server function on subinterface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:oper-state'),
    ] = None
    """
    Details if the dhcp server is operationally available
    """


class DnsResolutionContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    server: Annotated[
        Optional[List[ServerListEntry]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:server'),
    ] = None


class DnsResolutionContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    server: Annotated[
        Optional[List[ServerListEntry2]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:server'),
    ] = None


class Dot1xContainer(BaseModel):
    """
    dot1x configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel: Annotated[
        Optional[TunnelContainer], Field(alias='srl_nokia-dot1x:tunnel')
    ] = None
    authenticator: Annotated[
        Optional[AuthenticatorContainer], Field(alias='srl_nokia-dot1x:authenticator')
    ] = None


class EgressMappingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vlan_stack_action: Annotated[
        Optional[EnumerationEnum83],
        Field(alias='srl_nokia-interfaces-vlans:vlan-stack-action'),
    ] = None
    """
    The action to take on the VLAN stack of a packet

    This is optionally used in conjunction with adjacent leaves to override
    the values of the action.
    """
    outer_vlan_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-vlans:outer-vlan-id', ge=1, le=4094),
    ] = None
    """
    Optionally specifies the outer VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH' then this VLAN identifier is added to
    the stack. This value must be non-zero if the 'vlan-stack-action' requires
    the addition or replacement of a VLAN tag.
    """
    outer_tpid: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vlans:outer-tpid')
    ] = None
    """
    Optionally override the outer tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """
    inner_vlan_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-vlans:inner-vlan-id', ge=1, le=4094),
    ] = None
    """
    Optionally specifies the inner VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH-PUSH' then this VLAN identifier is added to
    the stack as inner vlan-id. This value must be non-zero if the
    'vlan-stack-action' requires the addition or replacement of an inner VLAN tag.
    """
    inner_tpid: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vlans:inner-tpid')
    ] = None
    """
    Optionally override the inner tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class EncapContainer(BaseModel):
    """
    VLAN match parmeters for the associated subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    single_tagged: Annotated[
        Optional[SingleTaggedContainer],
        Field(alias='srl_nokia-interfaces-vlans:single-tagged'),
    ] = None
    untagged: Annotated[
        Optional[UntaggedContainer], Field(alias='srl_nokia-interfaces-vlans:untagged')
    ] = None
    single_tagged_range: Annotated[
        Optional[SingleTaggedRangeContainer],
        Field(alias='srl_nokia-interfaces-vlans:single-tagged-range'),
    ] = None
    double_tagged: Annotated[
        Optional[DoubleTaggedContainer],
        Field(alias='srl_nokia-interfaces-vlans:double-tagged'),
    ] = None


class EthCfmContainer(BaseModel):
    """
    Configuration of ETH-CFM functions independent of Maintenance Domain context

    This is an ETH-CFM function that is configured directly under the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ingress_squelching: Annotated[
        Optional[IngressSquelchingContainer],
        Field(alias='srl_nokia-ethcfm:ingress-squelching'),
    ] = None


class EvpnContainer(BaseModel):
    """
    Configure which types of ARP or ND entries will be advertised in EVPN MAC/IP routes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    advertise: Annotated[
        Optional[List[AdvertiseListEntry]],
        Field(alias='srl_nokia-interfaces-nbr-evpn:advertise'),
    ] = None


class EvpnContainer2(BaseModel):
    """
    Configure which types of ARP or ND entries will be advertised in EVPN MAC/IP routes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    advertise: Annotated[
        Optional[List[AdvertiseListEntry2]],
        Field(alias='srl_nokia-interfaces-nbr-evpn:advertise'),
    ] = None


class HostRouteContainer(BaseModel):
    """
    Configure which types of ARP or ND entries will be populated in the route-table.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    populate: Annotated[
        Optional[List[PopulateListEntry]],
        Field(alias='srl_nokia-interfaces-nbr:populate'),
    ] = None


class HostRouteContainer2(BaseModel):
    """
    Configure which types of ARP or ND entries will be populated in the route-table.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    populate: Annotated[
        Optional[List[PopulateListEntry2]],
        Field(alias='srl_nokia-interfaces-nbr:populate'),
    ] = None


class IngressMappingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vlan_stack_action: Annotated[
        Optional[EnumerationEnum83],
        Field(alias='srl_nokia-interfaces-vlans:vlan-stack-action'),
    ] = None
    """
    The action to take on the VLAN stack of a packet

    This is optionally used in conjunction with adjacent leaves to override
    the values of the action.
    """
    outer_vlan_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-vlans:outer-vlan-id', ge=1, le=4094),
    ] = None
    """
    Optionally specifies the outer VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH' then this VLAN identifier is added to
    the stack. This value must be non-zero if the 'vlan-stack-action' requires
    the addition or replacement of a VLAN tag.
    """
    outer_tpid: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vlans:outer-tpid')
    ] = None
    """
    Optionally override the outer tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """
    inner_vlan_id: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-vlans:inner-vlan-id', ge=1, le=4094),
    ] = None
    """
    Optionally specifies the inner VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH-PUSH' then this VLAN identifier is added to
    the stack as inner vlan-id. This value must be non-zero if the
    'vlan-stack-action' is one 'PUSH-PUSH' or 'POP-SWAP'.
    """
    inner_tpid: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-vlans:inner-tpid')
    ] = None
    """
    Optionally override the inner tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class InterfaceTrackingContainer(BaseModel):
    """
    Interface reference for interface tracking
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    track_interface: Annotated[
        Optional[List[TrackInterfaceListEntry]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:track-interface'),
    ] = None


class InterfaceTrackingContainer2(BaseModel):
    """
    Interface reference for interface tracking
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    track_interface: Annotated[
        Optional[List[TrackInterfaceListEntry2]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:track-interface'),
    ] = None


class L2cpTransparencyContainer(BaseModel):
    """
    Configuration and state of the Layer-2 Control Protocol transparency
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    tunnel_all_l2cp: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-l2cp:tunnel-all-l2cp')
    ] = False
    """
    Configures the tunneling of all the L2CP protocols.

    When set to true this command triggers the installation of an ingress TCAM rule with the highest
    priority (above all the individual L2CP tunnel rules) which allows the forwarding of any
    Layer-2 Control Protocol coming into the interface. All the L2CP frames identified by
    MAC DA = 01:80:c2:00:00:0x or MAC DA = 01:80:c2:00:00:2x, with 'x' being any hex value, are
    tunneled. When set to false, all L2CP frames without a specific L2CP tunnel rule are discarded.
    """
    lldp: Annotated[
        Optional[LldpContainer], Field(alias='srl_nokia-interfaces-l2cp:lldp')
    ] = None
    lacp: Annotated[
        Optional[LacpContainer], Field(alias='srl_nokia-interfaces-l2cp:lacp')
    ] = None
    xstp: Annotated[
        Optional[XstpContainer], Field(alias='srl_nokia-interfaces-l2cp:xstp')
    ] = None
    dot1x: Annotated[
        Optional[Dot1xContainer2], Field(alias='srl_nokia-interfaces-l2cp:dot1x')
    ] = None
    ptp: Annotated[
        Optional[PtpContainer], Field(alias='srl_nokia-interfaces-l2cp:ptp')
    ] = None
    esmc: Annotated[
        Optional[EsmcContainer], Field(alias='srl_nokia-interfaces-l2cp:esmc')
    ] = None
    elmi: Annotated[
        Optional[ElmiContainer], Field(alias='srl_nokia-interfaces-l2cp:elmi')
    ] = None
    efm_oam: Annotated[
        Optional[EfmOamContainer], Field(alias='srl_nokia-interfaces-l2cp:efm-oam')
    ] = None


class LocalMirrorDestinationContainer(BaseModel):
    """
    Container for options related to local mirror destination
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-local-mirror-destination:admin-state'),
    ] = 'enable'
    """
    The configurable state of the local mirror destination
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-local-mirror-destination:oper-state'),
    ] = None
    """
    The operational state of the local mirror destination
    """


class MacTableContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    mac: Annotated[
        Optional[List[MacListEntry3]],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-table:mac'),
    ] = None


class MemberListEntry(BaseModel):
    """
    Reports the list of interfaces associated with the LAG instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-interfaces-lag:name')]
    """
    The name of the interface

    Valid options are:
    irb<N>, N=0..255
    lif-<lif_name>
    enp<bus>s<dev>f<fn>, bus=0..255, dev=0..31, fn=0..7
    vhn-<vhn_name>
    lag<N>, N=1..1000 [note1]
    lo<N>, N=0..255
    mgmt0
    mgmt0-standby
    ethernet-<slot>/<port>
    ethernet-<slot>/<mda>/<port>
    system0
    sync0

    <lif_name>=Linux interface name
    <vhn_name>=vhost interface name
    <slot>=slot number {1,2,3,..}
    <mda>=mda id {a,b,c,d,e,f}
    <port>=port id {1,2,3,..}

    [note1] The maximum number of LAGs per platform is as follows:
     D1: 32 (N must be 1..32)
     D2-D3: 128 (N must be 1..1000)
     D4-D5: 64 (N must be 1..64)
     H2-H3: 127 (N must be 1..127)
     H4: 255 (N must be 1..255)
     IXR: 128 (N must be 1..128)
     SXR-1d-32D: 128 (N must be 1..128)
     SXR-1x-44S: 128 (N must be 1..128)
     A1: 10 (N must be 1..10)
     IXR-X1b: 512 (N must be 1..512)
     IXR-X3b: 512 (N must be 1..512)
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42], Field(alias='srl_nokia-interfaces-lag:oper-state')
    ] = None
    """
    Operational state for the associated LAG
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum89],
        Field(alias='srl_nokia-interfaces-lag:oper-down-reason'),
    ] = None
    """
    Reason for operational down state for the associated LAG
    """
    microbfd_enabled: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-lag:microbfd-enabled')
    ] = None
    """
    Indicates if microBFD is currently used in the determination of the member-link oper-status
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-lag:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the most recent change to the LAG member-link state
    """
    lacp: Annotated[Optional[LacpContainer2], Field(alias='srl_nokia-lacp:lacp')] = None


class PacketLinkQualificationContainer(BaseModel):
    """
    gNOI Packet Link Qualification results
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    result: Annotated[
        Optional[List[ResultListEntry]],
        Field(alias='srl_nokia-packet-link-qual:result'),
    ] = None


class RouterAdvertisementContainer(BaseModel):
    """
    Container for configuring IPv6 router discovery options
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    router_role: Annotated[
        Optional[RouterRoleContainer],
        Field(alias='srl_nokia-interfaces-router-adv:router-role'),
    ] = None
    debug: Annotated[
        Optional[List[EnumerationEnum67]],
        Field(alias='srl_nokia-interfaces-router-adv:debug'),
    ] = []
    """
    List of events to debug
    """


class VirtualIpv4DiscoveryContainer(BaseModel):
    """
    Enable Virtual IPv4 discovery on the subinterface and configure associated parameters

    When enabled, the system will attempt to discover the configured virtual IPv4
    addresses on the listed bridged subinterfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Optional[List[AddressListEntry2]],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:address'),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer8],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics'),
    ] = None


class VirtualIpv6DiscoveryContainer(BaseModel):
    """
    Enable Virtual IPv6 discovery on the subinterface and configure associated parameters

    When enabled, the system will attempt to discover the configured virtual IPv6
    addresses on the listed bridged subinterfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Optional[List[AddressListEntry4]],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:address'),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer13],
        Field(alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics'),
    ] = None


class VlanContainer(BaseModel):
    """
    Parameters for VLAN definition under SRL interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vlan_discovery: Annotated[
        Optional[VlanDiscoveryContainer],
        Field(alias='srl_nokia-interfaces-vlans:vlan-discovery'),
    ] = None
    encap: Annotated[
        Optional[EncapContainer], Field(alias='srl_nokia-interfaces-vlans:encap')
    ] = None
    ingress_mapping: Annotated[
        Optional[IngressMappingContainer],
        Field(alias='srl_nokia-interfaces-vlans:ingress-mapping'),
    ] = None
    egress_mapping: Annotated[
        Optional[EgressMappingContainer],
        Field(alias='srl_nokia-interfaces-vlans:egress-mapping'),
    ] = None


class VrrpGroupListEntry(BaseModel):
    """
    VRRP Group Specific Configuration under IPv4 context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    virtual_router_id: Annotated[
        int, Field(alias='srl_nokia-interfaces-ip-vrrp:virtual-router-id', ge=1, le=255)
    ]
    """
    VRRP Group Index
    """
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-vrrp:admin-state'),
    ] = 'enable'
    """
    Administrative state for the associated VRRP group instance
    """
    priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:priority', ge=1, le=254),
    ] = 100
    """
    Base VRRP Priority for associated Virtual Address
    """
    preempt: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:preempt')
    ] = None
    """
    Enable VRRP master pre-emption.
    If enabled, router with higher priority can assume
    master role.
    If disabled, router can only become master if no
    other master is present
    """
    virtual_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:virtual-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    VRRP Instance generated virtual mac
    """
    preempt_delay: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:preempt-delay', ge=1, le=65535),
    ] = None
    """
    Delay in seconds before a router preempts an existing
    master router, only applicable if preempt is enabled
    """
    init_delay: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:init-delay', ge=1, le=65535),
    ] = None
    """
    Initialization delay in seconds before a router that
    just rebooted will preempt an existing master router.
    Only applicable if preempt is enabled
    """
    accept_mode: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:accept-mode')
    ] = None
    """
    Allows ssh,ping,traceroute to be accepted on the virtual
    IP address
    """
    advertise_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertise-interval', ge=1000, le=40950
        ),
    ] = 1000
    """
    The interval between VRRP messages in milliseconds
    """
    authentication: Annotated[
        Optional[AuthenticationContainer],
        Field(alias='srl_nokia-interfaces-ip-vrrp:authentication'),
    ] = None
    interface_tracking: Annotated[
        Optional[InterfaceTrackingContainer],
        Field(alias='srl_nokia-interfaces-ip-vrrp:interface-tracking'),
    ] = None
    state: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-ip-vrrp:state')
    ] = None
    """
    Virtual Router state (Initialize, Backup, Master)
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-state'),
    ] = None
    """
    VRRP Operational state
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum43],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-down-reason'),
    ] = None
    """
    The first (and possibly only) reason for the vrrp-group being operationally down
    """
    owner: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:owner')
    ] = None
    """
    VRRP instance is owner or not
    """
    operational_priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:operational-priority', ge=0, le=255),
    ] = None
    """
    Reports the current VRRP operational priority.
    """
    master_inherit_interval: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-ip-vrrp:master-inherit-interval'),
    ] = False
    """
    Learn VRRP advertisement interval from master
    """
    oper_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-interval', ge=0, le=65535),
    ] = None
    """
    The operational advertisement interval between VRRP messages
    """
    current_master: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:current-master'),
    ] = None
    """
    IP address of node currently acting as VRRP master
    """
    last_transition: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:last-transition',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    timestamp for last master router transition
    """
    statistics: Annotated[
        Optional[StatisticsContainer5],
        Field(alias='srl_nokia-interfaces-ip-vrrp:statistics'),
    ] = None
    virtual_address: Annotated[
        Optional[List[Union[Ipv4AddressType, Ipv6AddressType]]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:virtual-address'),
    ] = []
    """
    Associated Virtual IP address.
    """
    version: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-ip-vrrp:version', ge=2, le=3)
    ] = 2
    """
    VRRP version for the Instance
    """


class VrrpGroupListEntry2(BaseModel):
    """
    VRRP Group Specific Configuration under IPv6 context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    virtual_router_id: Annotated[
        int, Field(alias='srl_nokia-interfaces-ip-vrrp:virtual-router-id', ge=1, le=255)
    ]
    """
    VRRP Group Index
    """
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-vrrp:admin-state'),
    ] = 'enable'
    """
    Administrative state for the associated VRRP group instance
    """
    priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:priority', ge=1, le=254),
    ] = 100
    """
    Base VRRP Priority for associated Virtual Address
    """
    preempt: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:preempt')
    ] = None
    """
    Enable VRRP master pre-emption.
    If enabled, router with higher priority can assume
    master role.
    If disabled, router can only become master if no
    other master is present
    """
    virtual_mac: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:virtual-mac',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    VRRP Instance generated virtual mac
    """
    preempt_delay: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:preempt-delay', ge=1, le=65535),
    ] = None
    """
    Delay in seconds before a router preempts an existing
    master router, only applicable if preempt is enabled
    """
    init_delay: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:init-delay', ge=1, le=65535),
    ] = None
    """
    Initialization delay in seconds before a router that
    just rebooted will preempt an existing master router.
    Only applicable if preempt is enabled
    """
    accept_mode: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:accept-mode')
    ] = None
    """
    Allows ssh,ping,traceroute to be accepted on the virtual
    IP address
    """
    advertise_interval: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:advertise-interval', ge=1000, le=40950
        ),
    ] = 1000
    """
    The interval between VRRP messages in milliseconds
    """
    authentication: Annotated[
        Optional[AuthenticationContainer2],
        Field(alias='srl_nokia-interfaces-ip-vrrp:authentication'),
    ] = None
    interface_tracking: Annotated[
        Optional[InterfaceTrackingContainer2],
        Field(alias='srl_nokia-interfaces-ip-vrrp:interface-tracking'),
    ] = None
    state: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces-ip-vrrp:state')
    ] = None
    """
    Virtual Router state (Initialize, Backup, Master)
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-state'),
    ] = None
    """
    VRRP Operational state
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum43],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-down-reason'),
    ] = None
    """
    The first (and possibly only) reason for the vrrp-group being operationally down
    """
    owner: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-ip-vrrp:owner')
    ] = None
    """
    VRRP instance is owner or not
    """
    operational_priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:operational-priority', ge=0, le=255),
    ] = None
    """
    Reports the current VRRP operational priority.
    """
    master_inherit_interval: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-ip-vrrp:master-inherit-interval'),
    ] = False
    """
    Learn VRRP advertisement interval from master
    """
    oper_interval: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-ip-vrrp:oper-interval', ge=0, le=65535),
    ] = None
    """
    The operational advertisement interval between VRRP messages
    """
    current_master: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:current-master'),
    ] = None
    """
    IP address of node currently acting as VRRP master
    """
    last_transition: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:last-transition',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    timestamp for last master router transition
    """
    statistics: Annotated[
        Optional[StatisticsContainer10],
        Field(alias='srl_nokia-interfaces-ip-vrrp:statistics'),
    ] = None
    virtual_address: Annotated[
        Optional[List[VirtualAddressLeafList2]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:virtual-address'),
    ] = []
    """
    Associated Virtual IP address.
    """
    version: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-ip-vrrp:version', ge=2, le=3)
    ] = 3
    """
    VRRP version for the Instance
    """
    virtual_link_local_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-vrrp:virtual-link-local-address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Generated link local address based on virtual-mac for virtual router instance
    """


class VrrpContainer(BaseModel):
    """
    VRRP Configuration and State under a IPv4 context of a
    sub-interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vrrp_group: Annotated[
        Optional[List[VrrpGroupListEntry]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:vrrp-group'),
    ] = None


class VrrpContainer2(BaseModel):
    """
    VRRP Configuration and State under a IPv6 context of a
    sub-interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    vrrp_group: Annotated[
        Optional[List[VrrpGroupListEntry2]],
        Field(alias='srl_nokia-interfaces-ip-vrrp:vrrp-group'),
    ] = None


class AddressListEntry(BaseModel):
    """
    The list of  IPv4 addresses assigned to the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ip_prefix: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces:ip-prefix',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$',
        ),
    ]
    """
    The IPv4 address and prefix length in CIDR notation

    Subnets on the same subinterface are allowed to overlap as long as the host bits are different. When a locally originated unicast packet is destined to a host covered by multiple subnets associated with a subinterface, the source address is chosen to be the numerically lowest IP address among all these subnets. For example, if the addresses 172.16.1.1/12, 172.16.1.2/12, and 172.16.1.3/12 are configured on the same interface, 172.16.1.1 would be used as a local address when you issue a ping 172.16.1.5 command
    """
    anycast_gw: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:anycast-gw')
    ] = None
    """
    This designates the associated IPv4 address as an anycast-gateway IPv4 address of the subinterface.

    When this parameter is set to true:
    - The IPv4 address is associated with the anycast-gw MAC address in the same subinterface. ARP Requests received for the anycast-gw IPv4 address
      will be replied using this anycast-gw MAC address.
    - The IPv4 address can have duplicate IPv4 addresses in other IRB subinterfaces of routers attached to the same broadcast domain.
      Because of that ARP duplicate-address-detection procedures do not apply to anycast-gw IP addresses.
    """
    origin: Annotated[
        Optional[EnumerationEnum40], Field(alias='srl_nokia-interfaces:origin')
    ] = None
    """
    The origin of the IPv4 address.
    """
    primary: Annotated[
        Optional[PrimaryLeaf], Field(alias='srl_nokia-interfaces:primary')
    ] = None
    status: Annotated[
        Optional[EnumerationEnum41], Field(alias='srl_nokia-interfaces:status')
    ] = None
    """
    The status of an IPv4 address
    """
    vrrp: Annotated[
        Optional[VrrpContainer], Field(alias='srl_nokia-interfaces-ip-vrrp:vrrp')
    ] = None


class AddressListEntry3(BaseModel):
    """
    The list of IPv6 addresses assigned to the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ip_prefix: Annotated[
        str,
        Field(
            alias='srl_nokia-interfaces:ip-prefix',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$',
        ),
    ]
    """
    The IPv6 address and prefix-length in CIDR notation

    Up to 16 global unicast IPv6 addresses can be assigned to each subinterface. Global unicast IPv6 address subnets on the same subinterface are allowed to overlap as long as the host bits are different. When a locally originated unicast packet is destined to a host covered by multiple subnets associated with a subinterface, the source address is chosen to be the numerically lowest IP address among all these subnets.
    """
    type: Annotated[
        Optional[EnumerationEnum54], Field(alias='srl_nokia-interfaces:type')
    ] = 'global-unicast'
    """
    Specifies the explicit type of the IPv6 address being assigned to the subinterface

    By default, addresses are assumed to be global unicast.  Where a link-local address is to be explicitly configured, this leaf should be set to link-local.
    """
    anycast_gw: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:anycast-gw')
    ] = None
    """
    This designates the associated IPv6 address as an anycast-gateway IPv6 address of the subinterface.

    When this parameter is set to true:
    - The IPv6 address is associated with the anycast-gw MAC address in the same subinterface. Neighbor Solicitations received for the anycast-gw IPv6 address
      will be replied using this anycast-gw MAC address.
    - The IPv6 address can have duplicate IPv6 addresses in other IRB subinterfaces of routers attached to the same broadcast domain.
      Because of that, ND duplicate-address-detection procedures do not apply to anycast-gw IP addresses.
    """
    origin: Annotated[
        Optional[EnumerationEnum40], Field(alias='srl_nokia-interfaces:origin')
    ] = None
    """
    The origin of the IPv6 address
    """
    primary: Annotated[
        Optional[PrimaryLeaf2], Field(alias='srl_nokia-interfaces:primary')
    ] = None
    status: Annotated[
        Optional[EnumerationEnum55], Field(alias='srl_nokia-interfaces:status')
    ] = None
    """
    The status of an IPv6 address
    """
    vrrp: Annotated[
        Optional[VrrpContainer2], Field(alias='srl_nokia-interfaces-ip-vrrp:vrrp')
    ] = None


class ArpContainer(BaseModel):
    """
    Container for the IPv4 ARP protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    duplicate_address_detection: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-nbr:duplicate-address-detection'),
    ] = True
    """
    If set to true IPv4 Address Conflict Detection per RFC 5227 is performed on the IPv4 address assigned to the subinterface
    """
    timeout: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-nbr:timeout', ge=60, le=65535)
    ] = 14400
    """
    Duration of time that dynamic ARP entries remain in the ARP cache before they expire

    A change to this value does not affect existing entries until they are refreshed.
    """
    learn_unsolicited: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:learn-unsolicited')
    ] = False
    """
    If set to true an ARP entry should be learned from any received ARP packets.
    """
    neighbor: Annotated[
        Optional[List[NeighborListEntry]],
        Field(alias='srl_nokia-interfaces-nbr:neighbor'),
    ] = None
    host_route: Annotated[
        Optional[HostRouteContainer], Field(alias='srl_nokia-interfaces-nbr:host-route')
    ] = None
    proxy_arp: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:proxy-arp')
    ] = False
    """
    When set to true, the router replies with its own MAC to ARP Request destined to any host.
    """
    debug: Annotated[
        Optional[List[EnumerationEnum48]], Field(alias='srl_nokia-interfaces-nbr:debug')
    ] = []
    """
    List of events to debug
    """
    evpn: Annotated[
        Optional[EvpnContainer], Field(alias='srl_nokia-interfaces-nbr-evpn:evpn')
    ] = None
    virtual_ipv4_discovery: Annotated[
        Optional[VirtualIpv4DiscoveryContainer],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:virtual-ipv4-discovery'
        ),
    ] = None


class BridgeTableContainer(BaseModel):
    """
    Enable the Bridge Table on the subinterface and configure associated parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    discard_unknown_src_mac: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:discard-unknown-src-mac')
    ] = False
    """
    Discard frames with unknown source mac addresses. The source mac address of
    the discarded frame is never learned when this command is enabled.
    """
    mac_limit: Annotated[
        Optional[MacLimitContainer], Field(alias='srl_nokia-interfaces:mac-limit')
    ] = None
    mac_learning: Annotated[
        Optional[MacLearningContainer], Field(alias='srl_nokia-interfaces:mac-learning')
    ] = None
    mac_duplication: Annotated[
        Optional[MacDuplicationContainer],
        Field(alias='srl_nokia-interfaces:mac-duplication'),
    ] = None
    stp: Annotated[
        Optional[StpContainer], Field(alias='srl_nokia-interfaces-bridge-table-stp:stp')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer16],
        Field(alias='srl_nokia-interfaces-bridge-table-statistics:statistics'),
    ] = None
    mac_table: Annotated[
        Optional[MacTableContainer],
        Field(alias='srl_nokia-interfaces-bridge-table-mac-table:mac-table'),
    ] = None


class DhcpRelayContainer(BaseModel):
    """
    Container for options related to DHCPv4 relay
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:admin-state'),
    ] = 'enable'
    """
    The configurable state of the dhcp relay agent
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:oper-state'),
    ] = None
    """
    The operational state of the dhcp relay agent
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum50],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:oper-down-reason'),
    ] = None
    """
    The reason causing the dhcp relay agent to go into operational down state
    """
    option: Annotated[
        Optional[List[EnumerationEnum51]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:option'),
    ] = []
    """
    List of option82 suboptions to insert into relayed packet towards DHCPv4 server
    """
    server: Annotated[
        Optional[List[Union[Ipv4AddressType, DomainNameType]]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:server'),
    ] = []
    """
    List of the DHCPv4 servers that the DHCPv4 relay function will relay DHCPv4 packets to/from
    """
    gi_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:gi-address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    IPv4 address to be used as giaddr of the relayed packets towards DHCPv4 servers.
     This address can be any IPv4 address configured within the network-instance towards the DHCPv4 server
    """
    use_gi_addr_as_src_ip_addr: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:use-gi-addr-as-src-ip-addr'),
    ] = False
    """
    When this is set, the configured giaddress will be used as source ip address.
    """
    network_instance: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:network-instance',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,_:;?-]*$).*$',
        ),
    ] = None
    """
    network instance to relay dhcp packets to
    """
    trace_options: Annotated[
        Optional[TraceOptionsContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:trace-options'),
    ] = None
    dns_resolution: Annotated[
        Optional[DnsResolutionContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:dns-resolution'),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer9],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:statistics'),
    ] = None


class DhcpRelayContainer2(BaseModel):
    """
    Container for options related to DHCPv6 relay
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:admin-state'),
    ] = 'enable'
    """
    The configurable state of the dhcp relay agent
    """
    oper_state: Annotated[
        Optional[EnumerationEnum42],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:oper-state'),
    ] = None
    """
    The operational state of the dhcp relay agent
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum62],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:oper-down-reason'),
    ] = None
    """
    The reason causing the dhcp relay agent to go into operational down state
    """
    option: Annotated[
        Optional[List[EnumerationEnum63]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:option'),
    ] = []
    """
    List of options to insert into relayed packet towards DHCPv6 server
    """
    server: Annotated[
        Optional[List[Union[Ipv6AddressType, DomainNameType]]],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:server'),
    ] = []
    """
    List of the DHCPv6 servers that the DHCPv6 relay function will relay DHCPv6 packets to/from
    """
    source_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:source-address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Source IPv6 address of the relayed packets towards DHCPv6 servers
     this address can be any IPv6 address configured within the network-instance towards the DHCPv6 server
    """
    network_instance: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-ip-dhcp-relay:network-instance',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,_:;?-]*$).*$',
        ),
    ] = None
    """
    network instance to relay dhcp packets to
    """
    trace_options: Annotated[
        Optional[TraceOptionsContainer3],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:trace-options'),
    ] = None
    dns_resolution: Annotated[
        Optional[DnsResolutionContainer2],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:dns-resolution'),
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer14],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:statistics'),
    ] = None


class EthernetContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    aggregate_id: Annotated[
        Optional[str], Field(alias='srl_nokia-interfaces:aggregate-id')
    ] = None
    """
    lag interface with which this interface is associated
    """
    forwarding_viable: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:forwarding-viable')
    ] = None
    """
    If true:
    this LAG member link should be used for the transmission of traffic if all other LAG/port attributes allow it.

    If false:
    this LAG member link should not be used for the transmission of traffic.

    In all cases:
    This LAG member link should process any received frames when it is an active member link.  L2 protocols such as LLDP, LACP and micro-BFD should continue to be sent and processed.
    """
    auto_negotiate: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:auto-negotiate')
    ] = None
    """
    When set to true the interface uses auto-negotiation for speed, duplex and flow-control settings.

    When set to false, the transmission parameters are specified manually.
    """
    duplex_mode: Annotated[
        Optional[EnumerationEnum24], Field(alias='srl_nokia-interfaces:duplex-mode')
    ] = None
    """
    When auto-negotiate is true, this sets the duplex mode that will be advertised to the peer.  When auto-negotiate is false, this directly sets the duplex mode of the interface.
    """
    dac_link_training: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:dac-link-training')
    ] = None
    """
    If the system detects that the transceiver is connected to a DAC cable then a true setting enables link training for better link stability. The link training setting must be the same at both ends of the DAC cable or else the link may not come up.
    """
    flow_control: Annotated[
        Optional[FlowControlContainer], Field(alias='srl_nokia-interfaces:flow-control')
    ] = None
    lacp_port_priority: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:lacp-port-priority', ge=0, le=65535),
    ] = None
    """
    Configure the port priority for LACP.  This value is used to  determine which port should be activated with LACP fallback mode. Lower values are more preferred.
    """
    port_speed: Annotated[
        Optional[EnumerationEnum25], Field(alias='srl_nokia-interfaces:port-speed')
    ] = None
    """
    The speed of the port or channel

    If this parameter is configured, then the configured value will be applied.  If it is not configured, then there are two mechanisms that will set a speed for the port.

    Some platforms support a mechanism to automatically set the port-speed based on the form factor of the inserted transceiver.
       form-factor    speed
       QSFP28         100G
       SFP112         100G
       SFP56-DD       100G
       SFP            1G
       SFP+           10G
       QSFP56-DD      400G
       QSFP56         200G
       QSFP28-DD      200G
       SFP28          25G
       QSFP112        400G
       QSFP+          40G
       QSFP28-50G     50G
       SFP56          50G
       QSFP112-DD     800G
       CFP2-DCO       400G

    When the auto-configuration of speed based on form factor is not supported and the speed is not configured, then the default speed of a port (when auto-negotiation is disabled or unsupported) depends on the platform and port/connector number as follows:

    mgmt0 and mgmt0-standby ports: 1G
    J2 IMM ports 1-32:  100G
    J2 IMM ports 33-36: 100G
    7215 IXS-A1 ports 1-48: 1G
    7215 IXS-A1 ports 49-52: 10G
    7220-D1 ports 1-48: 1G
    7220-D1 ports 49-52: 10G
    7220-D2/D2L ports 1-48: 25G
    7220-D2/D2L ports 49-56: 100G
    7220-D2L ports 57-58: 10G
    7220-D3 ports 1-2: 10G
    7220-D3 ethernet-1/[3-34]: 100G
    7220-D3 ethernet-1/[3-33]/n: 25G
    7220-D3L ethernet-1/[1-32]: 100G
    7220-D3L ethernet-1/[1-31]/n: 25G
    7220-D3L ports 33-34: 10G
    7220-D4 ports 1-28: 100G
    7220-D4 ports 29-36: 400G
    7220-D5 ports 1-32: 400G
    7220-D5 ports 33-38: 10G
    7220-H2 ports 1-128: 100G
    7220-H3 ports 1-2: 10G
    7220-H3 ports 3-34: 400G
    7220-H4 ports 1-64: 400G
    7220-H4 ports 65-66: 10G
    7250 IXR-6e/10e 60p QSFP28 IMM all ports:  100G
    7250 IXR-6e/10e 36p QSFPDD-400 IMM all ports:  400G
    7250 IXR-X1b QSFP28 ports 1-24: 100G
    7250 IXR-X1b QSFPDD ports 25-36: 400G
    7250 IXR-X3b QSFPDD all ports: 400G
    7730 SXR-1d-32D QSFP28 ports 1-16,21-32: 100G
    7730 SXR-1d-32D QSFPDD ports 17-20: 400G
    7730 SXR-1x-44S SFPDD ports 1-20, 23-42: 100G
    7730 SXR-1x-44S QSFPDD ports 21,22,43,44: 400G

    Supported speeds:
    mgmt0 and mgmt0-standby ports: 1G
    J2 IMM ports 1-32: 40G, 100G (Note 1)
    J2 IMM ports 33-36: 40G, 100G, 400G
    7215 IXS-A1 ports 1-48: 10M, 100M, 1G
    7215 IXS-A1 ports 49-52: 1G, 10G
    7220-D1 ports 1-48: 10M, 100M, 1G
    7220-D1 ports 49-52: 10G
    7220-D2/D2L ports 1-48: 1G, 10G, 25G (Note 2)
    7220-D2 ports 49-56: 10G, 25G, 40G, 100G
    7220-D2L ports 49-56: 10G, 25G, 40G, 100G
    7220-D2L ports 57-58: 10G
    7220-D3 ports 1-2: 10G
    7220-D3 ethernet-1/[3-34]: 10G, 25G, 40G, 50G, 100G
    7220-D3 ethernet-1/[3-33]/n: 10G, 25G
    7220-D3L ethernet-1/[1-32]: 10G, 25G, 40G, 50G, 100G
    7220-D3L ethernet-1/[1-31]/n: 10G, 25G
    7220-D3L ports 33-34: 10G
    7220-D4 ports 1-8: 40G, 100G
    7220-D4 ports 9-28: 10G, 25G, 40G, 100G
    7220-D4 ports 29-36: 10G, 25G, 40G, 100G, 400G
    7220-D5 ports 1-32: 40G, 100G, 400G
    7220-D5 ports 33-38: 10G
    7220-H2 ports 1-128: 100G
    7220-H3 ports 1-2: 10G
    7220-H3 ports 3-34: 40G, 100G, 200G, 400G
    7220-H4 ports 1-64: 40G, 100G, 200G, 400G
    7220-H4 ports 65-66: 10G
    7250 IXR-6e/10e 60p QSFP28 IMM all ports:  100G
    7250 IXR-6e/10e 36p QSFPDD-400 IMM all ports:  40G, 100G, 400G
    7250 IXR-X1b QSFP28 ports 1-24: 40G, 100G (Note 4)
    7250 IXR-X1b QSFPDD ports 25-36: 40G, 100G, 400G
    7250 IXR-X3b QSFPDD all ports: 40G, 50G, 100G, 400G
    7730 SXR-1d-32D QSFP28 ports 1-16,21-32: 40G, 100G (Note 3)
    7730 SXR-1d-32D QSFPDD ports 17-20: 40G, 100G, 400G
    7730 SXR-1x-44S SFPDD ports 1-20, 23-42: 10G, 25G, 100G
    7730 SXR-1x-44S QSFPDD ports 21,22,43,44: 40G, 100G, 400G

    Note 1:
     Ports 9-12 cannot operate at different port speeds (some at 40G and others at 100G). The required speed of ports 9-12 is based on the port-speed of the first configured port in this block; if any subsequent port in the block is configured with a different port speed that port will not come up.

    Note 2:
     On 7220-D2: if one port in each consecutive group of 4 ports (1-4, 5-8, .. , 45-48) is enabled and has a configured speed of 25G then the other 3 ports may only be enabled if they also have a configured speed of 25G or no speed configured; if one port in each consecutive group of 4 ports (1-4, 5-8, .. , 45-48) is enabled and has a configured speed of 1G or 10G the other 3 ports may only be enabled if they also have a configured speed of 1G or 10G or no speed configured.
     On 7220-D2L: if one port in each port group of 4 ports ({1, 2, 3, 6}, {4, 5, 7, 9}, {8, 10, 11, 12}, {13, 14, 15, 18}, {16, 17, 19, 21}, {20, 22, 23, 24}, {25, 26, 27, 30}, {28, 29, 31, 33}, {32, 34, 35, 36}, {37, 38, 39, 42}, {40, 41, 43, 45}, {44, 46, 47, 48}) is enabled and has a configured speed of 25G the other 3 ports may only be enabled if they also have a configured speed of 25G or no speed configured; if one port in each port group of 4 ports is enabled and has a configured speed of 1G or 10G the other 3 ports may only be enabled if they also have a configured speed of 1G or 10G or no speed configured.

    Note 3: Breakout and 40G is only supported on odd numbered ports.
     For the QSFP28 four port groupings [1-4], [5-8], [9-12], [13-16], [21-24], [25-28], and [29-32] if either of the odd numbered ports within a group is configured for 40G, 4x10G, or 4x25G,
     then the other odd numbered port in the same group may only be configured if it is configured for one of 40G, 4x10G, or 4x25G (can differ between the odd ports) and neither of
     the two even numbered ports within the same group can be configured.

    Note 4: For the QSFP28 ports, the following port groups exist [n, n+1, n+2, n+3] for n = 1, 5, 9, 13, 17, 21.  Breakout for 4x25G or 4x10G is only supported on ports n+1 and n+3.
     When initially configuring a port with a breakout configuration or port speed that does not already exist on another configured port within the same group, then a link flap and traffic hit may occur on other ports within the same group.
     When the breakout configuration or port speed is changed for a port in a group, then a link flap and traffic hit may occur on other ports within the same group.
     If port n+1 within the group is configured for breakout, then port n cannot be configured.
     In addition if port n+1 is configured for breakout and port n+3 is configured without breakout, then port n+2 may only be configured with the same speed as port n+3.
     If port n+3 within the group is configured for breakout, then port n+2 cannot be configured.
     In addition if port n+3 is configured for breakout and port n+1 is configured without breakout, then port n may only be configured with the same speed as port n+1.

    7250 IXR details:
     If the interface corresponds to a connector that has no installed transceiver then the value is accepted without any checking or restriction, and info from state will display the configured value.  Otherwise if the configured port-speed is NOT supported by the installed transceiver the port is forced operationally down.

    Port Groups and auto-configuration:
     Manually configured and enabled port-speed (and breakout-modes) take precedence over the auto-configured port-speed.  This means that configuring and enabling a port within a port-group can have a side effect to take down an operational port that had its speed set based on the auto-configuration feature.  If there is risk of mixing transceiver types within a port group, then it is recommended to always manually configure the speed for enabled ports
    """
    hw_mac_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:hw-mac-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    The MAC address associated with the port
    """
    mac_address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:mac-address',
            pattern='^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$',
        ),
    ] = None
    """
    MAC address of the interface

    If not configured, this is set to the hw-mac-address, which is populated depending on interface type:

    - For interfaces with a discoverable MAC address (either populated by an external system or present in hardware) the discovered value is populated.
    - For interfaces without a discoverable MAC address, the address is generated from a hash of the interface name and the chassis MAC address.

    When deleted, will revert back to the value of hw-mac-address.
    """
    physical_medium: Annotated[
        Optional[EnumerationEnum26], Field(alias='srl_nokia-interfaces:physical-medium')
    ] = None
    """
    Indicates the PHY supported by the RJ45 port.

    If the port is supported by a SFP, QSFP+, QSFP28 or QSFP-DD transceiver no value is populated in this leaf.
    """
    ptp_asymmetry: Annotated[
        Optional[int],
        Field(
            alias='srl_nokia-interfaces:ptp-asymmetry', ge=-2147483648, le=2147483647
        ),
    ] = 0
    """
    This command configures the PTP asymmetry delay on the Ethernet port

    This command is used to correct known asymmetry as part of time of day or phase
    recovery using PTP packets on both local and downstream PTP clocks.
    """
    ptp_timestamping: Annotated[
        Optional[PtpTimestampingContainer],
        Field(alias='srl_nokia-interfaces:ptp-timestamping'),
    ] = None
    standby_signaling: Annotated[
        Optional[EnumerationEnum27],
        Field(alias='srl_nokia-interfaces:standby-signaling'),
    ] = None
    """
    Indicates the standby-signaling used in the interface.

    An application using a port-based redundancy mechanism will trigger the standby signaling on the ethernet
    interface if the interface is selected as standby.
    """
    link_loss_forwarding: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:link-loss-forwarding')
    ] = None
    """
    Indicates whether link-loss-forwarding is enabled in the interface

    When enabled, faults can be propagated to the devices connected to this interface. It is supported on interfaces
    with a single non-tagged subinterface that is associated to a network-instance of type vpws. On VPWS services,
    the propagation of faults from a connection-point to the opposite connection-point is known as Link Loss
    Forwarding and requires setting this command to true and the standby-signaling command to the type of propagation
    signaling to be used with the connected Customer Equipment.
    """
    reload_delay: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:reload-delay', ge=1, le=86400)
    ] = None
    """
    Configure reload-delay timer for Ethernet interfaces.

    The reload-delay timer starts when the associated XDP interface state is learned. While the timer is
    running, the interface transceiver laser is disabled to avoid attracting traffic from the connected
    device at the other end of the interface. The reload-delay timer should be used in multi-homing
    interfaces and be set to a value long enough to allow the system to recover all the network protocols
    upon reboot, before start attracting traffic from the multi-homed device.
    """
    reload_delay_expires: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:reload-delay-expires',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The remaining time until the reload-delay expires and the interface can go operationally up.
    """
    hold_time: Annotated[
        Optional[HoldTimeContainer], Field(alias='srl_nokia-interfaces:hold-time')
    ] = None
    crc_monitor: Annotated[
        Optional[CrcMonitorContainer], Field(alias='srl_nokia-interfaces:crc-monitor')
    ] = None
    symbol_monitor: Annotated[
        Optional[SymbolMonitorContainer],
        Field(alias='srl_nokia-interfaces:symbol-monitor'),
    ] = None
    exponential_port_dampening: Annotated[
        Optional[ExponentialPortDampeningContainer],
        Field(alias='srl_nokia-interfaces:exponential-port-dampening'),
    ] = None
    storm_control: Annotated[
        Optional[StormControlContainer],
        Field(alias='srl_nokia-interfaces:storm-control'),
    ] = None
    synce: Annotated[
        Optional[SynceContainer], Field(alias='srl_nokia-interfaces:synce')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer3], Field(alias='srl_nokia-interfaces:statistics')
    ] = None
    dot1x: Annotated[Optional[Dot1xContainer], Field(alias='srl_nokia-dot1x:dot1x')] = (
        None
    )
    l2cp_transparency: Annotated[
        Optional[L2cpTransparencyContainer],
        Field(alias='srl_nokia-interfaces-l2cp:l2cp-transparency'),
    ] = None


class Ipv4Container(BaseModel):
    """
    IPv4 configuration and state for the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Enable/disable IPv4 on the subinterface

    When set to enable, and even before an IPv4 address is configured, the subinterface starts to accept incoming packets with dest-ip 255.255.255.255, which is necessary to support dhcp-client functionality.
    """
    address: Annotated[
        Optional[List[AddressListEntry]], Field(alias='srl_nokia-interfaces:address')
    ] = None
    allow_directed_broadcast: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:allow-directed-broadcast')
    ] = False
    """
    When this is set to true the software is allowed to re-broadcast targeted broadcast IPv4 packets on this subinterface

    Detailed handling of subnet broadcast is as follows:

    If a targeted broadcast packet is received on subinterface X that has the matching subnet then it is delivered to the CPM and CPM will reply to an ICMP echo.

    If a targeted broadcast packet is received on subinterface X but the matching subnet is associated with subinterface Y, and subinterface Y is configured with allow-directed-broadcasts=false then it is delivered to the CPM and CPM replies to an ICMP echo per above, but it does not re-broadcast the packet on subinterface Y.

    If a targeted broadcast packet is received on subinterface X but the matching subnet is associated with subinterface Y, and subinterface Y is configured with allow-directed-broadcasts=true then it is delivered to the CPM and CPM replies to an ICMP echo per above, and CPM also re-broadcasts the packet on subinterface Y.
    """
    unnumbered: Annotated[
        Optional[UnnumberedContainer], Field(alias='srl_nokia-interfaces:unnumbered')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer6], Field(alias='srl_nokia-interfaces:statistics')
    ] = None
    arp: Annotated[
        Optional[ArpContainer], Field(alias='srl_nokia-interfaces-nbr:arp')
    ] = None
    dhcp_relay: Annotated[
        Optional[DhcpRelayContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:dhcp-relay'),
    ] = None
    dhcp_client: Annotated[
        Optional[DhcpClientContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp:dhcp-client'),
    ] = None
    dhcp_server: Annotated[
        Optional[DhcpServerContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:dhcp-server'),
    ] = None


class LagContainer(BaseModel):
    """
    Container for options related to LAG
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    lag_type: Annotated[
        Optional[EnumerationEnum86], Field(alias='srl_nokia-interfaces-lag:lag-type')
    ] = 'static'
    """
    Sets the type of LAG, i.e., how it is
    configured / maintained
    """
    min_links: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces-lag:min-links', ge=1, le=64)
    ] = 1
    """
    Specifies the mininum number of member
    interfaces that must be active for the aggregate interface
    to be available
    """
    member_speed: Annotated[
        Optional[EnumerationEnum87],
        Field(alias='srl_nokia-interfaces-lag:member-speed'),
    ] = None
    """
    Specifies the link speed of allowed member-links
    """
    lacp_fallback_mode: Annotated[
        Optional[EnumerationEnum88],
        Field(alias='srl_nokia-interfaces-lag:lacp-fallback-mode'),
    ] = None
    """
    Specifies lacp-fallback mode if enabled
    """
    lacp_fallback_timeout: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-lag:lacp-fallback-timeout', ge=4, le=3600),
    ] = None
    """
    Specifies the LACP-fallback timeout interval in seconds
    """
    lag_speed: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-lag:lag-speed', ge=0, le=4294967295),
    ] = None
    """
    reports current aggregate bandwidth speed of the associated LAG
    """
    member: Annotated[
        Optional[List[MemberListEntry]], Field(alias='srl_nokia-interfaces-lag:member')
    ] = None
    lacp: Annotated[Optional[LacpContainer3], Field(alias='srl_nokia-lacp:lacp')] = None


class NeighborDiscoveryContainer(BaseModel):
    """
    Container for the IPv6 Neighbor Discovery protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    duplicate_address_detection: Annotated[
        Optional[bool],
        Field(alias='srl_nokia-interfaces-nbr:duplicate-address-detection'),
    ] = True
    """
    Enables Duplicate Addres Detection on all tentative addresses

    This applies to link-local and global unicast addresses. Only one transmission is done; there are no retransmissions.

    Must be true on an IPv6 subinterface that has dhcp-client enabled.
    """
    reachable_time: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-nbr:reachable-time', ge=30, le=3600),
    ] = 30
    """
    The period of time that a dynamic IPv6 neighbor cache entry is considered reachable after a reachability confirmation event

    After this time expires the neighbor state moves to STALE.
    """
    stale_time: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces-nbr:stale-time', ge=60, le=65535),
    ] = 14400
    """
    The maximum time that a dynamic IPv6 neighbor cache entry can remain in the STALE state before it is removed

    This limit is reached only if no traffic is sent/queued towards the neighbor during the entire duration of the timer.
    """
    learn_unsolicited: Annotated[
        Optional[EnumerationEnum56],
        Field(alias='srl_nokia-interfaces-nbr:learn-unsolicited'),
    ] = 'none'
    """
    Sets if neighbors should be learned from unsolicited neighbor advertisements for global or link local addresses or both.
    """
    neighbor: Annotated[
        Optional[List[NeighborListEntry2]],
        Field(alias='srl_nokia-interfaces-nbr:neighbor'),
    ] = None
    host_route: Annotated[
        Optional[HostRouteContainer2],
        Field(alias='srl_nokia-interfaces-nbr:host-route'),
    ] = None
    limit: Annotated[
        Optional[LimitContainer], Field(alias='srl_nokia-interfaces-nbr:limit')
    ] = None
    proxy_nd: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-nbr:proxy-nd')
    ] = False
    """
    When set to true, the router replies with its own MAC to Neighbor Solicitations destined to any host.
    """
    debug: Annotated[
        Optional[List[EnumerationEnum60]], Field(alias='srl_nokia-interfaces-nbr:debug')
    ] = []
    """
    List of events to debug
    """
    evpn: Annotated[
        Optional[EvpnContainer2], Field(alias='srl_nokia-interfaces-nbr-evpn:evpn')
    ] = None
    virtual_ipv6_discovery: Annotated[
        Optional[VirtualIpv6DiscoveryContainer],
        Field(
            alias='srl_nokia-interfaces-nbr-virtual-ip-discovery:virtual-ipv6-discovery'
        ),
    ] = None


class Ipv6Container(BaseModel):
    """
    IPv6 configuration and state for the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'disable'
    """
    Enable/disable IPv6 on the subinterface

    When set to enable, and even before a global unicast IPv6 address is configured, chassis manager assigns an IPv6 link-local address to the subinterface, which will appear as a read-only entry in the address list. At this stage, the subinterface can receive IPv6 packets with any of the following destinations:
    -	IPv6 link-local address
    -	solicited-node multicast address for the link-local address
    -	ff02::1 (all IPv6 devices)
    -	ff02::2 (all IPv6 routers)
    """
    address: Annotated[
        Optional[List[AddressListEntry3]], Field(alias='srl_nokia-interfaces:address')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer11], Field(alias='srl_nokia-interfaces:statistics')
    ] = None
    neighbor_discovery: Annotated[
        Optional[NeighborDiscoveryContainer],
        Field(alias='srl_nokia-interfaces-nbr:neighbor-discovery'),
    ] = None
    dhcp_relay: Annotated[
        Optional[DhcpRelayContainer2],
        Field(alias='srl_nokia-interfaces-ip-dhcp-relay:dhcp-relay'),
    ] = None
    router_advertisement: Annotated[
        Optional[RouterAdvertisementContainer],
        Field(alias='srl_nokia-interfaces-router-adv:router-advertisement'),
    ] = None
    dhcp_client: Annotated[
        Optional[DhcpClientContainer2],
        Field(alias='srl_nokia-interfaces-ip-dhcp:dhcp-client'),
    ] = None
    dhcpv6_server: Annotated[
        Optional[Dhcpv6ServerContainer],
        Field(alias='srl_nokia-interfaces-ip-dhcp-server:dhcpv6-server'),
    ] = None


class SubinterfaceListEntry(BaseModel):
    """
    The list of subinterfaces (logical interfaces) associated with a physical interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    index: Annotated[int, Field(alias='srl_nokia-interfaces:index', ge=0, le=9999)]
    """
    The index of the subinterface, or logical interface number
    """
    type: Annotated[Optional[str], Field(alias='srl_nokia-interfaces:type')] = None
    """
    Indicates the context in which the ethernet subinterface will be used
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-interfaces:description', max_length=255, min_length=1),
    ] = None
    """
    A user-configured description of the interface
    """
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'enable'
    """
    The configured, desired state of the subinterface
    """
    ip_mtu: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:ip-mtu', ge=1280, le=9486)
    ] = None
    """
    IP MTU of the subinterface in bytes.

    Includes the IP header but excludes Ethernet encapsulation.

    IP MTU specifies the maximum sized IPv4 or IPv6 packet that can be transmitted on the subinterface. If an IPv4 or IPv6 packet exceeds this size it is dropped and this may result in the generation of an ICMP error message back to the source.

    The default IP MTU for a subinterface is taken from /system/mtu/default-ip-mtu.  For the mgmt0 and mgmt0-standby subinterfaces the default is the associated interface MTU minus the Ethernet encapsulation overhead.

    The IP MTU is not configurable for subinterfaces of loopback interfaces.

    The 7220 IXR-D1, 7220 IXR-D2, 7220 IXR-D3, 7220 IXR-D4, 7220 IXR-D5, 7220 IXR-H2, 7220 IXR-H3, and 7220 IXR-H4 systems support a maximum IP MTU of 9398 bytes.

    The 7730 SXR systems support a maximum IP MTU of 9394 bytes.

    Each 7250 IXR IMM supports a maximum of 4 different IP MTU values. 7220 IXR systems do not have any limit on the maximum number of different IP MTU values.
    """
    l2_mtu: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:l2-mtu', ge=1450, le=9500)
    ] = None
    """
    Layer-2 MTU of the subinterface in bytes.

    Includes the Ethernet header and VLAN tags, and excludes 4-bytes FCS.

    L2 MTU specifies the maximum sized Ethernet frame that can be transmitted on the subinterface. If a frame exceeds this size it is discarded. If the l2-mtu of the subinterface exceeds the port-mtu of the associated
    interface, the subinterface will remain operationally down.

    The default value for a subinterface is taken from /system/mtu/default-l2-mtu. The L2 MTU is only configurable for bridged subinterfaces.

    The 7220 IXR-D1, 7220 IXR-D2, 7220 IXR-D3, 7220 IXR-D4, 7220 IXR-D5, 7220 IXR-H2, 7220 IXR-H3, and 7220 IXR-H4 systems support a maximum L2 MTU of 9412 bytes and minimum of 1500 bytes.

    The 7730 SXR systems support a maximum L2 MTU of 9408 bytes.

    All other systems support a maximum L2 MTU of 9500 and minimum of 1500 bytes.
    """
    mpls_mtu: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:mpls-mtu', ge=1284, le=9496)
    ] = None
    """
    MPLS MTU of the subinterface in bytes, including the transmitted label stack.

    MPLS MTU specifies the maximum sized MPLS packet that can be transmitted on the subinterface. If an MPLS packet containing any payload exceeds this size then it is dropped. If the payload of the dropped packet is IPv4 or IPv6 then this may also result in the generation of an ICMP error message that is either tunneled or sent back to the source.

    The default MPLS MTU for a subinterface is taken from /system/mtu/default-mpls-mtu.

    The MPLS MTU is not configurable for subinterfaces of loopback interfaces.

    The 7730 SXR systems support a maximum MPLS MTU of 9404 bytes.

    Each 7250 IXR IMM supports a maximum of 4 different MPLS MTU values.
    """
    unidirectional_link_delay: Annotated[
        Optional[UnidirectionalLinkDelayContainer],
        Field(alias='srl_nokia-interfaces:unidirectional-link-delay'),
    ] = None
    name: Annotated[Optional[str], Field(alias='srl_nokia-interfaces:name')] = None
    """
    The system assigned name of the subinterface.

    It is formed by taking the base interface name and appending a dot (.) and the subinterface index number. For example, ethernet-2/1.0
    """
    ifindex: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:ifindex', ge=0, le=4294967295)
    ] = None
    """
    System-wide persistent unique ifIndex assigned to the subinterface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum38], Field(alias='srl_nokia-interfaces:oper-state')
    ] = None
    """
    The operational state of the subinterface
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum39],
        Field(alias='srl_nokia-interfaces:oper-down-reason'),
    ] = None
    """
    The first (and possibly only) reason for the subinterface being operationally down
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the most recent change to the subinterface state
    """
    collect_irb_stats: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:collect-irb-stats')
    ] = None
    """
    Set to false to disable statistics collection on the IRB subinterface

    By default basic statistics are collected for each IRB subinterface
    """
    collect_detailed_stats: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces:collect-detailed-stats')
    ] = None
    """
    Set to false to disable detailed statistics collection on the routed (non IRB) subinterface

    By default detailed statistics are collected for each routed (non IRB) subinterface
    """
    ipv4: Annotated[
        Optional[Ipv4Container], Field(alias='srl_nokia-interfaces:ipv4')
    ] = None
    ipv6: Annotated[
        Optional[Ipv6Container], Field(alias='srl_nokia-interfaces:ipv6')
    ] = None
    anycast_gw: Annotated[
        Optional[AnycastGwContainer], Field(alias='srl_nokia-interfaces:anycast-gw')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer15], Field(alias='srl_nokia-interfaces:statistics')
    ] = None
    bridge_table: Annotated[
        Optional[BridgeTableContainer], Field(alias='srl_nokia-interfaces:bridge-table')
    ] = None
    eth_cfm: Annotated[
        Optional[EthCfmContainer], Field(alias='srl_nokia-ethcfm:eth-cfm')
    ] = None
    vlan: Annotated[
        Optional[VlanContainer], Field(alias='srl_nokia-interfaces-vlans:vlan')
    ] = None
    ra_guard: Annotated[
        Optional[RaGuardContainer], Field(alias='srl_nokia-ra_guard:ra-guard')
    ] = None
    local_mirror_destination: Annotated[
        Optional[LocalMirrorDestinationContainer],
        Field(
            alias='srl_nokia-interfaces-local-mirror-destination:local-mirror-destination'
        ),
    ] = None
    mpls: Annotated[Optional[MplsContainer], Field(alias='srl_nokia-if-mpls:mpls')] = (
        None
    )
    uuid: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-vxdp:uuid',
            pattern='^(?=^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$).*$',
        ),
    ] = None
    """
    The system-generated or user-configured UUID for the sub interface
    """
    ethernet_segment_association: Annotated[
        Optional[EthernetSegmentAssociationContainer],
        Field(
            alias='srl_nokia-interfaces-ethernet-segment-association:ethernet-segment-association'
        ),
    ] = None


class InterfaceListEntry(BaseModel):
    """
    The list of named interfaces on the device
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-interfaces:name')]
    """
    The name of the interface

    Valid options are:
    irb<N>, N=0..255
    lif-<lif_name>
    enp<bus>s<dev>f<fn>, bus=0..255, dev=0..31, fn=0..7
    vhn-<vhn_name>
    lag<N>, N=1..1000 [note1]
    lo<N>, N=0..255
    mgmt0
    mgmt0-standby
    ethernet-<slot>/<port>
    ethernet-<slot>/<mda>/<port>
    system0
    sync0

    <lif_name>=Linux interface name
    <vhn_name>=vhost interface name
    <slot>=slot number {1,2,3,..}
    <mda>=mda id {a,b,c,d,e,f}
    <port>=port id {1,2,3,..}

    [note1] The maximum number of LAGs per platform is as follows:
     D1: 32 (N must be 1..32)
     D2-D3: 128 (N must be 1..1000)
     D4-D5: 64 (N must be 1..64)
     H2-H3: 127 (N must be 1..127)
     H4: 255 (N must be 1..255)
     IXR: 128 (N must be 1..128)
     SXR-1d-32D: 128 (N must be 1..128)
     SXR-1x-44S: 128 (N must be 1..128)
     A1: 10 (N must be 1..10)
     IXR-X1b: 512 (N must be 1..512)
     IXR-X3b: 512 (N must be 1..512)
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-interfaces:description', max_length=255, min_length=1),
    ] = None
    """
    A user-configured description of the interface
    """
    admin_state: Annotated[
        Optional[EnumerationEnum], Field(alias='srl_nokia-interfaces:admin-state')
    ] = 'enable'
    """
    The configured, desired state of the interface
    """
    num_physical_channels: Annotated[
        Optional[int],
        Field(alias='srl_nokia-interfaces:num-physical-channels', ge=1, le=8),
    ] = None
    """
    Sets the number of lanes or physical channels assigned to this interface or to the set of interfaces within this breakout group

    This leaf can be used to distinguish between transceivers that provide the same port-speed or breakout-configuration but using different PMAs.
    For example, if a port supports two transceivers providing 100G optical signal but one uses CAUI4 and the other uses 100GAUI-2, then this leaf
    can be set to 4 for the CAUI4 transceiver and 2 for the 100GAUI-2 transceiver.
    Similarly, a transceiver that provides a breakout of 4 ports of 100G using 4 x 100GAUI2 would set this leaf to 8 but a transceiver using 4 x 100GAUI-1 would have this leaf set to 4.

    If not set, then the default shall be as follows:
       1 is used for 10G, 25G
       2 is used for 50G
       4 is used for 40G, 100G, 2x50G, 1x100G, 4x10G, 4x25G
       6 is used for 3x100G (digital coherent optics)
       8 is used for 200G, 400G, 800G, 2x100G, 4x100G, 8x50G

    """
    breakout_mode: Annotated[
        Optional[BreakoutModeContainer],
        Field(alias='srl_nokia-interfaces:breakout-mode'),
    ] = None
    mtu: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:mtu', ge=1450, le=9500)
    ] = None
    """
    Port MTU in bytes including ethernet overhead but excluding 4-bytes FCS

    If a transmitted packet exceeds this size it is dropped.
    The default value for ethernet-x interfaces is taken from /system/mtu/default-port-mtu. For the mgmt0 and mgmt0-standby interfaces the default is 1514 bytes, but the value can be changed for each interface individually.
    Port MTU is not configurable for loopback interfaces or irb interfaces. For irb interfaces, if the size of the ip packets to be routed to a mac-vrf has to be restricted, the subinterface.ip-mtu should be configured instead.
    The max mtu for the mgmt0 and mgmt0-standby interfaces is 9216.
    The 7220 IXR-D1, 7220 IXR-D2, 7220 IXR-D3, 7220 IXR-D4, 7220 IXR-D5, 7220 IXR-H2, 7220 IXR-H3, and 7220 IXR-H4 systems support a maximum port MTU of 9412 bytes and minimum of 1500 bytes.
    The 7730 SXR systems support a maximum port MTU of 9408 bytes and minimum of 1500 bytes.
    All other systems support a maximum port MTU of 9500 and minimum of 1500 bytes.
    Each 7250 IXR IMM supports a maximum of 8 different port MTU values. 7220 IXR systems do not have any limit on the maximum number of different port MTU values.
    """
    ifindex: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:ifindex', ge=0, le=4294967295)
    ] = None
    """
    System-wide persistent unique ifIndex assigned to the interface
    """
    oper_state: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-interfaces:oper-state')
    ] = None
    """
    The operational state of the interface
    """
    oper_down_reason: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-interfaces:oper-down-reason')
    ] = None
    """
    The first (and possibly only) reason for the port being operationally down
    """
    last_change: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces:last-change',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time of the most recent change to the interface state
    """
    linecard: Annotated[
        Optional[int], Field(alias='srl_nokia-interfaces:linecard', ge=1, le=16)
    ] = None
    """
    The linecard on which this interface resides

    This field is not populated for non-forwarding-complex-attached interfaces, for example mgmt0.
    """
    forwarding_complex: Annotated[
        Optional[EnumerationEnum6],
        Field(alias='srl_nokia-interfaces:forwarding-complex'),
    ] = None
    """
    The forwarding-complex on which this interface resides

    This field is not populated for non-forwarding-complex-attached interfaces, for example mgmt0.
    """
    phy_group_members: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-interfaces:phy-group-members')
    ] = []
    """
    The group of interfaces sharing a phy with this interface

    On the 7220 IXR-D2 and 7220 IXR-D2L platforms this group of interfaces must be set to the same speed, either 1/10G or 25G.
    """
    physical_channel: Annotated[
        Optional[List[PhysicalChannelLeafList]],
        Field(alias='srl_nokia-interfaces:physical-channel'),
    ] = []
    """
    The list of transceiver channels associated with this port
    """
    forwarding_mode: Annotated[
        Optional[EnumerationEnum7], Field(alias='srl_nokia-interfaces:forwarding-mode')
    ] = None
    """
    The forwarding mode for Ethernet frames received on this interface
    """
    statistics: Annotated[
        Optional[StatisticsContainer], Field(alias='srl_nokia-interfaces:statistics')
    ] = None
    traffic_rate: Annotated[
        Optional[TrafficRateContainer], Field(alias='srl_nokia-interfaces:traffic-rate')
    ] = None
    adapter: Annotated[
        Optional[AdapterContainer], Field(alias='srl_nokia-interfaces:adapter')
    ] = None
    transceiver: Annotated[
        Optional[TransceiverContainer], Field(alias='srl_nokia-interfaces:transceiver')
    ] = None
    ethernet: Annotated[
        Optional[EthernetContainer], Field(alias='srl_nokia-interfaces:ethernet')
    ] = None
    subinterface: Annotated[
        Optional[List[SubinterfaceListEntry]],
        Field(alias='srl_nokia-interfaces:subinterface'),
    ] = None
    sflow: Annotated[
        Optional[SflowContainer], Field(alias='srl_nokia-interfaces:sflow')
    ] = None
    vlan_tagging: Annotated[
        Optional[bool], Field(alias='srl_nokia-interfaces-vlans:vlan-tagging')
    ] = None
    """
    When set to true the interface is allowed to accept frames with one or more VLAN tags
    """
    tpid: Annotated[Optional[str], Field(alias='srl_nokia-interfaces-vlans:tpid')] = (
        None
    )
    """
    Optionally set the tag protocol identifier field (TPID) that is accepted on the VLAN

    If not set, TPID 0x8100 is the default expected TPID on the interface for tagged
    frames. The behavior when processing untagged frames is unaffected by this command.
    """
    packet_link_qualification: Annotated[
        Optional[PacketLinkQualificationContainer],
        Field(alias='srl_nokia-packet-link-qual:packet-link-qualification'),
    ] = None
    lag: Annotated[
        Optional[LagContainer], Field(alias='srl_nokia-interfaces-lag:lag')
    ] = None
    p4rt: Annotated[
        Optional[P4rtContainer], Field(alias='srl_nokia-interfaces-p4rt:p4rt')
    ] = None
    uuid: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-interfaces-vxdp:uuid',
            pattern='^(?=^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$).*$',
        ),
    ] = None
    """
    The system-generated or user-configured UUID for the interface
    """
    vhost: Annotated[
        Optional[VhostContainer], Field(alias='srl_nokia-interfaces-vxdp:vhost')
    ] = None
    pci: Annotated[
        Optional[PciContainer], Field(alias='srl_nokia-interfaces-vxdp:pci')
    ] = None
    linux: Annotated[
        Optional[LinuxContainer], Field(alias='srl_nokia-interfaces-vxdp:linux')
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
    interface: Annotated[
        Optional[List[InterfaceListEntry]],
        Field(alias='srl_nokia-interfaces:interface'),
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