from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class AcceptModeLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Accept-modeLeaf")]
    """
    Allows ssh,ping,traceroute to be accepted on the virtual
    IP address
    """


class AcceptModeLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Accept-modeLeaf2")]
    """
    Allows ssh,ping,traceroute to be accepted on the virtual
    IP address
    """


class AddressLeaf5(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^[a-zA-Z0-9]{4}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{2}\\.[a-zA-Z0-9]$).*$",
            title="AddressLeaf5",
        ),
    ]
    """
    PCI address of the interface, unpopulated if interface is not present on PCI

    Unpopulated if interface is not available for PCI passthrough. This format follows the extended Domain:Bus:Device.Function (or BDF) notation. In most cases domain will be padded with four 0000's.
    """


class AdminKeyLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535, title="Admin-keyLeaf")]
    """
    Configure the LACP admin-key to be advertised by the local system.
    If this value is not specified a value starting from 32768 is automatically
    assigned by the system.
    """


class AdvertiseIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1000, le=40950, title="Advertise-intervalLeaf")]
    """
    The interval between VRRP messages in milliseconds
    """


class AdvertiseIntervalLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1000, le=40950, title="Advertise-intervalLeaf2")]
    """
    The interval between VRRP messages in milliseconds
    """


class AggregatableLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="AggregatableLeaf")]
    """
    A true value indicates that the participant will allow
    the link to be used as part of the aggregate. A false
    value indicates the link should be used as an individual
    link
    """


class AgingLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615, title="AgingLeaf")]
    """
    remaining age time for learnt macs
    """


class AllowDirectedBroadcastLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Allow-directed-broadcastLeaf")]
    """
    When this is set to true the software is allowed to re-broadcast targeted broadcast IPv4 packets on this subinterface

    Detailed handling of subnet broadcast is as follows:

    If a targeted broadcast packet is received on subinterface X that has the matching subnet then it is delivered to the CPM and CPM will reply to an ICMP echo.

    If a targeted broadcast packet is received on subinterface X but the matching subnet is associated with subinterface Y, and subinterface Y is configured with allow-directed-broadcasts=false then it is delivered to the CPM and CPM replies to an ICMP echo per above, but it does not re-broadcast the packet on subinterface Y.

    If a targeted broadcast packet is received on subinterface X but the matching subnet is associated with subinterface Y, and subinterface Y is configured with allow-directed-broadcasts=true then it is delivered to the CPM and CPM replies to an ICMP echo per above, and CPM also re-broadcasts the packet on subinterface Y.
    """


class AlphanumericType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$"
        ),
    ]
    """
    A simple, one-line string that does not contain any control characters
    """


class AnycastGwLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Anycast-gwLeaf")]
    """
    This designates the associated IPv4 address as an anycast-gateway IPv4 address of the subinterface.

    When this parameter is set to true:
    - The IPv4 address is associated with the anycast-gw MAC address in the same subinterface. ARP Requests received for the anycast-gw IPv4 address
      will be replied using this anycast-gw MAC address.
    - The IPv4 address can have duplicate IPv4 addresses in other IRB subinterfaces of routers attached to the same broadcast domain.
      Because of that ARP duplicate-address-detection procedures do not apply to anycast-gw IP addresses.
    """


class AnycastGwLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Anycast-gwLeaf2")]
    """
    This designates the associated IPv6 address as an anycast-gateway IPv6 address of the subinterface.

    When this parameter is set to true:
    - The IPv6 address is associated with the anycast-gw MAC address in the same subinterface. Neighbor Solicitations received for the anycast-gw IPv6 address
      will be replied using this anycast-gw MAC address.
    - The IPv6 address can have duplicate IPv6 addresses in other IRB subinterfaces of routers attached to the same broadcast domain.
      Because of that, ND duplicate-address-detection procedures do not apply to anycast-gw IP addresses.
    """


class AuthenticatePortLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Authenticate-portLeaf")]
    """
    Enable IEEE802.1X port control on an interface
    """


class AuthenticatorInitiatedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Authenticator-initiatedLeaf")]
    """
    When true the authenticator sends an EAP-Request/EAP-Identity to the Supplicant
    """


class AutoNegotiateLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Auto-negotiateLeaf")]
    """
    When set to true the interface uses auto-negotiation for speed, duplex and flow-control settings.

    When set to false, the transmission parameters are specified manually.
    """


class AutonomousFlagLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Autonomous-flagLeaf")]
    """
    When this is set in the prefix information option hosts can use the prefix for stateless address autoconfiguration (SLAAC). 
    """


class AverageLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf"),
    ]
    """
    Average BER received on the optical channel
    """


class AverageLeaf10(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf10"),
    ]
    """
    Indicates the average Polarization Dependent Loss received on the optical channel
    """


class AverageLeaf11(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf11"),
    ]
    """
    Indicates the average SOP-ROC received on the optical channel
    """


class AverageLeaf13(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf13"),
    ]
    """
    Average power transmitted on the optical channel
    """


class AverageLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf2"),
    ]
    """
    Average SNR received on the optical channel
    """


class AverageLeaf3(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf3"),
    ]
    """
    Average SNR received on the optical channel
    """


class AverageLeaf4(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="AverageLeaf4")]
    """
    Average chromatic dispersion received on the optical channel
    """


class AverageLeaf5(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf5"),
    ]
    """
    Average differential group delay received on the optical channel
    """


class AverageLeaf6(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="AverageLeaf6")]
    """
    Average frequency offset received on the optical channel
    """


class AverageLeaf7(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf7"),
    ]
    """
    Average quality received on the optical channel
    """


class AverageLeaf8(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf8"),
    ]
    """
    Average power received on the optical channel
    """


class AverageLeaf9(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="AverageLeaf9"),
    ]
    """
    Indicates the average total power received on the optical channel
    """


class BroadcastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=132000000, title="Broadcast-rateLeaf")]
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


class CollectDetailedStatsLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Collect-detailed-statsLeaf")]
    """
    Set to false to disable detailed statistics collection on the routed (non IRB) subinterface

    By default detailed statistics are collected for each routed (non IRB) subinterface
    """


class CollectIrbStatsLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Collect-irb-statsLeaf")]
    """
    Set to false to disable statistics collection on the IRB subinterface

    By default basic statistics are collected for each IRB subinterface
    """


class CollectingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="CollectingLeaf")]
    """
    If true, the participant is collecting incoming frames
    on the link, otherwise false
    """


class Counter64Type(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]
    """
    The counter64 type represents a non-negative integer
    that monotonically increases until it reaches a
    maximum value of 2^64-1 (18446744073709551615 decimal),
    when it wraps around and starts increasing again from zero.

    Counters have no defined 'initial' value, and thus, a
    single value of a counter has (in general) no information
    content.  Discontinuities in the monotonically increasing
    value normally occur at re-initialization of the
    management system, and at other times as specified in the
    description of a schema node using this type.  If such
    other times can occur, for example, the creation of
    a schema node of type counter64 at times other than
    re-initialization, then a corresponding schema node
    should be defined, with an appropriate type, to indicate
    the last discontinuity.

    The counter64 type should not be used for configuration
    schema nodes.  A default statement SHOULD NOT be used in
    combination with the type counter64.

    In the value set and its semantics, this type is equivalent
    to the Counter64 type of the SMIv2.
    """


class CurrentHopLimitLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Current-hop-limitLeaf")]
    """
    The current hop limit to advertise in the router advertisement messages.
    """


class CurrentLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf"),
    ]
    """
    Current BER received on the optical channel
    """


class CurrentLeaf10(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf10"),
    ]
    """
    Indicates the current Polarization Dependent Loss received on the optical channel
    """


class CurrentLeaf11(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf11"),
    ]
    """
    Indicates the current SOP-ROC received on the optical channel
    """


class CurrentLeaf13(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf13"),
    ]
    """
    Current power transmitted on the optical channel
    """


class CurrentLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf2"),
    ]
    """
    Current SNR received on the optical channel
    """


class CurrentLeaf3(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf3"),
    ]
    """
    Current SNR received on the optical channel
    """


class CurrentLeaf4(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="CurrentLeaf4")]
    """
    Current chromatic dispersion received on the optical channel
    """


class CurrentLeaf5(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf5"),
    ]
    """
    Current differential group delay received on the optical channel
    """


class CurrentLeaf6(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="CurrentLeaf6")]
    """
    Current frequency offset received on the optical channel
    """


class CurrentLeaf7(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf7"),
    ]
    """
    Current quality received on the optical channel
    """


class CurrentLeaf8(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf8"),
    ]
    """
    Current power received on the optical channel
    """


class CurrentLeaf9(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="CurrentLeaf9"),
    ]
    """
    Indicates the current total power received on the optical channel
    """


class DacLinkTrainingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Dac-link-trainingLeaf")]
    """
    If the system detects that the transceiver is connected to a DAC cable then a true setting enables link training for better link stability. The link training setting must be the same at both ends of the DAC cable or else the link may not come up.
    """


class DatapathProgrammingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Datapath-programmingLeaf")]
    """
    When set to true, the host route is programmed in the datapath
    """


class DatapathProgrammingLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Datapath-programmingLeaf2")]
    """
    When set to true, the host route is programmed in the datapath
    """


class DateAndTimeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$"
        ),
    ]
    """
    The date-and-time type is a profile of the ISO 8601
    standard for representation of dates and times using the
    Gregorian calendar.  The profile is defined by the
    date-time production in Section 5.6 of RFC 3339.

    The date-and-time type is compatible with the dateTime XML
    schema type with the following notable exceptions:

    (a) The date-and-time type does not allow negative years.

    (b) The date-and-time time-offset -00:00 indicates an unknown
        time zone (see RFC 3339) while -00:00 and +00:00 and Z
        all represent the same time zone in dateTime.

    (c) The canonical format (see below) of data-and-time values
        differs from the canonical format used by the dateTime XML
        schema type, which requires all times to be in UTC using
        the time-offset 'Z'.

    This type is not equivalent to the DateAndTime textual
    convention of the SMIv2 since RFC 3339 uses a different
    separator between full-date and full-time and provides
    higher resolution of time-secfrac.

    The canonical format for date-and-time values with a known time
    zone uses a numeric time zone offset that is calculated using
    the device's configured known offset to UTC time.  A change of
    the device's offset to UTC time will cause date-and-time values
    to change accordingly.  Such changes might happen periodically
    in case a server follows automatically daylight saving time
    (DST) time zone offset changes.  The canonical format for
    date-and-time values with an unknown time zone (usually
    referring to the notion of local time) uses the time-offset
    -00:00.
    """


class DdmEventsLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Ddm-eventsLeaf")]
    """
    Controls the reporting of DDM events

    When set to true, log events related to the Digital Diagnostic Monitoring (DDM) capabilities of the transceiver are generated.

    When set to false, no DDM-related log events are generated for this port/transceiver.

    When read from state this leaf always returns false (even if the configured value is true) when the Ethernet port is a copper/RJ45 port.
    """


class DescriptionType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(max_length=255, min_length=1)]
    """
    A user provided description string
    """


class DesignatedForwarderLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Designated-forwarderLeaf")]
    """
    The value of this leaf indicates if the interface is the designated
    forwarder for the ethernet-segment on the network-instance.
    """


class DeviceIdLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Device-idLeaf")]
    """
    PCI device ID

    This field is the two byte device ID reported over PCI.
    """


class DeviceIdLeaf2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Device-idLeaf2")]
    """
    PCI device ID

    This field is the two byte device ID reported over PCI.
    """


class DeviceNameLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Device-nameLeaf")]
    """
    PCI device name
    """


class DeviceNameLeaf2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Device-nameLeaf2")]
    """
    PCI device name
    """


class DeviceNameLeaf3(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(max_length=10, min_length=0, title="Device-nameLeaf3")]
    """
    Slow path device name of this interface in Linux

    This is the interface name that can be used to look at this interface within Linux.

    If not specified it is auto-derived by the system.
    """


class DisableIpTimestampingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Disable-ip-timestampingLeaf")]
    """
    Disables timestamping of PTP over IP messages on this port

    For platforms supporting PTP functionality, any transiting PTP over IP packets are timestamped in hardware by default, regardless of whether PTP is enabled on the system. To avoid unwanted correction-field updates of PTP transit packets on ports (ports involved in PTP packet transit only), this command can be used to disabled the timestmaping.
    """


class DiscardUnknownSrcMacLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Discard-unknown-src-macLeaf")]
    """
    Discard frames with unknown source mac addresses. The source mac address of
    the discarded frame is never learned when this command is enabled.
    """


class DispersionLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-50000, le=50000, title="DispersionLeaf")]
    """
    Residual chromatic dispersion compensation
    """


class DistributingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="DistributingLeaf")]
    """
    When true, the participant is distributing outgoing
    frames; when false, distribution is disabled
    """


class DomainNameType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^((([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*([a-zA-Z0-9_]([a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)|\\.$).*$"
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


class DomainLeaf(RootModel[DomainNameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DomainNameType, Field(title="DomainLeaf")]
    """
    The server domain name
    """


class DomainLeaf2(RootModel[DomainNameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DomainNameType, Field(title="DomainLeaf2")]
    """
    The server domain name
    """


class DoubleTaggedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Double-taggedLeaf")]
    """
    tunnel double tagged dot1x PDUs through the interface
    """


class DownLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=86400000, title="DownLeaf")]
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


class DuplicateAddressDetectionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Duplicate-address-detectionLeaf")]
    """
    If set to true IPv4 Address Conflict Detection per RFC 5227 is performed on the IPv4 address assigned to the subinterface
    """


class DuplicateAddressDetectionLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Duplicate-address-detectionLeaf2")]
    """
    Enables Duplicate Addres Detection on all tentative addresses

    This applies to link-local and global unicast addresses. Only one transmission is done; there are no retransmissions.

    Must be true on an IPv6 subinterface that has dhcp-client enabled.
    """


class EgressSamplingRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=2000000, title="Egress-sampling-rateLeaf")]
    """
    Specify sFlow Egress packet sample rate.
    This value is the rate at which traffic will be sampled at a rate of 1:N received packets.
    """


class EndLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-50000, le=50000, title="EndLeaf")]
    """
    Upper bound of the dispersion compensation range
    """


class EsManagedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Es-managedLeaf")]
    """
    The value of this leaf indicates if the interface is managed
    by the ethernet-segment on the network-instance.
    """


class EthernetPmdLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Ethernet-pmdLeaf")]
    """
    Specifies the Ethernet compliance code of the transceiver associated with the port
    """


class ExpectedRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Expected-rateLeaf")
    ]
    """
    Expected rate of the test

    This is the computed or
    observed rate that the service expected to be maintained
    throughout the qualification duration.
    """


class ExponentLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="ExponentLeaf")]
    """
    Signal-degrade exponent
    """


class ExponentLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="ExponentLeaf2")]
    """
    Signal-failure exponent
    """


class ExponentLeaf3(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="ExponentLeaf3")]
    """
    Signal-degrade exponent
    """


class ExponentLeaf4(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="ExponentLeaf4")]
    """
    Signal-failure exponent
    """


class FailedComplexListType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str, Field(pattern="^(?=^(\\(([0-9]|[1][0-9]|[2][0-4]),[0-1]\\))$).*$")
    ]


class FailedSlotsLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=16, title="Failed-slotsLeafList")]
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class FaultConditionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Fault-conditionLeaf")]
    """
    Indicates if a fault condition exists in the transceiver.
    """


class ForwardingViableLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Forwarding-viableLeaf")]
    """
    If true:
    this LAG member link should be used for the transmission of traffic if all other LAG/port attributes allow it.

    If false:
    this LAG member link should not be used for the transmission of traffic.

    In all cases:
    This LAG member link should process any received frames when it is an active member link.  L2 protocols such as LLDP, LACP and micro-BFD should continue to be sent and processed.
    """


class FunctionalTypeLeaf(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="Functional-typeLeaf")]
    """
    Indicates the module functional type which will be deployed for this interface

    This refines the set of leaves available within the transceiver configuration.
    """


class Gauge64Type(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615)]
    """
    The gauge64 type represents a non-negative integer, which
    may increase or decrease, but shall never exceed a maximum
    value, nor fall below a minimum value.  The maximum value
    cannot be greater than 2^64-1 (18446744073709551615), and
    the minimum value cannot be smaller than 0.  The value of
    a gauge64 has its maximum value whenever the information
    being modeled is greater than or equal to its maximum
    value, and has its minimum value whenever the information
    being modeled is smaller than or equal to its minimum value.
    If the information being modeled subsequently decreases
    below (increases above) the maximum (minimum) value, the
    gauge64 also decreases (increases).

    In the value set and its semantics, this type is equivalent
    to the CounterBasedGauge64 SMIv2 textual convention defined
    in RFC 2856
    """


class HalfLifeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=2000, title="Half-lifeLeaf")]
    """
    Half-life decay time
    """


class HighAlarmConditionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="High-alarm-conditionLeaf")]
    """
    High alarm threshold condition

    Set to true whenever the temperature is above the high-alarm-threshold and set to false whenever the temperature is below the high-alarm-threshold
    """


class HighAlarmConditionLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="High-alarm-conditionLeaf2")]
    """
    High alarm threshold condition.

    Set to true whenever the module voltage is above the high-alarm-threshold and set to false whenever the module voltage is below the high-alarm-threshold
    """


class HighAlarmThresholdLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="High-alarm-thresholdLeaf2",
        ),
    ]
    """
    High alarm threshold.

    Read from the installed transceiver
    """


class HighWarningConditionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="High-warning-conditionLeaf")]
    """
    High warning threshold condition.

    Set to true whenever the temperature is above the high-warning-threshold and set to false whenever the temperature is below the high-warning-threshold
    """


class HighWarningConditionLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="High-warning-conditionLeaf2")]
    """
    High warning threshold condition.

    Set to true whenever the module voltage is above the high-warning-threshold and set to false whenever the module voltage is below the high-warning-threshold
    """


class HighWarningThresholdLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="High-warning-thresholdLeaf2",
        ),
    ]
    """
    High warning threshold.

    Read from the installed transceiver
    """


class HoldDownTimeRemainingLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Hold-down-time-remainingLeaf")
    ]
    """
    remaining hold down time for duplicate mac
    """


class IdLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=4294967295, title="IdLeaf2")]
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


class IfindexLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="IfindexLeaf")]
    """
    System-wide persistent unique ifIndex assigned to the interface
    """


class IfindexLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="IfindexLeaf2")]
    """
    System-wide persistent unique ifIndex assigned to the subinterface
    """


class InBpsLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615, title="In-bpsLeaf")]
    """
    The ingress bandwidth utilization of the port
    """


class IndexLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=10)]
    """
    Index of the physical channel or lane
    """


class IndexLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=1, title="IndexLeaf2")]
    """
    Index of the optical channel
    """


class IndexLeaf3(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    Index of the current logical channel
    """


class IndexLeaf4(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=9999, title="IndexLeaf4")]
    """
    The index of the subinterface, or logical interface number
    """


class IngressSamplingRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=2000000, title="Ingress-sampling-rateLeaf")]
    """
    Specify sFlow Ingress packet sample rate.
    This value is the rate at which traffic will be sampled at a rate of 1:N received packets.
    """


class InitDelayLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535, title="Init-delayLeaf")]
    """
    Initialization delay in seconds before a router that
    just rebooted will preempt an existing master router.
    Only applicable if preempt is enabled
    """


class InitDelayLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535, title="Init-delayLeaf2")]
    """
    Initialization delay in seconds before a router that
    just rebooted will preempt an existing master router.
    Only applicable if preempt is enabled
    """


class InnerTpidLeaf(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="Inner-tpidLeaf")]
    """
    Optionally override the inner tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class InnerTpidLeaf2(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="Inner-tpidLeaf2")]
    """
    Optionally override the inner tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class InterfaceNameType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: str


class IpMtuLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1280, le=9486, title="Ip-mtuLeaf")]
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


class IpMtuLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1280, le=9486, title="Ip-mtuLeaf2")]
    """
    The IP MTU to advertise in the router advertisement messages and that hosts should associate with the link on which these messages are received.

    If no value is specified the option is not included.
    """


class Ipv4PrefixType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$"
        ),
    ]
    """
    An IPv4 prefix represented in dotted quad notation followed by a slash and a CIDR mask (0 <= mask <= 32).
    """


class Ipv4Type(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$"
        ),
    ]


class Ipv6PrefixType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$"
        ),
    ]
    """
    An IPv6 prefix represented in full, shortened, or mixed shortened format followed by a slash and CIDR mask (0 <= mask <=
    128).
    """


class Ipv6Type(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$"
        ),
    ]


class IsRouterLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Is-routerLeaf")]
    """
    Indicates that the neighbor node claims to be a router (R bit in the Neighbor Advertisement message)
    """


class L2MtuLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1450, le=9500, title="L2-mtuLeaf")]
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


class LacpFallbackTimeoutLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=4, le=3600, title="Lacp-fallback-timeoutLeaf")]
    """
    Specifies the LACP-fallback timeout interval in seconds
    """


class LacpPortPriorityLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Lacp-port-priorityLeaf")]
    """
    Configure the port priority for LACP.  This value is used to  determine which port should be activated with LACP fallback mode. Lower values are more preferred.
    """


class LacpPortPriorityLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Lacp-port-priorityLeaf2")]
    """
    Configure the port priority for LACP.  This value is used to  determine which port should be activated with LACP fallback mode. Lower values are more preferred.
    """


class LagSpeedLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="Lag-speedLeaf")]
    """
    reports current aggregate bandwidth speed of the associated LAG
    """


class LastFailedComplexesLeafList(RootModel[FailedComplexListType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[FailedComplexListType, Field(title="Last-failed-complexesLeafList")]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class LastFailedComplexesLeafList2(RootModel[FailedComplexListType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        FailedComplexListType, Field(title="Last-failed-complexesLeafList2")
    ]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class LastReportedDynamicDelayLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=2147483647, title="Last-reported-dynamic-delayLeaf")
    ]
    """
    Indicates the last delay measurement reported to the routing engine
    """


class LatestValueLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18, le=9.223372036854776e18, title="Latest-valueLeaf2"
        ),
    ]
    """
    The current voltage reading of the transceiver module (in Volts)
    """


class LearnUnsolicitedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Learn-unsolicitedLeaf")]
    """
    If set to true an ARP entry should be learned from any received ARP packets.
    """


class LinkLossForwardingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Link-loss-forwardingLeaf")]
    """
    Indicates whether link-loss-forwarding is enabled in the interface

    When enabled, faults can be propagated to the devices connected to this interface. It is supported on interfaces
    with a single non-tagged subinterface that is associated to a network-instance of type vpws. On VPWS services,
    the propagation of faults from a connection-point to the opposite connection-point is known as Link Loss
    Forwarding and requires setting this command to true and the standby-signaling command to the type of propagation
    signaling to be used with the connected Customer Equipment.
    """


class LinuxContainer(BaseModel):
    """
    Top-level container for configuration and state related to Linux interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    device_name: Annotated[
        DeviceNameLeaf3, Field(None, alias="srl_nokia-interfaces-vxdp:device-name")
    ]


class LocalFileType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern="^(?=^(/[0-9A-Za-z_\\-\\.]+)+$).*$")]
    """
    A regular expression matching a local file
    """


class LogOnlyLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Log-onlyLeaf")]
    """
    Generate only a log message when limit is reached

    When set to true, neighbor entries are still being learned after
    exceeding the max-entries limit.
    """


class LogicalChannelLeaf(RootModel[IndexLeaf3]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IndexLeaf3, Field(title="Logical-channelLeaf")]
    """
    Logical channel associated to this optical channel

    This is used to assist with the openconfig management of DCO using logical channels
    """


class LowAlarmConditionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Low-alarm-conditionLeaf")]
    """
    Low alarm threshold condition.

    Set to true whenever the temperature is below the low-alarm-threshold and set to false whenever the temperature is above the low-alarm-threshold
    """


class LowAlarmConditionLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Low-alarm-conditionLeaf2")]
    """
    Low alarm threshold condition.

    Set to true whenever the module voltage is below the low-alarm-threshold and set to false whenever the module voltage is above the low-alarm-threshold
    """


class LowAlarmThresholdLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Low-alarm-thresholdLeaf2",
        ),
    ]
    """
    Low alarm threshold.

    Read from the installed transceiver
    """


class LowWarningConditionLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Low-warning-conditionLeaf")]
    """
    Low warning threshold condition.

    Set to true whenever the temperature is below the low-warning-threshold and set to false whenever the temperature is above the low-warning-threshold
    """


class LowWarningConditionLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Low-warning-conditionLeaf2")]
    """
    Low warning threshold condition.

    Set to true whenever the module voltage is below the low-warning-threshold and set to false whenever the module voltage is above the low-warning-threshold
    """


class LowWarningThresholdLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Low-warning-thresholdLeaf2",
        ),
    ]
    """
    Low warning threshold .

    Read from the installed transceiver
    """


class MacAddressType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern="^(?=^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$).*$")]
    """
    The mac-address type represents an IEEE 802 MAC address.
    The canonical representation uses lowercase characters.

    In the value set and its semantics, this type is equivalent
    to the MacAddress textual convention of the SMIv2.
    """


class MacLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="MacLeaf")]
    """
    Source MAC address of a host that is authorized to use this interface
    """


class MacLeaf3(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: MacAddressType
    """
    Host MAC address
    """


class MajorRevisionLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Major-revisionLeaf")]
    """
    Major revision number
    """


class ManagedConfigurationFlagLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Managed-configuration-flagLeaf")]
    """
    When this is set the M-bit is set in the router advertisement messages, indicating that hosts should use DHCPv6 to obtain IPv6 addresses.
    """


class MasterInheritIntervalLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Master-inherit-intervalLeaf")]
    """
    Learn VRRP advertisement interval from master
    """


class MasterInheritIntervalLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Master-inherit-intervalLeaf2")]
    """
    Learn VRRP advertisement interval from master
    """


class MaxAdvertisementIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=4, le=1800, title="Max-advertisement-intervalLeaf")]
    """
    The maximum time between sending router advertisement messages to the all-nodes multicast address.

    Each subinterface has its own timer. Whenever the timer fires the message is sent and then the timer is reset to a uniformly distributed random value between min-advertisement-interval and max-advertisement-interval. The RA message can be sent before timer expiry in response to a RS message.
    """


class MaxAuthenticationRequestsLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=10, title="Max-authentication-requestsLeaf")]
    """
    Maximum number of RADIUS retries before the authentication fails

    In the case of challenge response, if the supplicant does not respond
    the authenticator will retransmit the challenge without going to the radius server.
    This parameter will be used toward supplicant as well when the challenge respond is
    dropped.
    """


class MaxEntriesLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="Max-entriesLeaf")]
    """
    The maximum number of neighbor entries allowed on the subinterface

    If not configured, the amount of neighbor entries on the subinterface
    is only limited by the total amount of entries supported by the router.
    """


class MaxRequestsLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=10, title="Max-requestsLeaf")]
    """
    Maximum number of times an EAPoL request packet is retransmitted to the supplicant before the authentication session fails
    """


class MaxSuppressTimeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=43200, title="Max-suppress-timeLeaf")]
    """
    Maximum suppression time
    """


class MaximumEntriesLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=8192, title="Maximum-entriesLeaf")]
    """
    Maximum number of mac addresses allowed in the bridge-table.
    """


class MaximumLeaf10(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf10"),
    ]
    """
    Maximum power received on the optical channel
    """


class MaximumLeaf11(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf11"),
    ]
    """
    Indicates the maximum total power received on the optical channel
    """


class MaximumLeaf12(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf12"),
    ]
    """
    Indicates the maximum Polarization Dependent Loss received on the optical channel
    """


class MaximumLeaf13(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf13"),
    ]
    """
    Indicates the maximum SOP-ROC received on the optical channel
    """


class MaximumLeaf14(RootModel[Gauge64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Gauge64Type, Field(title="MaximumLeaf14")]
    """
    Indicates the maximum Media Frame Rate Error Count received on the optical channel
    """


class MaximumLeaf15(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf15"),
    ]
    """
    Maximum power transmitted on the optical channel
    """


class MaximumLeaf16(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf16"),
    ]
    """
    Maximum configurable transmit power for the equipped optical module
    """


class MaximumLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-100000, le=100000, title="MaximumLeaf2")]
    """
    Chromatic dispersion sweep range maximum

    This has different defaults based on the setting of the operational-mode.
    """


class MaximumLeaf3(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf3"),
    ]
    """
    Maximum BER received on the optical channel
    """


class MaximumLeaf4(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf4"),
    ]
    """
    Maximum SNR received on the optical channel
    """


class MaximumLeaf5(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf5"),
    ]
    """
    Maximum SNR received on the optical channel
    """


class MaximumLeaf6(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="MaximumLeaf6")]
    """
    Maximum chromatic dispersion received on the optical channel
    """


class MaximumLeaf7(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf7"),
    ]
    """
    Maximum differential group delay received on the optical channel
    """


class MaximumLeaf8(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="MaximumLeaf8")]
    """
    Maximum frequency offset received on the optical channel
    """


class MaximumLeaf9(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MaximumLeaf9"),
    ]
    """
    Maximum quality received on the optical channel
    """


class MdLevelsOrderedTypeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^(0|0 1|0 1 2|0 1 2 3|0 1 2 3 4|0 1 2 3 4 5|0 1 2 3 4 5 6|0 1 2 3 4 5 6 7)$).*$"
        ),
    ]
    """
    Forced ascending order of the maintenance domain levels from 0 to 7 starting

    This forces the allowable maintenance domain levels within the range of 0..7 in ascending order, starting
    at 0.  Partial ranges can be entered and must start at 0 separated by space.
    For example, 0 1 2 3 4 would be acceptable based on the regular expression pattern match.
    However, 0 2 3 4 would cause an error condition because the numbers are not contiguous.  This pattern does
    not allow trailing spaces after the last numerical value.
    """


class MicrobfdEnabledLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Microbfd-enabledLeaf")]
    """
    Indicates if microBFD is currently used in the determination of the member-link oper-status
    """


class MinAdvertisementIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=3, le=1350, title="Min-advertisement-intervalLeaf")]
    """
    The minimum time between sending router advertisement messages to the all-nodes multicast address.

    Each subinterface has its own timer. Whenever the timer fires the message is sent and then the timer is reset to a uniformly distributed random value between min-advertisement-interval and max-advertisement-interval. The RA message can be sent before timer expiry in response to a RS message.
    """


class MinLinksLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=64, title="Min-linksLeaf")]
    """
    Specifies the mininum number of member
    interfaces that must be active for the aggregate interface
    to be available
    """


class MinimumLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-100000, le=0, title="MinimumLeaf")]
    """
    Chromatic dispersion sweep range minimum

    This has different defaults based on the setting of the operational-mode.  This value is usually a large negative number
    """


class MinimumLeaf10(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf10"),
    ]
    """
    Indicates the minimum total power received on the optical channel
    """


class MinimumLeaf11(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf11"),
    ]
    """
    Indicates the minimum Polarization Dependent Loss received on the optical channel
    """


class MinimumLeaf12(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf12"),
    ]
    """
    Indicates the minimum SOP-ROC received on the optical channel
    """


class MinimumLeaf13(RootModel[Gauge64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Gauge64Type, Field(title="MinimumLeaf13")]
    """
    Indicates the minimum Media Frame Rate Error Count received on the optical channel
    """


class MinimumLeaf14(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf14"),
    ]
    """
    Minimum power transmitted on the optical channel
    """


class MinimumLeaf15(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf15"),
    ]
    """
    Minimum configurable transmit power for the equipped optical module
    """


class MinimumLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf2"),
    ]
    """
    Minimum BER received on the optical channel
    """


class MinimumLeaf3(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf3"),
    ]
    """
    Minimum SNR received on the optical channel
    """


class MinimumLeaf4(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf4"),
    ]
    """
    Minimum SNR received on the optical channel
    """


class MinimumLeaf5(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="MinimumLeaf5")]
    """
    Minimum chromatic dispersion received on the optical channel
    """


class MinimumLeaf6(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf6"),
    ]
    """
    Minimum differential group delay received on the optical channel
    """


class MinimumLeaf7(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2147483648, le=2147483647, title="MinimumLeaf7")]
    """
    Minimum frequency offset received on the optical channel
    """


class MinimumLeaf8(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf8"),
    ]
    """
    Minimum quality received on the optical channel
    """


class MinimumLeaf9(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(ge=-9.223372036854776e18, le=9.223372036854776e18, title="MinimumLeaf9"),
    ]
    """
    Minimum power received on the optical channel
    """


class MinorRevisionLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Minor-revisionLeaf")]
    """
    Minor revision number
    """


class ModelNumberLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Model-numberLeaf")]
    """
    Model information for the adapter

    This is the information as read from the EEPROM of the part.  The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """


class MplsMtuLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1284, le=9496, title="Mpls-mtuLeaf")]
    """
    MPLS MTU of the subinterface in bytes, including the transmitted label stack.

    MPLS MTU specifies the maximum sized MPLS packet that can be transmitted on the subinterface. If an MPLS packet containing any payload exceeds this size then it is dropped. If the payload of the dropped packet is IPv4 or IPv6 then this may also result in the generation of an ICMP error message that is either tunneled or sent back to the source.

    The default MPLS MTU for a subinterface is taken from /system/mtu/default-mpls-mtu.

    The MPLS MTU is not configurable for subinterfaces of loopback interfaces.

    The 7730 SXR systems support a maximum MPLS MTU of 9404 bytes.

    Each 7250 IXR IMM supports a maximum of 4 different MPLS MTU values.
    """


class MstInstanceLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="Mst-instanceLeaf")]
    """
    Name of the subinterface bound to this mstp-policy
    """


class MtuLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1450, le=9500, title="MtuLeaf")]
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


class MulticastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=132000000, title="Multicast-rateLeaf")]
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


class MultiplierLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="MultiplierLeaf")]
    """
    Signal-degrade multiplier
    """


class MultiplierLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="MultiplierLeaf2")]
    """
    Signal-failure multiplier
    """


class MultiplierLeaf3(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="MultiplierLeaf3")]
    """
    Signal-degrade multiplier
    """


class MultiplierLeaf4(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=9, title="MultiplierLeaf4")]
    """
    Signal-failure multiplier
    """


class NameLeaf3(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="NameLeaf3")]
    """
    The system assigned name of the subinterface.

    It is formed by taking the base interface name and appending a dot (.) and the subinterface index number. For example, ethernet-2/1.0
    """


class NameType(RootModel[AlphanumericType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: AlphanumericType
    """
    A user provided name
    """


class NumPhysicalChannelsLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=8, title="Num-physical-channelsLeaf")]
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


class OnLinkFlagLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="On-link-flagLeaf")]
    """
    When this is set in the prefix information option hosts can use the prefix for on-link determination.
    """


class OperIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Oper-intervalLeaf")]
    """
    The operational advertisement interval between VRRP messages
    """


class OperIntervalLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Oper-intervalLeaf2")]
    """
    The operational advertisement interval between VRRP messages
    """


class OperKeyLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Oper-keyLeaf")]
    """
    Current operational value of the key for the aggregate
    interface
    """


class OperationalBroadcastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=4294967295, title="Operational-broadcast-rateLeaf")
    ]
    """
    The operational maximum rate for ingress broadcast frames programmed on the interface
    """


class OperationalMulticastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=4294967295, title="Operational-multicast-rateLeaf")
    ]
    """
    The operational maximum rate for ingress multicast frames programmed on the interface
    """


class OperationalPriorityLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Operational-priorityLeaf")]
    """
    Reports the current VRRP operational priority.
    """


class OperationalPriorityLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Operational-priorityLeaf2")]
    """
    Reports the current VRRP operational priority.
    """


class OperationalUnknownUnicastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=4294967295, title="Operational-unknown-unicast-rateLeaf")
    ]
    """
    The operational maximum rate for ingress unknown unicast frames programmed on the interface
    """


class OpticalDwdmFrequencyType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=191100000, le=196150000)]
    """
    Specifies the frequency of a tuneable DWDM optical interface

    Note that tunable DWDM optical interfaces operate at specific frequencies on grids. Traditionally, these have used the 100 GHz or 50 GHz grid but newer interfaces can support other grids such as 75 GHz, 33 GHz, 25 GHz, 12.5 GHz, 6.25 GHz and 3.125 GHz.  In addition, some interfaces allow for fine tuning of the frequency to values off grid.
    """


class OpticalSignalToNoiseRatioContainer(BaseModel):
    """
    Enter the optical-signal-to-noise-ratio context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf3, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf3, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf4, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf5, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class OtherConfigurationFlagLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Other-configuration-flagLeaf")]
    """
    When this is set the O-bit is set in the router advertisement messages, indicating that hosts should use DHCPv6 to obtain other configuration information (besides addresses).
    """


class OutBpsLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615, title="Out-bpsLeaf")]
    """
    The egress bandwidth utilization of the port
    """


class OuterTpidLeaf(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="Outer-tpidLeaf")]
    """
    Optionally override the outer tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class OuterTpidLeaf2(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="Outer-tpidLeaf2")]
    """
    Optionally override the outer tag protocol identifier field (TPID)

    The configured tpid is used by the action configured by 'vlan-stack-action'
    when modifying the VLAN stack.
    """


class OwnerLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="OwnerLeaf")]
    """
    VRRP instance is owner or not
    """


class OwnerLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="OwnerLeaf2")]
    """
    VRRP instance is owner or not
    """


class PacketLinkQualificationIdType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^[<>A-Za-z0-9!@#$%^&()|+=`~.,'/_:;?-][<>A-Za-z0-9 !@#$%^&()|+=`~.,'/_:;?-]*$).*$"
        ),
    ]
    """
    Packet link qualification test ID
    """


class PacketsDroppedLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Packets-droppedLeaf")
    ]
    """
    Number of packets dropped
    """


class PacketsErrorLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Packets-errorLeaf")
    ]
    """
    Number of packets transmitted that experienced corruption
    """


class PacketsReceivedLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Packets-receivedLeaf")
    ]
    """
    Number of packets received
    """


class PacketsSentLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615, title="Packets-sentLeaf")]
    """
    Number of packets sent
    """


class ParentIdLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=18446744073709551615, title="Parent-idLeaf")]
    """
    The numeric ID used by the controller to address the ASIC this interface resides on

    This is the ID configured at /platform/linecard/forwarding-complex/p4rt/id.

    This ID may be referred to as a 'device', 'node' or 'target' by the P4RT
    specification.

    Each switching ASIC (i.e., node) is addressed by the external entity
    based on its numeric identifier.
    """


class PartnerIdLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Partner-idLeaf")]
    """
    MAC address representing the protocol partner's interface
    system ID
    """


class PartnerKeyLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Partner-keyLeaf")]
    """
    Operational value of the protocol partner's key
    """


class PartnerPortNumLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Partner-port-numLeaf")]
    """
    Port number of the partner (remote) port for this member
    port
    """


class PhyGroupMembersLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Phy-group-membersLeafList")]
    """
    The group of interfaces sharing a phy with this interface

    On the 7220 IXR-D2 and 7220 IXR-D2L platforms this group of interfaces must be set to the same speed, either 1/10G or 25G.
    """


class PhysicalChannelLeafList(RootModel[IndexLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IndexLeaf, Field(title="Physical-channelLeafList")]
    """
    The list of transceiver channels associated with this port
    """


class PolarizationDependentLossContainer(BaseModel):
    """
    Enter the polarization-dependent-loss context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf10, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf10, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf11, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf12, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class PortNumLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Port-numLeaf")]
    """
    Port number of the local (actor) aggregation member
    """


class PowerContainer(BaseModel):
    """
    Enter the power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf8, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf8, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf9, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf10, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class PowerContainer2(BaseModel):
    """
    Enter the power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf13, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf13, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf14, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf15, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class PreemptDelayLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535, title="Preempt-delayLeaf")]
    """
    Delay in seconds before a router preempts an existing
    master router, only applicable if preempt is enabled
    """


class PreemptDelayLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535, title="Preempt-delayLeaf2")]
    """
    Delay in seconds before a router preempts an existing
    master router, only applicable if preempt is enabled
    """


class PreemptLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="PreemptLeaf")]
    """
    Enable VRRP master pre-emption.
    If enabled, router with higher priority can assume
    master role.
    If disabled, router can only become master if no
    other master is present
    """


class PreemptLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="PreemptLeaf2")]
    """
    Enable VRRP master pre-emption.
    If enabled, router with higher priority can assume
    master role.
    If disabled, router can only become master if no
    other master is present
    """


class PreferredLifetimeLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="Preferred-lifetimeLeaf")]
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
    )


class PrimaryLeaf2(BaseModel):
    """
    One of the IPv6 prefixes assigned to the subinterface can be explicitly configured as primary by setting this leaf to true. This designates the associated IPv6 address as a primary IPv6 address of the subinterface. By default, the numerically lowest value IPv6 address is selected as the primary address.

    The primary address is used as the source address for locally originated broadcast and multicast packets sent out the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )


class PriorityDecrementLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Priority-decrementLeaf")]
    """
    For each tracked interface that is down then the priority
    is decremented by the specific amount to a minimum value of 0
    """


class PriorityDecrementLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Priority-decrementLeaf2")]
    """
    For each tracked interface that is down then the priority
    is decremented by the specific amount to a minimum value of 0
    """


class PriorityLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=254, title="PriorityLeaf")]
    """
    Base VRRP Priority for associated Virtual Address
    """


class PriorityLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=254, title="PriorityLeaf2")]
    """
    Base VRRP Priority for associated Virtual Address
    """


class ProbeIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=86400, title="Probe-intervalLeaf")]
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


class ProbeIntervalLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=86400, title="Probe-intervalLeaf2")]
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


class ProxyArpLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Proxy-arpLeaf")]
    """
    When set to true, the router replies with its own MAC to ARP Request destined to any host.
    """


class ProxyNdLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Proxy-ndLeaf")]
    """
    When set to true, the router replies with its own MAC to Neighbor Solicitations destined to any host.
    """


class PtpAsymmetryLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=-2147483648, le=2147483647, title="Ptp-asymmetryLeaf")
    ]
    """
    This command configures the PTP asymmetry delay on the Ethernet port

    This command is used to correct known asymmetry as part of time of day or phase
    recovery using PTP packets on both local and downstream PTP clocks.
    """


class PtpTimestampingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    disable_ip_timestamping: Annotated[
        DisableIpTimestampingLeaf,
        Field(None, alias="srl_nokia-interfaces:disable-ip-timestamping"),
    ]


class QualificationRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        int, Field(ge=0, le=18446744073709551615, title="Qualification-rateLeaf")
    ]
    """
    Observed rate of the test

    This is the computed or
    observed rate that the service expected to be maintained
    throughout the qualification duration.
    """


class QualityContainer(BaseModel):
    """
    Enter the quality context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf7, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf7, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf8, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf9, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class QuietPeriodLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=3600, title="Quiet-periodLeaf")]
    """
    Time to wait after a failed session when no EAPoL frames are processed
    """


class RadiusPolicyLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Radius-policyLeaf")]
    """
    RADIUS policy used for 802.1x authentication
    """


class RangeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="RangeLeaf")]
    """
    The positive or negative offset that can be applied when using frequency fine tuning

    The offset is from a frequency of one of the grids supported by the equipped optical module.
    """


class ReachableTimeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=30, le=3600, title="Reachable-timeLeaf")]
    """
    The period of time that a dynamic IPv6 neighbor cache entry is considered reachable after a reachability confirmation event

    After this time expires the neighbor state moves to STALE.
    """


class ReachableTimeLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=3600000, title="Reachable-timeLeaf2")]
    """
    The time, in milliseconds, that is advertised as the reachable time in RA messages and that hosts use for the ICMPv6 Neighbor Unreachability Detection algorithm. A value of zero means unspecified by this router.
    """


class ReauthenticateIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Reauthenticate-intervalLeaf")]
    """
    Enable periodic re-authentication of the device connected to this port

    Send out a identity request once every unit seconds.
    Setting a value of 0 disables re-authentication on this port.
    """


class ReceiveLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="ReceiveLeaf")]
    """
    When this is true PAUSE frames received on this interface are accepted and processed, and, if auto-negotiation is enabled it also causes the capability to receive PAUSE frames to be signaled to the peer (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports).

    When this is false PAUSE frames received on this interface are ignored, and, if auto-negotiation is enabled it causes the capability to receive PAUSE frames to be signaled to the peer as non-support (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports)
    """


class ReloadDelayLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=86400, title="Reload-delayLeaf")]
    """
    Configure reload-delay timer for Ethernet interfaces.

    The reload-delay timer starts when the associated XDP interface state is learned. While the timer is
    running, the interface transceiver laser is disabled to avoid attracting traffic from the connected
    device at the other end of the interface. The reload-delay timer should be used in multi-homing
    interfaces and be set to a value long enough to allow the system to recover all the network protocols
    upon reboot, before start attracting traffic from the multi-homed device.
    """


class ResolutionLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="ResolutionLeaf")]
    """
    The resolution that can be used for frequency fine tuning.
    """


class RestrictedNameType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,_:;?-]*$).*$"
        ),
    ]
    """
    A simple, one-line string that does not contain any control characters, and is Linux-safe.
    """


class RetransmitIntervalLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Retransmit-intervalLeaf")]
    """
    How long the interface waits for a response before restarting authentication

    How long the interface waits for a response from an EAPoL Start before restarting 802.1X authentication on the port.
    """


class RetransmitTimeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=1800000, title="Retransmit-timeLeaf")]
    """
    The time, in milliseconds, that is advertised as the retrans-timer in RA messages and that hosts use for address resolution and the Neighbor Unreachability Detection algorithm. It represents the time between retransmitted NS messages. A value of zero means unspecified by this router.
    """


class ReuseThresholdLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=20000, title="Reuse-thresholdLeaf")]
    """
    Threshold which port-up state is no longer suppressed
    """


class RouterLifetimeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=9000, title="Router-lifetimeLeaf")]
    """
    The lifetime in seconds that is advertised as the router lifetime in RA messages. This indicates the time period for which the advertising router can be used as a default router/gateway. A value of 0 means the router should not be used as a default gateway.
    """


class RxElectricalSnrXPolarizationLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Rx-electrical-snr-x-polarizationLeaf",
        ),
    ]
    """
    Indicates the network received electrical SNR (Signal-to-Noise Ratio) of X polarization.
    """


class RxElectricalSnrYPolarizationLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Rx-electrical-snr-y-polarizationLeaf",
        ),
    ]
    """
    Indicates the network received electrical SNR (Signal-to-Noise Ratio) of Y polarization.
    """


class RxLosThreshLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-3000, le=-1300, title="Rx-los-threshLeaf")]
    """
    Average input power LOS threshold
    """


class RxOpticalSnrXPolarizationLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Rx-optical-snr-x-polarizationLeaf",
        ),
    ]
    """
    Indicates the network received estimated optical SNR (Signal-to-Noise Ratio) of X polarization.
    """


class RxOpticalSnrYPolarizationLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Rx-optical-snr-y-polarizationLeaf",
        ),
    ]
    """
    Indicates the network received estimated optical SNR (Signal-to-Noise Ratio) of Y polarization.
    """


class RxQualityMarginLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18,
            le=9.223372036854776e18,
            title="Rx-quality-marginLeaf",
        ),
    ]
    """
    Indicates the received quality margin.
    """


class SerialNumberLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Serial-numberLeaf")]
    """
    Transceiver serial number

    This is the information as read from the EEPROM of the part.
    """


class SignalDegradeContainer(BaseModel):
    """
    Signal-degrade parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    exponent: Annotated[ExponentLeaf, Field(5, alias="srl_nokia-interfaces:exponent")]
    multiplier: Annotated[
        MultiplierLeaf, Field(1, alias="srl_nokia-interfaces:multiplier")
    ]


class SignalDegradeContainer2(BaseModel):
    """
    Signal-degrade parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    exponent: Annotated[ExponentLeaf3, Field(5, alias="srl_nokia-interfaces:exponent")]
    multiplier: Annotated[
        MultiplierLeaf3, Field(1, alias="srl_nokia-interfaces:multiplier")
    ]


class SignalFailureContainer(BaseModel):
    """
    Signal-failure parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    exponent: Annotated[ExponentLeaf2, Field(5, alias="srl_nokia-interfaces:exponent")]
    multiplier: Annotated[
        MultiplierLeaf2, Field(1, alias="srl_nokia-interfaces:multiplier")
    ]


class SignalFailureContainer2(BaseModel):
    """
    Signal-failure parameters to calculate threshold M*10E-N where M is the configured multiplier and N the configured exponent
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    exponent: Annotated[ExponentLeaf4, Field(5, alias="srl_nokia-interfaces:exponent")]
    multiplier: Annotated[
        MultiplierLeaf4, Field(1, alias="srl_nokia-interfaces:multiplier")
    ]


class SingleTaggedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Single-taggedLeaf")]
    """
    tunnel single tagged dot1x PDUs through the interface
    """


class SlotLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=16)]
    """
    Numeric identifier for the linecard
    """


class SocketCpusLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Socket-cpusLeafList")]
    """
    List of CPUs present on the socket this interface is attached to
    """


class SocketCpusLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="Socket-cpusLeafList2")]
    """
    List of CPUs present on the socket this interface is attached to
    """


class SocketIdLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Socket-idLeaf")]
    """
    Socket this interface is physically or logically attached to

    This field is not populated for interfaces that have no socket preference - e.g. veth, tap.
    """


class SocketIdLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=255, title="Socket-idLeaf2")]
    """
    Socket this interface is physically or logically attached to

    This field is not populated for interfaces that have no socket preference - e.g. veth, tap.
    """


class SquelchLevelsLeaf(RootModel[MdLevelsOrderedTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MdLevelsOrderedTypeType, Field(title="Squelch-levelsLeaf")]
    """
    Contiguous ETH-CFM Maintenance Domain levels silently discarded at ingress, matching subinterface and level

    ETH-CFM packets ingressing a subinterface that match the definition of the subinterface and have an ETH-CFM level
    that is part of the squelching configuration will be silently discarded without processing. The lookup is an exact
    match of the subinterface followed immediately by the ETH-CFM etype 0x8902 and a level equal to any configured squelch
    values.  The lookup for the ETH-CFM level cannot exceed a total of two VLAN tags.  Ingress squelching will occur
    prior to any ingress ETH-CFM MP processing.  For example, if a down MEP exists on the subinterface with a level
    covered by the configured squelch levels the packet will be dropped before the packet it reaches the down MEP.
    """


class StaleTimeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=60, le=65535, title="Stale-timeLeaf")]
    """
    The maximum time that a dynamic IPv6 neighbor cache entry can remain in the STALE state before it is removed

    This limit is reached only if no traffic is sent/queued towards the neighbor during the entire duration of the timer.
    """


class StartLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-50000, le=50000, title="StartLeaf")]
    """
    Lower bound of the dispersion compensation range
    """


class StateOfPolarizationRateOfChangeContainer(BaseModel):
    """
    Enter the state-of-polarization-rate-of-change context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf11, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf11, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf12, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf13, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class StateLeaf(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="StateLeaf")]
    """
    Virtual Router state (Initialize, Backup, Master)
    """


class StateLeaf2(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="StateLeaf2")]
    """
    Virtual Router state (Initialize, Backup, Master)
    """


class StaticDelayLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=16777215, title="Static-delayLeaf")]
    """
    A statically configured unidirectional delay value that can be advertised as an interface attribute by an IGP
    """


class StatusMessageLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Status-messageLeaf")]
    """
    Status message of the test

    Only set when the test is in the error state.
    """


class StpPathCostTypeType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=65535)]
    """
    The interface path-cost is used by STP to calculate the path cost
    to the root bridge. STP defined this as a function of link bandwidth
    but this configuration is static.
    """


class StpPortNumberTypeType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=2047)]
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


class StpPortPriorityTypeType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=16, le=255)]
    """
    The port-priority command is used to populate the priority portion
    of the bridge ID field within outbound BPDUs (the most significant 4
    bits of the bridge ID). It is also used as part of the decision process
    when determining the best BPDU between messages received and sent.
    When running MSTP, this is the bridge priority used for the CIST.

    All values are truncated to multiples of 4096, conforming with
    IEEE 802.1t and 802.1D-2004.
    """


class SubinterfaceNameType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: str


class SupplicantTimeoutLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=300, title="Supplicant-timeoutLeaf")]
    """
    Time to wait for a response from the supplicant before restarting the authentication process
    """


class SuppressThresholdLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=20000, title="Suppress-thresholdLeaf")]
    """
    Threshold at which the port-up state is suppressed
    """


class SweepContainer(BaseModel):
    """
    Enter the sweep context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    start: Annotated[StartLeaf, Field(-25500, alias="srl_nokia-interfaces-dco:start")]
    end: Annotated[EndLeaf, Field(2000, alias="srl_nokia-interfaces-dco:end")]


class SystemIdMacLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="System-id-macLeaf")]
    """
    The MAC address portion of the node's System ID. This is
    combined with the system priority to construct the 8-octet
    system-id.
    If not configured, the system-ID configured at the system/ level is used.
    """


class SystemIdLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="System-idLeaf")]
    """
    MAC address that defines the local system ID for the
    aggregate interface
    """


class SystemPriorityLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=65535, title="System-priorityLeaf")]
    """
    System priority used by the node on this LAG interface.
    Lower value is higher priority for determining which node
    is the controlling system.
    If not configured, the system-priority configured at the system/ level is used.
    """


class TargetPowerLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-2000, le=300, title="Target-powerLeaf")]
    """
    Average output power target for the port
    """


class TemperatureType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=-32768, le=32767)]
    """
    Integer indicating a temperature, displayed as degrees celsius
    """


class TimeoutLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=60, le=65535, title="TimeoutLeaf")]
    """
    Duration of time that dynamic ARP entries remain in the ARP cache before they expire

    A change to this value does not affect existing entries until they are refreshed.
    """


class TotalPowerContainer(BaseModel):
    """
    Enter the total-power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf9, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf9, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf10, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf11, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class TpidLeaf(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="TpidLeaf")]
    """
    Optionally set the tag protocol identifier field (TPID) that is accepted on the VLAN

    If not set, TPID 0x8100 is the default expected TPID on the interface for tagged
    frames. The behavior when processing untagged frames is unaffected by this command.
    """


class TrafficRateContainer(BaseModel):
    """
    Container for traffic rate statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_bps: Annotated[InBpsLeaf, Field(None, alias="srl_nokia-interfaces:in-bps")]
    out_bps: Annotated[OutBpsLeaf, Field(None, alias="srl_nokia-interfaces:out-bps")]


class TransmitPowerContainer(BaseModel):
    """
    Enter the transmit-power context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    minimum: Annotated[
        MinimumLeaf15, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf16, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class TransmitLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TransmitLeaf")]
    """
    Enables/disables the sending of PAUSE frames.

    If auto-negotiation is enabled (applicable only to ports 1-48 of the 7220 IXR-D1 and to mgmt0 and mgmt0-standby ports) PAUSE frames are sent to the peer only if the peer advertised support for PAUSE frames.
    """


class TransmittedContainer(BaseModel):
    """
    Enter the transmitted context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    power: Annotated[
        PowerContainer2, Field(None, alias="srl_nokia-interfaces-dco:power")
    ]


class TunnelAllL2cpLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Tunnel-all-l2cpLeaf")]
    """
    Configures the tunneling of all the L2CP protocols.

    When set to true this command triggers the installation of an ingress TCAM rule with the highest
    priority (above all the individual L2CP tunnel rules) which allows the forwarding of any
    Layer-2 Control Protocol coming into the interface. All the L2CP frames identified by
    MAC DA = 01:80:c2:00:00:0x or MAC DA = 01:80:c2:00:00:2x, with 'x' being any hex value, are
    tunneled. When set to false, all L2CP frames without a specific L2CP tunnel rule are discarded.
    """


class TunnelAllLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Tunnel-allLeaf")]
    """
    tunnel all dot1x PDUs through the interface

    tunnel untagged and tagged dot1x PDUs.
    """


class TunnelLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf")]
    """
    Configures if incoming LLDP frames are tunneled.

    LLDP frames are identified by MAC DA 01-80-c2-00-00-00 and Ethertype 0x88cc.
    """


class TunnelLeaf2(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf2")]
    """
    Configures if incoming LACP frames are tunneled.

    LACP frames are identified by MAC DA 01-80-c2-00-00-02, Ethertype 0x8809 and slow-protocol
    sub-type 0x01.
    """


class TunnelLeaf3(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf3")]
    """
    Configures if incoming xSTP frames are tunneled.

    xSTP frames are identified by MAC DA 01-80-c2-00-00-00 and any Ethertype.
    """


class TunnelLeaf4(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf4")]
    """
    Configures if incoming dot1x frames are tunneled.

    Dot1x frames are identified by MAC DA 01-80-c2-00-00-03 and Ethertype 0x888e.
    """


class TunnelLeaf5(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf5")]
    """
    Configures if incoming ptp frames are tunneled.

    ptp frames are identified by MAC DA 01-80-c2-00-00-0e and Ethertype 0x88f7.
    """


class TunnelLeaf6(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf6")]
    """
    Configures if incoming esmc frames are tunneled

    ESMC frames are identified by Ethertype 0x8809 and slow protocol subtype 0x0A.
    """


class TunnelLeaf7(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf7")]
    """
    Configures if incoming ELMI frames are tunneled

    ELMI frames are identified by MAC DA 01-80-C2-00-00-07 and Ethertype 0x88ee.
    """


class TunnelLeaf8(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="TunnelLeaf8")]
    """
    Configures if incoming EFM-OAM frames are tunneled

    EFM-OAM frames are identified by Ethertype 0x8809 and slow protocol subtype 0x03.
    """


class TxFilterEnableLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Tx-filter-enableLeaf")]
    """
    Controls transmit filtering
    """


class TxLaserLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Tx-laserLeaf")]
    """
    Enable (true) or disable (false) the transmit laser of the transceiver

    When read from state this leaf always returns false (even if the configured value is true) when the Ethernet port is a copper/RJ45 port.

    Default is true (for interfaces that support transceivers).
    """


class TypeLeaf2(RootModel[Any]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Any, Field(title="TypeLeaf2")]
    """
    Indicates the context in which the ethernet subinterface will be used
    """


class UnicastMacAddressType(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: MacAddressType
    """
    A unicast MAC address.

    The least significant bit of a MAC address first octet
    is never set. The value 00:00:00:00:00:00 is not valid.
    """


class UnknownUnicastRateLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=132000000, title="Unknown-unicast-rateLeaf")]
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


class UntaggedContainer(BaseModel):
    """
    When present, untagged frames and VLAN ID 0 priority tagged frames are associated to the subinterface when it belongs to an interface with vlan-tagging enabled
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )


class UntaggedLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="UntaggedLeaf")]
    """
    tunnel untagged dot1x PDUs through the interface
    """


class UpLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=86400000, title="UpLeaf")]
    """
    Holds link up events for the configured time

    The hold-time up behavior is triggered with any event that tries to bring up the ethernet interface
    (interface admin-state enable, a reboot, etc). While the hold-time up is running, the transceiver
    laser will be enabled, however the higher layers will not be notified that the interface is
    operationally up until the timer expires.
    """


class UseGiAddrAsSrcIpAddrLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Use-gi-addr-as-src-ip-addrLeaf")]
    """
    When this is set, the configured giaddress will be used as source ip address.
    """


class UuidType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern="^(?=^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$).*$"
        ),
    ]
    """
    A Universally Unique IDentifier in the string representation
    defined in RFC 4122.  The canonical representation uses
    lowercase characters.

    The following is an example of a UUID in string representation:
    f81d4fae-7dec-11d0-a765-00a0c91e6bf6
    """


class ValidLifetimeLeaf1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4294967295, title="Valid-lifetimeLeaf")]
    """
    The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for the purpose of on-link determination. 
    """


class VendorIdLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-idLeaf")]
    """
    PCI device vendor ID

    This field is the two byte vendor ID reported over PCI.
    """


class VendorIdLeaf2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-idLeaf2")]
    """
    PCI device vendor ID

    This field is the two byte vendor ID reported over PCI.
    """


class VendorLotNumberLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-lot-numberLeaf")]
    """
    Vendor's lot number for the transceiver

    This is the information as read from the EEPROM of the part.
    """


class VendorManufactureDateLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-manufacture-dateLeaf")]
    """
    Vendor's date code.

    This is the information as read from the EEPROM of the part.  
    """


class VendorNameLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-nameLeaf")]
    """
    PCI device vendor
    """


class VendorNameLeaf2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-nameLeaf2")]
    """
    PCI device vendor
    """


class VendorOuiLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-ouiLeaf")]
    """
    Vendor's OUI which contains the IEEE company identifier for the vendor

    This is the information as read from the EEPROM of the part.  A value of all zero indicates that the vendor OUI is unspecified.
    """


class VendorPartNumberLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-part-numberLeaf")]
    """
    Vendor's part number or product name of the adapter

    This is the information as read from the EEPROM of the part.  An empty string indicates the vendor part number is unspecified. The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """


class VendorPartNumberLeaf2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-part-numberLeaf2")]
    """
    Vendor's part number for the transceiver

    This is the information as read from the EEPROM of the part.
    """


class VendorRevisionLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-revisionLeaf")]
    """
    Vendor's revision number for the transceiver

    This is the information as read from the EEPROM of the part.
    """


class VendorSerialNumberLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="Vendor-serial-numberLeaf")]
    """
    Vendor's serial number of the adapter

    This is the information as read from the EEPROM of the part.  An empty string indicates the vendor serial number is unspecified. The string is expected to contain printable ASCII characters, but unprintable ASCII characters read from the EEPROM are not filtered out.
    """


class VendorLeaf(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[str, Field(title="VendorLeaf")]
    """
    Name of the transceiver vendor

    This is the information as read from the EEPROM of the part.
    """


class VersionLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=2, le=3, title="VersionLeaf")]
    """
    VRRP version for the Instance
    """


class VersionLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=2, le=3, title="VersionLeaf2")]
    """
    VRRP version for the Instance
    """


class VhostSocketPathLeaf(RootModel[LocalFileType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LocalFileType, Field(title="Vhost-socket-pathLeaf")]
    """
    Filesystem path to the vhost-user socket
    """


class VhostSocketQueuesLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=1024, title="Vhost-socket-queuesLeaf")]
    """
    The number of vhost-user queues

    The number of queues are retrieved from the vhost-user socket if not configured. This should be set equivalent to the number of vCPUs allocated to the other end of the vhost-user interface. This value must not exceed the count of vCPUs provided as the vXDP cpu-set.
    """


class VirtualMacLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Virtual-macLeaf")]
    """
    VRRP Instance generated virtual mac
    """


class VirtualMacLeaf2(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Virtual-macLeaf2")]
    """
    VRRP Instance generated virtual mac
    """


class VirtualRouterIdLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=255, title="Virtual-router-idLeaf")]
    """
    VRRP Group Index
    """


class VirtualRouterIdLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=255, title="Virtual-router-idLeaf2")]
    """
    VRRP Group Index
    """


class VirtualRouterIdLeaf3(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=255, title="Virtual-router-idLeaf3")]
    """
    The Virtual Router Identifier (VRID) value used to auto-derive the anycast-gw-mac in the format 00:00:5E:00:01:VRID.
    """


class VlanIdLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=0, le=4095, title="Vlan-idLeaf2")]


class VlanIdType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
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
    )
    vlan_id: Annotated[VlanIdLeaf2, Field(None, alias="srl_nokia-ra_guard:vlan-id")]


class VlanTaggingLeaf(RootModel[bool]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[bool, Field(title="Vlan-taggingLeaf")]
    """
    When set to true the interface is allowed to accept frames with one or more VLAN tags
    """


class VoltageContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    latest_value: Annotated[
        LatestValueLeaf2, Field(None, alias="srl_nokia-interfaces:latest-value")
    ]
    high_alarm_condition: Annotated[
        HighAlarmConditionLeaf2,
        Field(None, alias="srl_nokia-interfaces:high-alarm-condition"),
    ]
    high_alarm_threshold: Annotated[
        HighAlarmThresholdLeaf2,
        Field(None, alias="srl_nokia-interfaces:high-alarm-threshold"),
    ]
    low_alarm_condition: Annotated[
        LowAlarmConditionLeaf2,
        Field(None, alias="srl_nokia-interfaces:low-alarm-condition"),
    ]
    low_alarm_threshold: Annotated[
        LowAlarmThresholdLeaf2,
        Field(None, alias="srl_nokia-interfaces:low-alarm-threshold"),
    ]
    high_warning_condition: Annotated[
        HighWarningConditionLeaf2,
        Field(None, alias="srl_nokia-interfaces:high-warning-condition"),
    ]
    high_warning_threshold: Annotated[
        HighWarningThresholdLeaf2,
        Field(None, alias="srl_nokia-interfaces:high-warning-threshold"),
    ]
    low_warning_condition: Annotated[
        LowWarningConditionLeaf2,
        Field(None, alias="srl_nokia-interfaces:low-warning-condition"),
    ]
    low_warning_threshold: Annotated[
        LowWarningThresholdLeaf2,
        Field(None, alias="srl_nokia-interfaces:low-warning-threshold"),
    ]


class WarningThresholdPctLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=1, le=100, title="Warning-threshold-pctLeaf")]
    """
    Threshold percentage of the configured maximum number of entries

    When exceeded, an event is triggered.
    """


class WarningThresholdPctLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=6, le=100, title="Warning-threshold-pctLeaf2")]
    """
    Percentage of the configured max-number-macs over which a warning is triggered.
    The warning message is cleared when the percentage drops below the configured
    percentage minus 5%
    """


class WavelengthLeaf(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18, le=9.223372036854776e18, title="WavelengthLeaf"
        ),
    ]
    """
    Wavelength of the transmitting laser in nanometers
    """


class WavelengthLeaf2(RootModel[float]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        float,
        Field(
            ge=-9.223372036854776e18, le=9.223372036854776e18, title="WavelengthLeaf2"
        ),
    ]
    """
    Wavelength of the transmitting laser in nanometers
    """


class WindowSizeLeaf(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=5, le=60, title="Window-sizeLeaf")]
    """
    Sliding window size over which errors are measured
    """


class WindowSizeLeaf2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[int, Field(ge=5, le=60, title="Window-sizeLeaf2")]
    """
    Sliding window size over which errors are measured
    """


class ZeroBasedCounter64Type(RootModel[Counter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Counter64Type
    """
    The zero-based-counter64 type represents a counter64 that
    has the defined 'initial' value zero.

    A schema node of this type will be set to zero (0) on creation
    and will thereafter increase monotonically until it reaches
    a maximum value of 2^64-1 (18446744073709551615 decimal),
    when it wraps around and starts increasing again from zero.

    Provided that an application discovers a new schema node
    of this type within the minimum time to wrap, it can use the
    'initial' value as a delta.  It is important for a management
    station to be aware of this minimum time and the actual time
    between polls, and to discard data if the actual time is too
    long or there is no defined minimum time.

    In the value set and its semantics, this type is equivalent
    to the ZeroBasedCounter64 textual convention of the SMIv2.
    """


class EnumerationEnum(Enum):
    enable = "enable"
    disable = "disable"


class EnumerationEnum10(Enum):
    not_present = "not-present"
    read_failure = "read-failure"
    checksum_failure = "checksum-failure"
    unknown_transceiver = "unknown-transceiver"
    tx_laser_disabled = "tx-laser-disabled"
    unsupported_breakout = "unsupported-breakout"
    port_disabled = "port-disabled"
    connector_transceiver_down = "connector-transceiver-down"
    unsupported_operational_mode = "unsupported-operational-mode"
    no_tunable_config = "no-tunable-config"


class EnumerationEnum11(Enum):
    cfp2 = "CFP2"
    cfp2_aco = "CFP2-ACO"
    cfp4 = "CFP4"
    qsfp = "QSFP"
    qsf_pplus = "QSFPplus"
    qsfp28 = "QSFP28"
    qsfpdd = "QSFPDD"
    sfp = "SFP"
    sf_pplus = "SFPplus"
    non_pluggable = "Non-pluggable"
    other = "Other"
    sfp28 = "SFP28"
    sfpdd = "SFPDD"
    qsfp56 = "QSFP56"
    sfp56 = "SFP56"


class EnumerationEnum12(Enum):
    sc = "SC"
    fc_style1_copper = "FC-STYLE1-COPPER"
    fc_style2_copper = "FC-STYLE2-COPPER"
    bnc_or_tnc = "BNC-OR-TNC"
    fc_coax = "FC-COAX"
    fiber_jack = "FIBER-JACK"
    lc = "LC"
    mt_rj = "MT-RJ"
    mu = "MU"
    sg = "SG"
    optical_pigtail = "OPTICAL-PIGTAIL"
    mpo_1x12 = "MPO-1x12"
    mpo_2x16 = "MPO-2x16"
    hssdc = "HSSDC"
    copper_pigtail = "COPPER-PIGTAIL"
    rj45 = "RJ45"
    no_separable_connector = "no-separable-connector"
    mxc_2x16 = "MXC-2x16"
    cs_optical_connector = "CS-OPTICAL-CONNECTOR"
    sn_optical_connector = "SN-OPTICAL-CONNECTOR"
    mpo_2x12 = "MPO-2x12"
    mpo_1x16 = "MPO-1x16"
    unknown = "unknown"


class EnumerationEnum13(Enum):
    unspecified = "unspecified"
    healthy = "healthy"
    unhealthy = "unhealthy"


class EnumerationEnum14(Enum):
    field_21 = "21"
    field_22 = "22"
    field_25 = "25"
    field_33 = "33"
    field_37 = "37"
    field_43 = "43"
    field_51 = "51"
    field_61 = "61"
    field_65 = "65"
    field_69 = "69"
    field_81 = "81"
    field_82 = "82"
    field_83 = "83"
    field_85 = "85"
    field_88 = "88"
    field_169 = "169"


class EnumerationEnum15(Enum):
    unequipped = "unequipped"
    not_tunable = "not-tunable"
    fully_tunable = "fully-tunable"
    tunable_100g = "tunable-100g"
    flex_tunable = "flex-tunable"


class EnumerationEnum16(Enum):
    grid_100_ghz = "grid-100-ghz"
    grid_75_ghz = "grid-75-ghz"
    grid_50_ghz = "grid-50-ghz"
    grid_33_ghz = "grid-33-ghz"
    grid_25_ghz = "grid-25-ghz"
    grid_12500_mhz = "grid-12500-mhz"
    grid_6250_mhz = "grid-6250-mhz"
    grid_3125_mhz = "grid-3125-mhz"


class EnumerationEnum17(Enum):
    automatic = "automatic"
    manual = "manual"


class EnumerationEnum18(Enum):
    none = "none"
    squelch = "squelch"


class EnumerationEnum19(Enum):
    reset = "reset"
    init = "init"
    low_power = "low-power"
    high_power_up = "high-power-up"
    high_power_down = "high-power-down"
    tx_off = "tx-off"
    tx_turn_off = "tx-turn-off"
    tx_turn_on = "tx-turn-on"
    ready = "ready"
    fault = "fault"


class EnumerationEnum2(Enum):
    field_1 = "1"
    field_2 = "2"
    field_3 = "3"
    field_4 = "4"
    field_8 = "8"


class EnumerationEnum20(Enum):
    init = "init"
    laser_turn_up = "laser-turn-up"
    laser_ready_off = "laser-ready-off"
    laser_ready = "laser-ready"
    modulator_converge = "modulator-converge"
    output_power_adjust = "output-power-adjust"


class EnumerationEnum21(Enum):
    init = "init"
    laser_ready = "laser-ready"
    wait_for_input = "wait-for-input"
    adc_signal = "adc-signal"
    optical_lock = "optical-lock"
    demod_lock = "demod-lock"


class EnumerationEnum22(Enum):
    module_fault = "module-fault"
    module_alarm = "module-alarm"
    media_receive_alarm = "media-receive-alarm"
    media_transmit_alarm = "media-transmit-alarm"
    host_transmit_alarm = "host-transmit-alarm"


class EnumerationEnum23(Enum):
    over_temp = "over-temp"
    hw_post = "hw-post"
    pld_flash_init = "pld-flash-init"
    power_supply = "power-supply"
    check_sum = "check-sum"
    ref_clock_in = "ref-clock-in"
    tx_jit_pll_lol = "tx-jit-pll-lol"
    tx_cmu_lol = "tx-cmu-lol"
    tx_loss_func = "tx-loss-func"
    host_tx_lol = "host-tx-lol"
    net_rx_lol = "net-rx-lol"
    host_tx_skew_high = "host-tx-skew-high"
    net_tx_tec = "net-tx-tec"
    net_tx_wave_unlk = "net-tx-wave-unlk"
    net_tx_losf = "net-tx-losf"
    net_rx_los = "net-rx-los"
    net_rx_fifo_err = "net-rx-fifo-err"
    net_rx_tec = "net-rx-tec"
    net_tx_out_of_align = "net-tx-out-of-align"
    net_tx_cmu_lock = "net-tx-cmu-lock"
    net_tx_ref_clk = "net-tx-ref-clk"
    net_rx_modem_sync_det = "net-rx-modem-sync-det"
    net_rx_modem_lock = "net-rx-modem-lock"
    host_tx_lane_fifo_err = "host-tx-lane-fifo-err"
    host_tx_deskew = "host-tx-deskew"
    host_rx_corr = "host-rx-corr"
    host_rx_uncorr = "host-rx-uncorr"
    comm_fail = "comm-fail"


class EnumerationEnum24(Enum):
    full = "full"
    half = "half"


class EnumerationEnum25(Enum):
    field_10_m = "10M"
    field_100_m = "100M"
    field_1_g = "1G"
    field_10_g = "10G"
    field_25_g = "25G"
    field_40_g = "40G"
    field_50_g = "50G"
    field_100_g = "100G"
    field_200_g = "200G"
    field_400_g = "400G"
    field_800_g = "800G"
    field_1_t = "1T"


class EnumerationEnum26(Enum):
    field_1000_base_t = "1000BASE-T"


class EnumerationEnum27(Enum):
    power_off = "power-off"
    lacp = "lacp"


class EnumerationEnum28(Enum):
    none = "none"
    sd_threshold_exceeded = "sd-threshold-exceeded"
    sf_threshold_exceeded = "sf-threshold-exceeded"


class EnumerationEnum29(Enum):
    active = "active"
    idle = "idle"


class EnumerationEnum3(Enum):
    field_10_g = "10G"
    field_25_g = "25G"
    field_50_g = "50G"
    field_100_g = "100G"
    field_200_g = "200G"
    field_400_g = "400G"


class EnumerationEnum30(Enum):
    kbps = "kbps"
    percentage = "percentage"


class EnumerationEnum31(Enum):
    none = "none"
    trigger_event = "trigger-event"
    disable_interface = "disable-interface"


class EnumerationEnum32(Enum):
    force_unauthorized = "force-unauthorized"
    auto = "auto"
    force_authorized = "force-authorized"


class EnumerationEnum33(Enum):
    single_host = "single-host"
    multi_host = "multi-host"
    multi_domain = "multi-domain"


class EnumerationEnum34(Enum):
    authenticated = "AUTHENTICATED"
    authenticating = "AUTHENTICATING"
    failed_authentication = "FAILED_AUTHENTICATION"
    supplicant_timeout = "SUPPLICANT_TIMEOUT"


class EnumerationEnum35(Enum):
    trap_to_cpu_untagged = "trap-to-cpu-untagged"
    drop_tagged_and_untagged = "drop-tagged-and-untagged"
    tunnel_tagged_and_untagged = "tunnel-tagged-and-untagged"
    tunnel_tagged_drop_untagged = "tunnel-tagged-drop-untagged"
    tunnel_tagged_trap_to_cpu_untagged = "tunnel-tagged-trap-to-cpu-untagged"


class EnumerationEnum36(Enum):
    none = "none"


class EnumerationEnum37(Enum):
    none = "none"


class EnumerationEnum38(Enum):
    up = "up"
    down = "down"


class EnumerationEnum39(Enum):
    admin_disabled = "admin-disabled"
    port_down = "port-down"
    ip_mtu_resource_exceeded = "ip-mtu-resource-exceeded"
    mpls_mtu_resource_exceeded = "mpls-mtu-resource-exceeded"
    ip_mtu_too_large = "ip-mtu-too-large"
    mpls_mtu_too_large = "mpls-mtu-too-large"
    l2_mtu_too_large = "l2-mtu-too-large"
    no_ip_config = "no-ip-config"
    ip_mtu_larger_than_oper_mac_vrf_mtu = "ip-mtu-larger-than-oper-mac-vrf-mtu"
    irb_mac_address_not_programmed = "irb-mac-address-not-programmed"
    missing_xdp_state = "missing-xdp-state"
    no_underlay_egress_next_hop_resources = "no-underlay-egress-next-hop-resources"
    cfm_ccm_defect = "cfm-ccm-defect"
    no_irb_hardware_resources = "no-irb-hardware-resources"
    other = "other"


class EnumerationEnum4(Enum):
    up = "up"
    down = "down"
    testing = "testing"


class EnumerationEnum40(Enum):
    other = "other"
    static = "static"
    dhcp = "dhcp"
    link_layer = "link-layer"
    random = "random"


class EnumerationEnum41(Enum):
    preferred = "preferred"
    inaccessible = "inaccessible"
    tentative = "tentative"
    duplicate = "duplicate"


class EnumerationEnum42(Enum):
    up = "up"
    down = "down"
    empty = "empty"
    downloading = "downloading"
    booting = "booting"
    starting = "starting"
    failed = "failed"
    synchronizing = "synchronizing"
    upgrading = "upgrading"
    low_power = "low-power"
    degraded = "degraded"
    warm_reboot = "warm-reboot"
    waiting = "waiting"


class EnumerationEnum43(Enum):
    admin_down = "admin-down"
    sub_intf_down = "sub-intf-down"
    virtual_ip_mismatch = "virtual-ip-mismatch"
    authentication_config = "authentication-config"
    other = "other"


class EnumerationEnum44(Enum):
    not_same_network_instance = "not-same-network-instance"
    referenced_interface_is_down = "referenced-interface-is-down"
    referenced_interface_ipv4_is_down = "referenced-interface-ipv4-is-down"
    referenced_interface_has_no_ipv4_addresses = (
        "referenced-interface-has-no-ipv4-addresses"
    )


class EnumerationEnum45(Enum):
    other = "other"
    static = "static"
    dynamic = "dynamic"
    evpn = "evpn"


class EnumerationEnum46(Enum):
    success = "success"
    failed = "failed"
    pending = "pending"


class EnumerationEnum47(Enum):
    static = "static"
    dynamic = "dynamic"
    evpn = "evpn"


class EnumerationEnum48(Enum):
    messages = "messages"


class EnumerationEnum49(Enum):
    static = "static"
    dynamic = "dynamic"


class EnumerationEnum5(Enum):
    port_admin_disabled = "port-admin-disabled"
    mda_admin_disabled = "mda-admin-disabled"
    transceiver_oper_down = "transceiver-oper-down"
    port_not_present = "port-not-present"
    mda_not_present = "mda-not-present"
    phy_initializing = "phy-initializing"
    lower_layer_down = "lower-layer-down"
    auto_negotiation_mismatch = "auto-negotiation-mismatch"
    port_mtu_resource_exceeded = "port-mtu-resource-exceeded"
    unsupported_speed = "unsupported-speed"
    unsupported_fec = "unsupported-fec"
    other = "other"
    fabric_availability = "fabric-availability"
    no_active_links = "no-active-links"
    min_link_threshold = "min-link-threshold"
    port_9_12_speed_mismatch = "port-9-12-speed-mismatch"
    lag_resource_exceeded = "lag-resource-exceeded"
    lag_member_resource_exceeded = "lag-member-resource-exceeded"
    standby_signaling = "standby-signaling"
    interface_hold_time_up_active = "interface-hold-time-up-active"
    interface_reload_timer_active = "interface-reload-timer-active"
    connector_down = "connector-down"
    event_handler = "event-handler"
    unsupported_breakout_port = "unsupported-breakout-port"
    cfm_ccm_defect = "cfm-ccm-defect"
    crc_monitor_fail_threshold = "crc-monitor-fail-threshold"
    symbol_monitor_fail_threshold = "symbol-monitor-fail-threshold"
    link_loss_forwarding = "link-loss-forwarding"
    storm_control_action = "storm-control-action"
    unsupported_num_channels_for_speed = "unsupported-num-channels-for-speed"


class EnumerationEnum50(Enum):
    dhcp_relay_admin_down = "dhcp-relay-admin-down"
    sub_interface_oper_down = "sub-interface-oper-down"
    all_dhcp_servers_unreachable_within_net_instance = (
        "all-dhcp-servers-unreachable-within-net-instance"
    )
    gi_address_not_matching_relay_sub_interface_ipv4_addresses = (
        "gi-address-not-matching-relay-sub-interface-ipv4-addresses"
    )
    no_valid_ipv4_address_on_sub_interface = "no-valid-ipv4-address-on-sub-interface"


class EnumerationEnum51(Enum):
    circuit_id = "circuit-id"
    remote_id = "remote-id"


class EnumerationEnum52(Enum):
    messages = "messages"


class EnumerationEnum53(Enum):
    messages = "messages"


class EnumerationEnum54(Enum):
    global_unicast = "global-unicast"
    link_local_unicast = "link-local-unicast"


class EnumerationEnum55(Enum):
    preferred = "preferred"
    deprecated = "deprecated"
    invalid = "invalid"
    inaccessible = "inaccessible"
    unknown = "unknown"
    tentative = "tentative"
    duplicate = "duplicate"
    optimistic = "optimistic"


class EnumerationEnum56(Enum):
    none = "none"
    global_ = "global"
    link_local = "link-local"
    both = "both"


class EnumerationEnum57(Enum):
    incomplete = "incomplete"
    reachable = "reachable"
    stale = "stale"
    delay = "delay"
    probe = "probe"


class EnumerationEnum58(Enum):
    success = "success"
    failed = "failed"
    pending = "pending"


class EnumerationEnum59(Enum):
    static = "static"
    dynamic = "dynamic"
    evpn = "evpn"


class EnumerationEnum6(Enum):
    field_0 = "0"
    field_1 = "1"


class EnumerationEnum60(Enum):
    messages = "messages"


class EnumerationEnum61(Enum):
    static = "static"
    dynamic = "dynamic"


class EnumerationEnum62(Enum):
    dhcp_relay_admin_down = "dhcp-relay-admin-down"
    sub_interface_oper_down = "sub-interface-oper-down"
    all_dhcpv6_servers_unreachable_within_net_instance = (
        "all-dhcpv6-servers-unreachable-within-net-instance"
    )
    source_address_not_matching_relay_sub_interface_ipv6_addresses = (
        "source-address-not-matching-relay-sub-interface-ipv6-addresses"
    )
    no_valid_ipv6_address_on_sub_interface = "no-valid-ipv6-address-on-sub-interface"


class EnumerationEnum63(Enum):
    interface_id = "interface-id"
    remote_id = "remote-id"
    client_link_layer_address = "client-link-layer-address"


class EnumerationEnum64(Enum):
    messages = "messages"


class EnumerationEnum65(Enum):
    infinite = "infinite"


class EnumerationEnum66(Enum):
    infinite = "infinite"


class EnumerationEnum67(Enum):
    messages = "messages"


class EnumerationEnum68(Enum):
    messages = "messages"


class EnumerationEnum69(Enum):
    configured = "configured"
    vrid_auto_derived = "vrid-auto-derived"


class EnumerationEnum7(Enum):
    store_and_forward = "store-and-forward"
    cut_through = "cut-through"


class EnumerationEnum70(Enum):
    disabled = "disabled"


class EnumerationEnum71(Enum):
    use_net_instance_action = "use-net-instance-action"
    stop_learning = "stop-learning"
    blackhole = "blackhole"
    oper_down = "oper-down"


class EnumerationEnum72(Enum):
    indefinite = "indefinite"


class EnumerationEnum73(Enum):
    yes = "yes"
    no = "no"


class EnumerationEnum74(Enum):
    yes = "yes"
    no = "no"


class EnumerationEnum75(Enum):
    shared = "shared"
    pt_pt = "pt-pt"


class EnumerationEnum76(Enum):
    yes = "yes"
    no = "no"


class EnumerationEnum77(Enum):
    static = "static"
    duplicate = "duplicate"
    learnt = "learnt"
    irb_interface = "irb-interface"
    evpn = "evpn"
    evpn_static = "evpn-static"
    irb_interface_anycast = "irb-interface-anycast"
    proxy_anti_spoof = "proxy-anti-spoof"
    reserved = "reserved"
    eth_cfm = "eth-cfm"
    irb_interface_vrrp = "irb-interface-vrrp"


class EnumerationEnum78(Enum):
    mac_limit = "mac-limit"
    failed_on_slots = "failed-on-slots"
    no_destination_index = "no-destination-index"
    reserved = "reserved"


class EnumerationEnum79(Enum):
    i_pv4 = "IPv4"
    i_pv6 = "IPv6"
    i_pv4v6 = "IPv4v6"


class EnumerationEnum8(Enum):
    unknown = "unknown"
    qsfp28_to_sfp__sfp28 = "qsfp28-to-sfp+/sfp28"
    cfp_to_qsfp28 = "cfp-to-qsfp28"


class EnumerationEnum80(Enum):
    optional = "optional"
    any = "any"


class EnumerationEnum81(Enum):
    any = "any"
    optional = "optional"


class EnumerationEnum82(Enum):
    any = "any"
    optional = "optional"


class EnumerationEnum83(Enum):
    push = "PUSH"
    pop = "POP"
    swap = "SWAP"
    preserve = "PRESERVE"
    push_push = "PUSH-PUSH"
    pop_pop = "POP-POP"
    pop_swap = "POP-SWAP"
    swap_swap = "SWAP-SWAP"


class EnumerationEnum84(Enum):
    unspecified = "unspecified"
    error = "error"
    idle = "idle"
    setup = "setup"
    running = "running"
    teardown = "teardown"
    completed = "completed"


class EnumerationEnum85(Enum):
    not_found = "not-found"
    invalid_argument = "invalid-argument"
    canceled = "canceled"
    deadline_exceeded = "deadline-exceeded"
    failed_precondition = "failed-precondition"
    internal = "internal"


class EnumerationEnum86(Enum):
    lacp = "lacp"
    static = "static"


class EnumerationEnum87(Enum):
    field_10_m = "10M"
    field_100_m = "100M"
    field_1_g = "1G"
    field_10_g = "10G"
    field_25_g = "25G"
    field_40_g = "40G"
    field_50_g = "50G"
    field_100_g = "100G"
    field_400_g = "400G"


class EnumerationEnum88(Enum):
    static = "static"


class EnumerationEnum89(Enum):
    port_disabled = "port-disabled"
    port_oper_disabled = "port-oper-disabled"
    lag_admin_disabled = "lag-admin-disabled"
    lacp_down = "lacp-down"
    micro_bfd_down = "microBFD-down"
    lag_min_link_threshold = "lag-min-link-threshold"
    lag_speed_mismatch = "lag-speed-mismatch"
    other = "other"


class EnumerationEnum9(Enum):
    up = "up"
    down = "down"


class EnumerationEnum90(Enum):
    active = "ACTIVE"
    passive = "PASSIVE"


class EnumerationEnum91(Enum):
    long = "LONG"
    short = "SHORT"


class EnumerationEnum92(Enum):
    in_sync = "IN_SYNC"
    out_sync = "OUT_SYNC"


class EnumerationEnum93(Enum):
    fast = "FAST"
    slow = "SLOW"


class EnumerationEnum94(Enum):
    server = "server"
    client = "client"


class ActionLeaf(RootModel[EnumerationEnum71]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum71, Field(title="ActionLeaf")]
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


class ActiveEntriesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Active-entriesLeaf")]
    """
    The total number of entries that are active on the sub-interface.
    """


class ActiveEntriesLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Active-entriesLeaf2")]
    """
    The total number of entries of this type on the sub-interface
    """


class AddressOriginType(RootModel[EnumerationEnum40]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum40
    """
    The origin of the IP address
    """


class AddressLeaf2(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="AddressLeaf2")]


class AddressLeaf3(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="AddressLeaf3")]


class AddressLeaf4(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="AddressLeaf4")]


class AdminStateType(RootModel[EnumerationEnum]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum
    """
    general admin-state option.
    """


class AdvertisementsDiscardedAddressMismatchLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-address-mismatchLeaf"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to address mismatch
    """


class AdvertisementsDiscardedAddressMismatchLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-address-mismatchLeaf2"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to address mismatch
    """


class AdvertisementsDiscardedAuthfailLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-authfailLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication failure
    """


class AdvertisementsDiscardedAuthfailLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-authfailLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication failure
    """


class AdvertisementsDiscardedAuthtypeMismatchLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-authtype-mismatchLeaf"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication type mismatch
    """


class AdvertisementsDiscardedAuthtypeMismatchLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-authtype-mismatchLeaf2"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to authentication type mismatch
    """


class AdvertisementsDiscardedIntervalLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-intervalLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to interval mismatch
    """


class AdvertisementsDiscardedIntervalLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-intervalLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to interval mismatch
    """


class AdvertisementsDiscardedLengthLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-lengthLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to length of the packet
    """


class AdvertisementsDiscardedLengthLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-lengthLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to length of the packet
    """


class AdvertisementsDiscardedTotalLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-totalLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages dicarded
    """


class AdvertisementsDiscardedTotalLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-totalLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages dicarded
    """


class AdvertisementsDiscardedTtlLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-ttlLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to ttl error
    """


class AdvertisementsDiscardedTtlLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-discarded-ttlLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to ttl error
    """


class AdvertisementsDiscardedVersionMismatchLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-version-mismatchLeaf"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to version mismatch
    """


class AdvertisementsDiscardedVersionMismatchLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type,
        Field(title="Advertisements-discarded-version-mismatchLeaf2"),
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages discarded due to version mismatch
    """


class AdvertisementsIntervalErrorLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-interval-errorLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages with interval mismatch
    """


class AdvertisementsIntervalErrorLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Advertisements-interval-errorLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages with interval mismatch
    """


class AdvertisementsReceivedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Advertisements-receivedLeaf")]
    """
    Counter for the total numebr fo VRRP advertisement messages received
    """


class AdvertisementsReceivedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Advertisements-receivedLeaf2")]
    """
    Counter for the total numebr fo VRRP advertisement messages received
    """


class AdvertisementsSentLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Advertisements-sentLeaf")]
    """
    Counter for the total number fo VRRP advertisement messages sent
    """


class AdvertisementsSentLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Advertisements-sentLeaf2")]
    """
    Counter for the total number fo VRRP advertisement messages sent
    """


class AgingLeaf(RootModel[Union[AgingLeaf1, EnumerationEnum70]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Union[AgingLeaf1, EnumerationEnum70], Field(title="AgingLeaf")]
    """
    remaining age time for learnt macs
    """


class AllowedMacsLeafList(RootModel[UnicastMacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[UnicastMacAddressType, Field(title="Allowed-macsLeafList")]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """


class AllowedMacsLeafList2(RootModel[UnicastMacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[UnicastMacAddressType, Field(title="Allowed-macsLeafList2")]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """


class AnycastGwMacOriginType(RootModel[EnumerationEnum69]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum69
    """
    The origin of the anycast-gw MAC address.
    """


class AnycastGwMacLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Anycast-gw-macLeaf")]
    """
    The MAC address of associated to the anycast-gw IP address.

    If the anycast-gw MAC address is not configured, it will be auto-derived from the virtual-router-id value
    as per draft-ietf-bess-evpn-inter-subnet-forwarding following the format 00:00:5E:00:01:VRID.
    """


class AverageLeaf12(RootModel[Gauge64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Gauge64Type, Field(title="AverageLeaf12")]
    """
    Indicates the average Media Frame Rate Error Count received on the optical channel
    """


class BitErrorRateContainer(BaseModel):
    """
    Enter the bit-error-rate context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf2, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf3, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class BreakoutPortSpeedLeaf(RootModel[EnumerationEnum3]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum3, Field(title="Breakout-port-speedLeaf")]
    """
    The speed of each breakout port
    """


class CarrierTransitionsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Carrier-transitionsLeaf")]
    """
    Number of times the interface state has transitioned from down to up.

    This is reset to zero when the device is started or reset or the counters are cleared.
    """


class ChannelListEntry(BaseModel):
    """
    List of physical channels supported by the transceiver associated with this port
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    index: Annotated[IndexLeaf, Field(None, alias="srl_nokia-interfaces:index")]
    wavelength: Annotated[
        WavelengthLeaf2, Field(None, alias="srl_nokia-interfaces:wavelength")
    ]


class ChromaticDispersionRangeContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    minimum: Annotated[
        MinimumLeaf, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf2, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class ChromaticDispersionContainer(BaseModel):
    """
    Enter the chromatic-dispersion context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf4, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf4, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf5, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf6, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class ClientPacketsDiscardedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Client-packets-discardedLeaf")]
    """
    Total discarded dhcp packets from dhcp client(s) towards DHCP server(s)
    """


class ClientPacketsDiscardedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Client-packets-discardedLeaf2")
    ]
    """
    Total discarded dhcp packets from dhcp client(s) towards DHCP server(s)
    """


class ClientPacketsReceivedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Client-packets-receivedLeaf")]
    """
    Total received dhcp packets from dhcp client(s) for DHCP Relay
    """


class ClientPacketsReceivedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Client-packets-receivedLeaf2")]
    """
    Total received dhcp packets from dhcp client(s) for DHCP Relay
    """


class ClientPacketsRelayedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Client-packets-relayedLeaf")]
    """
    Total relayed dhcp packets from dhcp client(s) towards DHCP server(s)
    """


class ClientPacketsRelayedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Client-packets-relayedLeaf2")]
    """
    Total relayed dhcp packets from dhcp client(s) towards DHCP server(s)
    """


class CoherentOperationalModeType(RootModel[EnumerationEnum14]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum14
    """
    Permitted operational-modes for a coherent port
    """


class CoherentOpticalAlarmType(RootModel[EnumerationEnum22]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum22
    """
    Specifies the type of coherent optical alarms currently active on the port
    """


class CoherentOpticalDefectPointType(RootModel[EnumerationEnum23]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum23
    """
    Specifies the type of coherent optical defects currently active on the port
    """


class ConnectorTypeLeaf(RootModel[EnumerationEnum12]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum12, Field(title="Connector-typeLeaf")]
    """
    Specifies the fiber connector type of the transceiver associated with the port
    """


class CurrentAlarmsLeafList(RootModel[CoherentOpticalAlarmType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[CoherentOpticalAlarmType, Field(title="Current-alarmsLeafList")]
    """
    Indicates the coherent optical alarms currently active on the port.
    """


class CurrentPenaltiesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Current-penaltiesLeaf")]
    """
    Indicates the accumulated penalties applied to the port

    Penalties are accumulated on every port down event except a system restart.
    """


class CurrentStateLeaf(RootModel[EnumerationEnum57]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum57, Field(title="Current-stateLeaf")]
    """
    The Neighbor Unreachability Detection state
    """


class CurrentLeaf12(RootModel[Gauge64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Gauge64Type, Field(title="CurrentLeaf12")]
    """
    Indicates the current Media Frame Rate Error Count received on the optical channel
    """


class DateAndTimeDeltaType(RootModel[DateAndTimeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: DateAndTimeType
    """
    When this type is used to store a date and time, show routines should display it as a delta
    with respect to the current date and time in the format 'dddd:hh:mm:ss ago' (for a past
    event) or 'in dddd:hh:mm:ss' (future event), where dddd is the number of days, hh is the
    number of  hours, mm is the number of  minutes and ss is the number of seconds.
    """


class DateCodeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Date-codeLeaf")]
    """
    Transceiver date code.
    """


class DebugLeafList(RootModel[EnumerationEnum48]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum48, Field(title="DebugLeafList")]
    """
    List of events to debug
    """


class DebugLeafList2(RootModel[EnumerationEnum60]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum60, Field(title="DebugLeafList2")]
    """
    List of events to debug
    """


class DebugLeafList3(RootModel[EnumerationEnum67]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum67, Field(title="DebugLeafList3")]
    """
    List of events to debug
    """


class DefectPointsLeafList(RootModel[CoherentOpticalDefectPointType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        CoherentOpticalDefectPointType, Field(title="Defect-pointsLeafList")
    ]
    """
    Indicates the coherent optical defect points currently active on the port.
    """


class DescriptionLeaf(RootModel[DescriptionType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DescriptionType, Field(title="DescriptionLeaf")]
    """
    A user-configured description of the interface
    """


class DescriptionLeaf2(RootModel[DescriptionType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DescriptionType, Field(title="DescriptionLeaf2")]
    """
    A user-configured description of the interface
    """


class DhcpRelayV4AgentOperDownReasonType(RootModel[EnumerationEnum50]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum50
    """
    The dhcp-relay-v4-agent-oper-down-reason represents the possible reasons causing DHCPv4 relay agent to go into operational down state
    """


class DhcpRelayV6AgentOperDownReasonType(RootModel[EnumerationEnum62]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum62
    """
    The dhcp-relay-v6-agent-oper-down-reason represents the possible reasons causing DHCPv6 relay agent to go into operational down state
    """


class DifferentialGroupDelayContainer(BaseModel):
    """
    Enter the differential-group-delay context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf5, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf5, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf6, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf7, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class DiscardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Discarded-packetsLeaf")]
    """
    The count of ETH-CFM packets discarded on the subinterface because of ingress squelching
    """


class DownExpiresLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Down-expiresLeaf")]
    """
    The remaining time until the hold-time down expires and the interface goes operationally down.
    """


class DupDetectTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Dup-detect-timeLeaf")]
    """
    The date and time when the mac was declared duplicate
    """


class DuplexModeLeaf(RootModel[EnumerationEnum24]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum24, Field(title="Duplex-modeLeaf")]
    """
    When auto-negotiate is true, this sets the duplex mode that will be advertised to the peer.  When auto-negotiate is false, this directly sets the duplex mode of the interface.
    """


class ElectricalSignalToNoiseRatioContainer(BaseModel):
    """
    Enter the electrical-signal-to-noise-ratio context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf2, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf2, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf3, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf4, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class EndTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="End-timeLeaf")]
    """
    End time of the test
    """


class EthernetMonitorReportStatusType(RootModel[EnumerationEnum28]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum28


class EthernetSegmentLeaf(RootModel[NameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameType, Field(title="Ethernet-segmentLeaf")]
    """
    The value of this leaf indicates the ethernet-segment, the
    sub-interface is associated to.
    """


class ExpirationTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Expiration-timeLeaf")]
    """
    The date and time when the dynamic ARP entry is set to expire
    """


class FailedEntriesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Failed-entriesLeaf")]
    """
    The total number of macs, which have not been programmed on atleast one slot
    """


class FailedEntriesLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Failed-entriesLeaf2")]
    """
    The total number of macs of this type, which have not been programmed on atleast one slot
    """


class FineTuningContainer(BaseModel):
    """
    State related to fine-tuning
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    range: Annotated[RangeLeaf, Field(None, alias="srl_nokia-interfaces-dco:range")]
    resolution: Annotated[
        ResolutionLeaf, Field(None, alias="srl_nokia-interfaces-dco:resolution")
    ]


class FirmwareVersionContainer(BaseModel):
    """
    Active firmware version

    This is the information as read from the EEPROM of the part.
    This is only available for digital coherent optic transceivers
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    major_revision: Annotated[
        MajorRevisionLeaf, Field(None, alias="srl_nokia-interfaces:major-revision")
    ]
    minor_revision: Annotated[
        MinorRevisionLeaf, Field(None, alias="srl_nokia-interfaces:minor-revision")
    ]


class FlowControlContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    receive: Annotated[ReceiveLeaf, Field(None, alias="srl_nokia-interfaces:receive")]
    transmit: Annotated[
        TransmitLeaf, Field(None, alias="srl_nokia-interfaces:transmit")
    ]


class FormFactorLeaf(RootModel[EnumerationEnum11]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum11, Field(title="Form-factorLeaf")]
    """
    Specifies the transceiver form factor associated with the port
    """


class ForwardingModeLeaf(RootModel[EnumerationEnum7]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum7, Field(title="Forwarding-modeLeaf")]
    """
    The forwarding mode for Ethernet frames received on this interface
    """


class FrequencyOffsetContainer(BaseModel):
    """
    Enter the frequency-offset context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf6, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf6, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf7, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf8, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class FrequencyLeaf(RootModel[OpticalDwdmFrequencyType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OpticalDwdmFrequencyType, Field(title="FrequencyLeaf")]
    """
    Center frequency for tunable DWDM optical interface
    """


class HighAlarmThresholdLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="High-alarm-thresholdLeaf")]
    """
    High alarm threshold

    Read from the installed transceiver
    """


class HighVlanIdLeaf(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="High-vlan-idLeaf")]
    """
    The high-value VLAN identifier in a range for single-tagged packets
    The range is matched inclusively.
    """


class HighWarningThresholdLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="High-warning-thresholdLeaf")]
    """
    High warning threshold.

    Read from the installed transceiver
    """


class HoldDownTimeRemainingLeaf(
    RootModel[Union[EnumerationEnum72, HoldDownTimeRemainingLeaf1]]
):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[EnumerationEnum72, HoldDownTimeRemainingLeaf1],
        Field(title="Hold-down-time-remainingLeaf"),
    ]
    """
    remaining hold down time for duplicate mac
    """


class HostModeLeaf(RootModel[EnumerationEnum33]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum33, Field(title="Host-modeLeaf")]
    """
    Allow for single or multiple hosts to communicate through an IEEE802.1X controlled port
    """


class HwMacAddressLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Hw-mac-addressLeaf")]
    """
    The MAC address associated with the port
    """


class IdLeaf(RootModel[PacketLinkQualificationIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[PacketLinkQualificationIdType, Field(title="IdLeaf")]
    """
    Packet link qualification test ID
    """


class In1024bTo1518bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-1024b-to-1518b-framesLeaf")]
    """
    Number of received Ethernet frames that are 1024-1518 bytes in length
    """


class In128bTo255bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-128b-to-255b-framesLeaf")]
    """
    Number of received Ethernet frames that are 128-255 bytes in length
    """


class In1519bOrLongerFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="In-1519b-or-longer-framesLeaf")
    ]
    """
    Number of received Ethernet frames that are 1519 bytes or longer
    """


class In256bTo511bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-256b-to-511b-framesLeaf")]
    """
    Number of received Ethernet frames that are 256-511 bytes in length
    """


class In512bTo1023bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-512b-to-1023b-framesLeaf")]
    """
    Number of received Ethernet frames that are 512-1023 bytes in length
    """


class In64bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-64b-framesLeaf")]
    """
    Number of received Ethernet frames that are exactly 64 bytes in length
    """


class In65bTo127bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-65b-to-127b-framesLeaf")]
    """
    Number of received Ethernet frames that are 65-127 bytes in length
    """


class InBroadcastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-broadcast-packetsLeaf")]
    """
    Corresponds to ifHCInBroadcastPkts from the IF-MIB
    """


class InCrcErrorFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-crc-error-framesLeaf")]
    """
    Number of receive error events due to FCS/CRC check failure
    """


class InDiscardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-discarded-packetsLeaf")]
    """
    Corresponds to ifInDiscards from the IFMIB.

    This counts the number of IP packets discarded due to VLAN mismatch, unknown dest MAC or drop by system-filter drop action. On 7250 IXR/IXRe systems this counter is not expected to increment above zero.
    """


class InDiscardedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-discarded-packetsLeaf2")]
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


class InDiscardedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-discarded-packetsLeaf3")]
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


class InDiscardedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-discarded-packetsLeaf4")]
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


class InDiscardedPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-discarded-packetsLeaf5")]
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


class InErrorPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-error-packetsLeaf")]
    """
    Corresponds to ifInErrors from the IF-MIB
    """


class InErrorPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-error-packetsLeaf2")]
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


class InErrorPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-error-packetsLeaf3")]
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


class InErrorPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-error-packetsLeaf4")]
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


class InErrorPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-error-packetsLeaf5")]
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


class InFcsErrorPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-fcs-error-packetsLeaf")]
    """
    Ingress FCS errors
    """


class InForwardedOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-octetsLeaf")]
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """


class InForwardedOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-octetsLeaf2")]
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """


class InForwardedOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-octetsLeaf3")]
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """


class InForwardedOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-octetsLeaf4")]
    """
    The number of octets in packets received on this subinterface counted in in-forwarded-packets
    """


class InForwardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-packetsLeaf")]
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """


class InForwardedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-packetsLeaf2")]
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """


class InForwardedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-packetsLeaf3")]
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """


class InForwardedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-forwarded-packetsLeaf4")]
    """
    The number of packets received on this subinterface for which the router was not the final destination and for which the router attempted to find a route to forward them to that final destination.

    Note that non-terminating IPv4 packets with options and non-terminating IPv6 packets with extension headers are included in this count as are packets that trigger ICMP/ICMPv6 redirect messages.
    """


class InFragmentFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-fragment-framesLeaf")]
    """
    Number of fragment frames received on the interface
    """


class InJabberFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-jabber-framesLeaf")]
    """
    Number of jabber frames received on the interface. Jabber frames are typically defined as oversize frames which also have a bad CRC
    """


class InMacPauseFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-mac-pause-framesLeaf")]
    """
    Number of MAC layer PAUSE frames received on the interface.
    """


class InMatchedRaPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-matched-ra-packetsLeaf")]
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """


class InMatchedRaPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-matched-ra-packetsLeaf2")]
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """


class InMatchedRaPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-matched-ra-packetsLeaf3")]
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """


class InMatchedRaPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-matched-ra-packetsLeaf4")]
    """
    The total number of IPv6 packets matched with applied RA-Guard policy
    """


class InMulticastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-multicast-packetsLeaf")]
    """
    Corresponds to ifHCInMulticastPkts from the IF-MIB
    """


class InOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-octetsLeaf")]
    """
    Corresponds to ifHCInOctets from the IFMIB
    """


class InOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-octetsLeaf2")]
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """


class InOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-octetsLeaf3")]
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """


class InOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-octetsLeaf4")]
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """


class InOctetsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-octetsLeaf5")]
    """
    The total number of octets received in input packets, counting transit and terminating traffic
    """


class InOversizeFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-oversize-framesLeaf")]
    """
    Number of oversize frames received on the interface (i.e. frames that exceed the operational port MTU)
    """


class InPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-packetsLeaf")]
    """
    Sum of all received packets, independent of protocol and forwarding type and before discards and errors
    """


class InPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-packetsLeaf2")]
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """


class InPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-packetsLeaf3")]
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """


class InPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-packetsLeaf4")]
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """


class InPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-packetsLeaf5")]
    """
    The total number of input packets received, counting transit and terminating traffic

    This equals the sum of:
    in-error-packets
    in-discarded-packets
    in-terminated-packets
    in-forwarded-packets
    """


class InTerminatedOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-octetsLeaf")]
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """


class InTerminatedOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-octetsLeaf2")]
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """


class InTerminatedOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-octetsLeaf3")]
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """


class InTerminatedOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-octetsLeaf4")]
    """
    The total number of octets in packets that were received on this subinterface and counted in in-terminated-packets
    """


class InTerminatedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-packetsLeaf")]
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """


class InTerminatedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-packetsLeaf2")]
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """


class InTerminatedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-packetsLeaf3")]
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """


class InTerminatedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-terminated-packetsLeaf4")]
    """
    The total number of input packets that were received on this subinterface that were extracted to the control plane

    The count includes packets eventually discarded by the CPM. Such discards include:
    - packets with unsupported IP protocol numbers
    - packets destined to TCP/UDP ports that are not open/listening
    - IPv4 packets with any IP options
    - IPv6 packets with any extension headers
    """


class InTrapToCpuPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-trap-to-cpu-packetsLeaf")]
    """
    System or interface level incoming 802.1x frames copied to CPU

    Cumulative of all Ethernet interfaces including all the copy-to-cpu 802.1x frames.
    802.1x frames are identified by a destination MAC value of 01:80:c2:00:00:03 and EtherType value of 0x888e.
    """


class InTunneledPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-tunneled-packetsLeaf")]
    """
    System or interface level incoming 802.1x tunneled frames

    Cumulative of all Ethernet interfaces including all the tunneled 802.1x frames.
    802.1x frames are identified by a destination MAC value of 01:80:c2:00:00:03 and EtherType value of 0x888e.
    """


class InUnicastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="In-unicast-packetsLeaf")]
    """
    Corresponds to ifHCInUcastPkts from the IF-MIB
    """


class InnerVlanIdLeaf(RootModel[Union[VlanIdType, EnumerationEnum81]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[VlanIdType, EnumerationEnum81], Field(title="Inner-vlan-idLeaf")
    ]
    """
    Inner VLAN tag identifier for double-tagged packets
    """


class InnerVlanIdLeaf2(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="Inner-vlan-idLeaf2")]
    """
    Optionally specifies the inner VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH-PUSH' then this VLAN identifier is added to
    the stack as inner vlan-id. This value must be non-zero if the
    'vlan-stack-action' is one 'PUSH-PUSH' or 'POP-SWAP'.
    """


class InnerVlanIdLeaf3(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="Inner-vlan-idLeaf3")]
    """
    Optionally specifies the inner VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH-PUSH' then this VLAN identifier is added to
    the stack as inner vlan-id. This value must be non-zero if the
    'vlan-stack-action' requires the addition or replacement of an inner VLAN tag.
    """


class InterfaceAllType(RootModel[InterfaceNameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[InterfaceNameType, Field(title="Interface-allType")]


class Ipv4AddressStatusType(RootModel[EnumerationEnum41]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum41
    """
    The IPv4 address status
    """


class Ipv4AddressType(RootModel[Ipv4Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Ipv4Type
    """
    An IPv4 address in dotted quad notation.
    """


class Ipv4PrefixWithHostBitsType(RootModel[Ipv4PrefixType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Ipv4PrefixType
    """
    An IPv4 prefix with host bits.
    """


class Ipv6AddressStatusType(RootModel[EnumerationEnum55]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum55
    """
    The IPv6 address status
    """


class Ipv6AddressTypeType(RootModel[EnumerationEnum54]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum54
    """
    The value represents the type of IPv6 address
    """


class Ipv6AddressType(RootModel[Ipv6Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Ipv6Type
    """
    An IPv6 address represented as either a full address; shortened
    or mixed-shortened formats.
    """


class Ipv6PrefixWithHostBitsType(RootModel[Ipv6PrefixType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Ipv6PrefixType
    """
    An IPv6 prefix with host bits.
    """


class Ipv6PrefixLeaf(RootModel[Ipv6PrefixType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6PrefixType, Field(title="Ipv6-prefixLeaf")]
    """
    An IPv6 global unicast address prefix.
    """


class L2cpOperRuleStateType(RootModel[EnumerationEnum35]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum35


class LacpActivityTypeType(RootModel[EnumerationEnum90]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum90
    """
    Describes the LACP membership type, active or passive, of the
    interface in the aggregate
    """


class LacpErrorsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-errorsLeaf")]
    """
    Number of LACPDU illegal packet errors
    """


class LacpFallbackTypeType(RootModel[EnumerationEnum88]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum88


class LacpInPktsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-in-pktsLeaf")]
    """
    Number of LACPDUs received
    """


class LacpModeLeaf(RootModel[LacpActivityTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpActivityTypeType, Field(title="Lacp-modeLeaf")]
    """
    ACTIVE is to initiate the transmission of LACP packets.
    PASSIVE is to wait for peer to initiate the transmission of
    LACP packets.
    """


class LacpOutPktsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-out-pktsLeaf")]
    """
    Number of LACPDUs transmitted
    """


class LacpPeriodTypeType(RootModel[EnumerationEnum93]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum93
    """
    Defines the period options for the time between sending
    LACP messages
    """


class LacpRxErrorsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-rx-errorsLeaf")]
    """
    Number of LACPDU receive packet errors
    """


class LacpSynchronizationTypeType(RootModel[EnumerationEnum92]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum92
    """
    Indicates LACP synchronization state of participant
    """


class LacpTimeoutTypeType(RootModel[EnumerationEnum91]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum91
    """
    Type of timeout used, short or long, by LACP participants
    """


class LacpTxErrorsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-tx-errorsLeaf")]
    """
    Number of LACPDU transmit packet errors
    """


class LacpUnknownErrorsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Lacp-unknown-errorsLeaf")]
    """
    Number of LACPDU unknown packet errors
    """


class LagTypeType(RootModel[EnumerationEnum86]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum86
    """
    Type to define the lag-type, i.e., how the LAG is
    defined and managed
    """


class LaserTunabilityLeaf(RootModel[EnumerationEnum15]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum15, Field(title="Laser-tunabilityLeaf")]
    """
    Tunability of the optical interface.

    Value 'unequipped' indicates the optical interface is not equipped with a laser.
    """


class LastChangeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-changeLeaf")]
    """
    The date and time of the most recent change to the interface state
    """


class LastChangeLeaf2(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-changeLeaf2")]
    """
    The date and time of the most recent change to the subinterface state
    """


class LastChangeLeaf3(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-changeLeaf3")]
    """
    The date and time of the most recent change to the LAG member-link state
    """


class LastClearLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf")]
    """
    Timestamp of the last time the interface counters were cleared
    """


class LastClearLeaf2(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf2")]
    """
    Timestamp of the last time the MAC counters were cleared
    """


class LastClearLeaf3(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf3")]
    """
    Timestamp of the last time the 802.1x counters were cleared
    """


class LastClearLeaf4(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf4")]
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class LastClearLeaf5(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf5")]
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class LastClearLeaf6(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf6")]
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class LastClearLeaf7(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-clearLeaf7")]
    """
    Timestamp of the last time the subinterface counters were cleared
    """


class LastReportedDynamicDelayLeaf(
    RootModel[Union[LastReportedDynamicDelayLeaf1, EnumerationEnum37]]
):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[LastReportedDynamicDelayLeaf1, EnumerationEnum37],
        Field(title="Last-reported-dynamic-delayLeaf"),
    ]
    """
    Indicates the last delay measurement reported to the routing engine
    """


class LastTransitionLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-transitionLeaf")]
    """
    timestamp for last master router transition
    """


class LastTransitionLeaf2(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-transitionLeaf2")]
    """
    timestamp for last master router transition
    """


class LastUnhealthyLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-unhealthyLeaf")]
    """
    Last unhealthy time

    The time at which the component was last observed to transition from
    the healthy state to any other state, represented as nanoseconds
    since the Unix epoch.
    """


class LastUpdateLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-updateLeaf")]
    """
    The date and time of the last update of the server IP address
    """


class LastUpdateLeaf2(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-updateLeaf2")]
    """
    The date and time of the last update of the server IP address
    """


class LastUpdateLeaf3(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-updateLeaf3")]
    """
    The date and time of the last update of this learnt mac
    """


class LastUpdateLeaf4(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Last-updateLeaf4")]
    """
    The date and time of the last update of this mac
    """


class LatestValueLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="Latest-valueLeaf")]
    """
    The current temperature of the transceiver module in degrees Celsius
    """


class LearnUnsolicitedLeaf2(RootModel[EnumerationEnum56]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum56, Field(title="Learn-unsolicitedLeaf2")]
    """
    Sets if neighbors should be learned from unsolicited neighbor advertisements for global or link local addresses or both.
    """


class LimitContainer(BaseModel):
    """
    Container for the configuration of Neighbor-Discovery limit
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    max_entries: Annotated[
        MaxEntriesLeaf, Field(None, alias="srl_nokia-interfaces-nbr:max-entries")
    ]
    log_only: Annotated[
        LogOnlyLeaf, Field(False, alias="srl_nokia-interfaces-nbr:log-only")
    ]
    warning_threshold_pct: Annotated[
        WarningThresholdPctLeaf,
        Field(90, alias="srl_nokia-interfaces-nbr:warning-threshold-pct"),
    ]


class LinecardLeaf(RootModel[SlotLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[SlotLeaf, Field(title="LinecardLeaf")]
    """
    The linecard on which this interface resides

    This field is not populated for non-forwarding-complex-attached interfaces, for example mgmt0.
    """


class LinkLayerAddressLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Link-layer-addressLeaf")]
    """
    The resolving MAC address of the ARP entry

    To configure a static ARP entry a value must be written into this leaf and the ipv4-address leaf.
    """


class LinkLayerAddressLeaf2(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Link-layer-addressLeaf2")]
    """
    The resolving MAC address of the ND cache entry

    To configure a static neighbor entry a value must be written into this leaf and the ipv6-address leaf.
    """


class LosReactionType(RootModel[EnumerationEnum18]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum18
    """
    Specifies the type of action that is taken in the event of a Loss Of Signal (LOS)
    """


class LowAlarmThresholdLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="Low-alarm-thresholdLeaf")]
    """
    Low alarm threshold.

    Read from the installed transceiver
    """


class LowWarningThresholdLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="Low-warning-thresholdLeaf")]
    """
    Low warning threshold.

    Read from the installed transceiver
    """


class MacAddressLeaf(RootModel[MacAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacAddressType, Field(title="Mac-addressLeaf")]
    """
    MAC address of the interface

    If not configured, this is set to the hw-mac-address, which is populated depending on interface type:

    - For interfaces with a discoverable MAC address (either populated by an external system or present in hardware) the discovered value is populated.
    - For interfaces without a discoverable MAC address, the address is generated from a hash of the interface name and the chassis MAC address.

    When deleted, will revert back to the value of hw-mac-address.
    """


class MacAddressListEntry(BaseModel):
    """
    Add a list entry for source mac-address
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[MacLeaf, Field(None, alias="srl_nokia-dot1x:mac")]


class MacLimitContainer(BaseModel):
    """
    Bridge Table size and thresholds.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    maximum_entries: Annotated[
        MaximumEntriesLeaf, Field(250, alias="srl_nokia-interfaces:maximum-entries")
    ]
    warning_threshold_pct: Annotated[
        WarningThresholdPctLeaf2,
        Field(95, alias="srl_nokia-interfaces:warning-threshold-pct"),
    ]


class MacTypeType(RootModel[EnumerationEnum77]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum77
    """
    type of mac addresses in the system
    """


class MacLeaf2(RootModel[MacLeaf3]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacLeaf3, Field(title="MacLeaf2")]
    """
    Authenticated device source MAC address
    """


class MacListEntry(BaseModel):
    """
    macs learnt on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    address: Annotated[
        AddressLeaf2,
        Field(
            None, alias="srl_nokia-interfaces-bridge-table-mac-learning-entries:address"
        ),
    ]
    last_update: Annotated[
        LastUpdateLeaf3,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-learning-entries:last-update",
        ),
    ]
    aging: Annotated[
        AgingLeaf,
        Field(
            None, alias="srl_nokia-interfaces-bridge-table-mac-learning-entries:aging"
        ),
    ]


class MacListEntry2(BaseModel):
    """
    macs duplicate on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    address: Annotated[
        AddressLeaf3,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-duplication-entries:address",
        ),
    ]
    dup_detect_time: Annotated[
        DupDetectTimeLeaf,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-duplication-entries:dup-detect-time",
        ),
    ]
    hold_down_time_remaining: Annotated[
        HoldDownTimeRemainingLeaf,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-duplication-entries:hold-down-time-remaining",
        ),
    ]


class MaxPenaltiesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Max-penaltiesLeaf")]
    """
    Indicates the maximum possible value of the accumulated penalties against the port
    """


class MaximumFrequencyLeaf(RootModel[OpticalDwdmFrequencyType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OpticalDwdmFrequencyType, Field(title="Maximum-frequencyLeaf")]
    """
    The maximum frequency supported by the equipped optical module.
    """


class MaximumTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Maximum-timeLeaf")]
    """
    Indicates the time this transceiver reached the temperature referenced in maximum
    """


class MaximumLeaf(RootModel[TemperatureType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TemperatureType, Field(title="MaximumLeaf")]
    """
    Represents the highest temperature the transceiver has reached since it booted
    """


class MediaFrameErrorCountContainer(BaseModel):
    """
    Enter the media-frame-error-count context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    current: Annotated[
        CurrentLeaf12, Field(None, alias="srl_nokia-interfaces-dco:current")
    ]
    average: Annotated[
        AverageLeaf12, Field(None, alias="srl_nokia-interfaces-dco:average")
    ]
    minimum: Annotated[
        MinimumLeaf13, Field(None, alias="srl_nokia-interfaces-dco:minimum")
    ]
    maximum: Annotated[
        MaximumLeaf14, Field(None, alias="srl_nokia-interfaces-dco:maximum")
    ]


class MemberLinkOperDownReasonType(RootModel[EnumerationEnum89]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum89


class MemberSpeedTypeType(RootModel[EnumerationEnum87]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum87
    """
    Enumeration for LAG member-link speeds
    """


class MemberSpeedLeaf(RootModel[MemberSpeedTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MemberSpeedTypeType, Field(title="Member-speedLeaf")]
    """
    Specifies the link speed of allowed member-links
    """


class MinimumFrequencyLeaf(RootModel[OpticalDwdmFrequencyType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OpticalDwdmFrequencyType, Field(title="Minimum-frequencyLeaf")]
    """
    The minimum frequency supported by the equipped optical module.
    """


class ModuleRxTurnUpStatesLeafList(RootModel[EnumerationEnum21]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum21, Field(title="Module-rx-turn-up-statesLeafList")]
    """
    Indicates the completed received turn-up states of the coherent optical module
    """


class ModuleStateLeaf(RootModel[EnumerationEnum19]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum19, Field(title="Module-stateLeaf")]
    """
    Indicates the state of the coherent optical module.
    """


class ModuleTxTurnUpStatesLeafList(RootModel[EnumerationEnum20]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum20, Field(title="Module-tx-turn-up-statesLeafList")]
    """
    Indicates the completed transmitted turn-up states of the coherent optical module
    """


class MstPathCostLeaf(RootModel[StpPathCostTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpPathCostTypeType, Field(title="Mst-path-costLeaf")]


class MstPortPriorityLeaf(RootModel[StpPortPriorityTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpPortPriorityTypeType, Field(title="Mst-port-priorityLeaf")]


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
    )
    mac_address: Annotated[
        List[MacAddressListEntry], Field(alias="srl_nokia-dot1x:mac-address")
    ]


class NameLeaf(RootModel[InterfaceAllType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: InterfaceAllType
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


class NameLeaf2(RootModel[EnumerationEnum6]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum6
    """
    The identifier of the forwarding complex
    """


class NameLeaf4(RootModel[NameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: NameType
    """
    The user configured name for the keychain
    """


class NameLeaf5(RootModel[NameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: NameType
    """
    A name used to identify the tag set
    """


class NameLeaf6(RootModel[RestrictedNameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: RestrictedNameType
    """
    A unique name identifying the network instance
    """


class NameLeaf7(RootModel[NameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: NameType
    """
    RA Guard Policy name
    """


class NameLeaf8(RootModel[NameLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf, Field(title="NameLeaf8")]


class NeighborOriginType(RootModel[EnumerationEnum45]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum45
    """
    The origin of the neighbor entry.
    """


class NetworkInstanceLeaf(RootModel[NameLeaf6]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf6, Field(title="Network-instanceLeaf")]
    """
    network instance to relay dhcp packets to
    """


class NetworkInstanceLeaf2(RootModel[NameLeaf6]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf6, Field(title="Network-instanceLeaf2")]
    """
    network instance to relay dhcp packets to
    """


class NextStateTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Next-state-timeLeaf")]
    """
    The date and time when the neighbor state is expected to transition to the next state
    """


class NotProgrammedReasonLeaf(RootModel[EnumerationEnum78]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum78, Field(title="Not-programmed-reasonLeaf")]
    """
    The reason why the mac is not programmed
    """


class NumBreakoutPortsLeaf(RootModel[EnumerationEnum2]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum2, Field(title="Num-breakout-portsLeaf")]
    """
    The number of breakout ports supported by this connector
    """


class OperDownReasonLeaf5(RootModel[DhcpRelayV4AgentOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        DhcpRelayV4AgentOperDownReasonType, Field(title="Oper-down-reasonLeaf5")
    ]
    """
    The reason causing the dhcp relay agent to go into operational down state
    """


class OperDownReasonLeaf7(RootModel[DhcpRelayV6AgentOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        DhcpRelayV6AgentOperDownReasonType, Field(title="Oper-down-reasonLeaf7")
    ]
    """
    The reason causing the dhcp relay agent to go into operational down state
    """


class OperDownReasonLeaf8(RootModel[MemberLinkOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MemberLinkOperDownReasonType, Field(title="Oper-down-reasonLeaf8")]
    """
    Reason for operational down state for the associated LAG
    """


class OperFrequencyLeaf(RootModel[OpticalDwdmFrequencyType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OpticalDwdmFrequencyType, Field(title="Oper-frequencyLeaf")]
    """
    The operating frequency of the optical-channel.
    """


class OperRuleLeaf(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf")]
    """
    The operational state of the TCAM rule applied to ingress LLDP frames.
    """


class OperRuleLeaf2(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf2")]
    """
    The operational state of the TCAM rule applied to ingress LACP frames.
    """


class OperRuleLeaf3(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf3")]
    """
    The operational state of the TCAM rule applied to ingress xSTP frames.
    """


class OperRuleLeaf4(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf4")]
    """
    The operational state of the TCAM rule applied to ingress dot1x frames.
    """


class OperRuleLeaf5(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf5")]
    """
    The operational state of the TCAM rule applied to ingress ptp frames.
    """


class OperRuleLeaf6(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf6")]
    """
    The operational state of the TCAM rule applied to ingress ESMC frames
    """


class OperRuleLeaf7(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf7")]
    """
    The operational state of the TCAM rule applied to ingress ELMI frames
    """


class OperRuleLeaf8(RootModel[L2cpOperRuleStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[L2cpOperRuleStateType, Field(title="Oper-ruleLeaf8")]
    """
    The operational state of the TCAM rule applied to ingress EFM-OAM frames.
    """


class OperStateLeaf(RootModel[EnumerationEnum4]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum4, Field(title="Oper-stateLeaf")]
    """
    The operational state of the interface
    """


class OperStateLeaf12(RootModel[EnumerationEnum84]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum84, Field(title="Oper-stateLeaf12")]
    """
    State of the qualification test
    """


class OperStateLeaf3(RootModel[EnumerationEnum29]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum29, Field(title="Oper-stateLeaf3")]
    """
    Indicates if the port up state of the port is suppressed or not

    The port up state is 'idle' if the value of current-penalties
    exceeds the value of suppress-threshold. The port up state will
    be 'active' when current-penalties falls below the value of
    reuse-threshold.
    """


class OperStateLeaf4(RootModel[EnumerationEnum38]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum38, Field(title="Oper-stateLeaf4")]
    """
    The operational state of the subinterface
    """


class OperStateType(RootModel[EnumerationEnum42]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum42
    """
    General operational state
    """


class OperationalModeLeaf(RootModel[CoherentOperationalModeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[CoherentOperationalModeType, Field(title="Operational-modeLeaf")]
    """
    Operational mode for the transceiver

    This is a numeric value the defines a set of operating characteristics such as modulation, bit-rate, max power range, fec, etc.
    Refer to Nokia documentation for details by transceiver part number.
    """


class OpticalDispersionControlModeType(RootModel[EnumerationEnum17]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum17
    """
    Specifies the operational control mode of the dispersion compensation module
    """


class OptionLeafList(RootModel[EnumerationEnum51]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum51, Field(title="OptionLeafList")]
    """
    List of option82 suboptions to insert into relayed packet towards DHCPv4 server
    """


class OptionLeafList2(RootModel[EnumerationEnum63]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum63, Field(title="OptionLeafList2")]
    """
    List of options to insert into relayed packet towards DHCPv6 server
    """


class OriginLeaf(RootModel[AddressOriginType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AddressOriginType, Field(title="OriginLeaf")]
    """
    The origin of the IPv4 address.
    """


class OriginLeaf2(RootModel[NeighborOriginType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NeighborOriginType, Field(title="OriginLeaf2")]
    """
    The origin of the ARP entry
    """


class OriginLeaf3(RootModel[AddressOriginType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AddressOriginType, Field(title="OriginLeaf3")]
    """
    The origin of the IPv6 address
    """


class OriginLeaf4(RootModel[NeighborOriginType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NeighborOriginType, Field(title="OriginLeaf4")]
    """
    The origin of the neighbor cache entry.
    """


class Out1024bTo1518bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Out-1024b-to-1518b-framesLeaf")
    ]
    """
    Number of transmitted Ethernet frames that are 1024-1518 bytes in length
    """


class Out128bTo255bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-128b-to-255b-framesLeaf")]
    """
    Number of transmitted Ethernet frames that are 128-255 bytes in length
    """


class Out1519bOrLongerFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Out-1519b-or-longer-framesLeaf")
    ]
    """
    Number of transmitted Ethernet frames that are 1519 bytes or longer
    """


class Out256bTo511bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-256b-to-511b-framesLeaf")]
    """
    Number of transmitted Ethernet frames that are 256-511 bytes in length
    """


class Out512bTo1023bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-512b-to-1023b-framesLeaf")]
    """
    Number of transmitted Ethernet frames that are 512-1023 bytes in length
    """


class Out64bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-64b-framesLeaf")]
    """
    Number of transmitted Ethernet frames that are exactly 64 bytes in length
    """


class Out65bTo127bFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-65b-to-127b-framesLeaf")]
    """
    Number of transmitted Ethernet frames that are 65-127 bytes in length
    """


class OutBroadcastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-broadcast-packetsLeaf")]
    """
    Corresponds to ifHCOutBroadcastPkts from the IF-MIB
    """


class OutDiscardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-discarded-packetsLeaf")]
    """
    Corresponds to ifOutDiscards from the IF-MIB.

    On Jericho2 systems this counts packets dropped by an egress IP ACL of any of the port's subinterfaces.
    """


class OutDiscardedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-discarded-packetsLeaf2")]
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """


class OutDiscardedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-discarded-packetsLeaf3")]
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """


class OutDiscardedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-discarded-packetsLeaf4")]
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """


class OutDiscardedPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-discarded-packetsLeaf5")]
    """
    The total number of packets, originating and transit, that should have been sent out this subinterface but were dropped

    This includes IP packets dropped by egress interface ACL drop action.
    """


class OutErrorPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-error-packetsLeaf")]
    """
    Corresponds to ifOutErrors from the IF-MIB
    """


class OutErrorPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-error-packetsLeaf2")]
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """


class OutErrorPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-error-packetsLeaf3")]
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """


class OutErrorPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-error-packetsLeaf4")]
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """


class OutErrorPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-error-packetsLeaf5")]
    """
    The number of packets, originating and transit, for which this router was successful in finding a path to their final destination through this subinterface but an error prevented their transmission

    On 7250 IXR systems this is incremented when the IPv4 packet size exceeds the IP MTU and fragmentation was not allowed or not supported. It is also incremented when the MPLS packet size exceeds the MPLS MTU of the subinterface.
    """


class OutForwardedOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-octetsLeaf")]
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-octetsLeaf2")]
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-octetsLeaf3")]
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-octetsLeaf4")]
    """
    The number of octets in transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-packetsLeaf")]
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-packetsLeaf2")]
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-packetsLeaf3")]
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """


class OutForwardedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-forwarded-packetsLeaf4")]
    """
    The number of transit packets which the router attempted to forward out this subinterface
    """


class OutMacPauseFramesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-mac-pause-framesLeaf")]
    """
    Number of MAC layer PAUSE frames sent on the interface
    """


class OutMirrorOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-mirror-octetsLeaf")]
    """
    This counts the number of outgoing mirrored octets
    """


class OutMirrorPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-mirror-packetsLeaf")]
    """
    This counts the number of outgoing mirrored packets
    """


class OutMulticastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-multicast-packetsLeaf")]
    """
    Corresponds to ifHCOutMulticastPkts from the IF-MIB
    """


class OutOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-octetsLeaf")]
    """
    Corresponds to ifHCOutOctets from the IF-MIB
    """


class OutOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-octetsLeaf2")]
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """


class OutOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-octetsLeaf3")]
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """


class OutOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-octetsLeaf4")]
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """


class OutOctetsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-octetsLeaf5")]
    """
    The total number of octets in packets delivered to the lower layers for transmission
    """


class OutOriginatedOctetsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-octetsLeaf")]
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedOctetsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-octetsLeaf2")]
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedOctetsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-octetsLeaf3")]
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedOctetsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-octetsLeaf4")]
    """
    The number of octets in packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-packetsLeaf")]
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-packetsLeaf2")]
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-packetsLeaf3")]
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutOriginatedPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-originated-packetsLeaf4")]
    """
    The number of packets which originated on the CPM and which the router attempted to forward out this subinterface
    """


class OutPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-packetsLeaf")]
    """
    Sum of all transmitted packets, independent of protocol and forwarding type and before discards and errors
    """


class OutPacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-packetsLeaf2")]
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """


class OutPacketsLeaf3(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-packetsLeaf3")]
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """


class OutPacketsLeaf4(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-packetsLeaf4")]
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """


class OutPacketsLeaf5(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-packetsLeaf5")]
    """
    The total number of packets that this router supplied to the lower layers for transmission

    This equals the sum of:
    out-error-packets
    out-discarded-packets
    out-originated-packets
    out-forwarded-packets
    """


class OutProbePacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-probe-packetsLeaf")]
    """
    The number of probe packets transmitted for the Virtual IP discovery.
    """


class OutProbePacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-probe-packetsLeaf2")]
    """
    The number of probe packets transmitted for the Virtual IP discovery.
    """


class OutTotalProbePacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-total-probe-packetsLeaf")]
    """
    The number of total probe packets transmitted for Virtual discovery.
    """


class OutTotalProbePacketsLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-total-probe-packetsLeaf2")]
    """
    The number of total probe packets transmitted for Virtual discovery.
    """


class OutUnicastPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Out-unicast-packetsLeaf")]
    """
    Corresponds to ifHCOutUcastPkts from the IF-MIB
    """


class OuterVlanIdLeaf(RootModel[Union[VlanIdType, EnumerationEnum82]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[VlanIdType, EnumerationEnum82], Field(title="Outer-vlan-idLeaf")
    ]
    """
    Outer VLAN tag identifier for double-tagged packets
    """


class OuterVlanIdLeaf2(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="Outer-vlan-idLeaf2")]
    """
    Optionally specifies the outer VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH' then this VLAN identifier is added to
    the stack. This value must be non-zero if the 'vlan-stack-action' requires
    the addition or replacement of a VLAN tag.
    """


class OuterVlanIdLeaf3(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="Outer-vlan-idLeaf3")]
    """
    Optionally specifies the outer VLAN tag identifier

    The vlan-id is used by the action configured in 'vlan-stack-action'. For
    example, if the action is 'PUSH' then this VLAN identifier is added to
    the stack. This value must be non-zero if the 'vlan-stack-action' requires
    the addition or replacement of a VLAN tag.
    """


class P4rtContainer(BaseModel):
    """
    Top-level container for P4Runtime interface configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    id: Annotated[IdLeaf2, Field(None, alias="srl_nokia-interfaces-p4rt:id")]
    parent_id: Annotated[
        ParentIdLeaf, Field(None, alias="srl_nokia-interfaces-p4rt:parent-id")
    ]


class PathCostLeaf(RootModel[StpPathCostTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpPathCostTypeType, Field(title="Path-costLeaf")]


class PhysicalMediumLeaf(RootModel[EnumerationEnum26]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum26, Field(title="Physical-mediumLeaf")]
    """
    Indicates the PHY supported by the RJ45 port.

    If the port is supported by a SFP, QSFP+, QSFP28 or QSFP-DD transceiver no value is populated in this leaf.
    """


class PolicyLeaf(RootModel[NameLeaf7]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf7, Field(title="PolicyLeaf")]
    """
    Reference to RA Guard Policy to apply to the associated subinterface
    """


class PortAccessEntityPortControlType(RootModel[EnumerationEnum32]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum32
    """
    Specifies if the port is forced authorized or it is authorized via IEEE802.1x procedures
    """


class PortControlLeaf(RootModel[PortAccessEntityPortControlType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[PortAccessEntityPortControlType, Field(title="Port-controlLeaf")]
    """
    IEEE802.1x authentication mode
    """


class PortNumberLeaf(RootModel[StpPortNumberTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpPortNumberTypeType, Field(title="Port-numberLeaf")]


class PortOperDownReasonType(RootModel[EnumerationEnum5]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum5


class PortSpeedLeaf(RootModel[EnumerationEnum25]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum25, Field(title="Port-speedLeaf")]
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


class PreferredLifetimeLeaf(
    RootModel[Union[EnumerationEnum65, PreferredLifetimeLeaf1]]
):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[EnumerationEnum65, PreferredLifetimeLeaf1],
        Field(title="Preferred-lifetimeLeaf"),
    ]
    """
    The length of time in seconds (relative to the time the packet is sent) that addresses generated from the prefix via stateless address autoconfiguration remain preferred.
    """


class PriorityZeroPacketsReceivedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Priority-zero-packets-receivedLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages received with priority 0
    """


class PriorityZeroPacketsReceivedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Priority-zero-packets-receivedLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages received with priority 0
    """


class PriorityZeroPacketsSentLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Priority-zero-packets-sentLeaf")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages sent out with priority 0
    """


class PriorityZeroPacketsSentLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Priority-zero-packets-sentLeaf2")
    ]
    """
    Counter for the total numebr fo VRRP advertisement messages sent out with priority 0
    """


class PriorityLeaf3(RootModel[StpPortPriorityTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpPortPriorityTypeType, Field(title="PriorityLeaf3")]


class PtpContainer(BaseModel):
    """
    Container for the configuration of Precision Time Protocol Peer-Delay frames.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf5, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf5, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class RaGuardContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    policy: Annotated[PolicyLeaf, Field(None, alias="srl_nokia-ra_guard:policy")]
    vlan_list: Annotated[
        List[VlanListListEntry], Field(alias="srl_nokia-ra_guard:vlan-list")
    ]


class RangeLowVlanIdLeaf(RootModel[VlanIdType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanIdType, Field(title="Range-low-vlan-idLeaf")]
    """
    The low-value VLAN identifier in a range for single-tagged packets
    The range is matched inclusively.
    """


class ReceivedContainer(BaseModel):
    """
    Enter the received context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    bit_error_rate: Annotated[
        BitErrorRateContainer,
        Field(None, alias="srl_nokia-interfaces-dco:bit-error-rate"),
    ]
    electrical_signal_to_noise_ratio: Annotated[
        ElectricalSignalToNoiseRatioContainer,
        Field(None, alias="srl_nokia-interfaces-dco:electrical-signal-to-noise-ratio"),
    ]
    optical_signal_to_noise_ratio: Annotated[
        OpticalSignalToNoiseRatioContainer,
        Field(None, alias="srl_nokia-interfaces-dco:optical-signal-to-noise-ratio"),
    ]
    chromatic_dispersion: Annotated[
        ChromaticDispersionContainer,
        Field(None, alias="srl_nokia-interfaces-dco:chromatic-dispersion"),
    ]
    differential_group_delay: Annotated[
        DifferentialGroupDelayContainer,
        Field(None, alias="srl_nokia-interfaces-dco:differential-group-delay"),
    ]
    frequency_offset: Annotated[
        FrequencyOffsetContainer,
        Field(None, alias="srl_nokia-interfaces-dco:frequency-offset"),
    ]
    quality: Annotated[
        QualityContainer, Field(None, alias="srl_nokia-interfaces-dco:quality")
    ]
    power: Annotated[
        PowerContainer, Field(None, alias="srl_nokia-interfaces-dco:power")
    ]
    total_power: Annotated[
        TotalPowerContainer, Field(None, alias="srl_nokia-interfaces-dco:total-power")
    ]
    polarization_dependent_loss: Annotated[
        PolarizationDependentLossContainer,
        Field(None, alias="srl_nokia-interfaces-dco:polarization-dependent-loss"),
    ]
    state_of_polarization_rate_of_change: Annotated[
        StateOfPolarizationRateOfChangeContainer,
        Field(
            None, alias="srl_nokia-interfaces-dco:state-of-polarization-rate-of-change"
        ),
    ]
    media_frame_error_count: Annotated[
        MediaFrameErrorCountContainer,
        Field(None, alias="srl_nokia-interfaces-dco:media-frame-error-count"),
    ]


class ReloadDelayExpiresLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Reload-delay-expiresLeaf")]
    """
    The remaining time until the reload-delay expires and the interface can go operationally up.
    """


class RisingThresholdActionLeaf(RootModel[EnumerationEnum31]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum31, Field(title="Rising-threshold-actionLeaf")]
    """
    Configures the action triggered when traffic exceeds the configured storm-control rates
    """


class RouteTypeLeaf(RootModel[EnumerationEnum47]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum47, Field(title="Route-typeLeaf")]
    """
    Controls what type of ARP or ND entries generate a host route.
    """


class RouteTypeLeaf2(RootModel[EnumerationEnum49]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum49, Field(title="Route-typeLeaf2")]
    """
    Controls what type of ARP or ND entries to advertise.
    """


class RouteTypeLeaf3(RootModel[EnumerationEnum59]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum59, Field(title="Route-typeLeaf3")]
    """
    Controls what type of ARP or ND entries generate a host route.
    """


class RouteTypeLeaf4(RootModel[EnumerationEnum61]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum61, Field(title="Route-typeLeaf4")]
    """
    Controls what type of ARP or ND entries to advertise.
    """


class RxLosReactionLeaf(RootModel[LosReactionType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LosReactionType, Field(title="Rx-los-reactionLeaf")]
    """
    Reaction to an RX LOS
    """


class ServerPacketsDiscardedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Server-packets-discardedLeaf")]
    """
    Total discarded dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class ServerPacketsDiscardedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Server-packets-discardedLeaf2")
    ]
    """
    Total discarded dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class ServerPacketsReceivedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Server-packets-receivedLeaf")]
    """
    Total received dhcp packets from DHCP server(s) for DHCP Relay
    """


class ServerPacketsReceivedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Server-packets-receivedLeaf2")]
    """
    Total received dhcp packets from DHCP server(s) for DHCP Relay
    """


class ServerPacketsRelayedLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Server-packets-relayedLeaf")]
    """
    Total relayed dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class ServerPacketsRelayedLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Server-packets-relayedLeaf2")]
    """
    Total relayed dhcp packets from DHCP server(s) towards dhcp client(s)
    """


class SetTagSetLeafList(RootModel[NameLeaf5]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf5, Field(title="Set-tag-setLeafList")]
    """
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList2(RootModel[NameLeaf5]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf5, Field(title="Set-tag-setLeafList2")]
    """
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList3(RootModel[NameLeaf5]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf5, Field(title="Set-tag-setLeafList3")]
    """
    Reference to a tag-set defined under routing-policy
    """


class SetTagSetLeafList4(RootModel[NameLeaf5]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf5, Field(title="Set-tag-setLeafList4")]
    """
    Reference to a tag-set defined under routing-policy
    """


class SourceAddressLeaf(RootModel[Ipv6AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressType, Field(title="Source-addressLeaf")]
    """
    Source IPv6 address of the relayed packets towards DHCPv6 servers
    this address can be any IPv6 address configured within the network-instance towards the DHCPv6 server
    """


class StandbySignalingLeaf(RootModel[EnumerationEnum27]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum27, Field(title="Standby-signalingLeaf")]
    """
    Indicates the standby-signaling used in the interface.

    An application using a port-based redundancy mechanism will trigger the standby signaling on the ethernet
    interface if the interface is selected as standby.
    """


class StartTimeLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Start-timeLeaf")]
    """
    Start time of the test
    """


class StaticDelayLeaf(RootModel[Union[StaticDelayLeaf1, EnumerationEnum36]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[StaticDelayLeaf1, EnumerationEnum36], Field(title="Static-delayLeaf")
    ]
    """
    A statically configured unidirectional delay value that can be advertised as an interface attribute by an IGP
    """


class StatisticsContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_packets: Annotated[
        InPacketsLeaf, Field(0, alias="srl_nokia-interfaces:in-packets")
    ]
    in_octets: Annotated[InOctetsLeaf, Field(0, alias="srl_nokia-interfaces:in-octets")]
    in_unicast_packets: Annotated[
        InUnicastPacketsLeaf, Field(0, alias="srl_nokia-interfaces:in-unicast-packets")
    ]
    in_broadcast_packets: Annotated[
        InBroadcastPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-broadcast-packets"),
    ]
    in_multicast_packets: Annotated[
        InMulticastPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-multicast-packets"),
    ]
    in_discarded_packets: Annotated[
        InDiscardedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-discarded-packets"),
    ]
    in_error_packets: Annotated[
        InErrorPacketsLeaf, Field(0, alias="srl_nokia-interfaces:in-error-packets")
    ]
    in_fcs_error_packets: Annotated[
        InFcsErrorPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-fcs-error-packets"),
    ]
    out_packets: Annotated[
        OutPacketsLeaf, Field(0, alias="srl_nokia-interfaces:out-packets")
    ]
    out_octets: Annotated[
        OutOctetsLeaf, Field(0, alias="srl_nokia-interfaces:out-octets")
    ]
    out_mirror_octets: Annotated[
        OutMirrorOctetsLeaf, Field(0, alias="srl_nokia-interfaces:out-mirror-octets")
    ]
    out_unicast_packets: Annotated[
        OutUnicastPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-unicast-packets"),
    ]
    out_broadcast_packets: Annotated[
        OutBroadcastPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-broadcast-packets"),
    ]
    out_multicast_packets: Annotated[
        OutMulticastPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-multicast-packets"),
    ]
    out_discarded_packets: Annotated[
        OutDiscardedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-discarded-packets"),
    ]
    out_error_packets: Annotated[
        OutErrorPacketsLeaf, Field(0, alias="srl_nokia-interfaces:out-error-packets")
    ]
    out_mirror_packets: Annotated[
        OutMirrorPacketsLeaf, Field(0, alias="srl_nokia-interfaces:out-mirror-packets")
    ]
    carrier_transitions: Annotated[
        CarrierTransitionsLeaf,
        Field(0, alias="srl_nokia-interfaces:carrier-transitions"),
    ]
    last_clear: Annotated[
        LastClearLeaf, Field(None, alias="srl_nokia-interfaces:last-clear")
    ]


class StatisticsContainer10(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    advertisements_sent: Annotated[
        AdvertisementsSentLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-sent"),
    ]
    advertisements_received: Annotated[
        AdvertisementsReceivedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-received"),
    ]
    advertisements_discarded_version_mismatch: Annotated[
        AdvertisementsDiscardedVersionMismatchLeaf2,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-version-mismatch",
        ),
    ]
    advertisements_discarded_authfail: Annotated[
        AdvertisementsDiscardedAuthfailLeaf2,
        Field(
            0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authfail"
        ),
    ]
    advertisements_discarded_authtype_mismatch: Annotated[
        AdvertisementsDiscardedAuthtypeMismatchLeaf2,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authtype-mismatch",
        ),
    ]
    advertisements_discarded_address_mismatch: Annotated[
        AdvertisementsDiscardedAddressMismatchLeaf2,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-address-mismatch",
        ),
    ]
    priority_zero_packets_sent: Annotated[
        PriorityZeroPacketsSentLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:priority-zero-packets-sent"),
    ]
    priority_zero_packets_received: Annotated[
        PriorityZeroPacketsReceivedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:priority-zero-packets-received"),
    ]
    advertisements_discarded_ttl: Annotated[
        AdvertisementsDiscardedTtlLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-ttl"),
    ]
    advertisements_discarded_length: Annotated[
        AdvertisementsDiscardedLengthLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-length"),
    ]
    advertisements_discarded_interval: Annotated[
        AdvertisementsDiscardedIntervalLeaf2,
        Field(
            0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-interval"
        ),
    ]
    advertisements_interval_error: Annotated[
        AdvertisementsIntervalErrorLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-interval-error"),
    ]
    advertisements_discarded_total: Annotated[
        AdvertisementsDiscardedTotalLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-total"),
    ]


class StatisticsContainer11(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_packets: Annotated[
        InPacketsLeaf3, Field(0, alias="srl_nokia-interfaces:in-packets")
    ]
    in_octets: Annotated[
        InOctetsLeaf3, Field(0, alias="srl_nokia-interfaces:in-octets")
    ]
    in_error_packets: Annotated[
        InErrorPacketsLeaf3, Field(0, alias="srl_nokia-interfaces:in-error-packets")
    ]
    in_discarded_packets: Annotated[
        InDiscardedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-discarded-packets"),
    ]
    in_terminated_packets: Annotated[
        InTerminatedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-terminated-packets"),
    ]
    in_terminated_octets: Annotated[
        InTerminatedOctetsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-terminated-octets"),
    ]
    in_forwarded_packets: Annotated[
        InForwardedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-packets"),
    ]
    in_forwarded_octets: Annotated[
        InForwardedOctetsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-octets"),
    ]
    in_matched_ra_packets: Annotated[
        InMatchedRaPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-matched-ra-packets"),
    ]
    out_forwarded_packets: Annotated[
        OutForwardedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-packets"),
    ]
    out_forwarded_octets: Annotated[
        OutForwardedOctetsLeaf2,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-octets"),
    ]
    out_originated_packets: Annotated[
        OutOriginatedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:out-originated-packets"),
    ]
    out_originated_octets: Annotated[
        OutOriginatedOctetsLeaf2,
        Field(0, alias="srl_nokia-interfaces:out-originated-octets"),
    ]
    out_error_packets: Annotated[
        OutErrorPacketsLeaf3, Field(0, alias="srl_nokia-interfaces:out-error-packets")
    ]
    out_discarded_packets: Annotated[
        OutDiscardedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:out-discarded-packets"),
    ]
    out_packets: Annotated[
        OutPacketsLeaf3, Field(0, alias="srl_nokia-interfaces:out-packets")
    ]
    out_octets: Annotated[
        OutOctetsLeaf3, Field(0, alias="srl_nokia-interfaces:out-octets")
    ]
    last_clear: Annotated[
        LastClearLeaf5, Field(None, alias="srl_nokia-interfaces:last-clear")
    ]


class StatisticsContainer12(BaseModel):
    """
    Statistics for the Virtual IP address
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    out_probe_packets: Annotated[
        OutProbePacketsLeaf2,
        Field(
            0, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:out-probe-packets"
        ),
    ]


class StatisticsContainer13(BaseModel):
    """
    Global statistics for Virtual IP discovery
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    out_total_probe_packets: Annotated[
        OutTotalProbePacketsLeaf2,
        Field(
            0,
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:out-total-probe-packets",
        ),
    ]


class StatisticsContainer14(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    client_packets_received: Annotated[
        ClientPacketsReceivedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-received"),
    ]
    client_packets_relayed: Annotated[
        ClientPacketsRelayedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-relayed"),
    ]
    client_packets_discarded: Annotated[
        ClientPacketsDiscardedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-discarded"),
    ]
    server_packets_received: Annotated[
        ServerPacketsReceivedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-received"),
    ]
    server_packets_relayed: Annotated[
        ServerPacketsRelayedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-relayed"),
    ]
    server_packets_discarded: Annotated[
        ServerPacketsDiscardedLeaf2,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-discarded"),
    ]


class StatisticsContainer15(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_packets: Annotated[
        InPacketsLeaf4, Field(0, alias="srl_nokia-interfaces:in-packets")
    ]
    in_octets: Annotated[
        InOctetsLeaf4, Field(0, alias="srl_nokia-interfaces:in-octets")
    ]
    in_error_packets: Annotated[
        InErrorPacketsLeaf4, Field(0, alias="srl_nokia-interfaces:in-error-packets")
    ]
    in_discarded_packets: Annotated[
        InDiscardedPacketsLeaf4,
        Field(0, alias="srl_nokia-interfaces:in-discarded-packets"),
    ]
    in_terminated_packets: Annotated[
        InTerminatedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-terminated-packets"),
    ]
    in_terminated_octets: Annotated[
        InTerminatedOctetsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-terminated-octets"),
    ]
    in_forwarded_packets: Annotated[
        InForwardedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-packets"),
    ]
    in_forwarded_octets: Annotated[
        InForwardedOctetsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-octets"),
    ]
    in_matched_ra_packets: Annotated[
        InMatchedRaPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:in-matched-ra-packets"),
    ]
    out_forwarded_packets: Annotated[
        OutForwardedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-packets"),
    ]
    out_forwarded_octets: Annotated[
        OutForwardedOctetsLeaf3,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-octets"),
    ]
    out_originated_packets: Annotated[
        OutOriginatedPacketsLeaf3,
        Field(0, alias="srl_nokia-interfaces:out-originated-packets"),
    ]
    out_originated_octets: Annotated[
        OutOriginatedOctetsLeaf3,
        Field(0, alias="srl_nokia-interfaces:out-originated-octets"),
    ]
    out_error_packets: Annotated[
        OutErrorPacketsLeaf4, Field(0, alias="srl_nokia-interfaces:out-error-packets")
    ]
    out_discarded_packets: Annotated[
        OutDiscardedPacketsLeaf4,
        Field(0, alias="srl_nokia-interfaces:out-discarded-packets"),
    ]
    out_packets: Annotated[
        OutPacketsLeaf4, Field(0, alias="srl_nokia-interfaces:out-packets")
    ]
    out_octets: Annotated[
        OutOctetsLeaf4, Field(0, alias="srl_nokia-interfaces:out-octets")
    ]
    last_clear: Annotated[
        LastClearLeaf6, Field(None, alias="srl_nokia-interfaces:last-clear")
    ]


class StatisticsContainer17(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    discarded_packets: Annotated[
        DiscardedPacketsLeaf, Field(0, alias="srl_nokia-ethcfm:discarded-packets")
    ]


class StatisticsContainer18(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_packets: Annotated[
        InPacketsLeaf5, Field(0, alias="srl_nokia-if-mpls:in-packets")
    ]
    in_octets: Annotated[InOctetsLeaf5, Field(0, alias="srl_nokia-if-mpls:in-octets")]
    in_error_packets: Annotated[
        InErrorPacketsLeaf5, Field(0, alias="srl_nokia-if-mpls:in-error-packets")
    ]
    in_discarded_packets: Annotated[
        InDiscardedPacketsLeaf5,
        Field(0, alias="srl_nokia-if-mpls:in-discarded-packets"),
    ]
    in_terminated_packets: Annotated[
        InTerminatedPacketsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:in-terminated-packets"),
    ]
    in_terminated_octets: Annotated[
        InTerminatedOctetsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:in-terminated-octets"),
    ]
    in_forwarded_packets: Annotated[
        InForwardedPacketsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:in-forwarded-packets"),
    ]
    in_forwarded_octets: Annotated[
        InForwardedOctetsLeaf4, Field(0, alias="srl_nokia-if-mpls:in-forwarded-octets")
    ]
    in_matched_ra_packets: Annotated[
        InMatchedRaPacketsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:in-matched-ra-packets"),
    ]
    out_forwarded_packets: Annotated[
        OutForwardedPacketsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:out-forwarded-packets"),
    ]
    out_forwarded_octets: Annotated[
        OutForwardedOctetsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:out-forwarded-octets"),
    ]
    out_originated_packets: Annotated[
        OutOriginatedPacketsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:out-originated-packets"),
    ]
    out_originated_octets: Annotated[
        OutOriginatedOctetsLeaf4,
        Field(0, alias="srl_nokia-if-mpls:out-originated-octets"),
    ]
    out_error_packets: Annotated[
        OutErrorPacketsLeaf5, Field(0, alias="srl_nokia-if-mpls:out-error-packets")
    ]
    out_discarded_packets: Annotated[
        OutDiscardedPacketsLeaf5,
        Field(0, alias="srl_nokia-if-mpls:out-discarded-packets"),
    ]
    out_packets: Annotated[
        OutPacketsLeaf5, Field(0, alias="srl_nokia-if-mpls:out-packets")
    ]
    out_octets: Annotated[
        OutOctetsLeaf5, Field(0, alias="srl_nokia-if-mpls:out-octets")
    ]
    last_clear: Annotated[
        LastClearLeaf7, Field(None, alias="srl_nokia-if-mpls:last-clear")
    ]


class StatisticsContainer19(BaseModel):
    """
    LACP protocol counters
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    lacp_in_pkts: Annotated[
        LacpInPktsLeaf, Field(0, alias="srl_nokia-lacp:lacp-in-pkts")
    ]
    lacp_out_pkts: Annotated[
        LacpOutPktsLeaf, Field(0, alias="srl_nokia-lacp:lacp-out-pkts")
    ]
    lacp_rx_errors: Annotated[
        LacpRxErrorsLeaf, Field(0, alias="srl_nokia-lacp:lacp-rx-errors")
    ]
    lacp_tx_errors: Annotated[
        LacpTxErrorsLeaf, Field(0, alias="srl_nokia-lacp:lacp-tx-errors")
    ]
    lacp_unknown_errors: Annotated[
        LacpUnknownErrorsLeaf, Field(0, alias="srl_nokia-lacp:lacp-unknown-errors")
    ]
    lacp_errors: Annotated[LacpErrorsLeaf, Field(0, alias="srl_nokia-lacp:lacp-errors")]


class StatisticsContainer2(BaseModel):
    """
    Enter the statistics context

    interface/statistics/last-clear indicates when these statistics were last cleared.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    received: Annotated[
        ReceivedContainer, Field(None, alias="srl_nokia-interfaces-dco:received")
    ]
    transmitted: Annotated[
        TransmittedContainer, Field(None, alias="srl_nokia-interfaces-dco:transmitted")
    ]


class StatisticsContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_mac_pause_frames: Annotated[
        InMacPauseFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-mac-pause-frames")
    ]
    in_oversize_frames: Annotated[
        InOversizeFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-oversize-frames")
    ]
    in_jabber_frames: Annotated[
        InJabberFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-jabber-frames")
    ]
    in_fragment_frames: Annotated[
        InFragmentFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-fragment-frames")
    ]
    in_crc_error_frames: Annotated[
        InCrcErrorFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-crc-error-frames")
    ]
    out_mac_pause_frames: Annotated[
        OutMacPauseFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-mac-pause-frames"),
    ]
    in_64b_frames: Annotated[
        In64bFramesLeaf, Field(0, alias="srl_nokia-interfaces:in-64b-frames")
    ]
    in_65b_to_127b_frames: Annotated[
        In65bTo127bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-65b-to-127b-frames"),
    ]
    in_128b_to_255b_frames: Annotated[
        In128bTo255bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-128b-to-255b-frames"),
    ]
    in_256b_to_511b_frames: Annotated[
        In256bTo511bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-256b-to-511b-frames"),
    ]
    in_512b_to_1023b_frames: Annotated[
        In512bTo1023bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-512b-to-1023b-frames"),
    ]
    in_1024b_to_1518b_frames: Annotated[
        In1024bTo1518bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-1024b-to-1518b-frames"),
    ]
    in_1519b_or_longer_frames: Annotated[
        In1519bOrLongerFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:in-1519b-or-longer-frames"),
    ]
    out_64b_frames: Annotated[
        Out64bFramesLeaf, Field(0, alias="srl_nokia-interfaces:out-64b-frames")
    ]
    out_65b_to_127b_frames: Annotated[
        Out65bTo127bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-65b-to-127b-frames"),
    ]
    out_128b_to_255b_frames: Annotated[
        Out128bTo255bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-128b-to-255b-frames"),
    ]
    out_256b_to_511b_frames: Annotated[
        Out256bTo511bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-256b-to-511b-frames"),
    ]
    out_512b_to_1023b_frames: Annotated[
        Out512bTo1023bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-512b-to-1023b-frames"),
    ]
    out_1024b_to_1518b_frames: Annotated[
        Out1024bTo1518bFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-1024b-to-1518b-frames"),
    ]
    out_1519b_or_longer_frames: Annotated[
        Out1519bOrLongerFramesLeaf,
        Field(0, alias="srl_nokia-interfaces:out-1519b-or-longer-frames"),
    ]
    last_clear: Annotated[
        LastClearLeaf2, Field(None, alias="srl_nokia-interfaces:last-clear")
    ]


class StatisticsContainer5(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    advertisements_sent: Annotated[
        AdvertisementsSentLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-sent"),
    ]
    advertisements_received: Annotated[
        AdvertisementsReceivedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-received"),
    ]
    advertisements_discarded_version_mismatch: Annotated[
        AdvertisementsDiscardedVersionMismatchLeaf,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-version-mismatch",
        ),
    ]
    advertisements_discarded_authfail: Annotated[
        AdvertisementsDiscardedAuthfailLeaf,
        Field(
            0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authfail"
        ),
    ]
    advertisements_discarded_authtype_mismatch: Annotated[
        AdvertisementsDiscardedAuthtypeMismatchLeaf,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-authtype-mismatch",
        ),
    ]
    advertisements_discarded_address_mismatch: Annotated[
        AdvertisementsDiscardedAddressMismatchLeaf,
        Field(
            0,
            alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-address-mismatch",
        ),
    ]
    priority_zero_packets_sent: Annotated[
        PriorityZeroPacketsSentLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:priority-zero-packets-sent"),
    ]
    priority_zero_packets_received: Annotated[
        PriorityZeroPacketsReceivedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:priority-zero-packets-received"),
    ]
    advertisements_discarded_ttl: Annotated[
        AdvertisementsDiscardedTtlLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-ttl"),
    ]
    advertisements_discarded_length: Annotated[
        AdvertisementsDiscardedLengthLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-length"),
    ]
    advertisements_discarded_interval: Annotated[
        AdvertisementsDiscardedIntervalLeaf,
        Field(
            0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-interval"
        ),
    ]
    advertisements_interval_error: Annotated[
        AdvertisementsIntervalErrorLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-interval-error"),
    ]
    advertisements_discarded_total: Annotated[
        AdvertisementsDiscardedTotalLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-vrrp:advertisements-discarded-total"),
    ]


class StatisticsContainer6(BaseModel):
    """
    Container for subinterface statistics, including all IPv4, IPv6 and MPLS packets belonging to a routed subinterface, or including just one of these protocols on a routed subinterface, or for all frames on a bridged subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    in_packets: Annotated[
        InPacketsLeaf2, Field(0, alias="srl_nokia-interfaces:in-packets")
    ]
    in_octets: Annotated[
        InOctetsLeaf2, Field(0, alias="srl_nokia-interfaces:in-octets")
    ]
    in_error_packets: Annotated[
        InErrorPacketsLeaf2, Field(0, alias="srl_nokia-interfaces:in-error-packets")
    ]
    in_discarded_packets: Annotated[
        InDiscardedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:in-discarded-packets"),
    ]
    in_terminated_packets: Annotated[
        InTerminatedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-terminated-packets"),
    ]
    in_terminated_octets: Annotated[
        InTerminatedOctetsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-terminated-octets"),
    ]
    in_forwarded_packets: Annotated[
        InForwardedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-packets"),
    ]
    in_forwarded_octets: Annotated[
        InForwardedOctetsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-forwarded-octets"),
    ]
    in_matched_ra_packets: Annotated[
        InMatchedRaPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:in-matched-ra-packets"),
    ]
    out_forwarded_packets: Annotated[
        OutForwardedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-packets"),
    ]
    out_forwarded_octets: Annotated[
        OutForwardedOctetsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-forwarded-octets"),
    ]
    out_originated_packets: Annotated[
        OutOriginatedPacketsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-originated-packets"),
    ]
    out_originated_octets: Annotated[
        OutOriginatedOctetsLeaf,
        Field(0, alias="srl_nokia-interfaces:out-originated-octets"),
    ]
    out_error_packets: Annotated[
        OutErrorPacketsLeaf2, Field(0, alias="srl_nokia-interfaces:out-error-packets")
    ]
    out_discarded_packets: Annotated[
        OutDiscardedPacketsLeaf2,
        Field(0, alias="srl_nokia-interfaces:out-discarded-packets"),
    ]
    out_packets: Annotated[
        OutPacketsLeaf2, Field(0, alias="srl_nokia-interfaces:out-packets")
    ]
    out_octets: Annotated[
        OutOctetsLeaf2, Field(0, alias="srl_nokia-interfaces:out-octets")
    ]
    last_clear: Annotated[
        LastClearLeaf4, Field(None, alias="srl_nokia-interfaces:last-clear")
    ]


class StatisticsContainer7(BaseModel):
    """
    Statistics for the Virtual IP address
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    out_probe_packets: Annotated[
        OutProbePacketsLeaf,
        Field(
            0, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:out-probe-packets"
        ),
    ]


class StatisticsContainer8(BaseModel):
    """
    Global statistics for Virtual IP discovery
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    out_total_probe_packets: Annotated[
        OutTotalProbePacketsLeaf,
        Field(
            0,
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:out-total-probe-packets",
        ),
    ]


class StatisticsContainer9(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    client_packets_received: Annotated[
        ClientPacketsReceivedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-received"),
    ]
    client_packets_relayed: Annotated[
        ClientPacketsRelayedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-relayed"),
    ]
    client_packets_discarded: Annotated[
        ClientPacketsDiscardedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:client-packets-discarded"),
    ]
    server_packets_received: Annotated[
        ServerPacketsReceivedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-received"),
    ]
    server_packets_relayed: Annotated[
        ServerPacketsRelayedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-relayed"),
    ]
    server_packets_discarded: Annotated[
        ServerPacketsDiscardedLeaf,
        Field(0, alias="srl_nokia-interfaces-ip-dhcp-relay:server-packets-discarded"),
    ]


class StatusLeaf(RootModel[EnumerationEnum13]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum13, Field(title="StatusLeaf")]
    """
    Health status

    The status of the component, indicating its current health.
    """


class StatusLeaf2(RootModel[EnumerationEnum34]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum34, Field(title="StatusLeaf2")]
    """
    The status of the 802.1X session for a device
    """


class StatusLeaf3(RootModel[Ipv4AddressStatusType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4AddressStatusType, Field(title="StatusLeaf3")]
    """
    The status of an IPv4 address
    """


class StatusLeaf4(RootModel[EnumerationEnum46]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum46, Field(title="StatusLeaf4")]
    """
    The status of the ARP or neighbor entry with respect to datapath programming
    """


class StatusLeaf5(RootModel[Ipv6AddressStatusType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressStatusType, Field(title="StatusLeaf5")]
    """
    The status of an IPv6 address
    """


class StatusLeaf6(RootModel[EnumerationEnum58]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum58, Field(title="StatusLeaf6")]
    """
    The status of the ARP or neighbor entry with respect to datapath programming
    """


class StatusLeaf7(RootModel[EnumerationEnum85]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum85, Field(title="StatusLeaf7")]
    """
    Status of the test

    Only set when the test is in the error state.
    """


class StpAutoEdgeTypeType(RootModel[EnumerationEnum74]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum74
    """
    When auto-edge is enabled, STP will send bpdu to determine if there
    exists a rstp peer. Upon receiving no response, the port is determined
    as edge-port. Auto-Edge is enabled by default. It dynamically sets the
    value of OPER_EDGE to true/false based on if stp bpdu is received on
    the interface. 
    """


class StpEdgePortTypeType(RootModel[EnumerationEnum73]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum73
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


class StpLinkTypeType(RootModel[EnumerationEnum75]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum75


class StpRootGuardTypeType(RootModel[EnumerationEnum76]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum76


class SubifOperDownReasonType(RootModel[EnumerationEnum39]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum39


class SubinterfaceAllType(RootModel[SubinterfaceNameType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: SubinterfaceNameType


class SubsystemContainer(BaseModel):
    """
    Top-level container for PCI subsystem state
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vendor_name: Annotated[
        VendorNameLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:vendor-name")
    ]
    vendor_id: Annotated[
        VendorIdLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:vendor-id")
    ]
    device_name: Annotated[
        DeviceNameLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:device-name")
    ]
    device_id: Annotated[
        DeviceIdLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:device-id")
    ]


class SupportedGridsLeafList(RootModel[EnumerationEnum16]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum16, Field(title="Supported-gridsLeafList")]
    """
    Indicates the frequency grids supported by the equipped tunable optical port.
    """


class SupportedOperationalModeLeafList(RootModel[CoherentOperationalModeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        CoherentOperationalModeType, Field(title="Supported-operational-modeLeafList")
    ]
    """
    Operational modes supported by the installed transceiver

    Lists the operational-modes supported by the installed transceiver.  If no transceiver is installed, nothing is reported.
    """


class SynchronizationLeaf(RootModel[LacpSynchronizationTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpSynchronizationTypeType, Field(title="SynchronizationLeaf")]
    """
    Indicates whether the participant is in-sync or
    out-of-sync
    """


class TemperatureContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    latest_value: Annotated[
        LatestValueLeaf, Field(None, alias="srl_nokia-interfaces:latest-value")
    ]
    maximum: Annotated[MaximumLeaf, Field(None, alias="srl_nokia-interfaces:maximum")]
    maximum_time: Annotated[
        MaximumTimeLeaf, Field(None, alias="srl_nokia-interfaces:maximum-time")
    ]
    high_alarm_condition: Annotated[
        HighAlarmConditionLeaf,
        Field(None, alias="srl_nokia-interfaces:high-alarm-condition"),
    ]
    high_alarm_threshold: Annotated[
        HighAlarmThresholdLeaf,
        Field(None, alias="srl_nokia-interfaces:high-alarm-threshold"),
    ]
    low_alarm_condition: Annotated[
        LowAlarmConditionLeaf,
        Field(None, alias="srl_nokia-interfaces:low-alarm-condition"),
    ]
    low_alarm_threshold: Annotated[
        LowAlarmThresholdLeaf,
        Field(None, alias="srl_nokia-interfaces:low-alarm-threshold"),
    ]
    high_warning_condition: Annotated[
        HighWarningConditionLeaf,
        Field(None, alias="srl_nokia-interfaces:high-warning-condition"),
    ]
    high_warning_threshold: Annotated[
        HighWarningThresholdLeaf,
        Field(None, alias="srl_nokia-interfaces:high-warning-threshold"),
    ]
    low_warning_condition: Annotated[
        LowWarningConditionLeaf,
        Field(None, alias="srl_nokia-interfaces:low-warning-condition"),
    ]
    low_warning_threshold: Annotated[
        LowWarningThresholdLeaf,
        Field(None, alias="srl_nokia-interfaces:low-warning-threshold"),
    ]


class TimeoutLeaf2(RootModel[LacpTimeoutTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpTimeoutTypeType, Field(title="TimeoutLeaf2")]
    """
    The timeout type (short or long) used by the
    participant
    """


class TotalEntriesLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Total-entriesLeaf")]
    """
    The total number of macs, active and inactive, on the sub-interface.
    """


class TotalEntriesLeaf2(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Total-entriesLeaf2")]
    """
    The total number of macs of this type , active and inactive, on the sub-interface.
    """


class TotalInDiscardedPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        ZeroBasedCounter64Type, Field(title="Total-in-discarded-packetsLeaf")
    ]
    """
    System or interface level incoming do1x discarded frames

    Cumulative of all Ethernet interfaces or specific interface including all the discarded dot1x frames.
    """


class TotalInPacketsLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Total-in-packetsLeaf")]
    """
    System or interface level total incoming dot1x frames

    Cumulative of all Ethernet interfaces or specific interface including the tunneled, discarded and copy-to-cpu dot1x frames.
    """


class TraceLeafList(RootModel[EnumerationEnum52]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum52, Field(title="TraceLeafList")]
    """
    List of events to trace
    """


class TraceLeafList2(RootModel[EnumerationEnum53]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum53, Field(title="TraceLeafList2")]
    """
    List of events to trace
    """


class TraceLeafList3(RootModel[EnumerationEnum64]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum64, Field(title="TraceLeafList3")]
    """
    List of events to trace
    """


class TraceLeafList4(RootModel[EnumerationEnum68]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum68, Field(title="TraceLeafList4")]
    """
    List of events to trace
    """


class TransceiverOperDownReasonType(RootModel[EnumerationEnum10]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum10


class TransceiverOperStateType(RootModel[EnumerationEnum9]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum9


class TypeLeaf(RootModel[EnumerationEnum8]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum8, Field(title="TypeLeaf")]
    """
    Type of adapter for the port
    """


class TypeLeaf3(RootModel[Ipv6AddressTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressTypeType, Field(title="TypeLeaf3")]
    """
    Specifies the explicit type of the IPv6 address being assigned to the subinterface

    By default, addresses are assumed to be global unicast.  Where a link-local address is to be explicitly configured, this leaf should be set to link-local.
    """


class TypeLeaf4(RootModel[MacTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacTypeType, Field(title="TypeLeaf4")]


class TypeLeaf5(RootModel[MacTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[MacTypeType, Field(title="TypeLeaf5")]
    """
    the type of the mac installed in the fib.
    """


class UnavailableAddressReasonLeaf(RootModel[EnumerationEnum44]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum44, Field(title="Unavailable-address-reasonLeaf")]
    """
    The reason why there is no operational IPv4 address to use for this subinterface
    """


class UnhealthyCountLeaf(RootModel[ZeroBasedCounter64Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[ZeroBasedCounter64Type, Field(title="Unhealthy-countLeaf")]
    """
    Unhealthy count

    The number of times the component has transitioned from the healthy
    state to any other state.
    """


class UnidirectionalLinkDelayContainer(BaseModel):
    """
    Unidirectional link delay configuration and state related to subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    static_delay: Annotated[
        StaticDelayLeaf, Field("none", alias="srl_nokia-interfaces:static-delay")
    ]
    last_reported_dynamic_delay: Annotated[
        LastReportedDynamicDelayLeaf,
        Field(None, alias="srl_nokia-interfaces:last-reported-dynamic-delay"),
    ]


class UnitsLeaf(RootModel[EnumerationEnum30]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum30, Field(title="UnitsLeaf")]
    """
    Units of storm-control policer in kbps or percentage of the interface bandwidth
    """


class UpExpiresLeaf(RootModel[DateAndTimeDeltaType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[DateAndTimeDeltaType, Field(title="Up-expiresLeaf")]
    """
    The remaining time until the hold-time up expires and the interface comes up.
    """


class UuidLeaf(RootModel[UuidType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[UuidType, Field(title="UuidLeaf")]
    """
    The system-generated or user-configured UUID for the sub interface
    """


class UuidLeaf2(RootModel[UuidType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[UuidType, Field(title="UuidLeaf2")]
    """
    The system-generated or user-configured UUID for the interface
    """


class ValidLifetimeLeaf(RootModel[Union[EnumerationEnum66, ValidLifetimeLeaf1]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        Union[EnumerationEnum66, ValidLifetimeLeaf1], Field(title="Valid-lifetimeLeaf")
    ]
    """
    The length of time in seconds (relative to the time the packet is sent) that the prefix is valid for the purpose of on-link determination. 
    """


class VhostSocketModeLeaf(RootModel[EnumerationEnum94]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[EnumerationEnum94, Field(title="Vhost-socket-modeLeaf")]
    """
    The vhost-user socket mode

    If set to server, the socket is created by SR Linux, if set to client SR Linux will connect to a pre-existing socket.
    """


class VhostContainer(BaseModel):
    """
    Top-level container for vhost-user interface configuration and state
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vhost_socket_path: Annotated[
        VhostSocketPathLeaf, Field(alias="srl_nokia-interfaces-vxdp:vhost-socket-path")
    ]
    vhost_socket_mode: Annotated[
        VhostSocketModeLeaf,
        Field("client", alias="srl_nokia-interfaces-vxdp:vhost-socket-mode"),
    ]
    vhost_socket_queues: Annotated[
        VhostSocketQueuesLeaf,
        Field(None, alias="srl_nokia-interfaces-vxdp:vhost-socket-queues"),
    ]
    socket_id: Annotated[
        SocketIdLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:socket-id")
    ]
    socket_cpus: Annotated[
        List[SocketCpusLeafList],
        Field([], alias="srl_nokia-interfaces-vxdp:socket-cpus"),
    ]
    """
    List of CPUs present on the socket this interface is attached to
    """


class VirtualAddressLeafList2(RootModel[Ipv6AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressType, Field(title="Virtual-addressLeafList2")]
    """
    Associated Virtual IP address.
    """


class VirtualLinkLocalAddressLeaf(RootModel[Ipv6AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressType, Field(title="Virtual-link-local-addressLeaf")]
    """
    Generated link local address based on virtual-mac for virtual router instance
    """


class VlanDiscoveryAddressTypeType(RootModel[EnumerationEnum79]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum79
    """
    Type definition with enumerations describing address type for vlan discovery
    """


class VlanIdLeaf(RootModel[Union[VlanIdType, EnumerationEnum80]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Union[VlanIdType, EnumerationEnum80], Field(title="Vlan-idLeaf")]
    """
    VLAN identifier for single-tagged packets
    """


class VlanStackActionType(RootModel[EnumerationEnum83]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum83
    """
    Operations that can be performed on a VLAN stack
    """


class VrrpOperDownReasonType(RootModel[EnumerationEnum43]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: EnumerationEnum43


class XstpContainer(BaseModel):
    """
    Container for the configuration of all the Spanning Tree Protocols.

    It includes Spanning Tree Protocol (STP), Rapid RSTP (RSTP) and Multiple STP (MSTP)
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf3, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf3, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class ActivityLeaf(RootModel[LacpActivityTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpActivityTypeType, Field(title="ActivityLeaf")]
    """
    Indicates participant is active or passive
    """


class AdapterContainer(BaseModel):
    """
    State for adapters
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    model_number: Annotated[
        ModelNumberLeaf, Field(None, alias="srl_nokia-interfaces:model-number")
    ]
    type: Annotated[TypeLeaf, Field(None, alias="srl_nokia-interfaces:type")]
    vendor_manufacture_date: Annotated[
        VendorManufactureDateLeaf,
        Field(None, alias="srl_nokia-interfaces:vendor-manufacture-date"),
    ]
    vendor_oui: Annotated[
        VendorOuiLeaf, Field(None, alias="srl_nokia-interfaces:vendor-oui")
    ]
    vendor_part_number: Annotated[
        VendorPartNumberLeaf,
        Field(None, alias="srl_nokia-interfaces:vendor-part-number"),
    ]
    vendor_serial_number: Annotated[
        VendorSerialNumberLeaf,
        Field(None, alias="srl_nokia-interfaces:vendor-serial-number"),
    ]


class AddressLeaf(RootModel[Ipv4AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4AddressType, Field(title="AddressLeaf")]
    """
    The operational IPv4 address borrowed from the referenced subinterface
    """


class AdminStateLeaf(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf")]
    """
    The configured, desired state of the interface
    """


class AdminStateLeaf10(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf10")]
    """
    The configurable state of the dhcp relay agent
    """


class AdminStateLeaf11(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf11")]
    """
    Enables/Disables DHCP server function on subinterface
    """


class AdminStateLeaf12(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf12")]
    """
    Enable/disable IPv6 on the subinterface

    When set to enable, and even before a global unicast IPv6 address is configured, chassis manager assigns an IPv6 link-local address to the subinterface, which will appear as a read-only entry in the address list. At this stage, the subinterface can receive IPv6 packets with any of the following destinations:
    -       IPv6 link-local address
    -       solicited-node multicast address for the link-local address
    -       ff02::1 (all IPv6 devices)
    -       ff02::2 (all IPv6 routers)
    """


class AdminStateLeaf13(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf13")]
    """
    Administrative state for the associated VRRP group instance
    """


class AdminStateLeaf14(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf14")]
    """
    The configurable state of the dhcp relay agent
    """


class AdminStateLeaf15(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf15")]
    """
    Administratively enable or disable the sending of router advertisements on the subinterface.
    """


class AdminStateLeaf16(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf16")]
    """
    Enables/Disables DHCPv6 server function on subinterface
    """


class AdminStateLeaf17(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf17")]
    """
    Configurable state of the learning procedures for dynamic mac addresses.
    If disabled, the existing macs in the bridge-table will be kept (and refreshed
    if new frames arrive for them) but no new mac addresses will be learned. Frames
    with unknown mac addresses are not dropped, unless discard-unknown-src-mac is
    configured.
    """


class AdminStateLeaf18(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf18")]
    """
    Configurable state of the aging for the dynamic mac entries in the bridge table.
    If disabled, dynamically learned mac entries will be programmed in the bridge table
    until the network instance is disabled.
    """


class AdminStateLeaf19(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf19")]
    """
    Administratively enable or disable the STP protocol for this interface
    When STP on the network instance is administratively disabled,
    any BPDUs are forwarded transparently.
    When STP on the network instance is administratively enabled,
    but the administrative state on a sub-interface is disabled,
    BPDUs received on such a subinterface are discarded.
    """


class AdminStateLeaf2(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf2")]
    """
    Administrative state of crc monitoring on the port
    """


class AdminStateLeaf20(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf20")]
    """
    The configurable state of the local mirror destination
    """


class AdminStateLeaf21(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf21")]
    """
    Administratively enable or disable sFlow on this interface
    """


class AdminStateLeaf3(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf3")]
    """
    Administrative state of symbol monitoring on the port
    """


class AdminStateLeaf4(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf4")]
    """
    Administrative state of exponential port dampening
    """


class AdminStateLeaf5(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf5")]
    """
    Configure the administrative state for SyncE in line/client ports.
    When enabled, the associated transmit and receiver ports are set to
    synchronous mode and ESMC/SSM processing is enabled.
    Otherwise, all syncE functions are disabled in the port.
    """


class AdminStateLeaf6(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf6")]
    """
    The configured, desired state of the subinterface
    """


class AdminStateLeaf7(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf7")]
    """
    Enable/disable IPv4 on the subinterface

    When set to enable, and even before an IPv4 address is configured, the subinterface starts to accept incoming packets with dest-ip 255.255.255.255, which is necessary to support dhcp-client functionality.
    """


class AdminStateLeaf8(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf8")]
    """
    Administrative state for the associated VRRP group instance
    """


class AdminStateLeaf9(RootModel[AdminStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AdminStateType, Field(title="Admin-stateLeaf9")]
    """
    When enabled, the subinterface should operate in unnumbered mode for IPv4
    """


class AggregateIdLeaf(RootModel[NameLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf, Field(title="Aggregate-idLeaf")]
    """
    lag interface with which this interface is associated
    """


class AgingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf18, Field("enable", alias="srl_nokia-interfaces:admin-state")
    ]


class AnycastGwMacOriginLeaf(RootModel[AnycastGwMacOriginType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[AnycastGwMacOriginType, Field(title="Anycast-gw-mac-originLeaf")]
    """
    Origin of the active anycast-gateway MAC address.

    If not configured, the anycast-gateway-mac will be auto-derived out of 00:00:5E:00:01:VRID, where VRID is the
    Virtual Router Identifier of the subinterface anycast-gw.
    """


class AnycastGwContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    virtual_router_id: Annotated[
        VirtualRouterIdLeaf3, Field(1, alias="srl_nokia-interfaces:virtual-router-id")
    ]
    anycast_gw_mac: Annotated[
        AnycastGwMacLeaf, Field(None, alias="srl_nokia-interfaces:anycast-gw-mac")
    ]
    anycast_gw_mac_origin: Annotated[
        AnycastGwMacOriginLeaf,
        Field(None, alias="srl_nokia-interfaces:anycast-gw-mac-origin"),
    ]


class AutoEdgeLeaf(RootModel[StpAutoEdgeTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpAutoEdgeTypeType, Field(title="Auto-edgeLeaf")]


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
    )
    num_breakout_ports: Annotated[
        NumBreakoutPortsLeaf, Field(alias="srl_nokia-interfaces:num-breakout-ports")
    ]
    breakout_port_speed: Annotated[
        BreakoutPortSpeedLeaf, Field(alias="srl_nokia-interfaces:breakout-port-speed")
    ]


class CurrentAlarmsLeafList2(RootModel[EthernetMonitorReportStatusType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        EthernetMonitorReportStatusType, Field(title="Current-alarmsLeafList2")
    ]
    """
    Current alarms of the Ethernet CRC monitoring, raised when corresponding threshold is exceeded
    """


class CurrentAlarmsLeafList3(RootModel[EthernetMonitorReportStatusType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        EthernetMonitorReportStatusType, Field(title="Current-alarmsLeafList3")
    ]
    """
    Current alarms of the Ethernet symbol monitoring, raised when corresponding threshold is exceeded
    """


class DatapathProgrammingContainer(BaseModel):
    """
    Container for state related to the datapath programming of the ARP or neighbor entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    status: Annotated[StatusLeaf4, Field(None, alias="srl_nokia-interfaces-nbr:status")]
    last_failed_complexes: Annotated[
        List[LastFailedComplexesLeafList],
        Field([], alias="srl_nokia-interfaces-nbr:last-failed-complexes"),
    ]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class DatapathProgrammingContainer2(BaseModel):
    """
    Container for state related to the datapath programming of the ARP or neighbor entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    status: Annotated[StatusLeaf6, Field(None, alias="srl_nokia-interfaces-nbr:status")]
    last_failed_complexes: Annotated[
        List[LastFailedComplexesLeafList2],
        Field([], alias="srl_nokia-interfaces-nbr:last-failed-complexes"),
    ]
    """
    List of forwarding complexes that reported a failure for the last operation. They appear in the format (slot-number,complex-number).
    """


class DispersionControlModeLeaf(RootModel[OpticalDispersionControlModeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        OpticalDispersionControlModeType, Field(title="Dispersion-control-modeLeaf")
    ]
    """
    Mode used to compensate for chromatic dispersion
    """


class Dot1xContainer2(BaseModel):
    """
    Container for the configuration of 802.1x Port based Network Access Control.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf4, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf4, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class DoubleTaggedContainer(BaseModel):
    """
    When present, double-tagged frames with a specific, non-zero, outer and inner VLAN ID values are associated to the subinterface

    By default, the specific configured vlan-id tags are stripped at ingress and pushed on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    inner_vlan_id: Annotated[
        InnerVlanIdLeaf, Field(alias="srl_nokia-interfaces-vlans:inner-vlan-id")
    ]
    outer_vlan_id: Annotated[
        OuterVlanIdLeaf, Field(alias="srl_nokia-interfaces-vlans:outer-vlan-id")
    ]


class DuplicateEntriesContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[
        List[MacListEntry2],
        Field(alias="srl_nokia-interfaces-bridge-table-mac-duplication-entries:mac"),
    ]


class EdgePortLeaf(RootModel[StpEdgePortTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpEdgePortTypeType, Field(title="Edge-portLeaf")]


class EfmOamContainer(BaseModel):
    """
    Container for the configuration of Ethernet in the First Mile OAM frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf8, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf8, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class ElmiContainer(BaseModel):
    """
    Container for the configuration of Ethernet local management interface frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf7, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf7, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class EsmcContainer(BaseModel):
    """
    Container for the configuration of Ethernet synchronization messaging channel frames
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf6, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf6, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class EthernetSegmentAssociationContainer(BaseModel):
    """
    ethernet-segment association information.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ethernet_segment: Annotated[
        EthernetSegmentLeaf,
        Field(
            None,
            alias="srl_nokia-interfaces-ethernet-segment-association:ethernet-segment",
        ),
    ]
    es_managed: Annotated[
        EsManagedLeaf,
        Field(
            False, alias="srl_nokia-interfaces-ethernet-segment-association:es-managed"
        ),
    ]
    designated_forwarder: Annotated[
        DesignatedForwarderLeaf,
        Field(
            False,
            alias="srl_nokia-interfaces-ethernet-segment-association:designated-forwarder",
        ),
    ]


class ExponentialPortDampeningContainer(BaseModel):
    """
    Exponential port dampening parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf4, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    half_life: Annotated[HalfLifeLeaf, Field(5, alias="srl_nokia-interfaces:half-life")]
    max_suppress_time: Annotated[
        MaxSuppressTimeLeaf, Field(20, alias="srl_nokia-interfaces:max-suppress-time")
    ]
    reuse_threshold: Annotated[
        ReuseThresholdLeaf, Field(1000, alias="srl_nokia-interfaces:reuse-threshold")
    ]
    suppress_threshold: Annotated[
        SuppressThresholdLeaf,
        Field(2000, alias="srl_nokia-interfaces:suppress-threshold"),
    ]
    current_penalties: Annotated[
        CurrentPenaltiesLeaf, Field(0, alias="srl_nokia-interfaces:current-penalties")
    ]
    max_penalties: Annotated[
        MaxPenaltiesLeaf, Field(0, alias="srl_nokia-interfaces:max-penalties")
    ]
    oper_state: Annotated[
        OperStateLeaf3, Field(None, alias="srl_nokia-interfaces:oper-state")
    ]


class ForwardingComplexLeaf(RootModel[NameLeaf2]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf2, Field(title="Forwarding-complexLeaf")]
    """
    The forwarding-complex on which this interface resides

    This field is not populated for non-forwarding-complex-attached interfaces, for example mgmt0.
    """


class GiAddressLeaf(RootModel[Ipv4AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4AddressType, Field(title="Gi-addressLeaf")]
    """
    IPv4 address to be used as giaddr of the relayed packets towards DHCPv4 servers.
    This address can be any IPv4 address configured within the network-instance towards the DHCPv4 server
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
    )
    status: Annotated[
        StatusLeaf, Field(None, alias="srl_nokia-platform-healthz:status")
    ]
    last_unhealthy: Annotated[
        LastUnhealthyLeaf,
        Field(None, alias="srl_nokia-platform-healthz:last-unhealthy"),
    ]
    unhealthy_count: Annotated[
        UnhealthyCountLeaf, Field(0, alias="srl_nokia-platform-healthz:unhealthy-count")
    ]


class HoldTimeContainer(BaseModel):
    """
    Configure interface hold timers for Ethernet interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    up: Annotated[UpLeaf, Field(0, alias="srl_nokia-interfaces:up")]
    up_expires: Annotated[
        UpExpiresLeaf, Field(None, alias="srl_nokia-interfaces:up-expires")
    ]
    down: Annotated[DownLeaf, Field(0, alias="srl_nokia-interfaces:down")]
    down_expires: Annotated[
        DownExpiresLeaf, Field(None, alias="srl_nokia-interfaces:down-expires")
    ]


class HostsContainer(BaseModel):
    """
    Top level state container for 802.1X
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[MacLeaf3, Field(None, alias="srl_nokia-dot1x:mac")]
    status: Annotated[StatusLeaf2, Field(None, alias="srl_nokia-dot1x:status")]


class Hostv4Type(RootModel[Union[Ipv4AddressType, DomainNameType]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Union[Ipv4AddressType, DomainNameType]
    """
    The hostv4 type represents either an IPv4 address or a DNS domain name.
    """


class Hostv6Type(RootModel[Union[Ipv6AddressType, DomainNameType]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Union[Ipv6AddressType, DomainNameType]
    """
    The hostv6 type represents either an IPv6 address or a DNS domain name.
    """


class IngressSquelchingContainer(BaseModel):
    """
    Ingress ETH-CFM functions independent of Maintenance Domain context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    squelch_levels: Annotated[
        SquelchLevelsLeaf, Field(None, alias="srl_nokia-ethcfm:squelch-levels")
    ]
    statistics: Annotated[
        StatisticsContainer17, Field(None, alias="srl_nokia-ethcfm:statistics")
    ]


class InterfaceLeaf(RootModel[NameLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf, Field(title="InterfaceLeaf")]
    """
    Interface to track
    """


class InterfaceLeaf2(RootModel[SubinterfaceAllType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[SubinterfaceAllType, Field(title="InterfaceLeaf2")]
    """
    Reference to the subinterface with the IPv4 address to be borrowed
    """


class InterfaceLeaf3(RootModel[NameLeaf]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf, Field(title="InterfaceLeaf3")]
    """
    Interface to track
    """


class InternalTagsContainer(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    set_tag_set: Annotated[
        List[SetTagSetLeafList], Field([], alias="srl_nokia-interfaces-nbr:set-tag-set")
    ]
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer2(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    set_tag_set: Annotated[
        List[SetTagSetLeafList2],
        Field([], alias="srl_nokia-interfaces-nbr-evpn:set-tag-set"),
    ]
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer3(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    set_tag_set: Annotated[
        List[SetTagSetLeafList3],
        Field([], alias="srl_nokia-interfaces-nbr:set-tag-set"),
    ]
    """
    Reference to a tag-set defined under routing-policy
    """


class InternalTagsContainer4(BaseModel):
    """
    Configuration and state of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    set_tag_set: Annotated[
        List[SetTagSetLeafList4],
        Field([], alias="srl_nokia-interfaces-nbr-evpn:set-tag-set"),
    ]
    """
    Reference to a tag-set defined under routing-policy
    """


class IntervalLeaf(RootModel[LacpPeriodTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpPeriodTypeType, Field(title="IntervalLeaf")]
    """
    Set the period between LACP messages -- uses
    the lacp-period-type enumeration.
    """


class IpAddressType(RootModel[Union[Ipv4AddressType, Ipv6AddressType]]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Union[Ipv4AddressType, Ipv6AddressType]
    """
    An IPv4 or IPv6 address with no prefix specified.
    """


class IpPrefixLeaf(RootModel[Ipv4PrefixWithHostBitsType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4PrefixWithHostBitsType, Field(title="Ip-prefixLeaf")]
    """
    The IPv4 address and prefix length in CIDR notation

    Subnets on the same subinterface are allowed to overlap as long as the host bits are different. When a locally originated unicast packet is destined to a host covered by multiple subnets associated with a subinterface, the source address is chosen to be the numerically lowest IP address among all these subnets. For example, if the addresses 172.16.1.1/12, 172.16.1.2/12, and 172.16.1.3/12 are configured on the same interface, 172.16.1.1 would be used as a local address when you issue a ping 172.16.1.5 command
    """


class IpPrefixLeaf2(RootModel[Ipv6PrefixWithHostBitsType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6PrefixWithHostBitsType, Field(title="Ip-prefixLeaf2")]
    """
    The IPv6 address and prefix-length in CIDR notation

    Up to 16 global unicast IPv6 addresses can be assigned to each subinterface. Global unicast IPv6 address subnets on the same subinterface are allowed to overlap as long as the host bits are different. When a locally originated unicast packet is destined to a host covered by multiple subnets associated with a subinterface, the source address is chosen to be the numerically lowest IP address among all these subnets.
    """


class Ipv4AddressLeaf(RootModel[Ipv4AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4AddressType, Field(title="Ipv4-addressLeaf")]
    """
    IPv4 address resolved by the ARP entry

    To configure a static neighbor entry a value must be written into this leaf and the link-layer-address leaf.
    """


class Ipv4AddressLeaf2(RootModel[Ipv4AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv4AddressType, Field(title="Ipv4-addressLeaf2")]
    """
    The virtual IPv4 address.
    """


class Ipv6AddressLeaf(RootModel[Ipv6AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressType, Field(title="Ipv6-addressLeaf")]
    """
    IPv6 address resolved by the ND cache entry

    To configure a static neighbor entry a value must be written into this leaf and the link-layer-address leaf.
    """


class Ipv6AddressLeaf2(RootModel[Ipv6AddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Ipv6AddressType, Field(title="Ipv6-addressLeaf2")]
    """
    The virtual IPv6 address.
    """


class KeychainLeaf(RootModel[NameLeaf4]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf4, Field(title="KeychainLeaf")]
    """
    Reference to a keychain. The keychain type must be md5 or clear-text
    """


class KeychainLeaf2(RootModel[NameLeaf4]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[NameLeaf4, Field(title="KeychainLeaf2")]
    """
    Reference to a keychain. The keychain type must be md5 or clear-text
    """


class LacpFallbackModeLeaf(RootModel[LacpFallbackTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LacpFallbackTypeType, Field(title="Lacp-fallback-modeLeaf")]
    """
    Specifies lacp-fallback mode if enabled
    """


class LacpContainer(BaseModel):
    """
    Container for L2CP transparency of the Link Aggregation Control Protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf2, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf2, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class LacpContainer2(BaseModel):
    """
    Operational status data for the member interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    activity: Annotated[ActivityLeaf, Field(None, alias="srl_nokia-lacp:activity")]
    timeout: Annotated[TimeoutLeaf2, Field(None, alias="srl_nokia-lacp:timeout")]
    synchronization: Annotated[
        SynchronizationLeaf, Field(None, alias="srl_nokia-lacp:synchronization")
    ]
    aggregatable: Annotated[
        AggregatableLeaf, Field(None, alias="srl_nokia-lacp:aggregatable")
    ]
    collecting: Annotated[
        CollectingLeaf, Field(None, alias="srl_nokia-lacp:collecting")
    ]
    distributing: Annotated[
        DistributingLeaf, Field(None, alias="srl_nokia-lacp:distributing")
    ]
    system_id: Annotated[SystemIdLeaf, Field(None, alias="srl_nokia-lacp:system-id")]
    oper_key: Annotated[OperKeyLeaf, Field(None, alias="srl_nokia-lacp:oper-key")]
    partner_id: Annotated[PartnerIdLeaf, Field(None, alias="srl_nokia-lacp:partner-id")]
    partner_key: Annotated[
        PartnerKeyLeaf, Field(None, alias="srl_nokia-lacp:partner-key")
    ]
    port_num: Annotated[PortNumLeaf, Field(None, alias="srl_nokia-lacp:port-num")]
    partner_port_num: Annotated[
        PartnerPortNumLeaf, Field(None, alias="srl_nokia-lacp:partner-port-num")
    ]
    lacp_port_priority: Annotated[
        LacpPortPriorityLeaf2, Field(None, alias="srl_nokia-lacp:lacp-port-priority")
    ]
    statistics: Annotated[
        StatisticsContainer19, Field(None, alias="srl_nokia-lacp:statistics")
    ]


class LacpContainer3(BaseModel):
    """
    LACP parameters for the associated LAG
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    interval: Annotated[IntervalLeaf, Field("SLOW", alias="srl_nokia-lacp:interval")]
    """
    Set the period between LACP messages -- uses
          the lacp-period-type enumeration.
    """
    lacp_mode: Annotated[
        LacpModeLeaf, Field("ACTIVE", alias="srl_nokia-lacp:lacp-mode")
    ]
    admin_key: Annotated[AdminKeyLeaf, Field(None, alias="srl_nokia-lacp:admin-key")]
    system_id_mac: Annotated[
        SystemIdMacLeaf, Field(None, alias="srl_nokia-lacp:system-id-mac")
    ]
    system_priority: Annotated[
        SystemPriorityLeaf, Field(None, alias="srl_nokia-lacp:system-priority")
    ]


class LagTypeLeaf(RootModel[LagTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[LagTypeType, Field(title="Lag-typeLeaf")]
    """
    Sets the type of LAG, i.e., how it is
    configured / maintained
    """


class LearntEntriesContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[
        List[MacListEntry],
        Field(alias="srl_nokia-interfaces-bridge-table-mac-learning-entries:mac"),
    ]


class LinkTypeLeaf(RootModel[StpLinkTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpLinkTypeType, Field(title="Link-typeLeaf")]


class LldpContainer(BaseModel):
    """
    Container for L2CP transparency of the Link Layer Discovery Protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[
        TunnelLeaf, Field(False, alias="srl_nokia-interfaces-l2cp:tunnel")
    ]
    oper_rule: Annotated[
        OperRuleLeaf, Field(None, alias="srl_nokia-interfaces-l2cp:oper-rule")
    ]


class LowVlanIdListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    range_low_vlan_id: Annotated[
        RangeLowVlanIdLeaf,
        Field(None, alias="srl_nokia-interfaces-vlans:range-low-vlan-id"),
    ]
    high_vlan_id: Annotated[
        HighVlanIdLeaf, Field(alias="srl_nokia-interfaces-vlans:high-vlan-id")
    ]


class MacDuplicationContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    action: Annotated[
        ActionLeaf,
        Field("use-net-instance-action", alias="srl_nokia-interfaces:action"),
    ]
    duplicate_entries: Annotated[
        DuplicateEntriesContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-duplication-entries:duplicate-entries",
        ),
    ]


class MacLearningContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf17, Field("enable", alias="srl_nokia-interfaces:admin-state")
    ]
    aging: Annotated[AgingContainer, Field(None, alias="srl_nokia-interfaces:aging")]
    learnt_entries: Annotated[
        LearntEntriesContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-learning-entries:learnt-entries",
        ),
    ]


class MacTypeListEntry(BaseModel):
    """
    the type of the mac on the sub-interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    type: Annotated[
        TypeLeaf4,
        Field(None, alias="srl_nokia-interfaces-bridge-table-statistics:type"),
    ]
    active_entries: Annotated[
        ActiveEntriesLeaf2,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:active-entries"),
    ]
    total_entries: Annotated[
        TotalEntriesLeaf2,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:total-entries"),
    ]
    failed_entries: Annotated[
        FailedEntriesLeaf2,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:failed-entries"),
    ]


class MacListEntry3(BaseModel):
    """
    macs learnt on the bridging instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    address: Annotated[
        AddressLeaf4,
        Field(None, alias="srl_nokia-interfaces-bridge-table-mac-table:address"),
    ]
    type: Annotated[
        TypeLeaf5, Field(None, alias="srl_nokia-interfaces-bridge-table-mac-table:type")
    ]
    last_update: Annotated[
        LastUpdateLeaf4,
        Field(None, alias="srl_nokia-interfaces-bridge-table-mac-table:last-update"),
    ]
    not_programmed_reason: Annotated[
        NotProgrammedReasonLeaf,
        Field(
            None,
            alias="srl_nokia-interfaces-bridge-table-mac-table:not-programmed-reason",
        ),
    ]
    failed_slots: Annotated[
        List[FailedSlotsLeafList],
        Field([], alias="srl_nokia-interfaces-bridge-table-mac-table:failed-slots"),
    ]
    """
    The list of slot IDs corresponding to the linecards that did not successfully program the mac
    """


class MplsContainer(BaseModel):
    """
    Container for MPLS configuration and state at the subinterface level
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    statistics: Annotated[
        StatisticsContainer18, Field(None, alias="srl_nokia-if-mpls:statistics")
    ]


class MstInstanceListEntry(BaseModel):
    """
    List of subinterfaces used by this mstp-policy
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    mst_instance: Annotated[
        MstInstanceLeaf,
        Field(None, alias="srl_nokia-interfaces-bridge-table-stp:mst-instance"),
    ]
    mst_port_priority: Annotated[
        MstPortPriorityLeaf,
        Field(128, alias="srl_nokia-interfaces-bridge-table-stp:mst-port-priority"),
    ]
    mst_path_cost: Annotated[
        MstPathCostLeaf,
        Field(16, alias="srl_nokia-interfaces-bridge-table-stp:mst-path-cost"),
    ]


class NeighborListEntry(BaseModel):
    """
    List of static and dynamic ARP cache entries that map an IPv4 address to a MAC address

    To configure a static ARP entry a value must be written into this leaf and the link-layer-address leaf.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ipv4_address: Annotated[
        Ipv4AddressLeaf, Field(None, alias="srl_nokia-interfaces-nbr:ipv4-address")
    ]
    link_layer_address: Annotated[
        LinkLayerAddressLeaf, Field(alias="srl_nokia-interfaces-nbr:link-layer-address")
    ]
    origin: Annotated[OriginLeaf2, Field(None, alias="srl_nokia-interfaces-nbr:origin")]
    expiration_time: Annotated[
        ExpirationTimeLeaf,
        Field(None, alias="srl_nokia-interfaces-nbr:expiration-time"),
    ]
    datapath_programming: Annotated[
        DatapathProgrammingContainer,
        Field(None, alias="srl_nokia-interfaces-nbr:datapath-programming"),
    ]


class NeighborListEntry2(BaseModel):
    """
    List of static and dynamic ND cache entries that map an IPv6 address to a MAC address
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ipv6_address: Annotated[
        Ipv6AddressLeaf, Field(None, alias="srl_nokia-interfaces-nbr:ipv6-address")
    ]
    link_layer_address: Annotated[
        LinkLayerAddressLeaf2,
        Field(alias="srl_nokia-interfaces-nbr:link-layer-address"),
    ]
    origin: Annotated[OriginLeaf4, Field(None, alias="srl_nokia-interfaces-nbr:origin")]
    is_router: Annotated[
        IsRouterLeaf, Field(None, alias="srl_nokia-interfaces-nbr:is-router")
    ]
    current_state: Annotated[
        CurrentStateLeaf, Field(None, alias="srl_nokia-interfaces-nbr:current-state")
    ]
    next_state_time: Annotated[
        NextStateTimeLeaf, Field(None, alias="srl_nokia-interfaces-nbr:next-state-time")
    ]
    datapath_programming: Annotated[
        DatapathProgrammingContainer2,
        Field(None, alias="srl_nokia-interfaces-nbr:datapath-programming"),
    ]


class OperDownReasonLeaf(RootModel[PortOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[PortOperDownReasonType, Field(title="Oper-down-reasonLeaf")]
    """
    The first (and possibly only) reason for the port being operationally down
    """


class OperDownReasonLeaf2(RootModel[TransceiverOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TransceiverOperDownReasonType, Field(title="Oper-down-reasonLeaf2")]
    """
    The reason for the transceiver being operationally down
    """


class OperDownReasonLeaf3(RootModel[SubifOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[SubifOperDownReasonType, Field(title="Oper-down-reasonLeaf3")]
    """
    The first (and possibly only) reason for the subinterface being operationally down
    """


class OperDownReasonLeaf4(RootModel[VrrpOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VrrpOperDownReasonType, Field(title="Oper-down-reasonLeaf4")]
    """
    The first (and possibly only) reason for the vrrp-group being operationally down
    """


class OperDownReasonLeaf6(RootModel[VrrpOperDownReasonType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VrrpOperDownReasonType, Field(title="Oper-down-reasonLeaf6")]
    """
    The first (and possibly only) reason for the vrrp-group being operationally down
    """


class OperStateLeaf10(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf10")]
    """
    Details if the dhcp server is operationally available
    """


class OperStateLeaf11(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf11")]
    """
    The operational state of the local mirror destination
    """


class OperStateLeaf13(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf13")]
    """
    Operational state for the associated LAG
    """


class OperStateLeaf2(RootModel[TransceiverOperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[TransceiverOperStateType, Field(title="Oper-stateLeaf2")]
    """
    The operational state of the transceiver

    The oper-state is always down when the Ethernet port is a copper/RJ45 port.
    """


class OperStateLeaf5(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf5")]
    """
    VRRP Operational state
    """


class OperStateLeaf6(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf6")]
    """
    The operational state of the dhcp relay agent
    """


class OperStateLeaf7(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf7")]
    """
    Details if the dhcp server is operationally available
    """


class OperStateLeaf8(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf8")]
    """
    VRRP Operational state
    """


class OperStateLeaf9(RootModel[OperStateType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[OperStateType, Field(title="Oper-stateLeaf9")]
    """
    The operational state of the dhcp relay agent
    """


class OpticalChannelListEntry(BaseModel):
    """
    List of optical channels supported by the transceiver associated with this port.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    index: Annotated[IndexLeaf2, Field(None, alias="srl_nokia-interfaces-dco:index")]
    frequency: Annotated[
        FrequencyLeaf, Field(alias="srl_nokia-interfaces-dco:frequency")
    ]
    operational_mode: Annotated[
        OperationalModeLeaf, Field(alias="srl_nokia-interfaces-dco:operational-mode")
    ]
    """
    Operational mode for the transceiver

     This is a numeric value the defines a set of operating characteristics such as modulation, bit-rate, max power range, fec, etc.
     Refer to Nokia documentation for details by transceiver part number.
    """
    tx_filter_enable: Annotated[
        TxFilterEnableLeaf,
        Field(False, alias="srl_nokia-interfaces-dco:tx-filter-enable"),
    ]
    chromatic_dispersion_range: Annotated[
        ChromaticDispersionRangeContainer,
        Field(None, alias="srl_nokia-interfaces-dco:chromatic-dispersion-range"),
    ]
    target_power: Annotated[
        TargetPowerLeaf, Field(100, alias="srl_nokia-interfaces-dco:target-power")
    ]
    laser_tunability: Annotated[
        LaserTunabilityLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:laser-tunability"),
    ]
    oper_frequency: Annotated[
        OperFrequencyLeaf, Field(None, alias="srl_nokia-interfaces-dco:oper-frequency")
    ]
    minimum_frequency: Annotated[
        MinimumFrequencyLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:minimum-frequency"),
    ]
    maximum_frequency: Annotated[
        MaximumFrequencyLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:maximum-frequency"),
    ]
    supported_grids: Annotated[
        List[SupportedGridsLeafList],
        Field([], alias="srl_nokia-interfaces-dco:supported-grids"),
    ]
    """
    Indicates the frequency grids supported by the equipped tunable optical port.
    """
    fine_tuning: Annotated[
        FineTuningContainer, Field(None, alias="srl_nokia-interfaces-dco:fine-tuning")
    ]
    dispersion: Annotated[
        DispersionLeaf, Field(None, alias="srl_nokia-interfaces-dco:dispersion")
    ]
    dispersion_control_mode: Annotated[
        DispersionControlModeLeaf,
        Field("automatic", alias="srl_nokia-interfaces-dco:dispersion-control-mode"),
    ]
    rx_los_reaction: Annotated[
        RxLosReactionLeaf,
        Field("squelch", alias="srl_nokia-interfaces-dco:rx-los-reaction"),
    ]
    rx_los_thresh: Annotated[
        RxLosThreshLeaf, Field(-2300, alias="srl_nokia-interfaces-dco:rx-los-thresh")
    ]
    module_state: Annotated[
        ModuleStateLeaf, Field(None, alias="srl_nokia-interfaces-dco:module-state")
    ]
    module_tx_turn_up_states: Annotated[
        List[ModuleTxTurnUpStatesLeafList],
        Field([], alias="srl_nokia-interfaces-dco:module-tx-turn-up-states"),
    ]
    """
    Indicates the completed transmitted turn-up states of the coherent optical module
    """
    module_rx_turn_up_states: Annotated[
        List[ModuleRxTurnUpStatesLeafList],
        Field([], alias="srl_nokia-interfaces-dco:module-rx-turn-up-states"),
    ]
    """
    Indicates the completed received turn-up states of the coherent optical module
    """
    rx_electrical_snr_x_polarization: Annotated[
        RxElectricalSnrXPolarizationLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:rx-electrical-snr-x-polarization"),
    ]
    rx_electrical_snr_y_polarization: Annotated[
        RxElectricalSnrYPolarizationLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:rx-electrical-snr-y-polarization"),
    ]
    rx_quality_margin: Annotated[
        RxQualityMarginLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:rx-quality-margin"),
    ]
    rx_optical_snr_x_polarization: Annotated[
        RxOpticalSnrXPolarizationLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:rx-optical-snr-x-polarization"),
    ]
    rx_optical_snr_y_polarization: Annotated[
        RxOpticalSnrYPolarizationLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:rx-optical-snr-y-polarization"),
    ]
    current_alarms: Annotated[
        List[CurrentAlarmsLeafList],
        Field([], alias="srl_nokia-interfaces-dco:current-alarms"),
    ]
    """
    Indicates the coherent optical alarms currently active on the port.
    """
    defect_points: Annotated[
        List[DefectPointsLeafList],
        Field([], alias="srl_nokia-interfaces-dco:defect-points"),
    ]
    """
    Indicates the coherent optical defect points currently active on the port.
    """
    sweep: Annotated[
        SweepContainer, Field(None, alias="srl_nokia-interfaces-dco:sweep")
    ]
    statistics: Annotated[
        StatisticsContainer2, Field(None, alias="srl_nokia-interfaces-dco:statistics")
    ]
    transmit_power: Annotated[
        TransmitPowerContainer,
        Field(None, alias="srl_nokia-interfaces-dco:transmit-power"),
    ]
    logical_channel: Annotated[
        LogicalChannelLeaf,
        Field(None, alias="srl_nokia-interfaces-dco:logical-channel"),
    ]


class PciContainer(BaseModel):
    """
    Top-level container for state related to PCI interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    address: Annotated[
        AddressLeaf5, Field(None, alias="srl_nokia-interfaces-vxdp:address")
    ]
    socket_id: Annotated[
        SocketIdLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:socket-id")
    ]
    socket_cpus: Annotated[
        List[SocketCpusLeafList2],
        Field([], alias="srl_nokia-interfaces-vxdp:socket-cpus"),
    ]
    """
    List of CPUs present on the socket this interface is attached to
    """
    vendor_name: Annotated[
        VendorNameLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:vendor-name")
    ]
    vendor_id: Annotated[
        VendorIdLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:vendor-id")
    ]
    device_name: Annotated[
        DeviceNameLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:device-name")
    ]
    device_id: Annotated[
        DeviceIdLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:device-id")
    ]
    subsystem: Annotated[
        SubsystemContainer, Field(None, alias="srl_nokia-interfaces-vxdp:subsystem")
    ]


class PopulateListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    route_type: Annotated[
        RouteTypeLeaf, Field(None, alias="srl_nokia-interfaces-nbr:route-type")
    ]
    datapath_programming: Annotated[
        DatapathProgrammingLeaf,
        Field(None, alias="srl_nokia-interfaces-nbr:datapath-programming"),
    ]
    internal_tags: Annotated[
        InternalTagsContainer,
        Field(None, alias="srl_nokia-interfaces-nbr:internal-tags"),
    ]


class PopulateListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    route_type: Annotated[
        RouteTypeLeaf3, Field(None, alias="srl_nokia-interfaces-nbr:route-type")
    ]
    datapath_programming: Annotated[
        DatapathProgrammingLeaf2,
        Field(None, alias="srl_nokia-interfaces-nbr:datapath-programming"),
    ]
    internal_tags: Annotated[
        InternalTagsContainer3,
        Field(None, alias="srl_nokia-interfaces-nbr:internal-tags"),
    ]


class PrefixListEntry(BaseModel):
    """
    The list of IPv6 prefixes to advertise in the router advertisement messages.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ipv6_prefix: Annotated[
        Ipv6PrefixLeaf, Field(None, alias="srl_nokia-interfaces-router-adv:ipv6-prefix")
    ]
    autonomous_flag: Annotated[
        AutonomousFlagLeaf,
        Field(True, alias="srl_nokia-interfaces-router-adv:autonomous-flag"),
    ]
    on_link_flag: Annotated[
        OnLinkFlagLeaf,
        Field(True, alias="srl_nokia-interfaces-router-adv:on-link-flag"),
    ]
    preferred_lifetime: Annotated[
        PreferredLifetimeLeaf,
        Field("604800", alias="srl_nokia-interfaces-router-adv:preferred-lifetime"),
    ]
    valid_lifetime: Annotated[
        ValidLifetimeLeaf,
        Field("2592000", alias="srl_nokia-interfaces-router-adv:valid-lifetime"),
    ]


class ProbeBridgedSubinterfacesLeafList(RootModel[SubinterfaceAllType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        SubinterfaceAllType, Field(title="Probe-bridged-subinterfacesLeafList")
    ]
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the ARP
    probes are sent.
    """


class ProbeBridgedSubinterfacesLeafList2(RootModel[SubinterfaceAllType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[
        SubinterfaceAllType, Field(title="Probe-bridged-subinterfacesLeafList2")
    ]
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the NS
    probes are sent.
    """


class ResolvedIpAddressLeaf(RootModel[IpAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IpAddressType, Field(title="Resolved-ip-addressLeaf")]
    """
    The resolved IP address of the server domain name.

    An entry of 0.0.0.0 indicates the server IP cannot be resolved.
    """


class ResolvedIpAddressLeaf2(RootModel[IpAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IpAddressType, Field(title="Resolved-ip-addressLeaf2")]
    """
    The resolved IP address of the server domain name.

    An entry of 0.0.0.0 indicates the server IP cannot be resolved.
    """


class ResultListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    id: Annotated[IdLeaf, Field(None, alias="srl_nokia-packet-link-qual:id")]
    oper_state: Annotated[
        OperStateLeaf12, Field(None, alias="srl_nokia-packet-link-qual:oper-state")
    ]
    packets_sent: Annotated[
        PacketsSentLeaf, Field(None, alias="srl_nokia-packet-link-qual:packets-sent")
    ]
    packets_received: Annotated[
        PacketsReceivedLeaf,
        Field(None, alias="srl_nokia-packet-link-qual:packets-received"),
    ]
    packets_error: Annotated[
        PacketsErrorLeaf, Field(None, alias="srl_nokia-packet-link-qual:packets-error")
    ]
    packets_dropped: Annotated[
        PacketsDroppedLeaf,
        Field(None, alias="srl_nokia-packet-link-qual:packets-dropped"),
    ]
    start_time: Annotated[
        StartTimeLeaf, Field(None, alias="srl_nokia-packet-link-qual:start-time")
    ]
    end_time: Annotated[
        EndTimeLeaf, Field(None, alias="srl_nokia-packet-link-qual:end-time")
    ]
    expected_rate: Annotated[
        ExpectedRateLeaf, Field(None, alias="srl_nokia-packet-link-qual:expected-rate")
    ]
    qualification_rate: Annotated[
        QualificationRateLeaf,
        Field(None, alias="srl_nokia-packet-link-qual:qualification-rate"),
    ]
    status: Annotated[
        StatusLeaf7, Field(None, alias="srl_nokia-packet-link-qual:status")
    ]
    status_message: Annotated[
        StatusMessageLeaf,
        Field(None, alias="srl_nokia-packet-link-qual:status-message"),
    ]


class RootGuardLeaf(RootModel[StpRootGuardTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[StpRootGuardTypeType, Field(title="Root-guardLeaf")]


class RouterRoleContainer(BaseModel):
    """
    IPv6 router advertisement options that apply when the role of the interface is a router interface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf15,
        Field("disable", alias="srl_nokia-interfaces-router-adv:admin-state"),
    ]
    current_hop_limit: Annotated[
        CurrentHopLimitLeaf,
        Field(64, alias="srl_nokia-interfaces-router-adv:current-hop-limit"),
    ]
    ip_mtu: Annotated[
        IpMtuLeaf2, Field(None, alias="srl_nokia-interfaces-router-adv:ip-mtu")
    ]
    managed_configuration_flag: Annotated[
        ManagedConfigurationFlagLeaf,
        Field(
            False, alias="srl_nokia-interfaces-router-adv:managed-configuration-flag"
        ),
    ]
    other_configuration_flag: Annotated[
        OtherConfigurationFlagLeaf,
        Field(False, alias="srl_nokia-interfaces-router-adv:other-configuration-flag"),
    ]
    max_advertisement_interval: Annotated[
        MaxAdvertisementIntervalLeaf,
        Field(600, alias="srl_nokia-interfaces-router-adv:max-advertisement-interval"),
    ]
    min_advertisement_interval: Annotated[
        MinAdvertisementIntervalLeaf,
        Field(200, alias="srl_nokia-interfaces-router-adv:min-advertisement-interval"),
    ]
    reachable_time: Annotated[
        ReachableTimeLeaf2,
        Field(0, alias="srl_nokia-interfaces-router-adv:reachable-time"),
    ]
    retransmit_time: Annotated[
        RetransmitTimeLeaf,
        Field(0, alias="srl_nokia-interfaces-router-adv:retransmit-time"),
    ]
    router_lifetime: Annotated[
        RouterLifetimeLeaf,
        Field(1800, alias="srl_nokia-interfaces-router-adv:router-lifetime"),
    ]
    prefix: Annotated[
        List[PrefixListEntry], Field(alias="srl_nokia-interfaces-router-adv:prefix")
    ]


class ServerLeafList(RootModel[Hostv4Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Hostv4Type, Field(title="ServerLeafList")]
    """
    List of the DHCPv4 servers that the DHCPv4 relay function will relay DHCPv4 packets to/from
    """


class ServerLeafList2(RootModel[Hostv6Type]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[Hostv6Type, Field(title="ServerLeafList2")]
    """
    List of the DHCPv6 servers that the DHCPv6 relay function will relay DHCPv6 packets to/from
    """


class ServerListEntry(BaseModel):
    """
    Reports the resolved IP address for server entries using domain names
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    domain: Annotated[
        DomainLeaf, Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:domain")
    ]
    resolved_ip_address: Annotated[
        ResolvedIpAddressLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:resolved-ip-address"),
    ]
    last_update: Annotated[
        LastUpdateLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:last-update"),
    ]


class ServerListEntry2(BaseModel):
    """
    Reports the resolved IP address for server entries using domain names
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    domain: Annotated[
        DomainLeaf2, Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:domain")
    ]
    resolved_ip_address: Annotated[
        ResolvedIpAddressLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:resolved-ip-address"),
    ]
    last_update: Annotated[
        LastUpdateLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:last-update"),
    ]


class SflowContainer(BaseModel):
    """
    Context to configure sFlow parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf21, Field(None, alias="srl_nokia-interfaces:admin-state")
    ]
    ingress_sampling_rate: Annotated[
        IngressSamplingRateLeaf,
        Field(None, alias="srl_nokia-interfaces:ingress-sampling-rate"),
    ]
    egress_sampling_rate: Annotated[
        EgressSamplingRateLeaf,
        Field(None, alias="srl_nokia-interfaces:egress-sampling-rate"),
    ]


class SingleTaggedRangeContainer(BaseModel):
    """
    When present, tagged frames with a specific, non-zero, outer VLAN ID contained in a specified set of range are associated to the subinterface

    The outer VLAN ID tag of the frame is not stripped off on ingress, and no tag is pushed on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    low_vlan_id: Annotated[
        List[LowVlanIdListEntry], Field(alias="srl_nokia-interfaces-vlans:low-vlan-id")
    ]


class SingleTaggedContainer(BaseModel):
    """
    When present, tagged frames with a specific, non-zero, outer VLAN ID are associated to the subinterface

    The outer VLAN-ID tag is considered service delimiting and it is by default stripped at ingress and restored/added on egress.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vlan_id: Annotated[
        VlanIdLeaf, Field(None, alias="srl_nokia-interfaces-vlans:vlan-id")
    ]


class SsmContainer(BaseModel):
    """
    This struct containing all attributes for QL/SSM with SyncE in these ports.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf5, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]


class StatisticsContainer16(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    active_entries: Annotated[
        ActiveEntriesLeaf,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:active-entries"),
    ]
    total_entries: Annotated[
        TotalEntriesLeaf,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:total-entries"),
    ]
    failed_entries: Annotated[
        FailedEntriesLeaf,
        Field(0, alias="srl_nokia-interfaces-bridge-table-statistics:failed-entries"),
    ]
    mac_type: Annotated[
        List[MacTypeListEntry],
        Field(alias="srl_nokia-interfaces-bridge-table-statistics:mac-type"),
    ]


class StatisticsContainer4(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    total_in_packets: Annotated[
        TotalInPacketsLeaf, Field(0, alias="srl_nokia-dot1x:total-in-packets")
    ]
    total_in_discarded_packets: Annotated[
        TotalInDiscardedPacketsLeaf,
        Field(0, alias="srl_nokia-dot1x:total-in-discarded-packets"),
    ]
    in_tunneled_packets: Annotated[
        InTunneledPacketsLeaf, Field(0, alias="srl_nokia-dot1x:in-tunneled-packets")
    ]
    in_trap_to_cpu_packets: Annotated[
        InTrapToCpuPacketsLeaf, Field(0, alias="srl_nokia-dot1x:in-trap-to-cpu-packets")
    ]
    last_clear: Annotated[
        LastClearLeaf3, Field(None, alias="srl_nokia-dot1x:last-clear")
    ]


class StormControlContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    units: Annotated[UnitsLeaf, Field("percentage", alias="srl_nokia-interfaces:units")]
    broadcast_rate: Annotated[
        BroadcastRateLeaf, Field(None, alias="srl_nokia-interfaces:broadcast-rate")
    ]
    multicast_rate: Annotated[
        MulticastRateLeaf, Field(None, alias="srl_nokia-interfaces:multicast-rate")
    ]
    unknown_unicast_rate: Annotated[
        UnknownUnicastRateLeaf,
        Field(None, alias="srl_nokia-interfaces:unknown-unicast-rate"),
    ]
    operational_broadcast_rate: Annotated[
        OperationalBroadcastRateLeaf,
        Field(None, alias="srl_nokia-interfaces:operational-broadcast-rate"),
    ]
    operational_multicast_rate: Annotated[
        OperationalMulticastRateLeaf,
        Field(None, alias="srl_nokia-interfaces:operational-multicast-rate"),
    ]
    operational_unknown_unicast_rate: Annotated[
        OperationalUnknownUnicastRateLeaf,
        Field(None, alias="srl_nokia-interfaces:operational-unknown-unicast-rate"),
    ]
    rising_threshold_action: Annotated[
        RisingThresholdActionLeaf,
        Field("none", alias="srl_nokia-interfaces:rising-threshold-action"),
    ]


class StpContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf19,
        Field("enable", alias="srl_nokia-interfaces-bridge-table-stp:admin-state"),
    ]
    port_number: Annotated[
        PortNumberLeaf,
        Field(0, alias="srl_nokia-interfaces-bridge-table-stp:port-number"),
    ]
    priority: Annotated[
        PriorityLeaf3,
        Field(128, alias="srl_nokia-interfaces-bridge-table-stp:priority"),
    ]
    path_cost: Annotated[
        PathCostLeaf, Field(16, alias="srl_nokia-interfaces-bridge-table-stp:path-cost")
    ]
    edge_port: Annotated[
        EdgePortLeaf,
        Field("no", alias="srl_nokia-interfaces-bridge-table-stp:edge-port"),
    ]
    auto_edge: Annotated[
        AutoEdgeLeaf,
        Field("no", alias="srl_nokia-interfaces-bridge-table-stp:auto-edge"),
    ]
    link_type: Annotated[
        LinkTypeLeaf,
        Field("pt-pt", alias="srl_nokia-interfaces-bridge-table-stp:link-type"),
    ]
    root_guard: Annotated[
        RootGuardLeaf,
        Field("no", alias="srl_nokia-interfaces-bridge-table-stp:root-guard"),
    ]
    mst_instance: Annotated[
        List[MstInstanceListEntry],
        Field(alias="srl_nokia-interfaces-bridge-table-stp:mst-instance"),
    ]


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
    )
    admin_state: Annotated[
        AdminStateLeaf3, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    window_size: Annotated[
        WindowSizeLeaf2, Field(10, alias="srl_nokia-interfaces:window-size")
    ]
    signal_degrade: Annotated[
        SignalDegradeContainer2,
        Field(None, alias="srl_nokia-interfaces:signal-degrade"),
    ]
    signal_failure: Annotated[
        SignalFailureContainer2,
        Field(None, alias="srl_nokia-interfaces:signal-failure"),
    ]
    current_alarms: Annotated[
        List[CurrentAlarmsLeafList3],
        Field([], alias="srl_nokia-interfaces:current-alarms"),
    ]
    """
    Current alarms of the Ethernet symbol monitoring, raised when corresponding threshold is exceeded
    """


class SynceContainer(BaseModel):
    """
    This struct containing all attributes for SyncE in line/client ports.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ssm: Annotated[SsmContainer, Field(None, alias="srl_nokia-interfaces:ssm")]


class TraceOptionsContainer(BaseModel):
    """
    Container for tracing DHCPv4 relay operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace: Annotated[
        List[TraceLeafList], Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:trace")
    ]
    """
    List of events to trace
    """


class TraceOptionsContainer2(BaseModel):
    """
    Container for tracing DHCPv4 operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace: Annotated[
        List[TraceLeafList2], Field([], alias="srl_nokia-interfaces-ip-dhcp:trace")
    ]
    """
    List of events to trace
    """


class TraceOptionsContainer3(BaseModel):
    """
    Container for tracing DHCPv6 relay operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace: Annotated[
        List[TraceLeafList3],
        Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:trace"),
    ]
    """
    List of events to trace
    """


class TraceOptionsContainer4(BaseModel):
    """
    Container for tracing DHCPv6 operations on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace: Annotated[
        List[TraceLeafList4], Field([], alias="srl_nokia-interfaces-ip-dhcp:trace")
    ]
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
    )
    interface: Annotated[
        InterfaceLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:interface")
    ]
    priority_decrement: Annotated[
        PriorityDecrementLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:priority-decrement"),
    ]


class TrackInterfaceListEntry2(BaseModel):
    """
    Interface reference for interface tracking.
    VRRP Group can track multiple interfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    interface: Annotated[
        InterfaceLeaf3, Field(None, alias="srl_nokia-interfaces-ip-vrrp:interface")
    ]
    priority_decrement: Annotated[
        PriorityDecrementLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:priority-decrement"),
    ]


class TransceiverContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    functional_type: Annotated[
        FunctionalTypeLeaf, Field(None, alias="srl_nokia-interfaces:functional-type")
    ]
    tx_laser: Annotated[TxLaserLeaf, Field(None, alias="srl_nokia-interfaces:tx-laser")]
    oper_state: Annotated[
        OperStateLeaf2, Field(None, alias="srl_nokia-interfaces:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf2, Field(None, alias="srl_nokia-interfaces:oper-down-reason")
    ]
    ddm_events: Annotated[
        DdmEventsLeaf, Field(None, alias="srl_nokia-interfaces:ddm-events")
    ]
    form_factor: Annotated[
        FormFactorLeaf, Field(None, alias="srl_nokia-interfaces:form-factor")
    ]
    ethernet_pmd: Annotated[
        EthernetPmdLeaf, Field(None, alias="srl_nokia-interfaces:ethernet-pmd")
    ]
    connector_type: Annotated[
        ConnectorTypeLeaf, Field(None, alias="srl_nokia-interfaces:connector-type")
    ]
    vendor: Annotated[VendorLeaf, Field(None, alias="srl_nokia-interfaces:vendor")]
    vendor_part_number: Annotated[
        VendorPartNumberLeaf2,
        Field(None, alias="srl_nokia-interfaces:vendor-part-number"),
    ]
    vendor_revision: Annotated[
        VendorRevisionLeaf, Field(None, alias="srl_nokia-interfaces:vendor-revision")
    ]
    vendor_lot_number: Annotated[
        VendorLotNumberLeaf, Field(None, alias="srl_nokia-interfaces:vendor-lot-number")
    ]
    serial_number: Annotated[
        SerialNumberLeaf, Field(None, alias="srl_nokia-interfaces:serial-number")
    ]
    date_code: Annotated[
        DateCodeLeaf, Field(None, alias="srl_nokia-interfaces:date-code")
    ]
    firmware_version: Annotated[
        FirmwareVersionContainer,
        Field(None, alias="srl_nokia-interfaces:firmware-version"),
    ]
    fault_condition: Annotated[
        FaultConditionLeaf, Field(None, alias="srl_nokia-interfaces:fault-condition")
    ]
    wavelength: Annotated[
        WavelengthLeaf, Field(None, alias="srl_nokia-interfaces:wavelength")
    ]
    temperature: Annotated[
        TemperatureContainer, Field(None, alias="srl_nokia-interfaces:temperature")
    ]
    voltage: Annotated[
        VoltageContainer, Field(None, alias="srl_nokia-interfaces:voltage")
    ]
    channel: Annotated[
        List[ChannelListEntry], Field(alias="srl_nokia-interfaces:channel")
    ]
    healthz: Annotated[
        HealthzContainer, Field(None, alias="srl_nokia-platform-healthz:healthz")
    ]
    optical_channel: Annotated[
        List[OpticalChannelListEntry],
        Field(alias="srl_nokia-interfaces-dco:optical-channel"),
    ]
    supported_operational_mode: Annotated[
        List[SupportedOperationalModeLeafList],
        Field([], alias="srl_nokia-interfaces-dco:supported-operational-mode"),
    ]
    """
    Operational modes supported by the installed transceiver

    Lists the operational-modes supported by the installed transceiver.  If no transceiver is installed, nothing is reported.
    """


class TunnelContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel_all: Annotated[
        TunnelAllLeaf, Field(False, alias="srl_nokia-dot1x:tunnel-all")
    ]
    untagged: Annotated[UntaggedLeaf, Field(False, alias="srl_nokia-dot1x:untagged")]
    single_tagged: Annotated[
        SingleTaggedLeaf, Field(True, alias="srl_nokia-dot1x:single-tagged")
    ]
    double_tagged: Annotated[
        DoubleTaggedLeaf, Field(True, alias="srl_nokia-dot1x:double-tagged")
    ]
    statistics: Annotated[
        StatisticsContainer4, Field(None, alias="srl_nokia-dot1x:statistics")
    ]


class TypeLeaf6(RootModel[VlanDiscoveryAddressTypeType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanDiscoveryAddressTypeType, Field(title="TypeLeaf6")]
    """
    Types of addresses over which vlan discovery is performed
    """


class UnnumberedContainer(BaseModel):
    """
    Top-level container for configuring unnumbered interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf9, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    interface: Annotated[
        InterfaceLeaf2, Field(None, alias="srl_nokia-interfaces:interface")
    ]
    address: Annotated[AddressLeaf, Field(None, alias="srl_nokia-interfaces:address")]
    unavailable_address_reason: Annotated[
        UnavailableAddressReasonLeaf,
        Field(None, alias="srl_nokia-interfaces:unavailable-address-reason"),
    ]


class VirtualAddressLeafList(RootModel[IpAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IpAddressType, Field(title="Virtual-addressLeafList")]
    """
    Associated Virtual IP address.
    """


class VlanDiscoveryContainer(BaseModel):
    """
    When present the subinterface should perform vlan discovery by broadcasting dhcp message on all vlanids
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    type: Annotated[TypeLeaf6, Field("IPv4v6", alias="srl_nokia-interfaces-vlans:type")]


class VlanStackActionLeaf(RootModel[VlanStackActionType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanStackActionType, Field(title="Vlan-stack-actionLeaf")]
    """
    The action to take on the VLAN stack of a packet

    This is optionally used in conjunction with adjacent leaves to override
    the values of the action.
    """


class VlanStackActionLeaf2(RootModel[VlanStackActionType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[VlanStackActionType, Field(title="Vlan-stack-actionLeaf2")]
    """
    The action to take on the VLAN stack of a packet

    This is optionally used in conjunction with adjacent leaves to override
    the values of the action.
    """


class AddressListEntry2(BaseModel):
    """
    The list of virtual IPv4 addresses to be discovered on the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ipv4_address: Annotated[
        Ipv4AddressLeaf2,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:ipv4-address"),
    ]
    allowed_macs: Annotated[
        List[AllowedMacsLeafList],
        Field([], alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:allowed-macs"),
    ]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """
    probe_interval: Annotated[
        ProbeIntervalLeaf,
        Field(0, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-interval"),
    ]
    probe_bridged_subinterfaces: Annotated[
        List[ProbeBridgedSubinterfacesLeafList],
        Field(
            [],
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-bridged-subinterfaces",
        ),
    ]
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the ARP
    probes are sent.
    """
    statistics: Annotated[
        StatisticsContainer7,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics"),
    ]


class AddressListEntry4(BaseModel):
    """
    The list of virtual IPv6 addresses to be discovered on the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ipv6_address: Annotated[
        Ipv6AddressLeaf2,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:ipv6-address"),
    ]
    allowed_macs: Annotated[
        List[AllowedMacsLeafList2],
        Field([], alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:allowed-macs"),
    ]
    """
    List of allowed mac addresses for a discovered virtual IP address.
    """
    probe_interval: Annotated[
        ProbeIntervalLeaf2,
        Field(0, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-interval"),
    ]
    probe_bridged_subinterfaces: Annotated[
        List[ProbeBridgedSubinterfacesLeafList2],
        Field(
            [],
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:probe-bridged-subinterfaces",
        ),
    ]
    """
    Configure the list of bridged sub-interfaces on the associated MAC-VRF to which the NS
    probes are sent.
    """
    statistics: Annotated[
        StatisticsContainer12,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics"),
    ]


class AdvertiseListEntry(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    route_type: Annotated[
        RouteTypeLeaf2, Field(None, alias="srl_nokia-interfaces-nbr-evpn:route-type")
    ]
    internal_tags: Annotated[
        InternalTagsContainer2,
        Field(None, alias="srl_nokia-interfaces-nbr-evpn:internal-tags"),
    ]


class AdvertiseListEntry2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    route_type: Annotated[
        RouteTypeLeaf4, Field(None, alias="srl_nokia-interfaces-nbr-evpn:route-type")
    ]
    internal_tags: Annotated[
        InternalTagsContainer4,
        Field(None, alias="srl_nokia-interfaces-nbr-evpn:internal-tags"),
    ]


class AuthenticatedSessionListEntry(BaseModel):
    """
    The list of authenticated sessions on this device
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[MacLeaf2, Field(None, alias="srl_nokia-dot1x:mac")]
    hosts: Annotated[HostsContainer, Field(None, alias="srl_nokia-dot1x:hosts")]


class AuthenticatedSessionsContainer(BaseModel):
    """
    Top level container for authenticated sessions state data
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    authenticated_session: Annotated[
        List[AuthenticatedSessionListEntry],
        Field(alias="srl_nokia-dot1x:authenticated-session"),
    ]


class AuthenticationContainer(BaseModel):
    """
    Context to configure authentication keychain
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    keychain: Annotated[
        KeychainLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:keychain")
    ]


class AuthenticationContainer2(BaseModel):
    """
    Context to configure authentication keychain
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    keychain: Annotated[
        KeychainLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:keychain")
    ]


class AuthenticatorContainer(BaseModel):
    """
    configure dot1x for an authenticator
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    authenticate_port: Annotated[
        AuthenticatePortLeaf, Field(True, alias="srl_nokia-dot1x:authenticate-port")
    ]
    port_control: Annotated[
        PortControlLeaf, Field("force-authorized", alias="srl_nokia-dot1x:port-control")
    ]
    authenticator_initiated: Annotated[
        AuthenticatorInitiatedLeaf,
        Field(True, alias="srl_nokia-dot1x:authenticator-initiated"),
    ]
    host_mode: Annotated[HostModeLeaf, Field(None, alias="srl_nokia-dot1x:host-mode")]
    reauthenticate_interval: Annotated[
        ReauthenticateIntervalLeaf,
        Field(None, alias="srl_nokia-dot1x:reauthenticate-interval"),
    ]
    retransmit_interval: Annotated[
        RetransmitIntervalLeaf, Field(None, alias="srl_nokia-dot1x:retransmit-interval")
    ]
    quiet_period: Annotated[
        QuietPeriodLeaf, Field(60, alias="srl_nokia-dot1x:quiet-period")
    ]
    supplicant_timeout: Annotated[
        SupplicantTimeoutLeaf, Field(30, alias="srl_nokia-dot1x:supplicant-timeout")
    ]
    max_requests: Annotated[
        MaxRequestsLeaf, Field(2, alias="srl_nokia-dot1x:max-requests")
    ]
    max_authentication_requests: Annotated[
        MaxAuthenticationRequestsLeaf,
        Field(2, alias="srl_nokia-dot1x:max-authentication-requests"),
    ]
    multi_domain_allowed_source_macs: Annotated[
        MultiDomainAllowedSourceMacsContainer,
        Field(None, alias="srl_nokia-dot1x:multi-domain-allowed-source-macs"),
    ]
    radius_policy: Annotated[
        RadiusPolicyLeaf, Field(None, alias="srl_nokia-dot1x:radius-policy")
    ]
    authenticated_sessions: Annotated[
        AuthenticatedSessionsContainer,
        Field(None, alias="srl_nokia-dot1x:authenticated-sessions"),
    ]


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
    )
    admin_state: Annotated[
        AdminStateLeaf2, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    window_size: Annotated[
        WindowSizeLeaf, Field(10, alias="srl_nokia-interfaces:window-size")
    ]
    signal_degrade: Annotated[
        SignalDegradeContainer, Field(None, alias="srl_nokia-interfaces:signal-degrade")
    ]
    signal_failure: Annotated[
        SignalFailureContainer, Field(None, alias="srl_nokia-interfaces:signal-failure")
    ]
    current_alarms: Annotated[
        List[CurrentAlarmsLeafList2],
        Field([], alias="srl_nokia-interfaces:current-alarms"),
    ]
    """
    Current alarms of the Ethernet CRC monitoring, raised when corresponding threshold is exceeded
    """


class CurrentMasterLeaf(RootModel[IpAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IpAddressType, Field(title="Current-masterLeaf")]
    """
    IP address of node currently acting as VRRP master
    """


class CurrentMasterLeaf2(RootModel[IpAddressType]):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    root: Annotated[IpAddressType, Field(title="Current-masterLeaf2")]
    """
    IP address of node currently acting as VRRP master
    """


class DhcpClientContainer(BaseModel):
    """
    Container for options related to DHCP
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace_options: Annotated[
        TraceOptionsContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp:trace-options"),
    ]


class DhcpClientContainer2(BaseModel):
    """
    Container for options related to DHCPv6
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    trace_options: Annotated[
        TraceOptionsContainer4,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp:trace-options"),
    ]


class DhcpServerContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf11,
        Field("disable", alias="srl_nokia-interfaces-ip-dhcp-server:admin-state"),
    ]
    oper_state: Annotated[
        OperStateLeaf7,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-server:oper-state"),
    ]


class Dhcpv6ServerContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf16,
        Field("disable", alias="srl_nokia-interfaces-ip-dhcp-server:admin-state"),
    ]
    oper_state: Annotated[
        OperStateLeaf10,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-server:oper-state"),
    ]


class DnsResolutionContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    server: Annotated[
        List[ServerListEntry], Field(alias="srl_nokia-interfaces-ip-dhcp-relay:server")
    ]


class DnsResolutionContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    server: Annotated[
        List[ServerListEntry2], Field(alias="srl_nokia-interfaces-ip-dhcp-relay:server")
    ]


class Dot1xContainer(BaseModel):
    """
    dot1x configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel: Annotated[TunnelContainer, Field(None, alias="srl_nokia-dot1x:tunnel")]
    authenticator: Annotated[
        AuthenticatorContainer, Field(None, alias="srl_nokia-dot1x:authenticator")
    ]


class EgressMappingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    vlan_stack_action: Annotated[
        VlanStackActionLeaf2,
        Field(None, alias="srl_nokia-interfaces-vlans:vlan-stack-action"),
    ]
    outer_vlan_id: Annotated[
        OuterVlanIdLeaf3, Field(None, alias="srl_nokia-interfaces-vlans:outer-vlan-id")
    ]
    outer_tpid: Annotated[
        OuterTpidLeaf2, Field(None, alias="srl_nokia-interfaces-vlans:outer-tpid")
    ]
    inner_vlan_id: Annotated[
        InnerVlanIdLeaf3, Field(None, alias="srl_nokia-interfaces-vlans:inner-vlan-id")
    ]
    inner_tpid: Annotated[
        InnerTpidLeaf2, Field(None, alias="srl_nokia-interfaces-vlans:inner-tpid")
    ]


class EncapContainer(BaseModel):
    """
    VLAN match parmeters for the associated subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    single_tagged: Annotated[
        SingleTaggedContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:single-tagged"),
    ]
    untagged: Annotated[
        UntaggedContainer, Field(None, alias="srl_nokia-interfaces-vlans:untagged")
    ]
    single_tagged_range: Annotated[
        SingleTaggedRangeContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:single-tagged-range"),
    ]
    double_tagged: Annotated[
        DoubleTaggedContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:double-tagged"),
    ]


class EthCfmContainer(BaseModel):
    """
    Configuration of ETH-CFM functions independent of Maintenance Domain context

    This is an ETH-CFM function that is configured directly under the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ingress_squelching: Annotated[
        IngressSquelchingContainer,
        Field(None, alias="srl_nokia-ethcfm:ingress-squelching"),
    ]


class EvpnContainer(BaseModel):
    """
    Configure which types of ARP or ND entries will be advertised in EVPN MAC/IP routes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    advertise: Annotated[
        List[AdvertiseListEntry], Field(alias="srl_nokia-interfaces-nbr-evpn:advertise")
    ]


class EvpnContainer2(BaseModel):
    """
    Configure which types of ARP or ND entries will be advertised in EVPN MAC/IP routes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    advertise: Annotated[
        List[AdvertiseListEntry2],
        Field(alias="srl_nokia-interfaces-nbr-evpn:advertise"),
    ]


class HostRouteContainer(BaseModel):
    """
    Configure which types of ARP or ND entries will be populated in the route-table.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    populate: Annotated[
        List[PopulateListEntry], Field(alias="srl_nokia-interfaces-nbr:populate")
    ]


class HostRouteContainer2(BaseModel):
    """
    Configure which types of ARP or ND entries will be populated in the route-table.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    populate: Annotated[
        List[PopulateListEntry2], Field(alias="srl_nokia-interfaces-nbr:populate")
    ]


class IngressMappingContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    vlan_stack_action: Annotated[
        VlanStackActionLeaf,
        Field(None, alias="srl_nokia-interfaces-vlans:vlan-stack-action"),
    ]
    outer_vlan_id: Annotated[
        OuterVlanIdLeaf2, Field(None, alias="srl_nokia-interfaces-vlans:outer-vlan-id")
    ]
    outer_tpid: Annotated[
        OuterTpidLeaf, Field(None, alias="srl_nokia-interfaces-vlans:outer-tpid")
    ]
    inner_vlan_id: Annotated[
        InnerVlanIdLeaf2, Field(None, alias="srl_nokia-interfaces-vlans:inner-vlan-id")
    ]
    inner_tpid: Annotated[
        InnerTpidLeaf, Field(None, alias="srl_nokia-interfaces-vlans:inner-tpid")
    ]


class InterfaceTrackingContainer(BaseModel):
    """
    Interface reference for interface tracking
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    track_interface: Annotated[
        List[TrackInterfaceListEntry],
        Field(alias="srl_nokia-interfaces-ip-vrrp:track-interface"),
    ]


class InterfaceTrackingContainer2(BaseModel):
    """
    Interface reference for interface tracking
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    track_interface: Annotated[
        List[TrackInterfaceListEntry2],
        Field(alias="srl_nokia-interfaces-ip-vrrp:track-interface"),
    ]


class L2cpTransparencyContainer(BaseModel):
    """
    Configuration and state of the Layer-2 Control Protocol transparency
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    tunnel_all_l2cp: Annotated[
        TunnelAllL2cpLeaf,
        Field(False, alias="srl_nokia-interfaces-l2cp:tunnel-all-l2cp"),
    ]
    lldp: Annotated[LldpContainer, Field(None, alias="srl_nokia-interfaces-l2cp:lldp")]
    lacp: Annotated[LacpContainer, Field(None, alias="srl_nokia-interfaces-l2cp:lacp")]
    xstp: Annotated[XstpContainer, Field(None, alias="srl_nokia-interfaces-l2cp:xstp")]
    dot1x: Annotated[
        Dot1xContainer2, Field(None, alias="srl_nokia-interfaces-l2cp:dot1x")
    ]
    ptp: Annotated[PtpContainer, Field(None, alias="srl_nokia-interfaces-l2cp:ptp")]
    esmc: Annotated[EsmcContainer, Field(None, alias="srl_nokia-interfaces-l2cp:esmc")]
    elmi: Annotated[ElmiContainer, Field(None, alias="srl_nokia-interfaces-l2cp:elmi")]
    efm_oam: Annotated[
        EfmOamContainer, Field(None, alias="srl_nokia-interfaces-l2cp:efm-oam")
    ]


class LocalMirrorDestinationContainer(BaseModel):
    """
    Container for options related to local mirror destination
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf20,
        Field(
            "enable", alias="srl_nokia-interfaces-local-mirror-destination:admin-state"
        ),
    ]
    oper_state: Annotated[
        OperStateLeaf11,
        Field(None, alias="srl_nokia-interfaces-local-mirror-destination:oper-state"),
    ]


class MacTableContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    mac: Annotated[
        List[MacListEntry3],
        Field(alias="srl_nokia-interfaces-bridge-table-mac-table:mac"),
    ]


class MemberListEntry(BaseModel):
    """
    Reports the list of interfaces associated with the LAG instance
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    name: Annotated[NameLeaf8, Field(None, alias="srl_nokia-interfaces-lag:name")]
    oper_state: Annotated[
        OperStateLeaf13, Field(None, alias="srl_nokia-interfaces-lag:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf8,
        Field(None, alias="srl_nokia-interfaces-lag:oper-down-reason"),
    ]
    microbfd_enabled: Annotated[
        MicrobfdEnabledLeaf,
        Field(None, alias="srl_nokia-interfaces-lag:microbfd-enabled"),
    ]
    last_change: Annotated[
        LastChangeLeaf3, Field(None, alias="srl_nokia-interfaces-lag:last-change")
    ]
    lacp: Annotated[LacpContainer2, Field(None, alias="srl_nokia-lacp:lacp")]


class PacketLinkQualificationContainer(BaseModel):
    """
    gNOI Packet Link Qualification results
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    result: Annotated[
        List[ResultListEntry], Field(alias="srl_nokia-packet-link-qual:result")
    ]


class RouterAdvertisementContainer(BaseModel):
    """
    Container for configuring IPv6 router discovery options
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    router_role: Annotated[
        RouterRoleContainer,
        Field(None, alias="srl_nokia-interfaces-router-adv:router-role"),
    ]
    debug: Annotated[
        List[DebugLeafList3], Field([], alias="srl_nokia-interfaces-router-adv:debug")
    ]
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
    )
    address: Annotated[
        List[AddressListEntry2],
        Field(alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:address"),
    ]
    statistics: Annotated[
        StatisticsContainer8,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics"),
    ]


class VirtualIpv6DiscoveryContainer(BaseModel):
    """
    Enable Virtual IPv6 discovery on the subinterface and configure associated parameters

    When enabled, the system will attempt to discover the configured virtual IPv6
    addresses on the listed bridged subinterfaces.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    address: Annotated[
        List[AddressListEntry4],
        Field(alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:address"),
    ]
    statistics: Annotated[
        StatisticsContainer13,
        Field(None, alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:statistics"),
    ]


class VlanContainer(BaseModel):
    """
    Parameters for VLAN definition under SRL interfaces
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vlan_discovery: Annotated[
        VlanDiscoveryContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:vlan-discovery"),
    ]
    encap: Annotated[
        EncapContainer, Field(None, alias="srl_nokia-interfaces-vlans:encap")
    ]
    ingress_mapping: Annotated[
        IngressMappingContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:ingress-mapping"),
    ]
    egress_mapping: Annotated[
        EgressMappingContainer,
        Field(None, alias="srl_nokia-interfaces-vlans:egress-mapping"),
    ]


class VrrpGroupListEntry(BaseModel):
    """
    VRRP Group Specific Configuration under IPv4 context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    virtual_router_id: Annotated[
        VirtualRouterIdLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:virtual-router-id"),
    ]
    admin_state: Annotated[
        AdminStateLeaf8,
        Field("enable", alias="srl_nokia-interfaces-ip-vrrp:admin-state"),
    ]
    priority: Annotated[
        PriorityLeaf, Field(100, alias="srl_nokia-interfaces-ip-vrrp:priority")
    ]
    preempt: Annotated[
        PreemptLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:preempt")
    ]
    virtual_mac: Annotated[
        VirtualMacLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:virtual-mac")
    ]
    preempt_delay: Annotated[
        PreemptDelayLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:preempt-delay"),
    ]
    init_delay: Annotated[
        InitDelayLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:init-delay")
    ]
    accept_mode: Annotated[
        AcceptModeLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:accept-mode")
    ]
    advertise_interval: Annotated[
        AdvertiseIntervalLeaf,
        Field(1000, alias="srl_nokia-interfaces-ip-vrrp:advertise-interval"),
    ]
    authentication: Annotated[
        AuthenticationContainer,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:authentication"),
    ]
    interface_tracking: Annotated[
        InterfaceTrackingContainer,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:interface-tracking"),
    ]
    state: Annotated[StateLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:state")]
    oper_state: Annotated[
        OperStateLeaf5, Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf4,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-down-reason"),
    ]
    owner: Annotated[OwnerLeaf, Field(None, alias="srl_nokia-interfaces-ip-vrrp:owner")]
    operational_priority: Annotated[
        OperationalPriorityLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:operational-priority"),
    ]
    master_inherit_interval: Annotated[
        MasterInheritIntervalLeaf,
        Field(False, alias="srl_nokia-interfaces-ip-vrrp:master-inherit-interval"),
    ]
    oper_interval: Annotated[
        OperIntervalLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-interval"),
    ]
    current_master: Annotated[
        CurrentMasterLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:current-master"),
    ]
    last_transition: Annotated[
        LastTransitionLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:last-transition"),
    ]
    statistics: Annotated[
        StatisticsContainer5,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:statistics"),
    ]
    virtual_address: Annotated[
        List[VirtualAddressLeafList],
        Field([], alias="srl_nokia-interfaces-ip-vrrp:virtual-address"),
    ]
    """
    Associated Virtual IP address.
    """
    version: Annotated[
        VersionLeaf, Field(2, alias="srl_nokia-interfaces-ip-vrrp:version")
    ]


class VrrpGroupListEntry2(BaseModel):
    """
    VRRP Group Specific Configuration under IPv6 context
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    virtual_router_id: Annotated[
        VirtualRouterIdLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:virtual-router-id"),
    ]
    admin_state: Annotated[
        AdminStateLeaf13,
        Field("enable", alias="srl_nokia-interfaces-ip-vrrp:admin-state"),
    ]
    priority: Annotated[
        PriorityLeaf2, Field(100, alias="srl_nokia-interfaces-ip-vrrp:priority")
    ]
    preempt: Annotated[
        PreemptLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:preempt")
    ]
    virtual_mac: Annotated[
        VirtualMacLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:virtual-mac")
    ]
    preempt_delay: Annotated[
        PreemptDelayLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:preempt-delay"),
    ]
    init_delay: Annotated[
        InitDelayLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:init-delay")
    ]
    accept_mode: Annotated[
        AcceptModeLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:accept-mode")
    ]
    advertise_interval: Annotated[
        AdvertiseIntervalLeaf2,
        Field(1000, alias="srl_nokia-interfaces-ip-vrrp:advertise-interval"),
    ]
    authentication: Annotated[
        AuthenticationContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:authentication"),
    ]
    interface_tracking: Annotated[
        InterfaceTrackingContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:interface-tracking"),
    ]
    state: Annotated[
        StateLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:state")
    ]
    oper_state: Annotated[
        OperStateLeaf8, Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf6,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-down-reason"),
    ]
    owner: Annotated[
        OwnerLeaf2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:owner")
    ]
    operational_priority: Annotated[
        OperationalPriorityLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:operational-priority"),
    ]
    master_inherit_interval: Annotated[
        MasterInheritIntervalLeaf2,
        Field(False, alias="srl_nokia-interfaces-ip-vrrp:master-inherit-interval"),
    ]
    oper_interval: Annotated[
        OperIntervalLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:oper-interval"),
    ]
    current_master: Annotated[
        CurrentMasterLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:current-master"),
    ]
    last_transition: Annotated[
        LastTransitionLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:last-transition"),
    ]
    statistics: Annotated[
        StatisticsContainer10,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:statistics"),
    ]
    virtual_address: Annotated[
        List[VirtualAddressLeafList2],
        Field([], alias="srl_nokia-interfaces-ip-vrrp:virtual-address"),
    ]
    """
    Associated Virtual IP address.
    """
    version: Annotated[
        VersionLeaf2, Field(3, alias="srl_nokia-interfaces-ip-vrrp:version")
    ]
    virtual_link_local_address: Annotated[
        VirtualLinkLocalAddressLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-vrrp:virtual-link-local-address"),
    ]


class VrrpContainer(BaseModel):
    """
    VRRP Configuration and State under a IPv4 context of a
    sub-interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vrrp_group: Annotated[
        List[VrrpGroupListEntry], Field(alias="srl_nokia-interfaces-ip-vrrp:vrrp-group")
    ]


class VrrpContainer2(BaseModel):
    """
    VRRP Configuration and State under a IPv6 context of a
    sub-interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    vrrp_group: Annotated[
        List[VrrpGroupListEntry2],
        Field(alias="srl_nokia-interfaces-ip-vrrp:vrrp-group"),
    ]


class AddressListEntry(BaseModel):
    """
    The list of  IPv4 addresses assigned to the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ip_prefix: Annotated[
        IpPrefixLeaf, Field(None, alias="srl_nokia-interfaces:ip-prefix")
    ]
    anycast_gw: Annotated[
        AnycastGwLeaf, Field(None, alias="srl_nokia-interfaces:anycast-gw")
    ]
    origin: Annotated[OriginLeaf, Field(None, alias="srl_nokia-interfaces:origin")]
    primary: Annotated[PrimaryLeaf, Field(None, alias="srl_nokia-interfaces:primary")]
    status: Annotated[StatusLeaf3, Field(None, alias="srl_nokia-interfaces:status")]
    vrrp: Annotated[
        VrrpContainer, Field(None, alias="srl_nokia-interfaces-ip-vrrp:vrrp")
    ]


class AddressListEntry3(BaseModel):
    """
    The list of IPv6 addresses assigned to the subinterface.
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    ip_prefix: Annotated[
        IpPrefixLeaf2, Field(None, alias="srl_nokia-interfaces:ip-prefix")
    ]
    type: Annotated[
        TypeLeaf3, Field("global-unicast", alias="srl_nokia-interfaces:type")
    ]
    anycast_gw: Annotated[
        AnycastGwLeaf2, Field(None, alias="srl_nokia-interfaces:anycast-gw")
    ]
    origin: Annotated[OriginLeaf3, Field(None, alias="srl_nokia-interfaces:origin")]
    primary: Annotated[PrimaryLeaf2, Field(None, alias="srl_nokia-interfaces:primary")]
    status: Annotated[StatusLeaf5, Field(None, alias="srl_nokia-interfaces:status")]
    vrrp: Annotated[
        VrrpContainer2, Field(None, alias="srl_nokia-interfaces-ip-vrrp:vrrp")
    ]


class ArpContainer(BaseModel):
    """
    Container for the IPv4 ARP protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    duplicate_address_detection: Annotated[
        DuplicateAddressDetectionLeaf,
        Field(True, alias="srl_nokia-interfaces-nbr:duplicate-address-detection"),
    ]
    timeout: Annotated[
        TimeoutLeaf, Field(14400, alias="srl_nokia-interfaces-nbr:timeout")
    ]
    learn_unsolicited: Annotated[
        LearnUnsolicitedLeaf,
        Field(False, alias="srl_nokia-interfaces-nbr:learn-unsolicited"),
    ]
    neighbor: Annotated[
        List[NeighborListEntry], Field(alias="srl_nokia-interfaces-nbr:neighbor")
    ]
    host_route: Annotated[
        HostRouteContainer, Field(None, alias="srl_nokia-interfaces-nbr:host-route")
    ]
    proxy_arp: Annotated[
        ProxyArpLeaf, Field(False, alias="srl_nokia-interfaces-nbr:proxy-arp")
    ]
    debug: Annotated[
        List[DebugLeafList], Field([], alias="srl_nokia-interfaces-nbr:debug")
    ]
    """
    List of events to debug
    """
    evpn: Annotated[
        EvpnContainer, Field(None, alias="srl_nokia-interfaces-nbr-evpn:evpn")
    ]
    virtual_ipv4_discovery: Annotated[
        VirtualIpv4DiscoveryContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:virtual-ipv4-discovery",
        ),
    ]


class BridgeTableContainer(BaseModel):
    """
    Enable the Bridge Table on the subinterface and configure associated parameters
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    discard_unknown_src_mac: Annotated[
        DiscardUnknownSrcMacLeaf,
        Field(False, alias="srl_nokia-interfaces:discard-unknown-src-mac"),
    ]
    mac_limit: Annotated[
        MacLimitContainer, Field(None, alias="srl_nokia-interfaces:mac-limit")
    ]
    mac_learning: Annotated[
        MacLearningContainer, Field(None, alias="srl_nokia-interfaces:mac-learning")
    ]
    mac_duplication: Annotated[
        MacDuplicationContainer,
        Field(None, alias="srl_nokia-interfaces:mac-duplication"),
    ]
    stp: Annotated[
        StpContainer, Field(None, alias="srl_nokia-interfaces-bridge-table-stp:stp")
    ]
    statistics: Annotated[
        StatisticsContainer16,
        Field(None, alias="srl_nokia-interfaces-bridge-table-statistics:statistics"),
    ]
    mac_table: Annotated[
        MacTableContainer,
        Field(None, alias="srl_nokia-interfaces-bridge-table-mac-table:mac-table"),
    ]


class DhcpRelayContainer(BaseModel):
    """
    Container for options related to DHCPv4 relay
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf10,
        Field("enable", alias="srl_nokia-interfaces-ip-dhcp-relay:admin-state"),
    ]
    oper_state: Annotated[
        OperStateLeaf6,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:oper-state"),
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf5,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:oper-down-reason"),
    ]
    option: Annotated[
        List[OptionLeafList],
        Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:option"),
    ]
    """
    List of option82 suboptions to insert into relayed packet towards DHCPv4 server
    """
    server: Annotated[
        List[ServerLeafList],
        Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:server"),
    ]
    """
    List of the DHCPv4 servers that the DHCPv4 relay function will relay DHCPv4 packets to/from
    """
    gi_address: Annotated[
        GiAddressLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:gi-address"),
    ]
    """
    IPv4 address to be used as giaddr of the relayed packets towards DHCPv4 servers.
     This address can be any IPv4 address configured within the network-instance towards the DHCPv4 server
    """
    use_gi_addr_as_src_ip_addr: Annotated[
        UseGiAddrAsSrcIpAddrLeaf,
        Field(
            False, alias="srl_nokia-interfaces-ip-dhcp-relay:use-gi-addr-as-src-ip-addr"
        ),
    ]
    network_instance: Annotated[
        NetworkInstanceLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:network-instance"),
    ]
    trace_options: Annotated[
        TraceOptionsContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:trace-options"),
    ]
    dns_resolution: Annotated[
        DnsResolutionContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:dns-resolution"),
    ]
    statistics: Annotated[
        StatisticsContainer9,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:statistics"),
    ]


class DhcpRelayContainer2(BaseModel):
    """
    Container for options related to DHCPv6 relay
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf14,
        Field("enable", alias="srl_nokia-interfaces-ip-dhcp-relay:admin-state"),
    ]
    oper_state: Annotated[
        OperStateLeaf9,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:oper-state"),
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf7,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:oper-down-reason"),
    ]
    option: Annotated[
        List[OptionLeafList2],
        Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:option"),
    ]
    """
    List of options to insert into relayed packet towards DHCPv6 server
    """
    server: Annotated[
        List[ServerLeafList2],
        Field([], alias="srl_nokia-interfaces-ip-dhcp-relay:server"),
    ]
    """
    List of the DHCPv6 servers that the DHCPv6 relay function will relay DHCPv6 packets to/from
    """
    source_address: Annotated[
        SourceAddressLeaf,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:source-address"),
    ]
    """
    Source IPv6 address of the relayed packets towards DHCPv6 servers
     this address can be any IPv6 address configured within the network-instance towards the DHCPv6 server
    """
    network_instance: Annotated[
        NetworkInstanceLeaf2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:network-instance"),
    ]
    trace_options: Annotated[
        TraceOptionsContainer3,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:trace-options"),
    ]
    dns_resolution: Annotated[
        DnsResolutionContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:dns-resolution"),
    ]
    statistics: Annotated[
        StatisticsContainer14,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:statistics"),
    ]


class EthernetContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
    )
    aggregate_id: Annotated[
        AggregateIdLeaf, Field(None, alias="srl_nokia-interfaces:aggregate-id")
    ]
    forwarding_viable: Annotated[
        ForwardingViableLeaf,
        Field(None, alias="srl_nokia-interfaces:forwarding-viable"),
    ]
    auto_negotiate: Annotated[
        AutoNegotiateLeaf, Field(None, alias="srl_nokia-interfaces:auto-negotiate")
    ]
    duplex_mode: Annotated[
        DuplexModeLeaf, Field(None, alias="srl_nokia-interfaces:duplex-mode")
    ]
    dac_link_training: Annotated[
        DacLinkTrainingLeaf, Field(None, alias="srl_nokia-interfaces:dac-link-training")
    ]
    flow_control: Annotated[
        FlowControlContainer, Field(None, alias="srl_nokia-interfaces:flow-control")
    ]
    lacp_port_priority: Annotated[
        LacpPortPriorityLeaf,
        Field(None, alias="srl_nokia-interfaces:lacp-port-priority"),
    ]
    port_speed: Annotated[
        PortSpeedLeaf, Field(None, alias="srl_nokia-interfaces:port-speed")
    ]
    hw_mac_address: Annotated[
        HwMacAddressLeaf, Field(None, alias="srl_nokia-interfaces:hw-mac-address")
    ]
    mac_address: Annotated[
        MacAddressLeaf, Field(None, alias="srl_nokia-interfaces:mac-address")
    ]
    physical_medium: Annotated[
        PhysicalMediumLeaf, Field(None, alias="srl_nokia-interfaces:physical-medium")
    ]
    ptp_asymmetry: Annotated[
        PtpAsymmetryLeaf, Field(0, alias="srl_nokia-interfaces:ptp-asymmetry")
    ]
    ptp_timestamping: Annotated[
        PtpTimestampingContainer,
        Field(None, alias="srl_nokia-interfaces:ptp-timestamping"),
    ]
    standby_signaling: Annotated[
        StandbySignalingLeaf,
        Field(None, alias="srl_nokia-interfaces:standby-signaling"),
    ]
    link_loss_forwarding: Annotated[
        LinkLossForwardingLeaf,
        Field(None, alias="srl_nokia-interfaces:link-loss-forwarding"),
    ]
    reload_delay: Annotated[
        ReloadDelayLeaf, Field(None, alias="srl_nokia-interfaces:reload-delay")
    ]
    reload_delay_expires: Annotated[
        ReloadDelayExpiresLeaf,
        Field(None, alias="srl_nokia-interfaces:reload-delay-expires"),
    ]
    hold_time: Annotated[
        HoldTimeContainer, Field(None, alias="srl_nokia-interfaces:hold-time")
    ]
    crc_monitor: Annotated[
        CrcMonitorContainer, Field(None, alias="srl_nokia-interfaces:crc-monitor")
    ]
    symbol_monitor: Annotated[
        SymbolMonitorContainer, Field(None, alias="srl_nokia-interfaces:symbol-monitor")
    ]
    exponential_port_dampening: Annotated[
        ExponentialPortDampeningContainer,
        Field(None, alias="srl_nokia-interfaces:exponential-port-dampening"),
    ]
    storm_control: Annotated[
        StormControlContainer, Field(None, alias="srl_nokia-interfaces:storm-control")
    ]
    synce: Annotated[SynceContainer, Field(None, alias="srl_nokia-interfaces:synce")]
    statistics: Annotated[
        StatisticsContainer3, Field(None, alias="srl_nokia-interfaces:statistics")
    ]
    dot1x: Annotated[Dot1xContainer, Field(None, alias="srl_nokia-dot1x:dot1x")]
    l2cp_transparency: Annotated[
        L2cpTransparencyContainer,
        Field(None, alias="srl_nokia-interfaces-l2cp:l2cp-transparency"),
    ]


class Ipv4Container(BaseModel):
    """
    IPv4 configuration and state for the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf7, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    address: Annotated[
        List[AddressListEntry], Field(alias="srl_nokia-interfaces:address")
    ]
    allow_directed_broadcast: Annotated[
        AllowDirectedBroadcastLeaf,
        Field(False, alias="srl_nokia-interfaces:allow-directed-broadcast"),
    ]
    unnumbered: Annotated[
        UnnumberedContainer, Field(None, alias="srl_nokia-interfaces:unnumbered")
    ]
    statistics: Annotated[
        StatisticsContainer6, Field(None, alias="srl_nokia-interfaces:statistics")
    ]
    arp: Annotated[ArpContainer, Field(None, alias="srl_nokia-interfaces-nbr:arp")]
    dhcp_relay: Annotated[
        DhcpRelayContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:dhcp-relay"),
    ]
    dhcp_client: Annotated[
        DhcpClientContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp:dhcp-client"),
    ]
    dhcp_server: Annotated[
        DhcpServerContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-server:dhcp-server"),
    ]


class LagContainer(BaseModel):
    """
    Container for options related to LAG
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    lag_type: Annotated[
        LagTypeLeaf, Field("static", alias="srl_nokia-interfaces-lag:lag-type")
    ]
    min_links: Annotated[
        MinLinksLeaf, Field(1, alias="srl_nokia-interfaces-lag:min-links")
    ]
    member_speed: Annotated[
        MemberSpeedLeaf, Field(None, alias="srl_nokia-interfaces-lag:member-speed")
    ]
    lacp_fallback_mode: Annotated[
        LacpFallbackModeLeaf,
        Field(None, alias="srl_nokia-interfaces-lag:lacp-fallback-mode"),
    ]
    lacp_fallback_timeout: Annotated[
        LacpFallbackTimeoutLeaf,
        Field(None, alias="srl_nokia-interfaces-lag:lacp-fallback-timeout"),
    ]
    lag_speed: Annotated[
        LagSpeedLeaf, Field(None, alias="srl_nokia-interfaces-lag:lag-speed")
    ]
    member: Annotated[
        List[MemberListEntry], Field(alias="srl_nokia-interfaces-lag:member")
    ]
    lacp: Annotated[LacpContainer3, Field(None, alias="srl_nokia-lacp:lacp")]


class NeighborDiscoveryContainer(BaseModel):
    """
    Container for the IPv6 Neighbor Discovery protocol
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    duplicate_address_detection: Annotated[
        DuplicateAddressDetectionLeaf2,
        Field(True, alias="srl_nokia-interfaces-nbr:duplicate-address-detection"),
    ]
    reachable_time: Annotated[
        ReachableTimeLeaf, Field(30, alias="srl_nokia-interfaces-nbr:reachable-time")
    ]
    stale_time: Annotated[
        StaleTimeLeaf, Field(14400, alias="srl_nokia-interfaces-nbr:stale-time")
    ]
    learn_unsolicited: Annotated[
        LearnUnsolicitedLeaf2,
        Field("none", alias="srl_nokia-interfaces-nbr:learn-unsolicited"),
    ]
    neighbor: Annotated[
        List[NeighborListEntry2], Field(alias="srl_nokia-interfaces-nbr:neighbor")
    ]
    host_route: Annotated[
        HostRouteContainer2, Field(None, alias="srl_nokia-interfaces-nbr:host-route")
    ]
    limit: Annotated[
        LimitContainer, Field(None, alias="srl_nokia-interfaces-nbr:limit")
    ]
    proxy_nd: Annotated[
        ProxyNdLeaf, Field(False, alias="srl_nokia-interfaces-nbr:proxy-nd")
    ]
    debug: Annotated[
        List[DebugLeafList2], Field([], alias="srl_nokia-interfaces-nbr:debug")
    ]
    """
    List of events to debug
    """
    evpn: Annotated[
        EvpnContainer2, Field(None, alias="srl_nokia-interfaces-nbr-evpn:evpn")
    ]
    virtual_ipv6_discovery: Annotated[
        VirtualIpv6DiscoveryContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-nbr-virtual-ip-discovery:virtual-ipv6-discovery",
        ),
    ]


class Ipv6Container(BaseModel):
    """
    IPv6 configuration and state for the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    admin_state: Annotated[
        AdminStateLeaf12, Field("disable", alias="srl_nokia-interfaces:admin-state")
    ]
    """
    Enable/disable IPv6 on the subinterface

    When set to enable, and even before a global unicast IPv6 address is configured, chassis manager assigns an IPv6 link-local address to the subinterface, which will appear as a read-only entry in the address list. At this stage, the subinterface can receive IPv6 packets with any of the following destinations:
    -	IPv6 link-local address
    -	solicited-node multicast address for the link-local address
    -	ff02::1 (all IPv6 devices)
    -	ff02::2 (all IPv6 routers)
    """
    address: Annotated[
        List[AddressListEntry3], Field(alias="srl_nokia-interfaces:address")
    ]
    statistics: Annotated[
        StatisticsContainer11, Field(None, alias="srl_nokia-interfaces:statistics")
    ]
    neighbor_discovery: Annotated[
        NeighborDiscoveryContainer,
        Field(None, alias="srl_nokia-interfaces-nbr:neighbor-discovery"),
    ]
    dhcp_relay: Annotated[
        DhcpRelayContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-relay:dhcp-relay"),
    ]
    router_advertisement: Annotated[
        RouterAdvertisementContainer,
        Field(None, alias="srl_nokia-interfaces-router-adv:router-advertisement"),
    ]
    dhcp_client: Annotated[
        DhcpClientContainer2,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp:dhcp-client"),
    ]
    dhcpv6_server: Annotated[
        Dhcpv6ServerContainer,
        Field(None, alias="srl_nokia-interfaces-ip-dhcp-server:dhcpv6-server"),
    ]


class SubinterfaceListEntry(BaseModel):
    """
    The list of subinterfaces (logical interfaces) associated with a physical interface
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    index: Annotated[IndexLeaf4, Field(None, alias="srl_nokia-interfaces:index")]
    type: Annotated[TypeLeaf2, Field(None, alias="srl_nokia-interfaces:type")]
    description: Annotated[
        DescriptionLeaf2, Field(None, alias="srl_nokia-interfaces:description")
    ]
    admin_state: Annotated[
        AdminStateLeaf6, Field("enable", alias="srl_nokia-interfaces:admin-state")
    ]
    ip_mtu: Annotated[IpMtuLeaf, Field(None, alias="srl_nokia-interfaces:ip-mtu")]
    l2_mtu: Annotated[L2MtuLeaf, Field(None, alias="srl_nokia-interfaces:l2-mtu")]
    mpls_mtu: Annotated[MplsMtuLeaf, Field(None, alias="srl_nokia-interfaces:mpls-mtu")]
    unidirectional_link_delay: Annotated[
        UnidirectionalLinkDelayContainer,
        Field(None, alias="srl_nokia-interfaces:unidirectional-link-delay"),
    ]
    name: Annotated[NameLeaf3, Field(None, alias="srl_nokia-interfaces:name")]
    ifindex: Annotated[IfindexLeaf2, Field(None, alias="srl_nokia-interfaces:ifindex")]
    oper_state: Annotated[
        OperStateLeaf4, Field(None, alias="srl_nokia-interfaces:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf3, Field(None, alias="srl_nokia-interfaces:oper-down-reason")
    ]
    last_change: Annotated[
        LastChangeLeaf2, Field(None, alias="srl_nokia-interfaces:last-change")
    ]
    collect_irb_stats: Annotated[
        CollectIrbStatsLeaf, Field(None, alias="srl_nokia-interfaces:collect-irb-stats")
    ]
    collect_detailed_stats: Annotated[
        CollectDetailedStatsLeaf,
        Field(None, alias="srl_nokia-interfaces:collect-detailed-stats"),
    ]
    ipv4: Annotated[Ipv4Container, Field(None, alias="srl_nokia-interfaces:ipv4")]
    ipv6: Annotated[Ipv6Container, Field(None, alias="srl_nokia-interfaces:ipv6")]
    anycast_gw: Annotated[
        AnycastGwContainer, Field(None, alias="srl_nokia-interfaces:anycast-gw")
    ]
    statistics: Annotated[
        StatisticsContainer15, Field(None, alias="srl_nokia-interfaces:statistics")
    ]
    bridge_table: Annotated[
        BridgeTableContainer, Field(None, alias="srl_nokia-interfaces:bridge-table")
    ]
    eth_cfm: Annotated[EthCfmContainer, Field(None, alias="srl_nokia-ethcfm:eth-cfm")]
    vlan: Annotated[VlanContainer, Field(None, alias="srl_nokia-interfaces-vlans:vlan")]
    ra_guard: Annotated[
        RaGuardContainer, Field(None, alias="srl_nokia-ra_guard:ra-guard")
    ]
    local_mirror_destination: Annotated[
        LocalMirrorDestinationContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-local-mirror-destination:local-mirror-destination",
        ),
    ]
    mpls: Annotated[MplsContainer, Field(None, alias="srl_nokia-if-mpls:mpls")]
    uuid: Annotated[UuidLeaf, Field(None, alias="srl_nokia-interfaces-vxdp:uuid")]
    ethernet_segment_association: Annotated[
        EthernetSegmentAssociationContainer,
        Field(
            None,
            alias="srl_nokia-interfaces-ethernet-segment-association:ethernet-segment-association",
        ),
    ]


class InterfaceListEntry(BaseModel):
    """
    The list of named interfaces on the device
    """

    model_config = ConfigDict(
        populate_by_name=True,
    )
    name: Annotated[NameLeaf, Field(None, alias="srl_nokia-interfaces:name")]
    description: Annotated[
        Optional[DescriptionLeaf], Field(None, alias="srl_nokia-interfaces:description")
    ] = None
    admin_state: Annotated[
        AdminStateLeaf, Field("enable", alias="srl_nokia-interfaces:admin-state")
    ]
    num_physical_channels: Annotated[
        NumPhysicalChannelsLeaf,
        Field(None, alias="srl_nokia-interfaces:num-physical-channels"),
    ]
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
        BreakoutModeContainer, Field(None, alias="srl_nokia-interfaces:breakout-mode")
    ]
    mtu: Annotated[MtuLeaf, Field(None, alias="srl_nokia-interfaces:mtu")]
    ifindex: Annotated[IfindexLeaf, Field(None, alias="srl_nokia-interfaces:ifindex")]
    oper_state: Annotated[
        OperStateLeaf, Field(None, alias="srl_nokia-interfaces:oper-state")
    ]
    oper_down_reason: Annotated[
        OperDownReasonLeaf, Field(None, alias="srl_nokia-interfaces:oper-down-reason")
    ]
    last_change: Annotated[
        LastChangeLeaf, Field(None, alias="srl_nokia-interfaces:last-change")
    ]
    linecard: Annotated[
        LinecardLeaf, Field(None, alias="srl_nokia-interfaces:linecard")
    ]
    forwarding_complex: Annotated[
        ForwardingComplexLeaf,
        Field(None, alias="srl_nokia-interfaces:forwarding-complex"),
    ]
    phy_group_members: Annotated[
        List[PhyGroupMembersLeafList],
        Field([], alias="srl_nokia-interfaces:phy-group-members"),
    ]
    """
    The group of interfaces sharing a phy with this interface

    On the 7220 IXR-D2 and 7220 IXR-D2L platforms this group of interfaces must be set to the same speed, either 1/10G or 25G.
    """
    physical_channel: Annotated[
        List[PhysicalChannelLeafList],
        Field([], alias="srl_nokia-interfaces:physical-channel"),
    ]
    """
    The list of transceiver channels associated with this port
    """
    forwarding_mode: Annotated[
        ForwardingModeLeaf, Field(None, alias="srl_nokia-interfaces:forwarding-mode")
    ]
    statistics: Annotated[
        StatisticsContainer, Field(None, alias="srl_nokia-interfaces:statistics")
    ]
    traffic_rate: Annotated[
        TrafficRateContainer, Field(None, alias="srl_nokia-interfaces:traffic-rate")
    ]
    adapter: Annotated[
        AdapterContainer, Field(None, alias="srl_nokia-interfaces:adapter")
    ]
    transceiver: Annotated[
        TransceiverContainer, Field(None, alias="srl_nokia-interfaces:transceiver")
    ]
    ethernet: Annotated[
        EthernetContainer, Field(None, alias="srl_nokia-interfaces:ethernet")
    ]
    subinterface: Annotated[
        List[SubinterfaceListEntry], Field(alias="srl_nokia-interfaces:subinterface")
    ]
    sflow: Annotated[SflowContainer, Field(None, alias="srl_nokia-interfaces:sflow")]
    vlan_tagging: Annotated[
        VlanTaggingLeaf, Field(None, alias="srl_nokia-interfaces-vlans:vlan-tagging")
    ]
    tpid: Annotated[TpidLeaf, Field(None, alias="srl_nokia-interfaces-vlans:tpid")]
    packet_link_qualification: Annotated[
        PacketLinkQualificationContainer,
        Field(None, alias="srl_nokia-packet-link-qual:packet-link-qualification"),
    ]
    lag: Annotated[LagContainer, Field(None, alias="srl_nokia-interfaces-lag:lag")]
    p4rt: Annotated[P4rtContainer, Field(None, alias="srl_nokia-interfaces-p4rt:p4rt")]
    uuid: Annotated[UuidLeaf2, Field(None, alias="srl_nokia-interfaces-vxdp:uuid")]
    vhost: Annotated[
        VhostContainer, Field(None, alias="srl_nokia-interfaces-vxdp:vhost")
    ]
    pci: Annotated[PciContainer, Field(None, alias="srl_nokia-interfaces-vxdp:pci")]
    linux: Annotated[
        LinuxContainer, Field(None, alias="srl_nokia-interfaces-vxdp:linux")
    ]


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
    )
    interface: Annotated[
        List[InterfaceListEntry], Field(alias="srl_nokia-interfaces:interface")
    ]


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
