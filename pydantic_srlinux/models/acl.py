from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class CodeLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]
    """
    Match if the ICMP code value is any value in the list

    Requires ICMP type to be specified because codes are type dependent.
    """


class CodeLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]
    """
    Match if the ICMPv6 code value is any value in the list

    Requires ICMPv6 type to be specified because codes are type dependent.
    """


class CopyCase(BaseModel):
    pass
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )


class DropContainer(BaseModel):
    """
    Drop matching packets.

    Dropped IP packets do not result in sending ICMP messages back to the source
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


class IcmpTypeType1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]


class Icmp6TypeType1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]


class IpProtocolTypeType1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=255)]
    """
    The IP protocol number or next-header value.
    """


class L4PortTypeType1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=65535)]
    """
    The IP protocol number may be expressed as a valid protocol
    number (integer) or using a protocol type defined by the
    IP_PROTOCOL identity
    """


class PrefixListListEntry2(BaseModel):
    """
    Match a packet if its source IP address is within the specified IPv4 prefix list.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv4 prefix list
    """


class PrefixListListEntry4(BaseModel):
    """
    Match a packet if its source IP address is within the specified IPv6 prefix list.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv6 prefix list
    """


class EnumerationEnum(Enum):
    ipv4 = 'ipv4'
    ipv6 = 'ipv6'
    mac = 'mac'


class EnumerationEnum10(Enum):
    default = 'default'
    ipv4_egress_scaled = 'ipv4-egress-scaled'
    acl_mfc_ipv4_only = 'acl-mfc-ipv4-only'


class EnumerationEnum2(Enum):
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


class EnumerationEnum3(Enum):
    echo_reply = 'echo-reply'
    dest_unreachable = 'dest-unreachable'
    source_quench = 'source-quench'
    redirect = 'redirect'
    echo = 'echo'
    router_advertise = 'router-advertise'
    router_solicit = 'router-solicit'
    time_exceeded = 'time-exceeded'
    param_problem = 'param-problem'
    timestamp = 'timestamp'
    timestamp_reply = 'timestamp-reply'


class EnumerationEnum4(Enum):
    ipv6_hop = 'ipv6-hop'
    icmp = 'icmp'
    igmp = 'igmp'
    ggp = 'ggp'
    ipv4 = 'ipv4'
    st = 'st'
    tcp = 'tcp'
    egp = 'egp'
    igp = 'igp'
    udp = 'udp'
    ipv6 = 'ipv6'
    idrp = 'idrp'
    rsvp = 'rsvp'
    gre = 'gre'
    esp = 'esp'
    ah = 'ah'
    icmp6 = 'icmp6'
    no_next_hdr = 'no-next-hdr'
    ipv6_dest_opts = 'ipv6-dest-opts'
    eigrp = 'eigrp'
    ospf = 'ospf'
    pim = 'pim'
    vrrp = 'vrrp'
    l2tp = 'l2tp'
    sctp = 'sctp'
    mpls_in_ip = 'mpls-in-ip'
    rohc = 'rohc'


class EnumerationEnum5(Enum):
    dest_unreachable = 'dest-unreachable'
    packet_too_big = 'packet-too-big'
    time_exceeded = 'time-exceeded'
    param_problem = 'param-problem'
    echo_request = 'echo-request'
    echo_reply = 'echo-reply'
    mld_query = 'mld-query'
    mld_report = 'mld-report'
    mld_done = 'mld-done'
    router_solicit = 'router-solicit'
    router_advertise = 'router-advertise'
    neighbor_solicit = 'neighbor-solicit'
    neighbor_advertise = 'neighbor-advertise'
    redirect = 'redirect'
    router_renumber = 'router-renumber'
    node_info_query = 'node-info-query'
    node_info_response = 'node-info-response'
    mld_v2 = 'mld-v2'
    mcast_rtr_adv = 'mcast-rtr-adv'
    mcast_rtr_solicit = 'mcast-rtr-solicit'
    mcast_rtr_term = 'mcast-rtr-term'


class EnumerationEnum6(Enum):
    le = 'le'
    ge = 'ge'
    eq = 'eq'


class EnumerationEnum7(Enum):
    acap = 'acap'
    afp_tcp = 'afp-tcp'
    arns = 'arns'
    asf_rmcp = 'asf-rmcp'
    ashare = 'ashare'
    atalk_rm = 'atalk-rm'
    aurp = 'aurp'
    auth = 'auth'
    bfd = 'bfd'
    bfd_echo = 'bfd-echo'
    bftp = 'bftp'
    bgmp = 'bgmp'
    bgp = 'bgp'
    bootpc = 'bootpc'
    bootps = 'bootps'
    ccso_ns = 'ccso-ns'
    chargen = 'chargen'
    cisco_tdp = 'cisco-tdp'
    citadel = 'citadel'
    clearcase = 'clearcase'
    commerce = 'commerce'
    courier = 'courier'
    daytime = 'daytime'
    dhcpv6_client = 'dhcpv6-client'
    dhcpv6_server = 'dhcpv6-server'
    dhcp_failover = 'dhcp-failover'
    dicom = 'dicom'
    discard = 'discard'
    dnsix = 'dnsix'
    domain = 'domain'
    dsp = 'dsp'
    echo = 'echo'
    epp = 'epp'
    esro = 'esro'
    exec = 'exec'
    finger = 'finger'
    ftp = 'ftp'
    ftp_data = 'ftp-data'
    ftps = 'ftps'
    ftps_data = 'ftps-data'
    godi = 'godi'
    gopher = 'gopher'
    gtp_c = 'gtp-c'
    gtp_prime = 'gtp-prime'
    gtp_u = 'gtp-u'
    ha_cluster = 'ha-cluster'
    hostname = 'hostname'
    hp_alarm_mgr = 'hp-alarm-mgr'
    http = 'http'
    http_alt = 'http-alt'
    http_mgmt = 'http-mgmt'
    http_rpc = 'http-rpc'
    https = 'https'
    ieee_mms_ssl = 'ieee-mms-ssl'
    imap = 'imap'
    imap3 = 'imap3'
    imaps = 'imaps'
    ipp = 'ipp'
    ipsec = 'ipsec'
    ipx = 'ipx'
    irc = 'irc'
    iris_beep = 'iris-beep'
    isakmp = 'isakmp'
    isakmp_nat = 'isakmp-nat'
    iscsi = 'iscsi'
    iso_tsap = 'iso-tsap'
    kerberos = 'kerberos'
    kerberos_adm = 'kerberos-adm'
    klogin = 'klogin'
    kpasswd = 'kpasswd'
    kshell = 'kshell'
    l2tp = 'l2tp'
    ldap = 'ldap'
    ldaps = 'ldaps'
    ldp = 'ldp'
    lmp = 'lmp'
    login = 'login'
    lpd = 'lpd'
    lsp_ping = 'lsp-ping'
    mac_server_adm = 'mac-server-adm'
    matip_a = 'matip-a'
    matip_b = 'matip-b'
    micro_bfd = 'micro-bfd'
    microsoft_ds = 'microsoft-ds'
    mobile_ip = 'mobile-ip'
    monitor = 'monitor'
    mpp = 'mpp'
    mssql_m = 'mssql-m'
    mssql_s = 'mssql-s'
    msdp = 'msdp'
    ms_exchange = 'ms-exchange'
    msp = 'msp'
    multihop_bfd = 'multihop-bfd'
    nas = 'nas'
    ncp = 'ncp'
    netrjs_1 = 'netrjs-1'
    netrjs_2 = 'netrjs-2'
    netrjs_3 = 'netrjs-3'
    netrjs_4 = 'netrjs-4'
    netbios_data = 'netbios-data'
    netbios_ns = 'netbios-ns'
    netbios_ss = 'netbios-ss'
    netnews = 'netnews'
    netwall = 'netwall'
    new_rwho = 'new-rwho'
    nfs = 'nfs'
    nntp = 'nntp'
    nntps = 'nntps'
    ntp = 'ntp'
    odmr = 'odmr'
    olsr = 'olsr'
    openvpn = 'openvpn'
    pim_auto_rp = 'pim-auto-rp'
    pkix_timestamp = 'pkix-timestamp'
    pop2 = 'pop2'
    pop3 = 'pop3'
    pop3s = 'pop3s'
    pptp = 'pptp'
    ptp_event = 'ptp-event'
    ptp_general = 'ptp-general'
    print_srv = 'print-srv'
    qmtp = 'qmtp'
    qotd = 'qotd'
    radius = 'radius'
    radius_acct = 'radius-acct'
    remote_mail = 'remote-mail'
    remotefs = 'remotefs'
    remotecmd = 'remotecmd'
    rip = 'rip'
    rje = 'rje'
    rlp = 'rlp'
    rlzdb = 'rlzdb'
    rmc = 'rmc'
    rmonitor = 'rmonitor'
    rpc2portmap = 'rpc2portmap'
    rsync = 'rsync'
    rtelnet = 'rtelnet'
    rtsp = 'rtsp'
    sgmp = 'sgmp'
    silc = 'silc'
    smux = 'smux'
    sna_gw = 'sna-gw'
    snmp = 'snmp'
    snmp_trap = 'snmp-trap'
    snpp = 'snpp'
    smtp = 'smtp'
    sql_svcs = 'sql-svcs'
    sql = 'sql'
    ssh = 'ssh'
    submission = 'submission'
    sunrpc = 'sunrpc'
    svcloc = 'svcloc'
    syslog = 'syslog'
    systat = 'systat'
    tacacs = 'tacacs'
    talk = 'talk'
    tcpmux = 'tcpmux'
    tcpnethaspsrv = 'tcpnethaspsrv'
    tftp = 'tftp'
    time = 'time'
    timed = 'timed'
    ups = 'ups'
    xdmcp = 'xdmcp'
    xns_ch = 'xns-ch'
    xns_mail = 'xns-mail'
    xns_time = 'xns-time'
    z3950 = 'z3950'


class EnumerationEnum8(Enum):
    in_ = 'in'
    out = 'out'
    exceed = 'exceed'
    in_plus = 'in-plus'
    in_low = 'in-low'
    out_low = 'out-low'


class EnumerationEnum9(Enum):
    global_ = 'global'
    subinterface = 'subinterface'


class DropCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    drop: Annotated[Optional[DropContainer], Field(alias='srl_nokia-acl:drop')] = None


class ForwardingComplexListEntry(BaseModel):
    """
    List of forwarding complexes in the system
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    complex_identifier: Annotated[str, Field(alias='srl_nokia-acl:complex-identifier')]
    """
    A forwarding complex in the format (slot-number,complex-number).
    """
    single_instance: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:single-instance', ge=0, le=65535)
    ] = None
    """
    The number of TCAM entries required to implement this entry if it is applied to only one subinterface and one traffic direction specific to this slot.

    This is non-zero even if the filter is not applied to any subinterfaces of this complex. It captures the effect of TCAM entry expansion to deal with L4 port or VLAN ranges, for example.
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


class PolicerContainer(BaseModel):
    """
    Policer stats for traffic matching the entry:

    Statistics under /acl/interfaces for policer configured with scope=subinterface and entry-specific=true, and acl configured with subinterface-specific=input-and-output.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    conforming_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered conforming by the policer
    """
    conforming_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered conforming by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    exceeding_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered exceeding by the policer
    """
    exceeding_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered exceeding by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """


class PolicerContainer2(BaseModel):
    """
    Policer stats for traffic matching one or multiple entries:

    List of ACL policer statistics of scope=subinterface and per-entry-statistics=false, and acl configured with subinterface-specific=false.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    conforming_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered conforming by the policer
    """
    conforming_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered conforming by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    exceeding_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered exceeding by the policer
    """
    exceeding_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered exceeding by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """


class PrefixListListEntry(BaseModel):
    """
    Match a packet if its destination IP address is within the specified IPv4 prefix list.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv4 prefix list
    """


class PrefixListListEntry3(BaseModel):
    """
    Match a packet if its destination IP address is within the specified IPv6 prefix list.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv6 prefix list
    """


class PrefixListEntry(BaseModel):
    """
    List of IPv4 prefixes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4_prefix: Annotated[
        str,
        Field(
            alias='srl_nokia-acl:ipv4-prefix',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$',
        ),
    ]
    """
    A user defined IPv4 prefix
    """


class PrefixListEntry2(BaseModel):
    """
    List of IPv6 prefixes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv6_prefix: Annotated[
        str,
        Field(
            alias='srl_nokia-acl:ipv6-prefix',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$',
        ),
    ]
    """
    A user defined IPv6 prefix
    """


class StatisticsContainer2(BaseModel):
    """
    Container for per-entry statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command performed by the user at this level or a higher level
    """
    matched_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:matched-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets matching the entry since it was programmed or since the last clear, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """
    matched_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:matched-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets packets matching the entry since it was programmed or since the last clear, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """
    last_match: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-match',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The elapsed time since a packet last matched the entry, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """


class StatisticsContainer3(BaseModel):
    """
    Container for policer scope=subinterface and per-entry-statistics=false statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command performed by the user at this level
    """
    policer: Annotated[
        Optional[PolicerContainer2], Field(alias='srl_nokia-acl:policer')
    ] = None


class StatisticsContainer4(BaseModel):
    """
    Container for system CPU policer statistics

    None of these statistics are populated if the policer is configured as entry-specific=true.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    conforming_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered conforming by the policer
    """
    conforming_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered conforming by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    exceeding_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered exceeding by the policer
    """
    exceeding_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered exceeding by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command that applied to these statistics
    """


class SystemCpuPolicerContainer(BaseModel):
    """
    System CPU policer stats for traffic matching the entry:

    Statistics for system cpu policer configured with scope=global and entry-specific=true, and acl configured with subinterface-specific=false.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    conforming_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered conforming by the policer
    """
    conforming_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered conforming by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    exceeding_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered exceeding by the policer
    """
    exceeding_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered exceeding by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """


class SystemCpuPolicerListEntry(BaseModel):
    """
    List of system CPU policer templates. For each policer in this list one or more policer instances are implemented in the XDP-CPM software and these policer instances process the aggregate of terminating traffic received from all linecards.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-acl:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-defined name of the policer
    """
    entry_specific: Annotated[
        Optional[bool], Field(alias='srl_nokia-acl:entry-specific')
    ] = False
    """
    If set to false, only one policer instance is created from this template and it is shared by all entries of all cpm-filter ACLs that refer to this policer.

    If set to true, multiple policer instances are created from this template, one for each cpm-filter entry that refers to the policer template.
    """
    peak_packet_rate: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:peak-packet-rate', ge=1, le=4000000)
    ] = None
    """
    The maximum number of packets per second (bucket empty/fill rate)
    """
    max_packet_burst: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:max-packet-burst', ge=16, le=4000000)
    ] = 16
    """
    The maximum depth of the policer bucket in number of packets
    """
    statistics: Annotated[
        Optional[StatisticsContainer4], Field(alias='srl_nokia-acl:statistics')
    ] = None


class TcamEntriesContainer(BaseModel):
    """
    Information about the TCAM entries used to implement the ACL entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_complex: Annotated[
        Optional[List[ForwardingComplexListEntry]],
        Field(alias='srl_nokia-acl:forwarding-complex'),
    ] = None


class AggregateContainer(BaseModel):
    """
    None of these statistics are populated if the policer is configured as entry-specific=true.

    If entry-specific=false and subinterface-specific=true, this is sum of all the entries and all the policer templates instantiated for all subintrefaces.

    If entry-specific=false and subinterface-specific=false, this is sum of all the entries using this policer template.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command that applied to these statistics
    """
    conforming_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered conforming by the policer
    """
    conforming_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:conforming-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered conforming by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """
    exceeding_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets (actually Ethernet frames) that were considered exceeding by the policer
    """
    exceeding_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:exceeding-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of bytes that were considered exceeding by the policer. The byte count includes 18 bytes of Ethernet overhead for every IP packet.
    """


class DestinationIpContainer(BaseModel):
    """
    Packet matching criteria based on destination IPv4 address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:prefix',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address is within the specified IPv4 prefix.
    """
    prefix_list: Annotated[
        Optional[List[PrefixListListEntry]], Field(alias='srl_nokia-acl:prefix-list')
    ] = None
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address logically anded with the inverse of the mask equals this IP address.
    """
    mask: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:mask',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address logically anded with the inverse of this mask equals the configured IP address.
    """


class DestinationIpContainer2(BaseModel):
    """
    Packet matching criteria based on destination IPv6 address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:prefix',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address is within the specified IPv6 prefix.
    """
    prefix_list: Annotated[
        Optional[List[PrefixListListEntry3]], Field(alias='srl_nokia-acl:prefix-list')
    ] = None
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address logically anded with the inverse of the mask equals this IP address.
    """
    mask: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:mask',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Match a packet if its destination IP address logically anded with the inverse of this mask equals the configured IP address.
    """


class EntryListEntry2(BaseModel):
    """
    ACL Filter statistics per entry and per subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[
        int, Field(alias='srl_nokia-acl:sequence-id', ge=0, le=65535)
    ]
    """
    Reference to type entry ID key
    """
    statistics: Annotated[
        Optional[StatisticsContainer2], Field(alias='srl_nokia-acl:statistics')
    ] = None
    policer: Annotated[
        Optional[PolicerContainer], Field(alias='srl_nokia-acl:policer')
    ] = None


class ForwardingComplexListEntry2(BaseModel):
    """
    List of forwarding complexes that are currently installed and online
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    slot_id: Annotated[int, Field(alias='srl_nokia-acl:slot-id', ge=0, le=255)]
    """
    The slot id
    """
    complex_id: Annotated[int, Field(alias='srl_nokia-acl:complex-id', ge=0, le=1)]
    """
    The complex id
    """
    programming_complete: Annotated[
        Optional[bool], Field(alias='srl_nokia-acl:programming-complete')
    ] = None
    """
    Reads false when there are still pending entries to program from prior configuration transactions

    Reads true when all datapath programming related to all prior ACL configuration changes is complete
    """
    last_completed_timestamp: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-completed-timestamp',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The date and time when the forwarding complex last completed all datapath programming related to prior ACL configuration changes.
    """


class Icmp6Container(BaseModel):
    """
    A packet matches this condition if its ICMPv6 type and code matches one of the specified combinations

    The rule should also have a condition that the next-header value equals 58 (ICMPv6) in order for this to be interpreted correctly.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        Optional[Union[Icmp6TypeType1, EnumerationEnum5]],
        Field(alias='srl_nokia-acl:type'),
    ] = None
    """
    Match a single ICMPv6 type value
    """
    code: Annotated[
        Optional[List[CodeLeafList2]], Field(alias='srl_nokia-acl:code')
    ] = []
    """
    Match if the ICMPv6 code value is any value in the list

    Requires ICMPv6 type to be specified because codes are type dependent.
    """


class IcmpContainer(BaseModel):
    """
    A packet matches this condition if its ICMP type and code matches one of the specified combinations

    The rule should also have a condition that the IP protocol equals 1 (ICMP) in order for this to be interpreted correctly.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    type: Annotated[
        Optional[Union[IcmpTypeType1, EnumerationEnum3]],
        Field(alias='srl_nokia-acl:type'),
    ] = None
    """
    Match a single ICMP type value.
    """
    code: Annotated[Optional[List[CodeLeafList]], Field(alias='srl_nokia-acl:code')] = (
        []
    )
    """
    Match if the ICMP code value is any value in the list

    Requires ICMP type to be specified because codes are type dependent.
    """


class Ipv4PrefixListListEntry(BaseModel):
    """
    A user defined IPv4 prefix list description
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv4 prefix list
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-acl:description', max_length=255, min_length=1),
    ] = None
    """
    Description string for the prefix list
    """
    prefix: Annotated[
        Optional[List[PrefixListEntry]], Field(alias='srl_nokia-acl:prefix')
    ] = None


class Ipv6PrefixListListEntry(BaseModel):
    """
    A user defined IPv6 prefix list description
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    Reference to the name of the IPv6 prefix list
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-acl:description', max_length=255, min_length=1),
    ] = None
    """
    Description string for the prefix list
    """
    prefix: Annotated[
        Optional[List[PrefixListEntry2]], Field(alias='srl_nokia-acl:prefix')
    ] = None


class MatchListContainer(BaseModel):
    """
    Top level container for match list model config and operational state data
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4_prefix_list: Annotated[
        Optional[List[Ipv4PrefixListListEntry]],
        Field(alias='srl_nokia-acl:ipv4-prefix-list'),
    ] = None
    ipv6_prefix_list: Annotated[
        Optional[List[Ipv6PrefixListListEntry]],
        Field(alias='srl_nokia-acl:ipv6-prefix-list'),
    ] = None


class RangeContainer(BaseModel):
    """
    Container used to specify a contiguous range of TCP/UDP port numbers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    start: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:start'),
    ] = None
    """
    The starting port number to include in the range
    """
    end: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:end'),
    ] = None
    """
    The ending port number to include in the range
    """


class RangeContainer2(BaseModel):
    """
    Container used to specify a contiguous range of TCP/UDP port numbers
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    start: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:start'),
    ] = None
    """
    The starting port number to include in the range
    """
    end: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:end'),
    ] = None
    """
    The ending port number to include in the range
    """


class RateLimitContainer(BaseModel):
    """
    Rate-limit accepted packets
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    system_cpu_policer: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:system-cpu-policer',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a system-cpu-policer.
    """
    policer: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:policer',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a policer
    """


class SourceIpContainer(BaseModel):
    """
    Packet matching criteria based on source IPv4 address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:prefix',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address is within the specified IPv4 prefix.
    """
    prefix_list: Annotated[
        Optional[List[PrefixListListEntry2]], Field(alias='srl_nokia-acl:prefix-list')
    ] = None
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:address',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address logically anded with the inverse of the mask equals this IP address.
    """
    mask: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:mask',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address logically anded with the inverse of this mask equals the configured IP address.
    """


class SourceIpContainer2(BaseModel):
    """
    Packet matching criteria based on source IPv6 address
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:prefix',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address is within the specified IPv6 prefix.
    """
    prefix_list: Annotated[
        Optional[List[PrefixListListEntry4]], Field(alias='srl_nokia-acl:prefix-list')
    ] = None
    address: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:address',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address logically anded with the inverse of the mask equals this IP address.
    """
    mask: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:mask',
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))$).*$',
        ),
    ] = None
    """
    Match a packet if its source IP address logically anded with the inverse of this mask equals the configured IP address.
    """


class SourcePortContainer(BaseModel):
    """
    A packet matches this condition if its source TCP or UDP port number matches the value or range that is specified

    The rule should also have a condition that the IP protocol equals 6 (TCP) or 17 (UDP) in order for this to be interpreted correctly.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operator: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-acl:operator')
    ] = None
    """
    Comparison operator

    eq = equal
    ge = greater than or equal to
    le = less than or equal to
    """
    value: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:value'),
    ] = None
    """
    A source port number
    """
    range: Annotated[Optional[RangeContainer2], Field(alias='srl_nokia-acl:range')] = (
        None
    )


class StatisticsContainer(BaseModel):
    """
    Container for per-entry statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command performed by the user at this level or a higher level
    """
    matched_packets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:matched-packets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of packets matching the entry since it was programmed or since the last clear, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """
    matched_octets: Annotated[
        Optional[int],
        Field(alias='srl_nokia-acl:matched-octets', ge=0, le=18446744073709551615),
    ] = 0
    """
    The number of octets packets matching the entry since it was programmed or since the last clear, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """
    last_match: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-match',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    The elapsed time since a packet last matched the entry, considering the mgmt0 subinterface and all subinterfaces of all linecard ports that use the ACL as an input ACL
    """
    system_cpu_policer: Annotated[
        Optional[SystemCpuPolicerContainer],
        Field(alias='srl_nokia-acl:system-cpu-policer'),
    ] = None


class StatisticsContainer5(BaseModel):
    """
    Container for linecard policer statistics.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    aggregate: Annotated[
        Optional[AggregateContainer], Field(alias='srl_nokia-acl:aggregate')
    ] = None


class AclFilterListEntry2(BaseModel):
    """
    MAC, IPv4, IPv6 ACL filter(s) to be applied on this subinterface direction

    On 7220 and 7250 IXR platforms only a single MAC, IPv4 or IPv6 filter is supported.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    ACL Filter policy name
    """
    type: Annotated[EnumerationEnum, Field(alias='srl_nokia-acl:type')]
    """
    Defines the type of ACL filter:
    ipv4: IPv4 ACL filter
    ipv6: IPv6 ACL filter
    mac: MAC ACL filter
    """
    entry: Annotated[
        Optional[List[EntryListEntry2]], Field(alias='srl_nokia-acl:entry')
    ] = None


class DatapathProgrammingContainer(BaseModel):
    """
    Container to represent the progress of ACL datapath programming
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_complex: Annotated[
        Optional[List[ForwardingComplexListEntry2]],
        Field(alias='srl_nokia-acl:forwarding-complex'),
    ] = None


class DestinationPortContainer(BaseModel):
    """
    A packet matches this condition if its destination TCP or UDP port number matches the value or range that is specified

    The rule should also have a condition that the IP protocol equals 6 (TCP) or 17 (UDP) in order for this to be interpreted correctly.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operator: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-acl:operator')
    ] = None
    """
    Comparison operator

    eq = equal
    ge = greater than or equal to
    le = less than or equal to
    """
    value: Annotated[
        Optional[Union[L4PortTypeType1, EnumerationEnum7]],
        Field(alias='srl_nokia-acl:value'),
    ] = None
    """
    A destination port number
    """
    range: Annotated[Optional[RangeContainer], Field(alias='srl_nokia-acl:range')] = (
        None
    )


class InputContainer(BaseModel):
    """
    Container for ACL filters that apply to ingress traffic on the subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    acl_filter: Annotated[
        Optional[List[AclFilterListEntry2]], Field(alias='srl_nokia-acl:acl-filter')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer3], Field(alias='srl_nokia-acl:statistics')
    ] = None


class InterfaceRefContainer(BaseModel):
    """
    Reference to an interface or subinterface
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface: Annotated[Optional[str], Field(alias='srl_nokia-acl:interface')] = None
    """
    Reference to a base interface, for example a port or LAG
    """
    subinterface: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:subinterface', ge=0, le=9999)
    ] = None
    """
    Reference to a subinterface

    This requires the base interface to be specified using the interface leaf in this container.
    """


class InterfaceListEntry(BaseModel):
    """
    List of interfaces and subinterfaces referencing ACL filters.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    interface_id: Annotated[str, Field(alias='srl_nokia-acl:interface-id')]
    """
    Identifier for the interface or subinterface.
    """
    interface_ref: Annotated[
        Optional[InterfaceRefContainer], Field(alias='srl_nokia-acl:interface-ref')
    ] = None
    input: Annotated[Optional[InputContainer], Field(alias='srl_nokia-acl:input')] = (
        None
    )


class Ipv4Container(BaseModel):
    """
    Container for the common layer-3 IPv4 match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    destination_ip: Annotated[
        Optional[DestinationIpContainer], Field(alias='srl_nokia-acl:destination-ip')
    ] = None
    dscp_set: Annotated[
        Optional[List[Union[DscpValueType, EnumerationEnum2]]],
        Field(alias='srl_nokia-acl:dscp-set'),
    ] = []
    """
    A list of DSCP values to be matched for incoming packets. An OR match should be performed, such that a packet must match one of the values defined in this list. If the field is left empty then any DSCP value matches.
    """
    fragment: Annotated[Optional[bool], Field(alias='srl_nokia-acl:fragment')] = None
    """
    Match an IPv4 fragment

    A packet matches the true condition if the IPv4 header indicates that the fragment-offset is zero and and the more-fragments bit is 1 or if the IPv4 header indicates that the fragment-offset is greater than 0. A packet matches the false condition if it is unfragmented.
    """
    first_fragment: Annotated[
        Optional[bool], Field(alias='srl_nokia-acl:first-fragment')
    ] = None
    """
    Match the first fragment of an IPv4 datagram

    A packet matches the true condition if the IPv4 header indicates that the fragment-offset is zero
    and and the more-fragments bit is 1. It is not valid to configure this leaf without configuring a
    match value for the fragment leaf.
    """
    icmp: Annotated[Optional[IcmpContainer], Field(alias='srl_nokia-acl:icmp')] = None
    protocol: Annotated[
        Optional[Union[IpProtocolTypeType1, EnumerationEnum4]],
        Field(alias='srl_nokia-acl:protocol'),
    ] = None
    """
    An IPv4 packet matches this condition if its IP protocol type field matches the specified value
    """
    source_ip: Annotated[
        Optional[SourceIpContainer], Field(alias='srl_nokia-acl:source-ip')
    ] = None


class Ipv6Container(BaseModel):
    """
    Container for the common layer-3 IPv6 match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    destination_ip: Annotated[
        Optional[DestinationIpContainer2], Field(alias='srl_nokia-acl:destination-ip')
    ] = None
    dscp_set: Annotated[
        Optional[List[Union[DscpValueType, EnumerationEnum2]]],
        Field(alias='srl_nokia-acl:dscp-set'),
    ] = []
    """
    A list of DSCP values to be matched for incoming packets. An OR match should be performed, such that a packet must match one of the values defined in this list. If the field is left empty then any DSCP value matches.
    """
    icmp6: Annotated[Optional[Icmp6Container], Field(alias='srl_nokia-acl:icmp6')] = (
        None
    )
    next_header: Annotated[
        Optional[Union[IpProtocolTypeType1, EnumerationEnum4]],
        Field(alias='srl_nokia-acl:next-header'),
    ] = None
    """
    An IPv6 packet matches this condition if its first next-header field (in the IPv6 fixed header) contains the specified value
    """
    source_ip: Annotated[
        Optional[SourceIpContainer2], Field(alias='srl_nokia-acl:source-ip')
    ] = None


class NextHopContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    address: Annotated[
        Optional[Union[Ipv4AddressType, Ipv6AddressType]],
        Field(alias='srl_nokia-acl:address'),
    ] = None
    """
    IP address of next hop to forward matching packets.
    """


class PolicerListEntry(BaseModel):
    """
    List of policer templates used in subintreface and CPM Filter ACL.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-acl:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    User-defined name of the policer
    """
    scope: Annotated[Optional[EnumerationEnum9], Field(alias='srl_nokia-acl:scope')] = (
        'global'
    )
    """
    Controls the instantiation of the policer between subinterfaces

    global: policer is instantiated per direction and shared between ACL, requires filter subinterface-specific disabled

    subinterface: policer is instantiated per subinterface and per direction, requires filter subinterface-specific input-and-ouput
    """
    peak_rate: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:peak-rate', ge=1, le=800000000)
    ] = None
    """
    The PIR rate in kbps (bucket empty/fill rate).
    """
    max_burst: Annotated[
        Optional[int], Field(alias='srl_nokia-acl:max-burst', ge=1, le=125000000)
    ] = None
    """
    The MBS bucket depth in bytes
    """
    statistics: Annotated[
        Optional[StatisticsContainer5], Field(alias='srl_nokia-acl:statistics')
    ] = None


class PolicersContainer(BaseModel):
    """
    Container for policer definitions used by ACL entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    system_cpu_policer: Annotated[
        Optional[List[SystemCpuPolicerListEntry]],
        Field(alias='srl_nokia-acl:system-cpu-policer'),
    ] = None
    policer: Annotated[
        Optional[List[PolicerListEntry]], Field(alias='srl_nokia-acl:policer')
    ] = None


class TransportContainer(BaseModel):
    """
    Container for the common layer-4 transport match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    destination_port: Annotated[
        Optional[DestinationPortContainer],
        Field(alias='srl_nokia-acl:destination-port'),
    ] = None
    source_port: Annotated[
        Optional[SourcePortContainer], Field(alias='srl_nokia-acl:source-port')
    ] = None
    tcp_flags: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:tcp-flags',
            pattern='^(?=^(\\(|\\)|&|\\||!|ack|rst|syn)+$).*$',
        ),
    ] = None
    """
    A logical expression using the &, | and ! logical operators and the TCP flag names: rst, syn and ack.
    """


class MatchContainer(BaseModel):
    """
    Container for the conditions that determine whether a packet matches this entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ipv4: Annotated[Optional[Ipv4Container], Field(alias='srl_nokia-acl:ipv4')] = None
    ipv6: Annotated[Optional[Ipv6Container], Field(alias='srl_nokia-acl:ipv6')] = None
    transport: Annotated[
        Optional[TransportContainer], Field(alias='srl_nokia-acl:transport')
    ] = None
    network_instance: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:network-instance',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a configured network-instance
    """


class NextHopCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    next_hop: Annotated[
        Optional[NextHopContainer], Field(alias='srl_nokia-acl:next-hop')
    ] = None


class ForwardContainer(BaseModel):
    """
    Enable the next-hop context
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forward_action: Annotated[
        Optional[NextHopCase], Field(alias='srl_nokia-acl:forward-action')
    ] = None


class AcceptContainer(BaseModel):
    """
    Accept matching packets and forward them towards their normal destination
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    forwarding_class: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:forwarding-class',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    The QoS forwarding class to which the packet is mapped
    """
    profile: Annotated[
        Optional[EnumerationEnum8], Field(alias='srl_nokia-acl:profile')
    ] = None
    """
    The QoS profile to which the packet is mapped
    """
    rate_limit: Annotated[
        Optional[RateLimitContainer], Field(alias='srl_nokia-acl:rate-limit')
    ] = None
    forward: Annotated[
        Optional[ForwardContainer], Field(alias='srl_nokia-acl:forward')
    ] = None


class AcceptCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    accept: Annotated[
        Optional[AcceptContainer], Field(alias='srl_nokia-acl:accept')
    ] = None


class ActionContainer(BaseModel):
    """
    Container for the actions to be applied to packets matching the filter entry.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    action: Annotated[
        Optional[Union[AcceptCase, DropCase, CopyCase]],
        Field(alias='srl_nokia-acl:action'),
    ] = None
    collect_stats: Annotated[
        Optional[bool], Field(alias='srl_nokia-acl:collect-stats')
    ] = False
    """
    Collect statistics for each entry of the ACL. If this is set to false no hardware resources are allocated to collecting statistics for this ACL entry.
    """


class EntryListEntry(BaseModel):
    """
    List of ACL entries comprising an ACL Filter
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    sequence_id: Annotated[
        int, Field(alias='srl_nokia-acl:sequence-id', ge=0, le=65535)
    ]
    """
    A number to indicate the relative evaluation order of the different entries; lower numbered entries are evaluated before higher numbered entries
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-acl:description', max_length=255, min_length=1),
    ] = None
    """
    Description string for the filter entry
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command performed by the user at this level
    """
    match: Annotated[Optional[MatchContainer], Field(alias='srl_nokia-acl:match')] = (
        None
    )
    action: Annotated[
        Optional[ActionContainer], Field(alias='srl_nokia-acl:action')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer], Field(alias='srl_nokia-acl:statistics')
    ] = None
    tcam_entries: Annotated[
        Optional[TcamEntriesContainer], Field(alias='srl_nokia-acl:tcam-entries')
    ] = None


class AclFilterListEntry(BaseModel):
    """
    List of MAC, IPv4, IPv6 filter policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[str, Field(alias='srl_nokia-acl:name')]
    """
    ACL Filter policy name
    """
    type: Annotated[EnumerationEnum, Field(alias='srl_nokia-acl:type')]
    """
    Defines the type of ACL filter:
    ipv4: IPv4 ACL filter
    ipv6: IPv6 ACL filter
    mac: MAC ACL filter
    """
    description: Annotated[
        Optional[str],
        Field(alias='srl_nokia-acl:description', max_length=255, min_length=1),
    ] = None
    """
    Description string for the filter policy
    """
    last_clear: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-acl:last-clear',
            pattern='^(?=^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[\\+\\-]\\d{2}:\\d{2})$).*$',
        ),
    ] = None
    """
    Time of the last clear command performed by the user at this level
    """
    entry: Annotated[
        Optional[List[EntryListEntry]], Field(alias='srl_nokia-acl:entry')
    ] = None


class AclContainer(BaseModel):
    """
    Top level container for configuration and operational state related to access control lists (ACLs)
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    acl_filter: Annotated[
        Optional[List[AclFilterListEntry]], Field(alias='srl_nokia-acl:acl-filter')
    ] = None
    interface: Annotated[
        Optional[List[InterfaceListEntry]], Field(alias='srl_nokia-acl:interface')
    ] = None
    policers: Annotated[
        Optional[PolicersContainer], Field(alias='srl_nokia-acl:policers')
    ] = None
    datapath_programming: Annotated[
        Optional[DatapathProgrammingContainer],
        Field(alias='srl_nokia-acl:datapath-programming'),
    ] = None
    match_list: Annotated[
        Optional[MatchListContainer], Field(alias='srl_nokia-acl:match-list')
    ] = None
    tcam_profile: Annotated[
        Optional[EnumerationEnum10], Field(alias='srl_nokia-acl:tcam-profile')
    ] = None
    """
    Specify the TCAM resource management profile
    """
    egress_mac_filtering: Annotated[
        Optional[bool], Field(alias='srl_nokia-acl:egress-mac-filtering')
    ] = False
    """
    Must be set to true in order to apply any MAC ACLs to any subinterface in the egress traffic direction.

    Internally this sets the following limits:
    - maximum number of IPv4 ACL instances that can be created to process egress traffic = 32
    - maximum number of IPv6 ACL instances that can be created to process egress traffic = 32
    - maximum number of MAC ACL instances that can be created to process egress traffic = 32

    Remember that the number of ACL instances per ACL policy is greater than one if subinterface-specific is set to input-and-output or output-only.

    A setting of true is blocked if the number of IPv4 ACL instances applied to egress traffic is already greater than 32, or if the number of IPv6 ACL instances applied to egress traffic is already greater than 32.
    """


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
    acl: Annotated[Optional[AclContainer], Field(alias='srl_nokia-acl:acl')] = None


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