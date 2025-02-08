from __future__ import annotations

from enum import Enum
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel
from typing_extensions import Annotated


class AsNumberType(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=4294967295)]
    """
    An autonomous system number
    """


class AsPathSetMemberLeafList(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(max_length=65535, min_length=1)]
    """
    A list of regular expressions
    """


class BgpExtCommunityRegexpType2Type1(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[\\^]?link-bandwidth:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+[kMGT]?[$]?$).*$'
        ),
    ]
    """
    Type definition for extended community regular expressions

    Each regex is a sequence of terms and operators. A term can be:
     - a single digit, such as ‟4”
     - a range term composed of two elementary terms separated by the ‛-’ character like ‟2-3”
     - the dot ‟.” wild-card character which matches any elementary term or ':'
     - a regular expression enclosed in parenthesis ‟( )”
     - a choice of digits and/or ranges enclosed in square brackets; for example, [51-37] matches digit 5 or any single digit between 1 and 3 or the digit 7

    Supported operators:
    | - match term on the left of the operator or the term on the right of the operator
    * - matches zero or more occurrences of the preceding term
    ? - matches zero or one occurrence of the preceding term
    + - matches one or more occurrences of the preceding term
    {m,n} - matches least m and at most n repetitions of the term
    {m} - matches exactly m repetitions of the term
    {m,} - matches m or more repetitions of the term
    ^ - matches the beginning of the string
    $ - matches the end of the string
    backslash - an escape character to indicate that the following character is a match criteria and not a grouping delimiter
    """


class BgpExtCommunityRegexpType2Type2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[\\^]?target:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+[$]?$).*$'
        ),
    ]
    """
    Type definition for extended community regular expressions

    Each regex is a sequence of terms and operators. A term can be:
     - a single digit, such as ‟4”
     - a range term composed of two elementary terms separated by the ‛-’ character like ‟2-3”
     - the dot ‟.” wild-card character which matches any elementary term or ':'
     - a regular expression enclosed in parenthesis ‟( )”
     - a choice of digits and/or ranges enclosed in square brackets; for example, [51-37] matches digit 5 or any single digit between 1 and 3 or the digit 7

    Supported operators:
    | - match term on the left of the operator or the term on the right of the operator
    * - matches zero or more occurrences of the preceding term
    ? - matches zero or one occurrence of the preceding term
    + - matches one or more occurrences of the preceding term
    {m,n} - matches least m and at most n repetitions of the term
    {m} - matches exactly m repetitions of the term
    {m,} - matches m or more repetitions of the term
    ^ - matches the beginning of the string
    $ - matches the end of the string
    backslash - an escape character to indicate that the following character is a match criteria and not a grouping delimiter
    """


class BgpExtCommunityRegexpType2Type3(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[\\^]?origin:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+:[0-9()*+,.{}\\[\\]\\-\\|\\?\\\\]+[$]?$).*$'
        ),
    ]
    """
    Type definition for extended community regular expressions

    Each regex is a sequence of terms and operators. A term can be:
     - a single digit, such as ‟4”
     - a range term composed of two elementary terms separated by the ‛-’ character like ‟2-3”
     - the dot ‟.” wild-card character which matches any elementary term or ':'
     - a regular expression enclosed in parenthesis ‟( )”
     - a choice of digits and/or ranges enclosed in square brackets; for example, [51-37] matches digit 5 or any single digit between 1 and 3 or the digit 7

    Supported operators:
    | - match term on the left of the operator or the term on the right of the operator
    * - matches zero or more occurrences of the preceding term
    ? - matches zero or one occurrence of the preceding term
    + - matches one or more occurrences of the preceding term
    {m,n} - matches least m and at most n repetitions of the term
    {m} - matches exactly m repetitions of the term
    {m,} - matches m or more repetitions of the term
    ^ - matches the beginning of the string
    $ - matches the end of the string
    backslash - an escape character to indicate that the following character is a match criteria and not a grouping delimiter
    """


class BgpExtCommunityRegexpTypeType1(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+$).*$'
        ),
    ]
    """
    Type definition for extended community regular expressions

    The format embeds two regular expressions separated by one colon ':' character; the first expression is applied to the as-value of the community string and the second to the local administrative value

    Each regex is a sequence of terms and operators. A term can be:
     - a single digit, such as '4'
     - a range term composed of two elementary terms separated by the '-' character like '2-3'
     - the dot '.' wild-card character which matches any elementary term or ':'
     - a regular expression enclosed in parenthesis '( )'
     - a choice of digits and/or ranges enclosed in square brackets; for example, [51-37] matches digit 5 or any single digit between 1 and 3 or the digit 7

    Supported operators:
    | - match term on the left of the operator or the term on the right of the operator
    * - matches zero or more occurrences of the preceding term
    ? - matches zero or one occurrence of the preceding term
    + - matches one or more occurrences of the preceding term
    {m,n} - matches least m and at most n repetitions of the term
    {m} - matches exactly m repetitions of the term
    {m,} - matches m or more repetitions of the term
    ^ - matches the beginning of the string
    $ - matches the end of the string
    backslash - an escape character to indicate that the following character is a match criteria and not a grouping delimite
    """


class BgpExtCommunityRegexpTypeType2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+$).*$'
        ),
    ]
    """
    Type definition for extended community regular expressions

    The format embeds two regular expressions separated by one colon ':' character; the first expression is applied to the as-value of the community string and the second to the local administrative value

    Each regex is a sequence of terms and operators. A term can be:
     - a single digit, such as '4'
     - a range term composed of two elementary terms separated by the '-' character like '2-3'
     - the dot '.' wild-card character which matches any elementary term or ':'
     - a regular expression enclosed in parenthesis '( )'
     - a choice of digits and/or ranges enclosed in square brackets; for example, [51-37] matches digit 5 or any single digit between 1 and 3 or the digit 7

    Supported operators:
    | - match term on the left of the operator or the term on the right of the operator
    * - matches zero or more occurrences of the preceding term
    ? - matches zero or one occurrence of the preceding term
    + - matches one or more occurrences of the preceding term
    {m,n} - matches least m and at most n repetitions of the term
    {m} - matches exactly m repetitions of the term
    {m,} - matches m or more repetitions of the term
    ^ - matches the beginning of the string
    $ - matches the end of the string
    backslash - an escape character to indicate that the following character is a match criteria and not a grouping delimite
    """


class BgpExtCommunityType2Type1(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^link-bandwidth:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):[0-9]+[kMGT]?$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type3(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type4(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type5(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type6(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type7(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type8(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^color:[0-1]{2}:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community members
    """


class BgpExtCommunityType2Type9(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern='^(?=^bgp-tunnel-encap:(VXLAN|MPLS)$).*$')]
    """
    Type definition for extended community members
    """


class BgpExtCommunityTypeType1(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType2(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType3(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^target:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType4(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType5(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType6(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^origin:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType7(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^color:[0-1]{2}:(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpExtCommunityTypeType8(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern='^(?=^bgp-tunnel-encap:(VXLAN|MPLS)$).*$')]
    """
    Type definition for extended community attributes. In the case that
    common communities are utilised, they are represented as a string
    of the form:
     - target:<2b AS>:<4b value> per RFC4360 section 4
     - target:<4b IPv4>:<2b value> per RFC4360 section 4
     - origin:<2b ASN>:<4b value> per RFC4360 section 5
     - origin:<4b IPv4>:<2b value> per RFC4360 section 5
     - color:<CO bits>:<4b value> per draft-ietf-idr-segment-routing-te-policy
       section 3
     - bgp-tunnel-encap:VXLAN, bgp-tunnel-encap:MPLS
    """


class BgpLargeCommunityRegexpTypeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+$).*$'
        ),
    ]
    """
    Type definition for regular expressions that match large BGP communities
    """


class BgpLargeCommunityTypeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9]):(429496729[0-5]|42949672[0-8][0-9]|4294967[0-1][0-9]{2}|429496[0-6][0-9]{3}|42949[0-5][0-9]{4}|4294[0-8][0-9]{5}|429[0-3][0-9]{6}|42[0-8][0-9]{7}|4[0-1][0-9]{8}|[1-3][0-9]{9}|[1-9][0-9]{1,8}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for large commmunity values represented as a string of the form A:B:C where A, B and C are integers between 0 and 4294967295
    """


class BgpStdCommunityRegexpTypeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+:[0-9$()*+,.^{}\\[\\]\\-\\|?\\\\]+$).*$'
        ),
    ]
    """
    Type definition for regular expressions that match standard BGP communities
    """


class BgpStdCommunityTypeType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]):(6553[0-5]|655[0-2][0-9]|654[0-9]{2}|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9])$).*$'
        ),
    ]
    """
    Type definition for standard commmunity values represented as a string of the form N:M where N and M are integers between 0 and 65535
    """


class HexStringType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[str, Field(pattern='^(?=^([0-9a-fA-F]{2}(:[0-9a-fA-F]{2})*)?$).*$')]
    """
    A hexadecimal string with octets represented as hex digits
    separated by colons.  The canonical representation uses
    lowercase characters.
    """


class Ipv4PrefixType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/(([0-9])|([1-2][0-9])|(3[0-2]))$).*$'
        ),
    ]
    """
    An IPv4 prefix represented in dotted quad notation followed by a slash and a CIDR mask (0 <= mask <= 32).
    """


class Ipv6PrefixType(RootModel[str]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[
        str,
        Field(
            pattern='^(?=^((:|[0-9a-fA-F]{0,4}):)([0-9a-fA-F]{0,4}:){0,5}((([0-9a-fA-F]{0,4}:)?(:|[0-9a-fA-F]{0,4}))|(((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])))(/(([0-9])|([0-9]{2})|(1[0-1][0-9])|(12[0-8])))$).*$'
        ),
    ]
    """
    An IPv6 prefix represented in full, shortened, or mixed shortened format followed by a slash and CIDR mask (0 <= mask <=
    128).
    """


class ReplaceLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=4294967295)]
    """
    Clear the existing AS path and replace it a new AS_SEQUENCE containing the listed AS numbers.
    """


class ReplaceLeafList2(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=4294967295)]
    """
    Clear the existing AS path and replace it a new AS_SEQUENCE containing the listed AS numbers.
    """


class RouteTypeLeafList(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=8)]
    """
    An EVPN route meets this condition if the route-type field in the NLRI is one of the values provided in this list.
    """


class SetLeaf21(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    The new value of the Multi-Exit Discriminator attribute value to write into the matching BGP routes. The route-table-cost option derives the MED from the route metric.
    """


class SetLeaf71(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=0, le=4294967295)]
    """
    The new value of the Multi-Exit Discriminator attribute value to write into the matching BGP routes. The route-table-cost option derives the MED from the route metric.
    """


class StatisticsContainer(BaseModel):
    """
    BGP Labeled unicast tunnel statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ingress: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:ingress')
    ] = None
    """
    Ingress statistics collection for BGP-LU tunnels
    """
    egress: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:egress')
    ] = None
    """
    Egress statistics collection for BGP-LU tunnels
    """


class StatisticsContainer2(BaseModel):
    """
    BGP Labeled unicast tunnel statistics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ingress: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:ingress')
    ] = None
    """
    Ingress statistics collection for BGP-LU tunnels
    """
    egress: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:egress')
    ] = None
    """
    Egress statistics collection for BGP-LU tunnels
    """


class TagTypeType1(RootModel[int]):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    root: Annotated[int, Field(ge=1, le=4294967295)]
    """
    Type for expressing route tags on a local system, including IS-IS and OSPF

    May be expressed as either decimal or hexidecimal integer
    """


class EnumerationEnum(Enum):
    any = 'any'
    all = 'all'
    invert = 'invert'


class EnumerationEnum10(Enum):
    internal = 'internal'
    external = 'external'


class EnumerationEnum11(Enum):
    narrow = 'narrow'
    wide = 'wide'


class EnumerationEnum12(Enum):
    any = 'any'


class EnumerationEnum13(Enum):
    any = 'any'


class EnumerationEnum14(Enum):
    eq = 'eq'
    ge = 'ge'
    le = 'le'


class EnumerationEnum15(Enum):
    any = 'any'
    all = 'all'
    invert = 'invert'


class EnumerationEnum16(Enum):
    any = 'any'
    all = 'all'
    invert = 'invert'


class EnumerationEnum17(Enum):
    any = 'any'
    all = 'all'
    invert = 'invert'


class EnumerationEnum18(Enum):
    internal = 'internal'
    external = 'external'


class EnumerationEnum19(Enum):
    accept = 'accept'
    reject = 'reject'
    next_statement = 'next-statement'
    next_policy = 'next-policy'


class EnumerationEnum2(Enum):
    accept = 'accept'
    reject = 'reject'
    next_policy = 'next-policy'


class EnumerationEnum20(Enum):
    auto = 'auto'


class EnumerationEnum21(Enum):
    reference = 'reference'


class EnumerationEnum22(Enum):
    reference = 'reference'


class EnumerationEnum23(Enum):
    route_table_cost = 'route-table-cost'


class EnumerationEnum24(Enum):
    igp = 'igp'
    egp = 'egp'
    incomplete = 'incomplete'


class EnumerationEnum3(Enum):
    auto = 'auto'


class EnumerationEnum4(Enum):
    add = 'add'
    remove = 'remove'
    replace = 'replace'


class EnumerationEnum5(Enum):
    reference = 'reference'


class EnumerationEnum6(Enum):
    reference = 'reference'


class EnumerationEnum7(Enum):
    route_table_cost = 'route-table-cost'


class EnumerationEnum8(Enum):
    self = 'self'


class EnumerationEnum9(Enum):
    igp = 'igp'
    egp = 'egp'
    incomplete = 'incomplete'


class EvpnContainer(BaseModel):
    """
    Container for match conditions that are specific to BGP EVPN routes.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    route_type: Annotated[
        Optional[List[RouteTypeLeafList]],
        Field(alias='srl_nokia-routing-policy:route-type'),
    ] = []
    """
    An EVPN route meets this condition if the route-type field in the NLRI is one of the values provided in this list.
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


class LocalPreferenceContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:set', ge=0, le=4294967295)
    ] = None
    """
    The new value of LOCAL_PREF to write into the matching BGP routes
    """


class LocalPreferenceContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:set', ge=0, le=4294967295)
    ] = None
    """
    The new value of LOCAL_PREF to write into the matching BGP routes
    """


class OspfContainer(BaseModel):
    """
    Configuration for OSPF-specific policy match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    area_id: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:area-id',
            pattern='^(?=^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$).*$',
        ),
    ] = None
    """
    The area identifier as a dotted-quad.
    """
    route_type: Annotated[
        Optional[str], Field(alias='srl_nokia-routing-policy:route-type')
    ] = None
    """
    The OSPF route type.
    """
    instance_id: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:instance-id', ge=0, le=255)
    ] = None
    """
    OSPFv3 instance identifier
    """


class PrefixSidContainer(BaseModel):
    """
    RIB-OUT label is based on prefix SID configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    reuse_igp: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:reuse-igp')
    ] = None
    """
    When true use the programmed SR-IGP label index for the matching prefix, resulting in a stitch to the IGP segment routing tunnel
    """


class PrefixSidContainer2(BaseModel):
    """
    RIB-OUT label is based on prefix SID configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    reuse_igp: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:reuse-igp')
    ] = None
    """
    When true use the programmed SR-IGP label index for the matching prefix, resulting in a stitch to the IGP segment routing tunnel
    """


class PrefixContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:prefix-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a prefix set name
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum12],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = None


class PrependContainer(BaseModel):
    """
    Prepend a BGP AS number to the AS Path attribute of routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_number: Annotated[
        Optional[Union[AsNumberType, EnumerationEnum3]],
        Field(alias='srl_nokia-routing-policy:as-number'),
    ] = None
    """
    The AS number to prepend to the AS Path attributes

    If 'auto' is specified then the peer's AS number is used in the context of an import policy and the local AS number is used in the context of an export policy.
    """
    repeat_n: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:repeat-n', ge=1, le=50)
    ] = None
    """
    The number of repetitions of the prepended AS number
    """


class PrependContainer2(BaseModel):
    """
    Prepend a BGP AS number to the AS Path attribute of routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_number: Annotated[
        Optional[Union[AsNumberType, EnumerationEnum20]],
        Field(alias='srl_nokia-routing-policy:as-number'),
    ] = None
    """
    The AS number to prepend to the AS Path attributes

    If 'auto' is specified then the peer's AS number is used in the context of an import policy and the local AS number is used in the context of an export policy.
    """
    repeat_n: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:repeat-n', ge=1, le=50)
    ] = None
    """
    The number of repetitions of the prepended AS number
    """


class ReferencedSetsLeafList(RootModel[str]):
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
    A name used to identify the community set
    """


class ReferencedSetsLeafList2(RootModel[str]):
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
    A name used to identify the community set
    """


class ReferencedSetsLeafList3(RootModel[str]):
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
    A name used to identify the community set
    """


class ReferencedSetsLeafList4(RootModel[str]):
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
    A name used to identify the community set
    """


class RoutePreferenceContainer(BaseModel):
    """
    Options for modifying route preference
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:set', ge=0, le=255)
    ] = None
    """
    Overwrite the route preference with the specified value

    The IP route table preference is sometimes called the administrative distance of the route. In general, when comparing any two routes, the route with the lower preference is the one that is activated and used for forwarding.

    This action has an effect only in BGP import policies and VRF import policies
    """


class RoutePreferenceContainer2(BaseModel):
    """
    Options for modifying route preference
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:set', ge=0, le=255)
    ] = None
    """
    Overwrite the route preference with the specified value

    The IP route table preference is sometimes called the administrative distance of the route. In general, when comparing any two routes, the route with the lower preference is the one that is activated and used for forwarding.

    This action has an effect only in BGP import policies and VRF import policies
    """


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


class SourceAddressContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:prefix-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Multicast source IP address

    Source address can be configured as a prefix.
    """


class StandardCommunitySetListEntry(BaseModel):
    """
    List of BGP standard community sets containing only standard BGP communities
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the community set
    """
    member: Annotated[
        Optional[
            List[Union[BgpStdCommunityTypeType, BgpStdCommunityRegexpTypeType, str]]
        ],
        Field(alias='srl_nokia-routing-policy:member'),
    ] = []
    """
    An extended BGP community value or regular expression
    """


class StandardCommunityContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operation: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-routing-policy:operation')
    ] = None
    """
    The type of operation for modifying the community attribute with the specified values
    """
    referenced_sets: Annotated[
        Optional[List[ReferencedSetsLeafList]],
        Field(alias='srl_nokia-routing-policy:referenced-sets'),
    ] = []
    method: Annotated[
        Optional[EnumerationEnum5], Field(alias='srl_nokia-routing-policy:method')
    ] = 'reference'
    """
    Indicates the method used to specify the standard communities for the action
    """


class StandardCommunityContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    standard_community_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:standard-community-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a standard-community-set name

    A route meets this condition if the configured match-set-options apply to the referenced standard-community-set
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum15],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = 'any'
    """
    Options that determine the matching criteria that applies to the members in the referenced set
    """


class StandardCommunityContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operation: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-routing-policy:operation')
    ] = None
    """
    The type of operation for modifying the community attribute with the specified values
    """
    referenced_sets: Annotated[
        Optional[List[ReferencedSetsLeafList3]],
        Field(alias='srl_nokia-routing-policy:referenced-sets'),
    ] = []
    method: Annotated[
        Optional[EnumerationEnum21], Field(alias='srl_nokia-routing-policy:method')
    ] = 'reference'
    """
    Indicates the method used to specify the standard communities for the action
    """


class TagSetLeafList(RootModel[str]):
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


class TagSetListEntry(BaseModel):
    """
    List of administrative tag sets
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the tag set
    """
    tag_value: Annotated[
        Optional[List[Union[TagTypeType1, HexStringType]]],
        Field(alias='srl_nokia-routing-policy:tag-value'),
    ] = []
    """
    Value of the tag set member
    """
    tag_set_index: Annotated[
        Optional[int],
        Field(alias='srl_nokia-routing-policy:tag-set-index', ge=0, le=4294967295),
    ] = None
    """
    System-wide persistent unique identifier assigned to the tag-set
    """


class AsPathLengthContainer(BaseModel):
    """
    A BGP route matches this condition if the number of (unique) AS numbers in its AS_PATH matches this value or the range implied by the value+operator.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    value: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:value', ge=0, le=255)
    ] = None
    """
    The number of (unique) AS numbers in the AS path
    """
    operator: Annotated[
        Optional[EnumerationEnum14], Field(alias='srl_nokia-routing-policy:operator')
    ] = None
    """
    The comparison operator that applies to the value
    """
    unique: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:unique')
    ] = None
    """
    Count a repeated sequence of the same AS number as just 1 element
    """


class AsPathSetListEntry(BaseModel):
    """
    AS Path regular expressions for use in policy entries
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the AS path regular expression
    """
    expression: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:expression', max_length=65535, min_length=1
        ),
    ] = None
    """
    A regular expression where each AS number is an elemental term
    """
    as_path_set_member: Annotated[
        Optional[List[AsPathSetMemberLeafList]],
        Field(alias='srl_nokia-routing-policy:as-path-set-member'),
    ] = []
    """
    A list of regular expressions
    """


class AsPathContainer(BaseModel):
    """
    Modify AS Path attribute of routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    remove: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:remove')
    ] = None
    """
    Clear the AS path to make it empty.
    """
    replace: Annotated[
        Optional[List[ReplaceLeafList]], Field(alias='srl_nokia-routing-policy:replace')
    ] = []
    """
    Clear the existing AS path and replace it a new AS_SEQUENCE containing the listed AS numbers.
    """
    prepend: Annotated[
        Optional[PrependContainer], Field(alias='srl_nokia-routing-policy:prepend')
    ] = None


class AsPathContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_path_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:as-path-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to an as-path-set name

    A route meets this condition if it matches the regular expression
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum13],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = None


class AsPathContainer3(BaseModel):
    """
    Modify AS Path attribute of routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    remove: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:remove')
    ] = None
    """
    Clear the AS path to make it empty.
    """
    replace: Annotated[
        Optional[List[ReplaceLeafList2]],
        Field(alias='srl_nokia-routing-policy:replace'),
    ] = []
    """
    Clear the existing AS path and replace it a new AS_SEQUENCE containing the listed AS numbers.
    """
    prepend: Annotated[
        Optional[PrependContainer2], Field(alias='srl_nokia-routing-policy:prepend')
    ] = None


class CallPolicyLeafList(RootModel[str]):
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
    Call another policy as a subroutine

    If the final action of the called policy (which may in turn call other policies) with respect to a route is 'accept' then the route is considered to satisfy this match condition. If the final action of the called policy with respect to a route is 'reject' then the route is considered a non-match of this condition and hence the policy statement
    """


class CommunitiesContainer(BaseModel):
    """
    Modify BGP communities attached to routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    add: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:add',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    All of the non-regex community members in the referenced community-set are added to the COMMUNTIES and LARGE_COMMUNITIES attributes.
    """
    remove: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:remove',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    The communities in the route are compared to all of the community members in the referenced community-set, and all matching communities are removed from the COMMUNITIES and LARGE_COMMUNITIES  attributes.
    """
    replace: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:replace',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    All of the existing communities are deleted and then all of the non-regex community members in the referenced community-set are encoded in new COMMUNTIES and LARGE_COMMUNITIES attributes.
    """


class CommunitiesContainer2(BaseModel):
    """
    Modify BGP communities attached to routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    add: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:add',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    All of the non-regex community members in the referenced community-set are added to the COMMUNTIES and LARGE_COMMUNITIES attributes.
    """
    remove: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:remove',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    The communities in the route are compared to all of the community members in the referenced community-set, and all matching communities are removed from the COMMUNITIES and LARGE_COMMUNITIES  attributes.
    """
    replace: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:replace',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    All of the existing communities are deleted and then all of the non-regex community members in the referenced community-set are encoded in new COMMUNTIES and LARGE_COMMUNITIES attributes.
    """


class CommunitySetListEntry(BaseModel):
    """
    List of BGP community sets containing standard, extended and large BGP communities
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the community set
    """
    member: Annotated[
        Optional[
            List[
                Union[
                    BgpStdCommunityTypeType,
                    BgpLargeCommunityTypeType,
                    BgpLargeCommunityRegexpTypeType,
                    BgpStdCommunityRegexpTypeType,
                    str,
                    Union[
                        BgpExtCommunityTypeType1,
                        BgpExtCommunityTypeType2,
                        BgpExtCommunityTypeType3,
                        BgpExtCommunityTypeType4,
                        BgpExtCommunityTypeType5,
                        BgpExtCommunityTypeType6,
                        BgpExtCommunityTypeType7,
                        BgpExtCommunityTypeType8,
                    ],
                    Union[
                        BgpExtCommunityRegexpTypeType1, BgpExtCommunityRegexpTypeType2
                    ],
                ]
            ]
        ],
        Field(alias='srl_nokia-routing-policy:member'),
    ] = []
    """
    A standard BGP community value, regular expression or well-known name or else a large BGP community value or regular expression
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = 'all'
    """
    Options that determine the matching criteria that applies to the list of community members
    """


class ExtendedCommunitySetListEntry(BaseModel):
    """
    List of BGP extended community sets containing only extended BGP communities
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the community set
    """
    member: Annotated[
        Optional[
            List[
                Union[
                    Union[
                        BgpExtCommunityType2Type1,
                        BgpExtCommunityType2Type2,
                        BgpExtCommunityType2Type3,
                        BgpExtCommunityType2Type4,
                        BgpExtCommunityType2Type5,
                        BgpExtCommunityType2Type6,
                        BgpExtCommunityType2Type7,
                        BgpExtCommunityType2Type8,
                        BgpExtCommunityType2Type9,
                    ],
                    Union[
                        BgpExtCommunityRegexpType2Type1,
                        BgpExtCommunityRegexpType2Type2,
                        BgpExtCommunityRegexpType2Type3,
                    ],
                ]
            ]
        ],
        Field(alias='srl_nokia-routing-policy:member'),
    ] = []
    """
    An extended BGP community value or regular expression
    """


class ExtendedCommunityContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operation: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-routing-policy:operation')
    ] = None
    """
    The type of operation for modifying the community attribute with the specified values
    """
    referenced_sets: Annotated[
        Optional[List[ReferencedSetsLeafList2]],
        Field(alias='srl_nokia-routing-policy:referenced-sets'),
    ] = []
    method: Annotated[
        Optional[EnumerationEnum6], Field(alias='srl_nokia-routing-policy:method')
    ] = 'reference'
    """
    Indicates the method used to specify the extended communities for the action
    """


class ExtendedCommunityContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    extended_community_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:extended-community-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to an extended-community-set name

    A route meets this condition if the configured match-set-options apply to the referenced extended-community-set
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum16],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = 'any'
    """
    Options that determine the matching criteria that applies to the members in the referenced set
    """


class ExtendedCommunityContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    operation: Annotated[
        Optional[EnumerationEnum4], Field(alias='srl_nokia-routing-policy:operation')
    ] = None
    """
    The type of operation for modifying the community attribute with the specified values
    """
    referenced_sets: Annotated[
        Optional[List[ReferencedSetsLeafList4]],
        Field(alias='srl_nokia-routing-policy:referenced-sets'),
    ] = []
    method: Annotated[
        Optional[EnumerationEnum22], Field(alias='srl_nokia-routing-policy:method')
    ] = 'reference'
    """
    Indicates the method used to specify the extended communities for the action
    """


class GroupAddressContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:prefix-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Multicast group IP address

    <S,G> the source needs to be present in the multicast source-address leafref and the
    group needs to present in the group-address leafref.  To match a <*,G> the group has to
    be programmed in the group-address leafref and no source in the source-address leafref.
    Group address can be configured as a prefix.
    """


class InternalTagsContainer(BaseModel):
    """
    Configuration of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList]],
        Field(alias='srl_nokia-routing-policy:set-tag-set'),
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
    tag_set: Annotated[
        Optional[List[TagSetLeafList]], Field(alias='srl_nokia-routing-policy:tag-set')
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """
    match_set_options: Annotated[
        Optional[EnumerationEnum17],
        Field(alias='srl_nokia-routing-policy:match-set-options'),
    ] = 'any'
    """
    Options that determine the matching criteria that applies to the members in the referenced set
    """


class InternalTagsContainer3(BaseModel):
    """
    Configuration of internal tags
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[List[SetTagSetLeafList2]],
        Field(alias='srl_nokia-routing-policy:set-tag-set'),
    ] = []
    """
    Reference to a tag-set defined under routing-policy
    """


class IsisContainer2(BaseModel):
    """
    Configuration for ISIS-specific policy match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    level: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:level', ge=1, le=2)
    ] = None
    """
    Match an IS-IS route based on its level
    """
    route_type: Annotated[
        Optional[EnumerationEnum18], Field(alias='srl_nokia-routing-policy:route-type')
    ] = None
    """
    Match an IS-IS route based on its type

    An IS-IS IPv4 prefix is external if it is signalled in TLV 130 or TLV135 with RFC 7794 X flag=1. An IS-IS IPv6 prefix is external if the TLV 236/TLV 237 external bit = 1.
    """


class MedContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[Union[SetLeaf21, EnumerationEnum7]],
        Field(alias='srl_nokia-routing-policy:set'),
    ] = None
    """
    The new value of the Multi-Exit Discriminator attribute value to write into the matching BGP routes. The route-table-cost option derives the MED from the route metric.
    """


class MedContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[Union[SetLeaf71, EnumerationEnum23]],
        Field(alias='srl_nokia-routing-policy:set'),
    ] = None
    """
    The new value of the Multi-Exit Discriminator attribute value to write into the matching BGP routes. The route-table-cost option derives the MED from the route metric.
    """


class MetricContainer(BaseModel):
    """
    Policy actions related to ISIS metrics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_type: Annotated[
        Optional[EnumerationEnum10], Field(alias='srl_nokia-routing-policy:set-type')
    ] = None
    """
    Set the metric type, internal or external
    """
    set_style: Annotated[
        Optional[EnumerationEnum11], Field(alias='srl_nokia-routing-policy:set-style')
    ] = None
    """
    Set the style of the metric, narrow or wide
    """
    set_value: Annotated[
        Optional[int],
        Field(alias='srl_nokia-routing-policy:set-value', ge=0, le=16777215),
    ] = None
    """
    Set the metric of the IS-IS prefix
    """


class MetricContainer2(BaseModel):
    """
    Policy actions related to ISIS metrics
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_type: Annotated[
        Optional[EnumerationEnum10], Field(alias='srl_nokia-routing-policy:set-type')
    ] = None
    """
    Set the metric type, internal or external
    """
    set_style: Annotated[
        Optional[EnumerationEnum11], Field(alias='srl_nokia-routing-policy:set-style')
    ] = None
    """
    Set the style of the metric, narrow or wide
    """
    set_value: Annotated[
        Optional[int],
        Field(alias='srl_nokia-routing-policy:set-value', ge=0, le=16777215),
    ] = None
    """
    Set the metric of the IS-IS prefix
    """


class MulticastContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    group_address: Annotated[
        Optional[GroupAddressContainer],
        Field(alias='srl_nokia-routing-policy:group-address'),
    ] = None
    source_address: Annotated[
        Optional[SourceAddressContainer],
        Field(alias='srl_nokia-routing-policy:source-address'),
    ] = None


class NextHopResolutionContainer(BaseModel):
    """
    Actions related to next-hop resolution of matched BGP routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:set-tag-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a tag-set to be used for controlling next-hop resolution
    """


class NextHopResolutionContainer2(BaseModel):
    """
    Actions related to next-hop resolution of matched BGP routes
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set_tag_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:set-tag-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a tag-set to be used for controlling next-hop resolution
    """


class OriginContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[EnumerationEnum9], Field(alias='srl_nokia-routing-policy:set')
    ] = None
    """
    The new value of the ORIGIN attribute to write into the matching BGP routes
    """


class OriginContainer2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[EnumerationEnum24], Field(alias='srl_nokia-routing-policy:set')
    ] = None
    """
    The new value of the ORIGIN attribute to write into the matching BGP routes
    """


class PrefixSidCase(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_sid: Annotated[
        Optional[PrefixSidContainer], Field(alias='srl_nokia-routing-policy:prefix-sid')
    ] = None


class PrefixSidCase2(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_sid: Annotated[
        Optional[PrefixSidContainer2],
        Field(alias='srl_nokia-routing-policy:prefix-sid'),
    ] = None


class PrefixListEntry(BaseModel):
    """
    List of prefixes in the prefix set
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    ip_prefix: Annotated[
        Union[Ipv4PrefixType, Ipv6PrefixType],
        Field(alias='srl_nokia-routing-policy:ip-prefix'),
    ]
    """
    The IPv4 or IPv6 prefix in CIDR notation
    """
    mask_length_range: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:mask-length-range',
            pattern='^(?=^([0-9]+\\.\\.[0-9]+)|exact$).*$',
        ),
    ]
    """
    The range of prefix lengths to match

    Example: 10.3.192.0/21 through 10.3.192.0/24 would be expressed as prefix: 10.3.192.0/21, mask-length-range: 21..24.

    Example: 10.3.192.0/21 would be expressed as prefix: 10.3.192.0/21,
    mask-length-range: exact
    """


class BgpContainer2(BaseModel):
    """
    Configuration for BGP-specific policy match criteria
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_path_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:as-path-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to an as-path-set name

    A route meets this condition if it matches the regular expression
    """
    as_path: Annotated[
        Optional[AsPathContainer2], Field(alias='srl_nokia-routing-policy:as-path')
    ] = None
    as_path_length: Annotated[
        Optional[AsPathLengthContainer],
        Field(alias='srl_nokia-routing-policy:as-path-length'),
    ] = None
    community_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:community-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a community-set name

    A route meets this condition if has any community value matching a community member in the referenced community-set
    """
    standard_community: Annotated[
        Optional[StandardCommunityContainer2],
        Field(alias='srl_nokia-routing-policy:standard-community'),
    ] = None
    extended_community: Annotated[
        Optional[ExtendedCommunityContainer2],
        Field(alias='srl_nokia-routing-policy:extended-community'),
    ] = None
    evpn: Annotated[
        Optional[EvpnContainer], Field(alias='srl_nokia-routing-policy:evpn')
    ] = None


class IsisContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    level: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:level', ge=1, le=2)
    ] = None
    """
    Set the level that a prefix is to be imported into
    """
    metric: Annotated[
        Optional[MetricContainer], Field(alias='srl_nokia-routing-policy:metric')
    ] = None


class IsisContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    level: Annotated[
        Optional[int], Field(alias='srl_nokia-routing-policy:level', ge=1, le=2)
    ] = None
    """
    Set the level that a prefix is to be imported into
    """
    metric: Annotated[
        Optional[MetricContainer2], Field(alias='srl_nokia-routing-policy:metric')
    ] = None


class LabelAllocationContainer(BaseModel):
    """
    Actions that determine the method used to assign labels to BGP LU routes matched and accepted by route-table-import policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    label_allocation_method: Annotated[
        Optional[PrefixSidCase],
        Field(alias='srl_nokia-routing-policy:label-allocation-method'),
    ] = None


class LabelAllocationContainer2(BaseModel):
    """
    Actions that determine the method used to assign labels to BGP LU routes matched and accepted by route-table-import policies
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    label_allocation_method: Annotated[
        Optional[PrefixSidCase2],
        Field(alias='srl_nokia-routing-policy:label-allocation-method'),
    ] = None


class MatchContainer(BaseModel):
    """
    Match conditions of the policy statement
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    prefix_set: Annotated[
        Optional[str],
        Field(
            alias='srl_nokia-routing-policy:prefix-set',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ] = None
    """
    Reference to a prefix set name
    """
    prefix: Annotated[
        Optional[PrefixContainer], Field(alias='srl_nokia-routing-policy:prefix')
    ] = None
    bgp: Annotated[
        Optional[BgpContainer2], Field(alias='srl_nokia-routing-policy:bgp')
    ] = None
    family: Annotated[
        Optional[List[str]], Field(alias='srl_nokia-routing-policy:family')
    ] = []
    """
    The name of an address family

    A route meets this condition if the prefix belongs to one of the indicated address families.
    """
    protocol: Annotated[
        Optional[str], Field(alias='srl_nokia-routing-policy:protocol')
    ] = None
    """
    The route type to match
    """
    call_policy: Annotated[
        Optional[List[CallPolicyLeafList]],
        Field(alias='srl_nokia-routing-policy:call-policy'),
    ] = []
    """
    Call another policy as a subroutine

    If the final action of the called policy (which may in turn call other policies) with respect to a route is 'accept' then the route is considered to satisfy this match condition. If the final action of the called policy with respect to a route is 'reject' then the route is considered a non-match of this condition and hence the policy statement
    """
    internal_tags: Annotated[
        Optional[InternalTagsContainer2],
        Field(alias='srl_nokia-routing-policy:internal-tags'),
    ] = None
    isis: Annotated[
        Optional[IsisContainer2], Field(alias='srl_nokia-routing-policy:isis')
    ] = None
    ospf: Annotated[
        Optional[OspfContainer], Field(alias='srl_nokia-routing-policy:ospf')
    ] = None
    multicast: Annotated[
        Optional[MulticastContainer], Field(alias='srl_nokia-routing-policy:multicast')
    ] = None


class PrefixSetListEntry(BaseModel):
    """
    List of defined prefix sets
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the prefix set
    """
    prefix: Annotated[
        Optional[List[PrefixListEntry]], Field(alias='srl_nokia-routing-policy:prefix')
    ] = None


class NextHopContainer(BaseModel):
    """
    Container for BGP next-hop modifications
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[Union[EnumerationEnum8, Union[Ipv4AddressType, Ipv6AddressType]]],
        Field(alias='srl_nokia-routing-policy:set'),
    ] = None
    """
    Set the protocol next-hop addres of matched BGP routes
    """


class NextHopContainer2(BaseModel):
    """
    Container for BGP next-hop modifications
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    set: Annotated[
        Optional[Union[EnumerationEnum8, Union[Ipv4AddressType, Ipv6AddressType]]],
        Field(alias='srl_nokia-routing-policy:set'),
    ] = None
    """
    Set the protocol next-hop addres of matched BGP routes
    """


class BgpContainer(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_path: Annotated[
        Optional[AsPathContainer], Field(alias='srl_nokia-routing-policy:as-path')
    ] = None
    communities: Annotated[
        Optional[CommunitiesContainer],
        Field(alias='srl_nokia-routing-policy:communities'),
    ] = None
    standard_community: Annotated[
        Optional[StandardCommunityContainer],
        Field(alias='srl_nokia-routing-policy:standard-community'),
    ] = None
    extended_community: Annotated[
        Optional[ExtendedCommunityContainer],
        Field(alias='srl_nokia-routing-policy:extended-community'),
    ] = None
    disable_ip_route_install: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:disable-ip-route-install')
    ] = None
    """
    Accept the route, allowing its re-advertisement, but do not install the route to the IP FIB
    """
    local_preference: Annotated[
        Optional[LocalPreferenceContainer],
        Field(alias='srl_nokia-routing-policy:local-preference'),
    ] = None
    med: Annotated[
        Optional[MedContainer], Field(alias='srl_nokia-routing-policy:med')
    ] = None
    next_hop: Annotated[
        Optional[NextHopContainer], Field(alias='srl_nokia-routing-policy:next-hop')
    ] = None
    next_hop_resolution: Annotated[
        Optional[NextHopResolutionContainer],
        Field(alias='srl_nokia-routing-policy:next-hop-resolution'),
    ] = None
    origin: Annotated[
        Optional[OriginContainer], Field(alias='srl_nokia-routing-policy:origin')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer],
        Field(alias='srl_nokia-routing-policy:statistics'),
    ] = None
    label_allocation: Annotated[
        Optional[LabelAllocationContainer],
        Field(alias='srl_nokia-routing-policy:label-allocation'),
    ] = None


class BgpContainer3(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_path: Annotated[
        Optional[AsPathContainer3], Field(alias='srl_nokia-routing-policy:as-path')
    ] = None
    communities: Annotated[
        Optional[CommunitiesContainer2],
        Field(alias='srl_nokia-routing-policy:communities'),
    ] = None
    standard_community: Annotated[
        Optional[StandardCommunityContainer3],
        Field(alias='srl_nokia-routing-policy:standard-community'),
    ] = None
    extended_community: Annotated[
        Optional[ExtendedCommunityContainer3],
        Field(alias='srl_nokia-routing-policy:extended-community'),
    ] = None
    disable_ip_route_install: Annotated[
        Optional[bool], Field(alias='srl_nokia-routing-policy:disable-ip-route-install')
    ] = None
    """
    Accept the route, allowing its re-advertisement, but do not install the route to the IP FIB
    """
    local_preference: Annotated[
        Optional[LocalPreferenceContainer2],
        Field(alias='srl_nokia-routing-policy:local-preference'),
    ] = None
    med: Annotated[
        Optional[MedContainer2], Field(alias='srl_nokia-routing-policy:med')
    ] = None
    next_hop: Annotated[
        Optional[NextHopContainer2], Field(alias='srl_nokia-routing-policy:next-hop')
    ] = None
    next_hop_resolution: Annotated[
        Optional[NextHopResolutionContainer2],
        Field(alias='srl_nokia-routing-policy:next-hop-resolution'),
    ] = None
    origin: Annotated[
        Optional[OriginContainer2], Field(alias='srl_nokia-routing-policy:origin')
    ] = None
    statistics: Annotated[
        Optional[StatisticsContainer2],
        Field(alias='srl_nokia-routing-policy:statistics'),
    ] = None
    label_allocation: Annotated[
        Optional[LabelAllocationContainer2],
        Field(alias='srl_nokia-routing-policy:label-allocation'),
    ] = None


class DefaultActionContainer(BaseModel):
    """
    Actions for routes that do not match any policy entry
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policy_result: Annotated[
        Optional[EnumerationEnum2],
        Field(alias='srl_nokia-routing-policy:policy-result'),
    ] = None
    """
    Select the action type for routes that do not match any policy statement.
    """
    bgp: Annotated[
        Optional[BgpContainer], Field(alias='srl_nokia-routing-policy:bgp')
    ] = None
    isis: Annotated[
        Optional[IsisContainer], Field(alias='srl_nokia-routing-policy:isis')
    ] = None
    route_preference: Annotated[
        Optional[RoutePreferenceContainer],
        Field(alias='srl_nokia-routing-policy:route-preference'),
    ] = None
    internal_tags: Annotated[
        Optional[InternalTagsContainer],
        Field(alias='srl_nokia-routing-policy:internal-tags'),
    ] = None


class ActionContainer(BaseModel):
    """
    Actions for routes that match the policy statement
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    policy_result: Annotated[
        Optional[EnumerationEnum19],
        Field(alias='srl_nokia-routing-policy:policy-result'),
    ] = None
    """
    Select the action to apply to matching routes

    If no value is configured for the policy-result then the entire statement is skipped and ignored.
    """
    bgp: Annotated[
        Optional[BgpContainer3], Field(alias='srl_nokia-routing-policy:bgp')
    ] = None
    isis: Annotated[
        Optional[IsisContainer3], Field(alias='srl_nokia-routing-policy:isis')
    ] = None
    route_preference: Annotated[
        Optional[RoutePreferenceContainer2],
        Field(alias='srl_nokia-routing-policy:route-preference'),
    ] = None
    internal_tags: Annotated[
        Optional[InternalTagsContainer3],
        Field(alias='srl_nokia-routing-policy:internal-tags'),
    ] = None


class StatementListEntry(BaseModel):
    """
    Policy statements group conditions and actions within a policy definition.  They are evaluated in configuration order.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    Name given to the policy statement (rule).
    """
    match: Annotated[
        Optional[MatchContainer], Field(alias='srl_nokia-routing-policy:match')
    ] = None
    action: Annotated[
        Optional[ActionContainer], Field(alias='srl_nokia-routing-policy:action')
    ] = None


class PolicyListEntry(BaseModel):
    """
    List of policy definitions, keyed by unique name
    These policy definitions are expected to be referenced (by name) in policy in import-policy and/or export-policy statements.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    name: Annotated[
        str,
        Field(
            alias='srl_nokia-routing-policy:name',
            pattern='^(?=^[A-Za-z0-9!@#$%^&()|+=`~.,/_:;?-][A-Za-z0-9 !@#$%^&()|+=`~.,/_:;?-]*$).*$',
        ),
    ]
    """
    A name used to identify the policy
    """
    default_action: Annotated[
        Optional[DefaultActionContainer],
        Field(alias='srl_nokia-routing-policy:default-action'),
    ] = None
    statement: Annotated[
        Optional[List[StatementListEntry]],
        Field(alias='srl_nokia-routing-policy:statement'),
    ] = None


class RoutingPolicyContainer(BaseModel):
    """
    Top-level container for all routing policy configuration
    """

    model_config = ConfigDict(
        populate_by_name=True,
        regex_engine="python-re",
    )
    as_path_set: Annotated[
        Optional[List[AsPathSetListEntry]],
        Field(alias='srl_nokia-routing-policy:as-path-set'),
    ] = None
    prefix_set: Annotated[
        Optional[List[PrefixSetListEntry]],
        Field(alias='srl_nokia-routing-policy:prefix-set'),
    ] = None
    community_set: Annotated[
        Optional[List[CommunitySetListEntry]],
        Field(alias='srl_nokia-routing-policy:community-set'),
    ] = None
    standard_community_set: Annotated[
        Optional[List[StandardCommunitySetListEntry]],
        Field(alias='srl_nokia-routing-policy:standard-community-set'),
    ] = None
    extended_community_set: Annotated[
        Optional[List[ExtendedCommunitySetListEntry]],
        Field(alias='srl_nokia-routing-policy:extended-community-set'),
    ] = None
    tag_set: Annotated[
        Optional[List[TagSetListEntry]], Field(alias='srl_nokia-routing-policy:tag-set')
    ] = None
    policy: Annotated[
        Optional[List[PolicyListEntry]], Field(alias='srl_nokia-routing-policy:policy')
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
    routing_policy: Annotated[
        Optional[RoutingPolicyContainer],
        Field(alias='srl_nokia-routing-policy:routing-policy'),
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