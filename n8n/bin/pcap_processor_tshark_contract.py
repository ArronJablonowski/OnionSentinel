"""Immutable TShark field and command contract."""
from __future__ import annotations

from pathlib import Path


FIELD_NAMES = (
    "frame_number", "timestamp_epoch", "frame_length", "protocol",
    "ipv4_src", "ipv6_src", "ipv4_dst", "ipv6_dst",
    "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
    "dns_query", "dns_query_type", "dns_rcode", "dns_answer_ipv4",
    "dns_answer_ipv6", "dns_cname", "tls_sni", "tls_handshake_version",
    "tls_supported_version", "tls_record_version", "http_host", "http_uri",
    "http_user_agent", "http2_user_agent", "icmp_type", "icmp_code",
    "icmpv6_type", "icmpv6_code", "icmp_identifier", "icmp_sequence",
    "data_length", "data_payload",
)

TSHARK_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a", "dns.aaaa",
    "dns.cname", "tls.handshake.extensions_server_name", "tls.handshake.version",
    "tls.handshake.extensions.supported_version", "tls.record.version",
    "http.host", "http.request.uri", "http.user_agent",
    "http2.headers.user_agent", "icmp.type", "icmp.code", "icmpv6.type",
    "icmpv6.code", "icmp.ident", "icmp.seq", "data.len", "data.data",
)


def tshark_command(
    executable: str,
    pcap: Path,
    occurrence_separator: str,
) -> list[str]:
    """Build the stable full-field streaming command."""
    command = [
        executable,
        "-n",
        "-r",
        str(pcap),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-E",
        f"aggregator={occurrence_separator}",
    ]
    for field_name in TSHARK_FIELDS:
        command.extend(["-e", field_name])
    return command
