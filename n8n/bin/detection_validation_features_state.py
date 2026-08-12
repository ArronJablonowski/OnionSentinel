"""Mutable bounded aggregation state for detection packet features."""
from __future__ import annotations

import collections


class FeatureState:
    """Own counters while keeping raw packet bytes out of the public result."""

    def __init__(self, marker_values: list[tuple[dict[str, object], bytes]]) -> None:
        self.type_counts: collections.Counter[int] = collections.Counter()
        self.code_counts: collections.Counter[int] = collections.Counter()
        self.identifiers: collections.Counter[int] = collections.Counter()
        self.sequences: collections.Counter[int] = collections.Counter()
        self.payload_lengths: collections.Counter[int] = collections.Counter()
        self.frame_lengths: collections.Counter[int] = collections.Counter()
        self.marker_offsets: dict[str, collections.Counter[int]] = {
            str(item["id"]): collections.Counter() for item, _ in marker_values
        }
        self.marker_packets: collections.Counter[str] = collections.Counter()
        self.marker_constraint_evaluated: collections.Counter[str] = collections.Counter()
        self.marker_constraint_satisfied: collections.Counter[str] = collections.Counter()
        self.marker_constraint_violated: collections.Counter[str] = collections.Counter()
        self.marker_constraint_unsupported: set[str] = set()
        self.entropies: list[float] = []
        self.parsed_packet_count = 0
        self.content_packet_count = 0
        self.icmp_packet_count = 0
        self.udp_packet_count = 0
        self.unsupported_protocol_packets = 0
        self.protocol_counts: collections.Counter[str] = collections.Counter()
        self.udp_payload_lengths: collections.Counter[int] = collections.Counter()
        self.stun_kinds: collections.Counter[str] = collections.Counter()
        self.stun_body_lengths: collections.Counter[int] = collections.Counter()
        self.candidate_count = 0
        self.parse_errors = 0
        self.truncated = False
