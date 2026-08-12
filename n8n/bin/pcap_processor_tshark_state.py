"""Bounded mutable aggregation state for TShark evidence."""
from __future__ import annotations

from collections import Counter
from typing import Any


class TsharkState:
    """Own bounded counters while raw line payloads remain ephemeral."""

    def __init__(
        self,
        dependencies: dict[str, Any],
        limits: dict[str, int],
        markers: list[dict[str, Any]] | None,
        selected_scope: dict[str, Any] | None,
    ) -> None:
        self.commands: list[dict[str, Any]] = []
        self.per_file: list[dict[str, Any]] = []
        self._init_collections(dependencies, limits)
        self.pending_icmp_requests: dict[tuple[str, str, str, str], float] = {}
        self.marker_values: list[tuple[dict[str, Any], bytes]] = []
        self.marker_offsets: dict[str, Any] = {}
        self.marker_packet_counts: Counter[str] = Counter()
        self._admit_markers(markers, dependencies["BoundedTopCounter"])
        self._init_counts()
        self._init_scope(selected_scope)
        self.summary_limit = limits["summary_limit"]
        self.query_index_limit = limits["query_index_limit"]
        self.heavy_hitter_capacity = limits["heavy_hitter_capacity"]
        self.sample_limit = limits["sample_limit"]
        self.icmp_pair_state_limit = limits["icmp_pair_state_limit"]
        self.icmp_abnormal_min_frame_bytes = limits["icmp_abnormal_min_frame_bytes"]

    def _init_collections(
        self,
        dependencies: dict[str, Any],
        limits: dict[str, int],
    ) -> None:
        counter = dependencies["BoundedTopCounter"]
        reservoir = dependencies["DeterministicReservoir"]
        heavy = limits["heavy_hitter_capacity"]
        query_limit = limits["query_index_limit"]
        sample_limit = limits["sample_limit"]
        self.coverage = dependencies["CoverageTracker"]()
        self.reservoir = reservoir(sample_limit)
        self.dns_record_samples = reservoir(query_limit)
        self.tls_record_samples = reservoir(query_limit)
        self.http_record_samples = reservoir(query_limit)
        self.icmp_fact_samples = reservoir(query_limit)
        self.protocols = counter(128)
        self.conversations = counter(heavy)
        self.dns_queries = counter(heavy)
        self.dns_answers = counter(heavy)
        self.dns_query_types = counter(128)
        self.dns_rcodes = counter(128)
        self.user_agents = counter(heavy)
        self.tls_versions = counter(128)
        self.icmp_anomalies = counter(heavy)
        self.icmp_anomaly_samples = reservoir(min(sample_limit, 100))
        self.icmp_type_codes = counter(128)
        self.icmp_identifiers = counter(heavy)
        self.icmp_sequences = counter(heavy)
        self.icmp_payload_lengths = counter(heavy)
        self.icmp_pair_latencies = counter(heavy)
        self.geoip_candidates = counter(heavy)

    def _init_counts(self) -> None:
        self.dns_packet_count = 0
        self.dns_query_count = 0
        self.dns_answer_count = 0
        self.user_agent_count = 0
        self.tls_version_observation_count = 0
        self.icmp_packet_count = 0
        self.capture_icmp_packet_count = 0
        self.icmp_excluded_endpoint = 0
        self.icmp_excluded_time = 0
        self.icmp_excluded_missing_timestamp = 0
        self.icmp_abnormal_count = 0
        self.icmp_max_frame_bytes = 0

    def _init_scope(self, selected_scope: object) -> None:
        self.scope = selected_scope if isinstance(selected_scope, dict) else {}
        self.endpoint_filter_applied = bool(
            self.scope.get("source_ip") or self.scope.get("destination_ip")
        )
        self.endpoint_pair_complete = bool(
            self.scope.get("source_ip") and self.scope.get("destination_ip")
        )
        self.time_filter_applied = isinstance(
            self.scope.get("window_start_epoch"), (int, float)
        ) and isinstance(self.scope.get("window_end_epoch"), (int, float))
        self.files_processed = 0

    def _admit_markers(self, markers: object, counter: Any) -> None:
        for marker in markers if isinstance(markers, list) else []:
            if not isinstance(marker, dict):
                continue
            try:
                decoded = bytes.fromhex(str(marker.get("hex") or ""))
            except ValueError:
                continue
            marker_id = str(marker.get("id") or "")[:100]
            if not marker_id or not decoded:
                continue
            self.marker_values.append((marker, decoded))
            self.marker_offsets[marker_id] = counter(128)
