"""Bounded packet decoding and deployed-rule predicate primitives."""
from __future__ import annotations

from detection_validation_rule import *  # noqa: F401,F403
from detection_validation_rule import _nested  # noqa: F401
def _network_packet_envelope(packet: bytes, linktype: int = 1) -> dict[str, Any] | None:
    """Return bounded IP transport metadata without exposing packet contents."""
    if not packet or len(packet) > MAX_PACKET_BYTES:
        return None
    offset = 0
    ethertype = 0
    if linktype == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack("!H", packet[12:14])[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(packet) < offset + 4:
                return None
            ethertype = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
            offset += 4
    elif packet[0] >> 4 == 4:
        ethertype = 0x0800
    elif packet[0] >> 4 == 6:
        ethertype = 0x86DD
    if ethertype == 0x0800:
        if len(packet) < offset + 20 or packet[offset] >> 4 != 4:
            return None
        ihl = (packet[offset] & 0x0F) * 4
        if ihl < 20 or len(packet) < offset + ihl:
            return None
        total_length = struct.unpack("!H", packet[offset + 2:offset + 4])[0]
        if total_length < ihl:
            return None
        end = min(len(packet), offset + total_length)
        return {
            "family": "ipv4",
            "protocol_number": int(packet[offset + 9]),
            "transport_offset": offset + ihl,
            "end": end,
        }
    if ethertype == 0x86DD:
        if len(packet) < offset + 40 or packet[offset] >> 4 != 6:
            return None
        payload_length = struct.unpack("!H", packet[offset + 4:offset + 6])[0]
        end = min(len(packet), offset + 40 + payload_length)
        return {
            "family": "ipv6",
            "protocol_number": int(packet[offset + 6]),
            "transport_offset": offset + 40,
            "end": end,
        }
    return None


def _udp_from_packet(
    packet: bytes,
    envelope: dict[str, Any],
) -> dict[str, Any] | None:
    if int(envelope.get("protocol_number", -1)) != 17:
        return None
    offset = int(envelope.get("transport_offset") or 0)
    end = int(envelope.get("end") or 0)
    if offset < 0 or end < offset + 8 or len(packet) < offset + 8:
        return None
    source_port, destination_port, udp_length = struct.unpack(
        "!HHH", packet[offset:offset + 6]
    )
    if udp_length < 8 or offset + udp_length > end:
        return None
    return {
        "source_port": source_port,
        "destination_port": destination_port,
        "payload_length": udp_length - 8,
        "_payload": packet[offset + 8:offset + udp_length],
    }


def _stun_binding_semantics(payload: bytes) -> dict[str, Any] | None:
    """Recognize a complete RFC 5389 STUN message without retaining identifiers."""
    if len(payload) < 20:
        return None
    message_type, message_length, magic_cookie = struct.unpack("!HHI", payload[:8])
    if message_type & 0xC000 or magic_cookie != 0x2112A442:
        return None
    if message_length % 4 or 20 + message_length > len(payload):
        return None
    method = (
        (message_type & 0x000F)
        | ((message_type & 0x00E0) >> 1)
        | ((message_type & 0x3E00) >> 2)
    )
    message_class = ((message_type & 0x0010) >> 4) | ((message_type & 0x0100) >> 7)
    if method != 0x001:
        return None
    kind = {
        0: "binding_request",
        1: "binding_indication",
        2: "binding_success_response",
        3: "binding_error_response",
    }.get(message_class)
    if kind is None:
        return None
    return {
        "kind": kind,
        "declared_body_bytes": message_length,
    }


def _bounded_counter(counter: collections.Counter[int]) -> list[dict[str, int]]:
    return [
        {"value": int(value), "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _bounded_text_counter(counter: collections.Counter[str]) -> list[dict[str, Any]]:
    return [
        {"value": str(value)[:80], "count": int(count)}
        for value, count in counter.most_common(MAX_COUNTER_VALUES)
    ]


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = collections.Counter(payload)
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def marker_specs(rule_context: dict[str, Any], playbook: dict[str, Any] | None) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    parsed_rule = rule_context.get("parsed_rule")
    if isinstance(parsed_rule, dict):
        for item in parsed_rule.get("contents", []) if isinstance(parsed_rule.get("contents"), list) else []:
            if not isinstance(item, dict) or not str(item.get("hex") or ""):
                continue
            specs.append({
                "id": str(item.get("id") or f"deployed-content-{len(specs) + 1}")[:100],
                "hex": str(item.get("hex") or "")[:512],
                "modifiers": dict(item.get("modifiers") or {}) if isinstance(item.get("modifiers"), dict) else {},
                "buffer": str(item.get("buffer") or "")[:80],
                "negated": bool(item.get("negated")),
                "source": "deployed_rule",
            })
    if isinstance(playbook, dict):
        values = playbook.get("marker_predicates")
        for item in values if isinstance(values, list) else []:
            if not isinstance(item, dict) or not str(item.get("hex") or ""):
                continue
            applies = (
                {str(value) for value in item.get("applies_to_sids", [])}
                if isinstance(item.get("applies_to_sids"), list)
                else set()
            )
            if applies and str(rule_context.get("sid") or "") not in applies:
                continue
            specs.append({
                "id": str(item.get("id") or f"playbook-marker-{len(specs) + 1}")[:100],
                "hex": str(item.get("hex") or "")[:512],
                "expected_offset": item.get("expected_offset"),
                "modifiers": {},
                "negated": False,
                "source": "playbook",
            })
    unique: list[dict[str, Any]] = []
    seen = set()
    for item in specs:
        key = (item["id"], item["hex"].lower())
        if key not in seen and len(unique) < MAX_MARKERS:
            seen.add(key)
            unique.append(item)
    return unique


def _nonnegative_modifier(value: object) -> int | None:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+", text):
        return None
    return int(text)


def _content_constraint(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
) -> bool | None:
    """Evaluate the supported subset of Suricata payload-content semantics."""
    positions = _content_match_positions(payload, marker, spec)
    if positions is None:
        return None
    present = bool(positions)
    return not present if bool(spec.get("negated")) else present


def _content_evaluation_supported(
    spec: dict[str, Any],
    *,
    application_buffer: str | None = None,
) -> bool:
    """Return whether a content clause can use the supplied bounded buffer."""
    if spec.get("source") != "deployed_rule":
        return True
    buffer_name = str(spec.get("buffer") or "").strip().lower()
    modifiers = (
        spec.get("modifiers")
        if isinstance(spec.get("modifiers"), dict)
        else {}
    )
    if application_buffer is None:
        if buffer_name not in {"", "pkt_data"}:
            return False
        if any(name in modifiers for name in ("dotprefix", "bsize")):
            return False
    elif buffer_name != application_buffer:
        return False
    if "rawbytes" in modifiers:
        return False
    if "bsize" in modifiers and _nonnegative_modifier(
        modifiers.get("bsize")
    ) is None:
        return False
    return True


def _content_match_positions(
    payload: bytes,
    marker: bytes,
    spec: dict[str, Any],
    *,
    previous_match_end: int | None = None,
    application_buffer: str | None = None,
) -> list[int] | None:
    """Return bounded matches for one absolute or cursor-relative content clause."""
    if not _content_evaluation_supported(
        spec,
        application_buffer=application_buffer,
    ):
        return None
    modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
    if "bsize" in modifiers:
        expected_size = _nonnegative_modifier(modifiers.get("bsize"))
        if expected_size is None:
            return None
        if len(payload) != expected_size:
            return []
    if application_buffer is not None and "dotprefix" in modifiers:
        # Suricata's dotprefix transform gives a domain buffer one virtual
        # leading dot so `.example.com` also matches the apex `example.com`.
        payload = b"." + payload.lstrip(b".")
    relative = "distance" in modifiers or "within" in modifiers
    if relative and any(key in modifiers for key in ("offset", "depth")):
        return None
    if relative:
        if previous_match_end is None:
            return None
        distance = 0
        if "distance" in modifiers:
            distance = _nonnegative_modifier(modifiers.get("distance"))
            if distance is None:
                return None
        start = previous_match_end + distance
        end = len(payload)
        if "within" in modifiers:
            within = _nonnegative_modifier(modifiers.get("within"))
            if within is None:
                return None
            end = min(len(payload), start + within)
    else:
        start = 0
        if "offset" in modifiers:
            start = _nonnegative_modifier(modifiers.get("offset"))
            if start is None:
                return None
        end = len(payload)
        if "depth" in modifiers:
            depth = _nonnegative_modifier(modifiers.get("depth"))
            if depth is None:
                return None
            end = min(len(payload), start + depth)
    if start < 0 or start > len(payload) or end < start:
        return []
    haystack = payload.lower() if "nocase" in modifiers else payload
    needle = marker.lower() if "nocase" in modifiers else marker
    if "startswith" in modifiers:
        if start <= 0 and len(needle) <= end and haystack.startswith(needle):
            return [0]
        return []
    if "endswith" in modifiers:
        position = len(haystack) - len(needle)
        if position >= start and position + len(needle) <= end and haystack.endswith(needle):
            return [position]
        return []
    positions: list[int] = []
    cursor = start
    while len(positions) < MAX_MARKER_MATCHES_PER_PACKET:
        position = haystack.find(needle, cursor, end)
        if position < 0:
            break
        positions.append(position)
        cursor = position + 1
    return positions


def _ordered_deployed_content_constraints(
    payload: bytes,
    marker_values: list[tuple[dict[str, Any], bytes]],
    *,
    application_buffer: str | None = None,
) -> dict[str, bool | None]:
    """Evaluate deployed content clauses in rule order with bounded cursor paths."""
    results: dict[str, bool | None] = {}
    cursors: set[int | None] = {None}
    cursor_unknown = False
    current_buffer: str | None = None
    for spec, marker in marker_values:
        if spec.get("source") != "deployed_rule":
            continue
        marker_id = str(spec["id"])
        modifiers = spec.get("modifiers") if isinstance(spec.get("modifiers"), dict) else {}
        relative = "distance" in modifiers or "within" in modifiers
        buffer_name = str(spec.get("buffer") or "pkt_data").strip().lower()
        if buffer_name != current_buffer:
            current_buffer = buffer_name
            cursors = {None}
            cursor_unknown = False
        if relative and not cursors:
            results[marker_id] = None if cursor_unknown else False
            continue
        if relative:
            candidate_cursors = sorted(
                cursors,
                key=lambda value: -1 if value is None else value,
            )
        else:
            candidate_cursors = [None]
        supported = True
        satisfied = False
        next_cursors: set[int | None] = set()
        for previous_end in candidate_cursors[:MAX_MARKER_MATCHES_PER_PACKET]:
            positions = _content_match_positions(
                payload,
                marker,
                spec,
                previous_match_end=previous_end,
                application_buffer=application_buffer,
            )
            if positions is None:
                supported = False
                continue
            if spec.get("negated"):
                if not positions:
                    satisfied = True
                    if relative:
                        next_cursors.add(previous_end)
                    else:
                        next_cursors.update(cursors)
                continue
            if positions:
                satisfied = True
                next_cursors.update(
                    position + len(marker)
                    for position in positions[:MAX_MARKER_MATCHES_PER_PACKET]
                )
        if not supported:
            results[marker_id] = None
            cursors = set()
            cursor_unknown = True
            continue
        results[marker_id] = satisfied
        cursors = next_cursors if satisfied else set()
        cursor_unknown = False
    return results


def _bounded_application_buffers(
    raw: dict[str, Any],
    message: dict[str, Any],
    alert: dict[str, Any],
    marker_values: list[tuple[dict[str, Any], bytes]] | None = None,
) -> dict[str, bytes]:
    """Project Suricata application evidence without retaining raw payloads."""
    decoded_value = (
        _nested(raw, "network.data.decoded")
        or message.get("payload_printable")
        or ""
    )
    decoded = (
        str(decoded_value)
        if isinstance(decoded_value, str)
        and len(decoded_value.encode("utf-8", "replace")) <= MAX_PACKET_BYTES
        else ""
    )
    buffers: dict[str, bytes] = {}
    if decoded:
        lines = re.split(r"\r?\n", decoded)
        if lines:
            request = lines[0].split()
            if len(request) >= 2 and re.fullmatch(
                r"[A-Z]{2,16}",
                request[0],
            ):
                buffers["http.method"] = request[0].encode(
                    "latin-1",
                    "replace",
                )
                buffers["http.uri"] = request[1].encode(
                    "latin-1",
                    "replace",
                )
        for line in lines[1:256]:
            name, separator, value = line.partition(":")
            if not separator:
                continue
            key = {
                "host": "http.host",
                "server": "http.server",
                "user-agent": "http.user_agent",
            }.get(name.strip().lower())
            if key and value.strip():
                buffers[key] = value.strip().encode(
                    "latin-1",
                    "replace",
                )[:MAX_PACKET_BYTES]

    dns_name = str(
        _nested(raw, "dns.query.name")
        or _nested(raw, "dns.question.name")
        or _nested(raw, "dns.query_name")
        or _nested(alert, "dns.query_name")
        or _nested(message, "dns.rrname")
        or ""
    ).strip().rstrip(".")
    if dns_name and len(dns_name.encode("utf-8", "replace")) <= 253:
        buffers["dns.query"] = dns_name.encode("utf-8", "replace")

    tls_name = str(
        _nested(raw, "tls.server.name")
        or _nested(raw, "tls.sni")
        or _nested(alert, "tls.server.name")
        or _nested(alert, "tls.sni")
        or _nested(message, "tls.sni")
        or ""
    ).strip().rstrip(".")
    if not tls_name and decoded:
        # Suricata's decoded ClientHello projection contains the SNI as a
        # bounded printable hostname. Select only a single canonical domain
        # token; ambiguity remains unsupported instead of guessing.
        candidates = {
            value.rstrip(".").lower()
            for value in re.findall(
                r"(?i)(?<![A-Za-z0-9-])"
                r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"[A-Za-z]{2,63}(?![A-Za-z0-9-])",
                decoded,
            )
            if len(value) <= 253
        }
        tls_markers = {
            marker.decode("latin-1", "ignore").lower().lstrip(".")
            for spec, marker in marker_values or []
            if str(spec.get("buffer") or "").strip().lower() == "tls.sni"
        }
        matching = {
            candidate
            for candidate in candidates
            if any(
                candidate == marker or candidate.endswith(f".{marker}")
                for marker in tls_markers
                if marker
            )
        }
        if len(matching) == 1:
            tls_name = next(iter(matching))
    if tls_name and len(tls_name.encode("utf-8", "replace")) <= 253:
        buffers["tls.sni"] = tls_name.encode("utf-8", "replace")
    return buffers
