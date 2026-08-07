"""Structured Security Onion evidence sections for alert-detail reports."""
from __future__ import annotations

from dashboard_alert_detail_values import (
    detail_table,
    nested_object,
    nested_value,
    present_values,
    raw_event_for_details,
)


def detail_section_markdown(
    title: str,
    rows: list[tuple[str, object]],
    empty_message: str,
    max_len: int = 420,
) -> str:
    """Render one required report section, including an explicit empty state."""
    lines = detail_table(title, rows, max_len=max_len)
    if lines:
        return "\n".join(lines).strip()
    return f"## {title}\n\n{empty_message}"


def security_onion_details(raw: dict, event: dict) -> str:
    return detail_section_markdown(
        "Security Onion Detail Fields",
        [
            ("Message", raw.get("message") or event.get("message")),
            ("Tags", raw.get("tags") or event.get("tags")),
            ("Event action", nested_object(event, "event", "action")),
            ("Event kind", nested_object(event, "event", "kind")),
            ("Event type", nested_object(event, "event", "type")),
            ("Event outcome", nested_object(event, "event", "outcome")),
            ("Module", raw.get("event_module") or nested_object(event, "event", "module")),
            ("Dataset", raw.get("event_dataset") or nested_object(event, "event", "dataset")),
            ("Rule category", raw.get("rule_category") or nested_object(event, "rule", "category")),
            ("Rule action", raw.get("rule_action") or nested_object(event, "rule", "action")),
            ("Rule ruleset", raw.get("rule_ruleset") or nested_object(event, "rule", "ruleset")),
            ("Rule reference", raw.get("rule_reference") or nested_object(event, "rule", "reference")),
            ("Rule metadata", raw.get("rule_metadata") or nested_object(event, "rule", "metadata")),
        ],
        "No additional Security Onion detail fields were recorded for this alert.",
    )


def network_flow_details(raw: dict, event: dict) -> str:
    return detail_section_markdown(
        "Network And Flow Details",
        [
            ("Transport", nested_object(raw, "network", "transport") or nested_object(event, "network", "transport")),
            ("Community ID", nested_object(raw, "network", "community_id") or nested_object(event, "network", "community_id")),
            ("VLAN", nested_object(raw, "network", "vlan") or nested_object(event, "network", "vlan")),
            ("Direction", nested_object(event, "network", "direction")),
            ("Protocol", nested_object(event, "network", "protocol") or nested_object(event, "suricata", "eve", "proto")),
            ("Application protocol", nested_object(event, "suricata", "eve", "app_proto")),
            ("Source ASN/org", present_values(nested_object(raw, "source", "asn"), nested_object(raw, "source", "org"))),
            ("Source geo", nested_object(event, "source", "geo")),
            ("Destination ASN/org", present_values(nested_object(raw, "destination", "asn"), nested_object(raw, "destination", "org"))),
            ("Destination geo", nested_object(event, "destination", "geo")),
            ("Flow", nested_object(event, "suricata", "eve", "flow")),
            ("Flow ID", nested_object(event, "suricata", "eve", "flow_id")),
            ("Related IPs", nested_object(event, "related", "ip") or nested_object(raw, "related", "ip")),
        ],
        "No additional network or flow fields were recorded for this alert.",
    )


def protocol_details(raw: dict, event: dict) -> str:
    return detail_section_markdown(
        "Protocol Details",
        [
            ("DNS", raw.get("dns") or event.get("dns") or nested_object(event, "suricata", "eve", "dns")),
            ("HTTP", raw.get("http") or event.get("http") or nested_object(event, "suricata", "eve", "http")),
            ("URL", raw.get("url") or event.get("url")),
            ("TLS", raw.get("tls") or event.get("tls") or nested_object(event, "suricata", "eve", "tls")),
        ],
        "No additional protocol fields were recorded for this alert.",
        max_len=700,
    )


def host_sensor_details(raw: dict, event: dict) -> str:
    return detail_section_markdown(
        "Host And Sensor Details",
        [
            ("Host", raw.get("host") or event.get("host")),
            ("Observer", raw.get("observer") or event.get("observer")),
            ("Agent", raw.get("agent") or event.get("agent")),
            ("Log", raw.get("log") or event.get("log")),
            ("User", raw.get("user") or event.get("user")),
            ("Process", raw.get("process") or event.get("process")),
            ("File", raw.get("file") or event.get("file")),
        ],
        "No additional host or sensor fields were recorded for this alert.",
        max_len=700,
    )


def threat_context_details(raw: dict, event: dict) -> str:
    return detail_section_markdown(
        "Threat Context",
        [
            ("Threat", raw.get("threat") or event.get("threat")),
            ("Related hosts", nested_object(event, "related", "hosts") or nested_object(raw, "related", "hosts")),
            ("Related hashes", nested_object(event, "related", "hash") or nested_object(raw, "related", "hash")),
            ("Suricata alert", nested_object(event, "suricata", "eve", "alert")),
            ("Security Onion enrichment note", nested_value(raw, "security_onion", "enrichment_note")),
        ],
        "No additional threat-context fields were recorded for this alert.",
        max_len=700,
    )


def standard_alert_detail_sections(raw: dict) -> dict[str, str]:
    """Build the fixed structured-evidence sections from normalized/raw data."""
    event = raw_event_for_details(raw)
    return {
        "security onion detail fields": security_onion_details(raw, event),
        "network and flow details": network_flow_details(raw, event),
        "protocol details": protocol_details(raw, event),
        "host and sensor details": host_sensor_details(raw, event),
        "threat context": threat_context_details(raw, event),
    }


def alert_detail_markdown(raw: dict) -> str:
    """Return the fixed structured-evidence sequence for compatibility."""
    sections = standard_alert_detail_sections(raw)
    order = (
        "network and flow details",
        "protocol details",
        "host and sensor details",
        "threat context",
        "security onion detail fields",
    )
    return "\n\n".join(sections[title] for title in order)
