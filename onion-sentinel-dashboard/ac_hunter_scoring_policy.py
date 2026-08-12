"""Pure deterministic phases for AC Hunter finding scoring."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping

from ac_hunter_config import _safe_text
from ac_hunter_normalization import (
    GENERIC_INFRASTRUCTURE_MARKERS,
    _integer_value,
    _number,
)


BenignExplainer = Callable[[Mapping[str, Any]], str]


@dataclass
class _ScoringContext:
    finding: Dict[str, Any]
    module_count: int
    rare_signature_count: int
    benign: str
    module: str
    score: float
    duration: float
    fqdn: str
    source: str
    destination: str
    port: int
    protocol: str
    generic_infrastructure: bool
    points: int = 0
    reasons: List[str] = field(default_factory=list)


def _build_context(
    finding: Dict[str, Any],
    module_count: int,
    rare_signature_count: int,
    benign_explainer: BenignExplainer,
) -> _ScoringContext:
    module = str(finding.get("module") or "")
    score = _number(finding.get("score"), 0.0)
    duration = _number(finding.get("duration_seconds"), 0.0)
    fqdn = _safe_text(finding.get("fqdn"), 512)
    source = _safe_text(finding.get("source_ip"), 128)
    destination = _safe_text(finding.get("destination_ip"), 128)
    port = _integer_value(finding.get("port"))
    protocol = _safe_text(finding.get("protocol"), 64)
    searchable = (
        fqdn
        + " "
        + json.dumps(finding.get("evidence", {}), sort_keys=True)
    ).lower()
    benign = benign_explainer(finding)
    generic_infrastructure = any(
        marker in searchable for marker in GENERIC_INFRASTRUCTURE_MARKERS
    )
    return _ScoringContext(
        finding=finding,
        module_count=module_count,
        rare_signature_count=rare_signature_count,
        benign=benign,
        module=module,
        score=score,
        duration=duration,
        fqdn=fqdn,
        source=source,
        destination=destination,
        port=port,
        protocol=protocol,
        generic_infrastructure=generic_infrastructure,
    )


def _apply_module_signals(context: _ScoringContext) -> None:
    if context.module == "blacklist":
        context.points += 70
        context.reasons.append("AC Hunter reported a blacklist match")
    if context.module == "strobe":
        context.points += 55
        context.reasons.append("AC Hunter reported strobe/scanning behavior")


def _apply_score_signal(context: _ScoringContext) -> None:
    if context.score >= 0.95:
        context.points += 35
        context.reasons.append(
            f"high AC Hunter behavioral score ({context.score:.3f})"
        )
    elif context.score >= 0.80:
        context.points += 22
        context.reasons.append(
            f"elevated AC Hunter behavioral score ({context.score:.3f})"
        )
    elif context.score >= 0.50:
        context.points += 12
        context.reasons.append(
            "AC Hunter behavioral score met the review threshold "
            f"({context.score:.3f})"
        )


def _apply_destination_signals(context: _ScoringContext) -> None:
    beacon_like_modules = {
        "beacons",
        "beacons_sni",
        "beacons_proxy",
        "long_connections",
        "unexpected_ports",
    }
    if not context.fqdn and context.module in beacon_like_modules:
        context.points += 12
        context.reasons.append("no FQDN/SNI/DNS explanation was present")
    if context.generic_infrastructure:
        context.points += 12
        context.reasons.append(
            "destination context is generic cloud/VPS infrastructure"
        )
    elif (context.fqdn or context.destination) and not context.benign:
        context.points += 8
        context.reasons.append(
            "destination was not recognized as a common vendor, update, "
            "push, or other expected service"
        )


def _apply_correlation_signals(context: _ScoringContext) -> None:
    if context.module == "unexpected_ports":
        context.points += 25
        context.reasons.append("protocol/port behavior was unexpected")
    if context.duration >= 18_000:
        context.points += 20
        context.reasons.append(
            f"connection lasted {context.duration / 3600:.1f} hours"
        )
    if context.module_count > 1:
        added = min(30, (context.module_count - 1) * 10)
        context.points += added
        context.reasons.append(
            f"source appeared across {context.module_count} AC Hunter modules"
        )
    if context.rare_signature_count >= 10:
        context.points += 10
        context.reasons.append(
            "source was associated with "
            f"{context.rare_signature_count} rare client-signature observations"
        )


def _matches_watch_one(context: _ScoringContext) -> bool:
    return (
        context.source == "10.66.6.209"
        and context.destination == "208.70.182.48"
        and context.port == 1610
        and context.protocol
        in {
            "",
            "TCP",
            "TLS",
            "SSL",
            "UNKNOWN",
            "TLS/UNKNOWN",
            "SSL/UNKNOWN",
        }
        and not context.fqdn
    )


def _matches_watch_two(context: _ScoringContext) -> bool:
    return (
        context.source == "10.100.4.245"
        and context.destination == "98.84.79.102"
        and context.port == 443
        and context.duration >= 18_000
    )


def _apply_environment_watches(context: _ScoringContext) -> bool:
    watch_one = _matches_watch_one(context)
    watch_two = _matches_watch_two(context)
    if watch_one:
        context.points = max(context.points, 40)
        context.reasons.append(
            "environment watch: TCP/1610 TLS/unknown traffic to "
            "208.70.182.48 lacks FQDN context"
        )
    if watch_two:
        context.points = max(context.points, 40)
        context.reasons.append(
            "environment watch: very long TCP/443 connection to a generic "
            "AWS destination"
        )
    return bool(watch_one or watch_two)


def _apply_benign_context(
    context: _ScoringContext,
    watch_match: bool,
) -> None:
    hard_signal = context.module in {"blacklist", "strobe"} or watch_match
    if not context.benign or hard_signal:
        return
    context.points = max(0, context.points - 35)
    beacon_modules = {"beacons", "beacons_sni", "beacons_proxy"}
    if context.score >= 0.95 and context.module in beacon_modules:
        context.points = max(context.points, 25)
    context.reasons.append(f"lowered priority: {context.benign}")


def _verdict(context: _ScoringContext, watch_match: bool) -> str:
    if watch_match and context.module not in {"blacklist", "strobe"}:
        return "Needs review"
    if context.points >= 65:
        return "High concern"
    if context.points >= 25:
        return "Needs review"
    if context.benign:
        return "Likely benign"
    return "Informational"


def apply_scoring_policy(
    finding: Dict[str, Any],
    module_count: int,
    rare_signature_count: int,
    benign_explainer: BenignExplainer,
) -> Dict[str, Any]:
    """Apply the deterministic phases and mutate only scoring output fields."""

    context = _build_context(
        finding,
        module_count,
        rare_signature_count,
        benign_explainer,
    )
    _apply_module_signals(context)
    _apply_score_signal(context)
    _apply_destination_signals(context)
    _apply_correlation_signals(context)
    watch_match = _apply_environment_watches(context)
    _apply_benign_context(context, watch_match)
    if not context.reasons:
        context.reasons.append(
            "behavioral evidence is limited and requires context before escalation"
        )
    finding["priority_score"] = context.points
    finding["verdict"] = _verdict(context, watch_match)
    finding["reason"] = "; ".join(context.reasons)
    finding["watch_match"] = watch_match
    return finding
