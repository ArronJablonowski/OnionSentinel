#!/usr/bin/env python3
"""Return bounded role-specific objectives for investigation prompts."""
from __future__ import annotations


SPECIALIST_TASKS = {
    "siem-engineer": (
        "Produce a detection-engineering assessment of this alert group. "
        "Evaluate the exact deployed rule predicates, evidence coverage, false-positive "
        "drivers, severity and scoring, then propose bounded tuning or validation steps "
        "with expected impact and rollback criteria. Preserve detection coverage and "
        "never claim a rule change or query execution occurred unless supplied evidence "
        "records it."
    ),
    "cyber-threat-intel": (
        "Produce a threat-intelligence assessment for this alert group. Separate observed "
        "telemetry from external reporting and hypotheses; assess indicator relevance, "
        "confidence, recency, likely behaviors, collection gaps, and defensible pivots. "
        "Avoid unsupported attribution and never claim enrichment or query results that "
        "are not present in the supplied evidence."
    ),
    "threat-hunter": (
        "Produce a threat-hunting assessment for this alert group. Develop prioritized, "
        "falsifiable hypotheses from observed facts, identify expected corroborating and "
        "disconfirming evidence, and recommend bounded read-only pivots using the supplied "
        "query contract. Clearly distinguish proposed queries from executed queries and "
        "never claim results that are absent from the evidence."
    ),
}
DEFAULT_TASK = (
    "Explain likely meaning, repeat frequency, false positive possibilities, urgency, "
    "next investigative steps, tuning actions, and whether an independent second-model "
    "opinion is warranted."
)
ESCALATE_LEVELS = frozenset({"critical", "high"})


def build_model_policy(level: str | None) -> dict:
    """Return the stable hosted-review and prompt-privacy policy."""
    normalized = str(level or "").lower()
    return {
        "default_model_path": "local_llm",
        "hosted_second_opinion_allowed": normalized in ESCALATE_LEVELS,
        "hosted_second_opinion_rule": "Only use hosted GPT-class analysis for critical/high alerts or when local analysis requests escalation.",
        "privacy_rule": "Do not send raw packet payloads, packet samples, local PCAP query results, credentials, tokens, or unnecessary internal notes to hosted models.",
    }


def _incident_responder_task(blind_reanalysis: bool) -> str:
    historical_context = (
        "human analyst adjudications and operator-confirmed context"
        if blind_reanalysis
        else "prior SOC analyses"
    )
    return (
        "Produce a senior incident-response investigation report for the complete alert group. "
        f"Use its full timeline and frequency, {historical_context}, public enrichment, "
        "parsed PCAP evidence, analyst notes, correlations, memory, and the supplied "
        "read-only Security Onion query results. Build a fact-grounded timeline and "
        "determine scope, affected systems, likely impact, containment, eradication, "
        "recovery, evidence gaps, and safe next actions. Clearly distinguish observed "
        "facts from hypotheses. Never claim a query or response action occurred unless "
        "the supplied evidence records it."
    )


def build_agent_task(agent_role: str, *, blind_reanalysis: bool = False) -> str:
    """Return one immutable objective without changing the evidence contract."""
    if agent_role == "incident-responder":
        return _incident_responder_task(blind_reanalysis)
    return SPECIALIST_TASKS.get(agent_role, DEFAULT_TASK)
