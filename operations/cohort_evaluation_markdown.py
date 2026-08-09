#!/usr/bin/env python3
"""Render secret-free cohort evaluation summaries as bounded Markdown."""
from __future__ import annotations

from typing import Any, Mapping, Sequence


def markdown_cell(value: object, maximum: int = 160) -> str:
    text = " ".join(str(value if value is not None else "").split())[:maximum]
    return text.replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def _role_summary(
    roles: Mapping[str, Mapping[str, Any]], labels: Mapping[str, str]
) -> list[str]:
    lines = [
        "## Role summary",
        "",
        "| Role | Complete | Pass | Review | Fail | Effective mean | "
        "Exact verdicts | Hard-fail cases | Shadow gate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for role, role_report in roles.items():
        aggregate = role_report["aggregate"]
        counts = aggregate["classification_counts"]
        values = [
            markdown_cell(labels.get(role, role)),
            f"{aggregate['completed_count']}/{aggregate['expected_count']}",
            str(counts["pass"]),
            str(counts["needs_review"]),
            str(counts["fail"]),
            f"{aggregate['score']['effective_mean']:.2f}",
            f"{aggregate['exact_verdict_count']}/{aggregate['expected_count']}",
            str(aggregate["hard_failure_case_count"]),
            "PASS" if aggregate["shadow_acceptance_gate"]["passed"] else "NOT MET",
        ]
        lines.append("| " + " | ".join(values) + " |")
    return lines


def _criterion_lines(aggregate: Mapping[str, Any]) -> list[str]:
    lines = [
        "### Criterion averages",
        "",
        "| Criterion | Mean | Maximum | Full-score cases |",
        "|---|---:|---:|---:|",
    ]
    for criterion, details in aggregate["criteria"].items():
        lines.append(
            f"| `{criterion}` | {details['mean']:.2f} | "
            f"{details['maximum']} | {details['full_score_count']} |"
        )
    return lines


def _case_lines(cases: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = [
        "### Per-case comparison",
        "",
        "| Rank | Stable group | Result | Score | Grade | Exact | "
        "Mismatched labels | Hard failures | Improvement codes |",
        "|---:|---|---|---:|---|---|---|---|---|",
    ]
    for item in cases:
        values = [
            str(item["rank"]),
            f"`{markdown_cell(item['stable_group_id'])}`",
            markdown_cell(item["result_state"]),
            f"{float(item['effective_score']):.2f}",
            markdown_cell(item["classification"]),
            "yes" if item["exact_verdict_match"] else "no",
            markdown_cell(", ".join(item["mismatched_labels"]) or "none"),
            markdown_cell(", ".join(item["hard_failures"]) or "none"),
            markdown_cell(", ".join(item["improvement_codes"]) or "none"),
        ]
        lines.append("| " + " | ".join(values) + " |")
    return lines


def _count_summary(values: Mapping[str, Any]) -> str:
    return markdown_cell(", ".join(f"{key}={value}" for key, value in values.items()) or "none")


def _finding_lines(aggregate: Mapping[str, Any]) -> list[str]:
    return [
        "### Aggregate finding codes",
        "",
        "- Failure modes: " + _count_summary(aggregate["failure_mode_counts"]),
        "- Recommended improvements: "
        + _count_summary(aggregate["improvement_code_counts"]),
        "- Scope note: " + aggregate["shadow_acceptance_gate"]["scope_warning"],
    ]


def _role_details(
    roles: Mapping[str, Mapping[str, Any]], labels: Mapping[str, str]
) -> list[str]:
    lines: list[str] = []
    for role, role_report in roles.items():
        aggregate = role_report["aggregate"]
        lines.extend(["", f"## {labels.get(role, role)}", ""])
        lines.extend(_criterion_lines(aggregate))
        lines.extend([""] + _case_lines(role_report["cases"]))
        lines.extend([""] + _finding_lines(aggregate))
    return lines


def _cross_role_lines(cross_role: object) -> list[str]:
    if not isinstance(cross_role, dict):
        return []
    lines = [
        "",
        "## Cross-role comparison",
        "",
        "Agent verdicts differed on "
        f"{cross_role['agent_verdict_disagreement_case_count']} of "
        f"{cross_role['common_case_count']} common cases.",
        "",
        "| Stable group | IR score | SOC score | IR-SOC | Agent label disagreements |",
        "|---|---:|---:|---:|---|",
    ]
    for item in cross_role["cases"]:
        disagreements = ", ".join(item["agent_verdict_disagreements"]) or "none"
        lines.append(
            f"| `{markdown_cell(item['stable_group_id'])}` | "
            f"{float(item['incident_responder_score']):.2f} | "
            f"{float(item['soc_analyst_score']):.2f} | "
            f"{float(item['incident_minus_soc_score']):.2f} | "
            f"{markdown_cell(disagreements)} |"
        )
    return lines


def _header(report: Mapping[str, Any]) -> list[str]:
    contract = report["execution_contract"]
    return [
        "# Onion Sentinel investigation cohort evaluation",
        "",
        f"- Experiment: `{markdown_cell(report['experiment_id'])}`",
        f"- Cases per role: {int(report['expected_count'])}",
        "- Dual-role execution gate: passed "
        f"({int(report['dual_role_execution_gate']['analysis_count'])} "
        "fresh shadow-harness analyses)",
        f"- Generated: `{markdown_cell(report['generated_at'])}`",
        "- Evaluation profile: `"
        f"{markdown_cell(contract.get('evaluation_profile') or 'generic')}`",
        f"- Primary route: `{markdown_cell(contract['expected_assigned_route'])}`",
        "- Required reviewer route: `"
        f"{markdown_cell(contract['expected_reviewer_route'])}`",
        f"- Report digest: `{markdown_cell(report['report_sha256'])}`",
        "",
        "This report contains verdict labels, rubric scores, digests, and "
        "machine-readable finding codes only. It contains no raw alerts, "
        "evidence, prompts, queries, query results, credentials, or model responses.",
        "",
    ]


def render_markdown(
    report: Mapping[str, Any],
    *,
    role_labels: Mapping[str, str],
    maximum_bytes: int,
    error: type[RuntimeError] = RuntimeError,
) -> str:
    lines = _header(report)
    lines.extend(_role_summary(report["roles"], role_labels))
    lines.extend(_role_details(report["roles"], role_labels))
    lines.extend(_cross_role_lines(report.get("cross_role")))
    rendered = "\n".join(lines).rstrip() + "\n"
    if len(rendered.encode("utf-8")) > maximum_bytes:
        raise error("rendered Markdown exceeds the size bound")
    return rendered
