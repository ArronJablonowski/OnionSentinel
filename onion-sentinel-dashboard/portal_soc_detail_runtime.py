"""Runtime composition for SOC group identity, enrichment, and detail HTML."""
from __future__ import annotations

from typing import Any


def normalize_soc_alert_status_meta(r: Any, value: object, *, now: str | None = None) -> dict | None:
    return r.normalize_status_meta(value, now_iso=r.now_iso_utc, now=now)


def ensure_soc_alert_status_table(r: Any, conn: Any) -> None:
    r.ensure_soc_alert_status_schema(conn)


def soc_alert_group_key_from_values(
    r: Any, triage_level: object, rule_name: object, source_ip: object,
    destination_ip: object, filter_status: object, suppression_key: object = None,
) -> str:
    if suppression_key:
        return str(suppression_key)
    return "|".join([
        str(triage_level or "unknown-level"), str(rule_name or "unknown-rule"),
        str(source_ip or "unknown-source"), str(destination_ip or "unknown-destination"),
        str(filter_status or "accepted"),
    ])


def soc_alert_group_id(r: Any, group_key: object) -> str:
    return r.hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def soc_alert_group_key_sql(r: Any) -> str:
    return """
      COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      )
    """


def soc_alert_public_enrichment_status(r: Any, enrichment_json: object) -> dict:
    return r.compose_enrichment_status(enrichment_json)


def soc_alert_group_enrichment_json(r: Any, conn: Any, group_key: object) -> str:
    key = str(group_key or "").strip()
    return r.soc_alert_group_enrichment_json_map(conn, [key]).get(key, "") if key else ""


def soc_alert_group_enrichment_json_map(
    r: Any, conn: Any, group_keys: list[object]
) -> dict[str, str]:
    plan = r.group_enrichment_query_plan(group_keys, r.soc_alert_group_key_sql())
    if not plan.args:
        return {}
    try:
        rows = conn.execute(plan.sql, plan.args).fetchall()
    except r.sqlite3.Error:
        return {}
    return r.project_group_enrichment_rows(rows)


def directory_size_bytes(r: Any, path: Any) -> int:
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def soc_alert_validate_detail_layout_html(r: Any, detail_html: str) -> list[str]:
    issues = []
    match = r.re.search(r'data-layout-version="([^"]+)"', detail_html or "")
    version = match.group(1) if match else "missing"
    if version != r.SOC_ALERT_DETAIL_LAYOUT_VERSION:
        issues.append(
            f"Report layout version is {version}; expected {r.SOC_ALERT_DETAIL_LAYOUT_VERSION}. "
            "The dashboard must be rebuilt from the current report template."
        )
    issues.extend(_detail_layout_marker_issues(r, detail_html))
    return list(dict.fromkeys(issues))


def _detail_layout_marker_issues(r: Any, detail_html: str) -> list[str]:
    issues = []
    positions = []
    for label, marker in r.SOC_ALERT_DETAIL_LAYOUT_MARKERS:
        count = (detail_html or "").count(marker)
        if count != 1:
            issues.append(f'Required section "{label}" appeared {count} time(s); exactly one is required.')
        positions.append((detail_html or "").find(marker))
    present = [position for position in positions if position >= 0]
    if present != sorted(present):
        issues.append("Required report sections are not in the canonical order.")
    return issues


def soc_alert_layout_error_html(r: Any, issues: list[str]) -> str:
    items = "".join(f"<li>{r.html.escape(issue)}</li>" for issue in issues)
    return (
        f'<section class="detail-layout-error" role="alert" data-layout-version="{r.SOC_ALERT_DETAIL_LAYOUT_VERSION}">'
        "<strong>Detailed Alert Report layout error</strong>"
        "<p>Historical or malformed report data could not be mapped to the required layout. "
        "The report is shown for recovery context, but it does not satisfy the current standard.</p>"
        f"<ul>{items}</ul></section>"
    )


def soc_alert_append_live_pcap_detail(r: Any, group_id: str, detail_html: str) -> str:
    _ = r, group_id
    return detail_html


def soc_alert_normalize_heading_text(r: Any, value: str) -> str:
    text = r.re.sub(r"<[^>]+>", "", value or "")
    text = r.html.unescape(text)
    return r.re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def soc_alert_collapse_detail_sections(r: Any, detail_html: str) -> str:
    if not detail_html or "detail-collapsible-section" in detail_html:
        return detail_html
    heading_re = r.re.compile(r"<h([2-6])([^>]*)>(.*?)</h\1>", r.re.IGNORECASE | r.re.DOTALL)
    matches = list(heading_re.finditer(detail_html))
    if not matches:
        return detail_html
    chunks, cursor, index = [], 0, 0
    while index < len(matches):
        match = matches[index]
        level = int(match.group(1))
        normalized = r.soc_alert_normalize_heading_text(match.group(3))
        summary = r.SOC_ALERT_COLLAPSIBLE_DETAIL_SECTIONS.get(normalized)
        if not summary:
            index += 1
            continue
        end, next_index = len(detail_html), index + 1
        while next_index < len(matches):
            if int(matches[next_index].group(1)) <= level:
                end = matches[next_index].start()
                break
            next_index += 1
        slug = r.re.sub(r"[^a-z0-9]+", "-", normalized).strip("-") or "detail"
        chunks.append(detail_html[cursor:match.start()])
        chunks.append(
            f'<details class="detail-report-section detail-collapsible-section detail-section-{slug}">'
            f"<summary>{r.html.escape(summary)}</summary>"
            f'<div class="detail-collapsible-body">{detail_html[match.end():end]}</div>'
            "</details>"
        )
        cursor, index = end, next_index
    chunks.append(detail_html[cursor:])
    return "".join(chunks)
