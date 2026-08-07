"""Pure public-enrichment rendering and status summaries for alert details."""
from __future__ import annotations

from dashboard_alert_detail_values import json_object, markdown_cell, nested_object
from dashboard_time_format import normalize_iso_display_text


ENRICHMENT_LIST_KEYS = ("records", "skipped", "errors")


def list_field(parent: dict, key: str) -> list:
    """Return one list-valued enrichment field or an empty list."""
    value = parent.get(key)
    return value if isinstance(value, list) else []


def external_intel_record(enrichment_json: object) -> dict | None:
    """Return stored external-intelligence data when it has object shape."""
    external_intel = json_object(enrichment_json).get("external_intel")
    return external_intel if isinstance(external_intel, dict) else None


def report_external_intel(raw: dict, enrichment_json: object) -> dict | None:
    """Prefer embedded evidence, falling back to the grouped SQLite record."""
    embedded = nested_object(raw, "enrichment", "external_intel")
    if isinstance(embedded, dict) and any(embedded.get(key) for key in ENRICHMENT_LIST_KEYS):
        return embedded
    stored = external_intel_record(enrichment_json)
    if stored is not None:
        return stored
    return embedded if isinstance(embedded, dict) else None


def enrichment_record_rows(records: list) -> list[str]:
    """Render bounded completed-enrichment table rows."""
    rows: list[str] = []
    for record in records[:24]:
        if not isinstance(record, dict):
            continue
        raw_tags = record.get("tags")
        tags = raw_tags if isinstance(raw_tags, list) else []
        rows.append(
            f'| {markdown_cell(record.get("source"))} | '
            f'{markdown_cell(record.get("indicator"), 120)} | '
            f'{markdown_cell(record.get("indicator_type"))} | '
            f'{markdown_cell(record.get("verdict"))} | '
            f'{markdown_cell(record.get("confidence"))} | '
            f'{markdown_cell(", ".join(str(tag) for tag in tags if str(tag).strip()), 180)} | '
            f'{markdown_cell(normalize_iso_display_text(record.get("cached_at") or ""))} |'
        )
    return rows


def enrichment_limit_rows(skipped: list, errors: list) -> list[str]:
    """Render bounded skipped-source and lookup-error rows."""
    rows: list[str] = []
    for item in [*skipped, *errors]:
        if not isinstance(item, dict):
            continue
        rows.append(
            f'| {markdown_cell(item.get("source"))} | '
            f'{markdown_cell(item.get("indicator"), 120)} | '
            f'{markdown_cell(item.get("reason"), 220)} | '
            f'{markdown_cell(item.get("limit_note"), 260)} |'
        )
        if len(rows) == 32:
            break
    return rows


def public_enrichment_markdown(raw: dict, enrichment_json: object = None) -> str:
    """Render analyst-facing public enrichment evidence."""
    external_intel = report_external_intel(raw, enrichment_json)
    if external_intel is None:
        return ""
    records = list_field(external_intel, "records")
    skipped = list_field(external_intel, "skipped")
    errors = list_field(external_intel, "errors")
    if not records and not skipped and not errors:
        return "\n".join([
            "## Enriched Alert Details",
            "",
            "No public enrichment lookups were applicable for this alert.",
        ])
    lines = ["## Enriched Alert Details", ""]
    if records:
        lines.extend([
            "| Source | Indicator | Type | Verdict | Confidence | Tags | Cached |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            *enrichment_record_rows(records),
            "",
        ])
    limit_rows = enrichment_limit_rows(skipped, errors)
    if limit_rows:
        lines.extend([
            "### Skipped / Limits",
            "",
            "| Source | Indicator | Reason | Limit note |",
            "| --- | --- | --- | --- |",
            *limit_rows,
            "",
        ])
    return "\n".join(lines).strip()


def public_enrichment_has_content(enrichment_json: object) -> bool:
    """Report whether stored enrichment has records, skips, or errors."""
    external_intel = external_intel_record(enrichment_json)
    if external_intel is None:
        return False
    return any(list_field(external_intel, key) for key in ENRICHMENT_LIST_KEYS)


def indicator_count(external_intel: dict) -> int:
    """Count supported public indicator values in one enrichment record."""
    indicators = external_intel.get("indicators")
    if not isinstance(indicators, dict):
        return 0
    keys = ("public_ips", "domains", "urls", "hashes", "cves")
    return sum(len(indicators[key]) for key in keys if isinstance(indicators.get(key), list))


def public_enrichment_status(enrichment_json: object) -> tuple[str, str, str, int, int, int]:
    """Summarize enrichment state and bounded record counts for dashboard cards."""
    external_intel = external_intel_record(enrichment_json)
    if external_intel is None:
        return ("none", "None", "No public enrichment data recorded for this alert group", 0, 0, 0)
    records = list_field(external_intel, "records")
    skipped = list_field(external_intel, "skipped")
    errors = list_field(external_intel, "errors")
    if records:
        detail = f"{len(records)} enrichment record(s), {len(skipped)} skipped source(s), {len(errors)} error(s)"
        return ("enriched", "Enriched", detail, len(records), len(skipped), len(errors))
    if errors:
        detail = f"{len(errors)} enrichment error(s), {len(skipped)} skipped source(s)"
        return ("error", "Error", detail, 0, len(skipped), len(errors))
    if skipped:
        detail = f"Indicators found, but {len(skipped)} source(s) skipped or unavailable"
        return ("checked", "Checked", detail, 0, len(skipped), 0)
    pending = indicator_count(external_intel)
    if pending:
        return ("pending", "Pending", f"{pending} public indicator(s) found with no completed enrichment records yet", 0, 0, 0)
    return ("none", "None", "No public indicators were recorded for enrichment", 0, 0, 0)
