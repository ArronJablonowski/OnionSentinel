"""Grouped SOC public-enrichment query and page merge policy."""
from __future__ import annotations

from dataclasses import dataclass


Row = object


@dataclass(frozen=True)
class SocGroupEnrichmentQueryPlan:
    sql: str
    args: list[str]


ENRICHMENT_QUERY_SQL = """
    WITH ranked_enrichment AS (
      SELECT
        {group_expr} AS resolved_group_key,
        enrichment_json,
        ROW_NUMBER() OVER (
          PARTITION BY {group_expr}
          ORDER BY
            CASE
              WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.records')), 0) > 0 THEN 0
              WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.errors')), 0) > 0 THEN 1
              WHEN COALESCE(json_array_length(json_extract(enrichment_json, '$.external_intel.skipped')), 0) > 0 THEN 2
              ELSE 3
            END,
            replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
            alert_id DESC
        ) AS enrichment_rank
      FROM alerts
      WHERE {group_expr} IN ({placeholders})
        AND enrichment_json IS NOT NULL
        AND TRIM(enrichment_json) != ''
    )
    SELECT resolved_group_key, enrichment_json
    FROM ranked_enrichment
    WHERE enrichment_rank = 1
"""


def normalized_group_keys(group_keys: list[object]) -> list[str]:
    """Return unique, nonblank group keys in caller order."""
    return list(dict.fromkeys(
        str(value or "").strip()
        for value in group_keys
        if str(value or "").strip()
    ))


def group_enrichment_query_plan(group_keys: list[object],
                                group_expr: str) -> SocGroupEnrichmentQueryPlan:
    """Build one parameterized best-enrichment query for a bounded group set."""
    keys = normalized_group_keys(group_keys)
    if not keys:
        return SocGroupEnrichmentQueryPlan("", [])
    placeholders = ",".join("?" for _ in keys)
    return SocGroupEnrichmentQueryPlan(
        ENRICHMENT_QUERY_SQL.format(
            group_expr=group_expr,
            placeholders=placeholders,
        ),
        keys,
    )


def project_group_enrichment_rows(rows: list[Row]) -> dict[str, str]:
    """Project repository rows to a group-key enrichment map."""
    result: dict[str, str] = {}
    for row in rows:
        group_key = str(row["resolved_group_key"] or "").strip()
        if group_key:
            result[group_key] = str(row["enrichment_json"] or "")
    return result


def page_group_keys(rows: list[Row]) -> list[str]:
    """Return the visible group keys required by the page repository query."""
    keys: list[object] = []
    for row in rows:
        try:
            if "group_key" in row.keys():
                keys.append(row["group_key"])
        except AttributeError:
            continue
    return normalized_group_keys(keys)


def merge_page_enrichment(rows: list[Row], enrichment_by_group: object) -> list[dict]:
    """Preserve embedded enrichment and fill only missing values from the repository."""
    enrichment_map = enrichment_by_group if isinstance(enrichment_by_group, dict) else {}
    merged: list[dict] = []
    for row in rows:
        item = dict(row)
        group_key = str(item.get("group_key") or "")
        item["enrichment_json"] = (
            item.get("enrichment_json") or enrichment_map.get(group_key, "")
        )
        merged.append(item)
    return merged
