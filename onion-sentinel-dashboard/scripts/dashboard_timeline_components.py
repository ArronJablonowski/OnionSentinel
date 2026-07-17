#!/usr/bin/env python3
"""Timeline rendering components for SOC alert detail panels.

The dashboard builder owns data loading and page assembly. This module keeps
duplicate-alert timeline rendering isolated so UI layout changes do not require
editing the large builder script.
"""
from __future__ import annotations

import datetime as dt
import html
import math
import re
from typing import Any


ISO_DATE_TIME_SEPARATOR_RE = re.compile(r'(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})')
ISO_TIMESTAMP_RE = re.compile(
    r'\b\d{4}-\d{2}-\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'
)


def safe_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def parse_iso_datetime(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    cleaned = value.strip().strip('"\'')
    if not cleaned:
        return None
    try:
        parseable = ISO_DATE_TIME_SEPARATOR_RE.sub(r'\1T', cleaned).replace('Z', '+00:00')
        parsed = dt.datetime.fromisoformat(parseable)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def format_project_timestamp(value: dt.datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    local_value = value.astimezone()
    timespec = 'milliseconds' if local_value.microsecond else 'seconds'
    return local_value.isoformat(timespec=timespec).replace('T', '  ')


def normalize_iso_display_text(value: object) -> str:
    """Display timestamps as local ISO 8601 with two spaces instead of `T`."""
    def replace_timestamp(match: re.Match[str]) -> str:
        parsed = parse_iso_datetime(match.group(0))
        return format_project_timestamp(parsed) if parsed else ISO_DATE_TIME_SEPARATOR_RE.sub(r'\1  ', match.group(0))

    return ISO_TIMESTAMP_RE.sub(replace_timestamp, str(value))


def timeline_timestamp(value: object) -> float | None:
    parsed = parse_iso_datetime(str(value)) if value not in (None, '') else None
    return parsed.timestamp() if parsed else None


def human_timeline_duration(seconds: float) -> str:
    remaining = max(0, int(round(seconds)))
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, seconds = divmod(remaining, 60)
    parts = []
    if days:
        parts.append(f'{days} day{"s" if days != 1 else ""}')
    if hours or parts:
        parts.append(f'{hours} hour{"s" if hours != 1 else ""}')
    if minutes or parts:
        parts.append(f'{minutes} minute{"s" if minutes != 1 else ""}')
    parts.append(f'{seconds} second{"s" if seconds != 1 else ""}')
    return ', '.join(parts)


def short_alert_id(alert_id: object) -> str:
    value = str(alert_id or '')
    if ':' in value:
        return value.rsplit(':', 1)[-1]
    return value[-16:] if len(value) > 16 else value


def timeline_display_percent(point_ts: float, first_ts: float, span: float) -> float:
    """Map timestamps into the visible rail while keeping the endpoints padded."""
    if span <= 1.0:
        return 50.0
    raw_percent = ((point_ts - first_ts) / span) * 100
    return max(2.0, min(98.0, round(2 + (raw_percent * 0.96), 2)))


def row_get(row: Any, key: str, default: object = None) -> object:
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


def alert_seen_timeline_html(row: Any) -> str:
    """Render duplicate/repeat timing for a grouped alert detail panel."""
    events = row_get(row, 'member_timeline', [])
    if not events:
        return ''
    normalized: list[dict[str, object]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        first_seen = str(event.get('first_seen') or '')
        last_seen = str(event.get('last_seen') or first_seen)
        fired_at = normalize_iso_display_text(event.get('timestamp') or event.get('fired_at') or last_seen or first_seen)
        point_ts = timeline_timestamp(fired_at) or timeline_timestamp(last_seen) or timeline_timestamp(first_seen)
        if point_ts is None:
            continue
        normalized.append({
            'alert_id': str(event.get('alert_id') or ''),
            'timestamp': fired_at or 'n/a',
            'first_seen': normalize_iso_display_text(first_seen or 'n/a'),
            'last_seen': normalize_iso_display_text(last_seen or first_seen or 'n/a'),
            'seen_count': max(1, safe_int(event.get('seen_count'))),
            'source_ip': str(event.get('source_ip') or 'n/a'),
            'destination_ip': str(event.get('destination_ip') or 'n/a'),
            'destination_port': str(event.get('destination_port') or 'n/a'),
            'point_ts': point_ts,
        })
    normalized.sort(key=lambda event: (event['point_ts'], str(event['alert_id'])))
    if not normalized:
        return ''
    first_ts = float(normalized[0]['point_ts'])
    last_ts = float(normalized[-1]['point_ts'])
    span = max(1.0, last_ts - first_ts)
    last_event_index = len(normalized)
    visual_bucket_width_pct = max(0.75, min(2.0, 100 / max(24, min(90, last_event_index))))
    visual_buckets: dict[int, dict[str, object]] = {}
    markers = []
    burst_bands = []
    rows = []
    observation_index = 0
    for index, event in enumerate(normalized, start=1):
        point_ts = float(event['point_ts'])
        percent = timeline_display_percent(point_ts, first_ts, span)
        bucket_key = int(round(percent / visual_bucket_width_pct))
        bucket = visual_buckets.setdefault(bucket_key, {
            'percent_sum': 0.0,
            'events': [],
            'observations': 0,
            'first_index': index,
            'last_index': index,
            'first_seen': event['first_seen'],
            'last_seen': event['last_seen'],
            'source_ip': event['source_ip'],
            'destination_ip': event['destination_ip'],
            'destination_port': event['destination_port'],
        })
        bucket['percent_sum'] = float(bucket['percent_sum']) + percent
        bucket['events'].append(event)
        bucket['observations'] = safe_int(bucket['observations']) + safe_int(event['seen_count'])
        bucket['first_index'] = min(safe_int(bucket['first_index']), index)
        bucket['last_index'] = max(safe_int(bucket['last_index']), index)
        bucket['first_seen'] = min(str(bucket['first_seen']), str(event['first_seen']))
        bucket['last_seen'] = max(str(bucket['last_seen']), str(event['last_seen']))
        repeat_count = max(1, safe_int(event['seen_count']))
        for repeat_index in range(1, repeat_count + 1):
            observation_index += 1
            title = (
                f"Stored alert row {index}, observation {repeat_index} of {repeat_count}"
                if repeat_count > 1 else f"Stored alert row {index}"
            )
            rows.append(
                f'<tr data-timeline-row data-timeline-index="{observation_index}" title="{html.escape(title, quote=True)}">'
                f'<td>{observation_index}</td>'
                f'<td>{html.escape(str(event["timestamp"]))}</td>'
                '<td>1</td>'
                f'<td><code>{html.escape(str(event["source_ip"]))}</code></td>'
                f'<td><code>{html.escape(str(event["destination_ip"]))}</code></td>'
                f'<td><code>{html.escape(str(event["destination_port"]))}</code></td>'
                f'<td><code>{html.escape(short_alert_id(event["alert_id"]))}</code></td>'
                '</tr>'
            )
    for bucket in sorted(visual_buckets.values(), key=lambda value: safe_int(value['first_index'])):
        bucket_events = bucket['events']
        event_count = len(bucket_events)
        observation_count = max(event_count, safe_int(bucket['observations']))
        percent = max(2, min(98, round(float(bucket['percent_sum']) / max(1, event_count), 2)))
        marker_size = max(8, min(28, round(7 + (math.log2(observation_count + 1) * 3.4))))
        contains_first = safe_int(bucket['first_index']) == 1
        contains_last = safe_int(bucket['last_index']) == last_event_index
        marker_classes = ['alert-timeline-marker']
        if contains_first:
            marker_classes.append('marker-first')
        if contains_last:
            marker_classes.append('marker-last')
        if contains_first and contains_last:
            label = 'Only'
        else:
            label = 'First' if contains_first else ('Last' if contains_last else (f'x{event_count}' if event_count > 1 else ''))
        title = (
            f"Events {bucket['first_index']}-{bucket['last_index']} | "
            f"observations {observation_count} | "
            f"{bucket['first_seen']} to {bucket['last_seen']} | "
            f"{bucket['source_ip']} -> {bucket['destination_ip']}:{bucket['destination_port']}"
        )
        markers.append(
            f'<span class="{" ".join(marker_classes)}" '
            f'style="left:{percent}%;--marker-size:{marker_size}px" title="{html.escape(title, quote=True)}">'
            f'{f"<span>{html.escape(label)}</span>" if label else ""}</span>'
        )
    cluster_gap_seconds = max(60.0, min(900.0, span * 0.01))
    clusters: list[list[dict[str, object]]] = []
    for event in normalized:
        if not clusters:
            clusters.append([event])
            continue
        previous_ts = float(clusters[-1][-1]['point_ts'])
        if float(event['point_ts']) - previous_ts <= cluster_gap_seconds:
            clusters[-1].append(event)
        else:
            clusters.append([event])
    for cluster in clusters:
        if len(cluster) < 2:
            continue
        start_percent = timeline_display_percent(float(cluster[0]['point_ts']), first_ts, span)
        end_percent = timeline_display_percent(float(cluster[-1]['point_ts']), first_ts, span)
        observations = sum(safe_int(event['seen_count']) for event in cluster)
        width = max(4.0, min(24.0, end_percent - start_percent))
        left = max(2.0, min(98.0 - width, start_percent))
        title = (
            f"Activity burst | events {len(cluster)} | observations {observations} | "
            f"{cluster[0]['timestamp']} to {cluster[-1]['timestamp']}"
        )
        burst_bands.append(
            f'<span class="alert-timeline-burst" style="left:{left}%;width:{round(width, 2)}%" '
            f'title="{html.escape(title, quote=True)}"><i>{observations}</i></span>'
        )
    seen_candidates = []
    for event in normalized:
        for key in ('first_seen', 'timestamp', 'last_seen'):
            display_value = str(event.get(key) or '')
            parsed_ts = timeline_timestamp(display_value)
            if parsed_ts is not None:
                seen_candidates.append((parsed_ts, display_value))
    first_seen_ts, first_seen_display = min(seen_candidates, default=(first_ts, str(normalized[0]['timestamp'])))
    last_seen_ts, last_seen_display = max(seen_candidates, default=(last_ts, str(normalized[-1]['timestamp'])))
    duration_text = human_timeline_duration(last_seen_ts - first_seen_ts)
    total_seen = sum(safe_int(event['seen_count']) for event in normalized)
    page_size = 25
    total_pages = max(1, math.ceil(total_seen / page_size))
    pagination_html = ''
    if total_seen > page_size:
        pagination_html = f'''
    <div class="alert-timeline-pagination" data-timeline-page-size="{page_size}" data-timeline-total="{total_seen}">
      <button class="timeline-page-button" type="button" data-timeline-prev disabled>Previous</button>
      <span data-timeline-page-label>Page 1 of {total_pages} · Showing 1-{min(page_size, total_seen)} of {total_seen}</span>
      <button class="timeline-page-button" type="button" data-timeline-next>Next</button>
    </div>'''
    return f'''
<details class="alert-timeline-section" aria-label="Duplicate alert timeline" data-timeline-page-size="{page_size}" open>
  <summary>Duplicate Alert Timeline <span>{len(normalized)} alert row(s), {total_seen} observation(s)</span></summary>
  <div class="alert-timeline-body">
    <dl class="alert-timeline-summary">
      <div><dt>First Seen:</dt><dd>{html.escape(first_seen_display)}</dd></div>
      <div><dt>Last Seen:</dt><dd>{html.escape(last_seen_display)}</dd></div>
      <div><dt>Duration:</dt><dd>{html.escape(duration_text)}</dd></div>
    </dl>
    <div class="alert-timeline-rail" aria-hidden="true">{''.join(burst_bands)}{''.join(markers)}</div>
    <div class="table-wrap alert-timeline-table"><table><colgroup><col class="timeline-col-index"><col class="timeline-col-timestamp"><col class="timeline-col-seen"><col class="timeline-col-source"><col class="timeline-col-destination"><col class="timeline-col-port"><col class="timeline-col-alert"></colgroup><thead><tr><th>#</th><th>Timestamp</th><th>Seen</th><th>Source IP</th><th>Destination IP</th><th>Destination Port</th><th>Alert</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
    {pagination_html}
  </div>
</details>
'''
