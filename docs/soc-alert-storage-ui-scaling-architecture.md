# SOC Alert Storage And UI Scaling Architecture

## Current Finding

The LAN Portal SOC Alerts UI is currently generated from Markdown files in:

```text
$HOME/Documents/SOC Alerts
```

The generated page is useful and polished for analyst browsing, but it is a
static HTML build. At larger alert volumes, rebuilding and shipping one large
HTML document from hundreds or thousands of Markdown files will become slow and
memory-heavy.

Current live scale observed on 2026-07-01:

```text
alert-store SQLite rows in last 24h: hundreds
Markdown reports: dozens
Markdown corpus size: hundreds of KB
SQLite DB size: a few MB
```

## Recommended Direction

Use a hybrid backend:

```text
Security Onion
  -> Pi transport relay
  -> n8n intake
  -> alert-store SQLite operational database
  -> suppression/routing/report decisions
  -> Markdown AI corpus for selected alerts
  -> LAN Portal API/UI backed by SQLite
```

SQLite should become the fast operational source of truth for the web UI.
Markdown should remain the human-readable and local-AI-readable knowledge
corpus, but not the primary query backend for high-volume UI updates.

## Storage Roles

| Layer | Purpose | Backing Store |
| --- | --- | --- |
| Raw relay batches | Forensics and replay after failures | Pi JSON batch files |
| Operational alert state | Fast ingest, filtering, suppression, routing, metrics | Mac Studio SQLite |
| Notification state | Telegram cooldown and suppression accounting | Mac Studio SQLite |
| Analyst/AI corpus | Selected alert narratives and investigation notes | Markdown files |
| Web UI | Fast browsing, filtering, pagination, metrics | SQLite-backed API |

## Why SQLite First

SQLite is a strong fit for this deployment because:

- It is local, simple, and durable.
- It handles hundreds of thousands to millions of rows on a Mac Studio.
- It supports indexes for time, severity, routing, rule, source, destination,
  and suppression status.
- It can support FTS5 full-text search for rule names, reasons, and alert JSON.
- It avoids regenerating a giant static page after every alert burst.

## Recommended SQLite Enhancements

Add or maintain indexes for:

```sql
CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_triage_level ON alerts(triage_level);
CREATE INDEX IF NOT EXISTS idx_alerts_routing ON alerts(routing);
CREATE INDEX IF NOT EXISTS idx_alerts_filter_status ON alerts(filter_status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_source_port ON alerts(source_port);
CREATE INDEX IF NOT EXISTS idx_alerts_destination_port ON alerts(destination_port);
CREATE INDEX IF NOT EXISTS idx_alerts_transport_protocol ON alerts(transport_protocol);
```

As of 2026-07-02, alert-store stores the following endpoint/protocol fields as
first-class SQLite columns in addition to preserving the complete raw evidence
in JSON:

| Column | Purpose |
| --- | --- |
| `source_port` | Fast source-port filtering and timeline display |
| `destination_port` | Fast destination-port filtering, timeline display, and future grouping/tuning |
| `network_protocol` | ECS `network.protocol` when available |
| `transport_protocol` | ECS `network.transport` or protocol identifier when available |

These columns are additive derived fields. `alert_json`, `raw_event_json`, and
`enrichment_json` remain the evidence source of truth.

Add an FTS table later for fast free-text search:

```sql
CREATE VIRTUAL TABLE IF NOT EXISTS alert_search USING fts5(
  alert_id,
  rule_name,
  source_ip,
  destination_ip,
  triage_level,
  routing,
  filter_status,
  alert_text
);
```

## LAN Portal Backend Recommendation

Move the SOC Alerts UI from static Markdown-only rendering to API-backed
pagination:

```text
GET /api/soc-alerts?since=24h&level=critical,high&limit=100&cursor=...
GET /api/soc-alerts/:alert_id
GET /api/soc-alerts/metrics
GET /api/soc-alerts/suppressions
POST /api/soc-alerts/:alert_id/ack
```

Target dashboard:

```text
http://10.77.7.225:8765/view/b68c5a48b9778061/
```

As of the 2026-07-01 implementation check, the dashboard still rendered from the
Markdown corpus and showed 59 report-backed alerts, while the operational
SQLite database contained 1,042 alert rows. This confirmed why the dashboard
needed SQLite for tables and metrics.

As of 2026-07-02, the SOC Alerts dashboard builder reads the `alerts` table
from SQLite first. The dashboard now groups repeated detections before
rendering the table. Validation showed 1,138 raw SQLite alert rows collapsed
into 64 visible grouped rows on the live dashboard, while Markdown remains the
accepted-alert report and local-LLM corpus.

Current SOC Alerts metric row:

- `Visible / Total`: one combined count card. The visible value changes when
  the analyst filters/searches; the total value remains the full grouped alert
  count for the current dashboard build.
- `Last n8n beacon`: last observed alert event timestamp from the SQLite-backed alert
  set, used as the durable proxy for the most recent n8n alert-ingestion
  trigger until explicit n8n execution telemetry is stored.
- `AI:{status}`: current local AI analysis state and queue depth, such as `AI:Idle` or `AI:Analyzing`.
- `Latest Alert`: newest generated Markdown report timestamp.
- `Total Size`: total generated Markdown corpus size represented by the
  current dashboard build.

Live UI state:

- The static dashboard bundle now includes `soc-alerts-status.json` beside the
  generated HTML.
- Every generated page polls `soc-alerts-status.json` every 5 seconds with
  `cache: no-store`.
- The JSON payload contains the AI metric state, queue counts, generated time,
  and per-row AI status keyed by dashboard report digest.
- The browser updates the `AI:{status}` metric card, the cross-page SOC Alerts
  sidebar badge, and each alert row/mobile card AI status pill in place, without
  a manual page refresh. On non-alert pages, the badge uses the grouped count
  from the status payload. On the SOC Alerts table page, active table filters
  own the badge so it reflects the currently visible rows.
- The local AI scheduler still rebuilds and syncs the static dashboard while an
  analysis runner is active and again after completion; the polling layer lets
  analysts see those state changes quickly once each rebuild lands.

## Grouped Analyst State API

As of 2026-07-03, analyst workflow state is moving from browser-side filtering
to server-side grouped detection state.

SQLite state table:

```sql
CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
  group_id TEXT PRIMARY KEY,
  group_key TEXT,
  status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
  repeat_count INTEGER NOT NULL DEFAULT 0,
  reason TEXT,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);
```

`group_id` is the first 12 hex characters of SHA-1 over the grouped detection
key. The grouped detection key is `suppression_key` when available, otherwise:

```text
triage_level|rule_name|source_ip|destination_ip|filter_status
```

Source ports are intentionally excluded because they can rotate per connection.
The UI should acknowledge/suppress by `group_id`, not by raw `alert_id`, so
state follows the detection even when a newer matching alert becomes the visible
representative row.

Current API contract:

```text
GET  /api/soc-alerts?analyst_status=open&limit=100&cursor=<last_seen>|<group_id>
GET  /api/soc-alerts?analyst_status=acknowledged&limit=100
GET  /api/soc-alerts?analyst_status=suppressed&limit=100
GET  /api/soc-alerts/<group_id>/detail
GET  /api/soc-alerts/events
GET  /api/soc-alerts/metrics?since=7d
GET  /api/soc-alerts/status
POST /api/soc-alerts/<group_id>/ack
```

`POST /api/soc-alerts/<group_id>/ack` accepts:

```json
{
  "status": "acknowledged",
  "repeat_count": 123,
  "reason": "optional 140 char suppression reason"
}
```

Use `"status": "open"` to expose/unacknowledge a group and
`"status": "suppressed"` to suppress a group. The backend auto-expires
acknowledgements when the grouped detection count increases, making the alert
visible again for analysts. Suppressed groups remain hidden until exposed.

The SOC Alerts table now uses phase-one paginated API rendering. The builder
ships a small empty table shell instead of embedding every grouped alert row in
the HTML. On load, the browser requests the selected state slice from:

```text
GET /api/soc-alerts?analyst_status=open&limit=25&page=1
```

The table renders a rows-per-page selector plus Previous, Next, and direct page
selection. Search text, severity, last-seen window, `Show acknowledged`, and
`Show suppressed` changes trigger a fresh server-side query, so the browser no
longer downloads every alert and then filters locally. Single-group
acknowledge/suppress/expose writes still use the shared API. Every browser
opens `/api/soc-alerts/events` for live updates, with slower polling retained
as a fallback for multi-analyst convergence.

Validation on 2026-07-03:

```text
live index.html before API table shell: ~15.2 MB
live index.html after API table shell: 83,779 bytes
pre-script static table rows: 0
GET /api/soc-alerts?analyst_status=open&limit=25&page=1 -> 25 of 187 grouped detections, 8 pages
GET /api/soc-alerts?analyst_status=open&limit=25&page=1&levels=critical -> first page of matching critical detections
GET /api/soc-alerts?analyst_status=open&limit=25&page=1&since=60m -> first page of matching recent detections
GET /api/soc-alerts?analyst_status=open&limit=25&page=1&q=ssh -> first page of matching search results
GET /api/soc-alerts/events -> Server-Sent Event with AI state, analyst counts, metrics, and n8n beacon
```

SSE is now the primary live-update path for row state, badge counts, AI queue
state, n8n beacon updates, and table refresh hints. WebSockets are unnecessary
at the current scale because the browser only needs server-to-client updates.

## Lazy Detail Loading

Implemented 2026-07-03.

The dashboard builder keeps all rich report rendering in one place, but writes
each grouped detection's full detail body to:

```text
$HOME/SOC Alerts Web/details/<group_id>.html
$HOME/report_portal/library/Cybersecurity/SOC Alerts/details/<group_id>.html
```

The LAN Portal serves those fragments through:

```text
GET /api/soc-alerts/<group_id>/detail
```

The initial table API response includes only lightweight row fields and a small
placeholder detail summary. When an analyst expands a row for the first time,
the browser fetches the detail fragment, replaces the placeholder, and marks
that row as loaded. This preserves the full Detailed Alert Report experience
without making the browser download every Markdown/AI/raw-JSON report upfront.

Browser validation on 2026-07-03:

```text
Initial rows loaded: 25
Preloaded full detail sections: 0
Page status: Showing 1-25 of 187 grouped detections
Expanded group: 318792740295
Detail endpoint: /api/soc-alerts/318792740295/detail -> HTTP 200
Injected detail length: 85,625 HTML characters
AI sections present: yes
Raw Alert / Complete Alert JSON sections present: yes
```

Live status paths:

```text
$HOME/SOC Alerts Web/soc-alerts-status.json
$HOME/report_portal/library/Cybersecurity/SOC Alerts/soc-alerts-status.json
http://10.77.7.225:8765/view/b68c5a48b9778061/soc-alerts-status.json
```

Current builder:

```text
$HOME/.hermes/scripts/build_soc_alerts_dashboard.py
```

DR repo copy:

```text
onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py
```

The UI should request only the visible page of rows, then fetch detail content
on demand. This keeps the interface fast as alert volume grows.

## Live Update Channel

Implemented 2026-07-03.

The LAN Portal serves a Server-Sent Events stream at:

```text
GET /api/soc-alerts/events
```

The stream emits compact `soc-alerts` events containing:

- Shared analyst state counts and status map from SQLite.
- AI analysis activity and per-group AI status from `soc-alerts-status.json`.
- `Last n8n beacon` data from `n8n-beacon.json`.
- Seven-day alert metrics from SQLite.

The dashboard opens this stream with browser `EventSource`. When the payload
signature changes, the page updates metric cards immediately and reloads the
current API page slice after a short debounce. The stream also sends
keepalive comments and recycles periodically so browsers can reconnect cleanly.

Validation on 2026-07-03:

```text
SSE connected in browser: yes
Initial API rows loaded: 25
Page status: Showing 1-25 of 187 grouped detections
Preloaded full detail sections: 0
Expanded detail endpoint: /api/soc-alerts/318792740295/detail
Expanded detail loaded: yes
Console errors: none
```

## Static Pages

As of 2026-07-02, the SOC Alerts portal uses real static pages for each
left-navigation item instead of in-page JavaScript tabs. `index.html` is the
default SOC Alerts page and lands directly on the grouped SQLite alert table.
`home.html` is the executive summary page. It renders KPI cards, donut charts,
and horizontal bar charts from the grouped SQLite alert data: grouped
detections, total observations, urgent exposure, AI coverage, suppression
pressure, severity mix, workflow status, top detection families, top source and
destination assets, recent volume, and log source mix. `flow.html` is the
dedicated data-flow route and uses a simple inline ocean-wave SVG icon in the
left navigation. The icon is code-native, inherits the existing sidebar stroke
color, and intentionally does not use a generated bitmap so it matches the
current menu icons at collapsed and expanded sizes.

Generated pages:

```text
index.html          SOC Alerts default page
soc-alerts.html     Direct SOC Alerts bookmark
home.html           Executive KPI and chart overview
flow.html           Data-flow overview via Flow nav item
investigations.html Incident Responder workspace placeholder
siem-engineering.html SIEM Engineer tuning and detection recommendation workspace
reports.html        Reports workspace placeholder
playbooks.html      Playbooks workspace placeholder
automations.html    Automations workspace placeholder
sources.html        Sources workspace placeholder
threat-hunter.html  Threat Hunter workspace with expandable hunt plans and copyable queries
siem-tuning.html    Backward-compatible alias for SIEM Engineer
settings.html       Settings page with AI model routing plus collapsed SOC Analyst, Incident Responder, SIEM Engineer, and Threat Hunter prompt editors
```

The Flow page is intentionally simple: it gives an analyst a fast visual model
of the deployed data flow before they move into other SOC pages. The current
diagram shows Security Onion, Raspberry Pi Relay, Docker, n8n Workflow, Mac
Studio AI Lab, Ollama, AI Reports, SQLite, Telegram, and Onion Sentinel as
distinct stages.
The Ollama node displays the current local model name used by alert analysis,
currently `devstral:latest`, and shows the AI findings path into the AI Reports
node. The AI Reports node counts `*-local-ai-analysis.md` and
`*-local-ai-analysis.json` artifacts from
`$HOME/n8n-local/soc-alerts/ai-analysis`, uses same-size paired
logo badges with Obsidian's official purple mark and the `{JSON}` vector logo,
and renders compact text-only format metric pills so analysts can see the
human-readable and machine-readable corpus sizes at a glance. The JSON vector
keeps its official shape but gets a small CSS brightness lift so it remains
legible against the dark Flow card background. SQLite and
Telegram are rendered as full nodes with bundled brand marks so analysts can
quickly distinguish operational storage from mobile notification. The SQLite
node now uses the same compact metric-pill treatment as AI Reports, showing
grouped detections and total observations from the alert-store database. The
Telegram node uses the same metric style for mobile notification counts and
reads actual Critical and High send totals from `notification_log.sent_count`
where `channel = 'telegram'`.
Onion Sentinel is rendered as the analyst-facing dashboard endpoint using
`onion-sentinel-dashboard/assets/onion-sentinel-logo.png`; the diagram shows both SQLite
and AI Reports feeding directly into that dashboard node through two animated
downward arrows. The Onion Sentinel node spans both the AI Reports and SQLite
columns so it reads as the shared dashboard destination for report context and
database-backed alert state. Its logo is intentionally larger than the standard
node logos so the analyst-facing endpoint stands out. The node also exposes a
compact metric strip for the current grouped detection count, total repeated observations, AI analysis
coverage percentage, and critical/high group count so the diagram carries useful
state without turning into a full dashboard table. The metric-node card heights
and footer padding are sized so labels such as `Findings + actions`, `Fast
dashboard store`, and `Mobile notification` stay inside the cards. The diagram wraps into
equal-card rows so all node cards remain the same size and connector labels do
not clip at desktop widths. Every connector segment has a faster animated packet
marker so flow visibly continues across the full route, not only through the
first row. The Flow hero summary uses a thin pulsing cyan divider instead of
summary chips, matching the connector line style without adding an arrow.
Connector labels have padded opaque chips so wording does not sit on top of the
arrows or animated packets. Horizontal connector labels sit above and centered over each arrow segment, with enough clearance that they never intersect the animated arrow path; vertical connector labels sit to the side of the animated stem. Brand SVGs are bundled under
`onion-sentinel-dashboard/assets/brand/` and copied into the served portal during each
dashboard rebuild so the page does not depend on external image hosts. The Flow
page also ships `privacy-eye-button.png`, a generated eye-style privacy control
in the upper-right of the hero card. Node IP addresses are masked as `xxx.xxx.xxx.xxx` by default and
are revealed only when the analyst clicks that control.

Settings page behavior:

- Keeps the full `AI Analysis Model Selection` panel collapsed by default.
- Reads `$HOME/n8n-local/config/ai_model_settings.json`.
- Displays model routing controls for Ollama local-only, frontier/cloud CLI-only,
  or local-first hybrid analysis.
- Orders the model controls as a focused numbered 1-2-3 workflow: Analysis
  Mode first, Ollama Settings second, and Cloud Provider Settings third.
- Populates the Ollama model dropdown from `ollama ls` through
  `/api/soc-settings/ollama-models`; the list refreshes every 60 seconds while
  the Settings page is open, and the current configured model is preserved even
  if it is not returned by the local model inventory.
- Saves model routing through `/api/soc-settings/ai-model`.
- Reads `$HOME/n8n-local/config/soc_analyst_system_prompt.md`.
- Displays the current `SOC Analyst` prompt in a collapsible editor that is
  collapsed by default.
- Saves through `/api/soc-settings/analyst-prompt`.
- Reads `$HOME/n8n-local/config/incident_responder_system_prompt.md`.
- Displays the current `Incident Responder` prompt in a matching collapsible
  editor below the SOC Analyst prompt.
- Saves through `/api/soc-settings/incident-responder-prompt`.
- The Incident Responder prompt is for senior incident response planning and
  future external host artifact collection guidance. Direct external tooling is
  a TODO until a dedicated incident response host is connected, authenticated,
  logged, and approved.
- Reads `$HOME/n8n-local/config/siem_engineer_system_prompt.md`.
- Displays the current `SIEM Engineer` prompt in a matching collapsible editor
  below the Incident Responder prompt.
- Saves through `/api/soc-settings/siem-engineer-prompt`.
- Reads `$HOME/n8n-local/config/threat_hunter_system_prompt.md`.
- Displays the current `Threat Hunter` prompt in a matching collapsible editor
  below the SIEM Engineer prompt.
- Saves through `/api/soc-settings/threat-hunter-prompt`.
- The SIEM Engineer prompt is for a 2-4 hour engineering review that runs only
  after all eligible alerts/detections have finished AI analysis. It reviews
  alerts, enrichments, notes, acknowledgments, suppressions, and related context
  before recommending current-rule tuning or new detection creation.
- Requires a LAN Portal Administration session for saves.
- Does not require an n8n or scheduler restart; the AI runner reads the model
  routing and prompt files for each analysis request.

Current Flow page model:

```text
Security Onion -> Raspberry Pi relay -> Docker -> n8n Workflow -> Mac Studio AI Lab
Mac Studio AI Lab -> Ollama devstral:latest -> AI Reports
Mac Studio AI Lab -> SQLite grouped detection store
AI Reports + SQLite -> Onion Sentinel dashboard
n8n Workflow -> Telegram high/critical notifications
```

The implementation lives in:

```text
onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py
```

The generated page should contain:

```text
data-view="overview"
flow-product-hero
flow-system-node
flow-dot-horizontal
flow-dot-vertical
node-ollama
node-sqlite
node-telegram
node-onion-sentinel
flow-format-metrics
flow-node-metrics
flow-dashboard-bus
flow-dashboard-branch
Ollama logo
Obsidian logo
JSON logo
SQLite logo
Telegram logo
Onion Sentinel logo
Markdown
JSON
Grouped
Observations
AI coverage
Critical/high
devstral:latest
data-view-target="alerts"
```

The `SOC Alerts` nav item switches to the grouped table view. The table must
continue to show `Count` and must not promote random source ports into the
primary table. On non-alert pages, the sidebar badge for this nav item mirrors
the grouped alert count from `soc-alerts-status.json`. On the SOC Alerts table
page, the badge mirrors the table's current visible row count, not the raw
SQLite row count. The same client-side `applyFilter()` pass that updates the
`Visible / Total` metric also updates the nav badge, so search text,
acknowledged/suppressed visibility toggles, severity filtering, and last-seen
time-window filtering all change the badge immediately. The badge color follows
the highest severity among currently visible open alerts, using the same
Critical, High, Medium, Low, or Informational colors shown in the table.

## Duplicate Alert Grouping

The dashboard does not show every raw Security Onion document as a unique alert
row. It groups repeated alerts and shows a visible `Count` column.

There are two duplicate concepts:

| Type | Meaning | Current storage |
| --- | --- | --- |
| Exact duplicate | Same `alert_id` delivered more than once | One SQLite row with `seen_count` incremented |
| Repeated pattern | Different `alert_id` values but same practical alert pattern | Multiple SQLite rows, often sharing `suppression_key` or source/rule/destination |

Implemented dashboard grouping key:

```text
COALESCE(
  suppression_key,
  triage_level || '|' || rule_name || '|' || source_ip || '|' || destination_ip || '|' || COALESCE(filter_status, 'accepted')
)
```

Do not include source port in the grouping key. Source ports are usually
ephemeral client ports, so including them fragments repeated detections into
many fake-unique rows. Keep source port in the detail view and raw alert JSON,
but exclude it from duplicate/repeat grouping and consider removing it from the
primary table columns. Destination port is usually more useful and may remain
visible.

The dashboard uses this visible count column:

```text
Count
```

Grouped SQL shape for verification:

```sql
WITH grouped AS (
  SELECT
    COALESCE(
      suppression_key,
      COALESCE(triage_level, 'unscored') || '|' ||
      COALESCE(rule_name, 'unknown-rule') || '|' ||
      COALESCE(source_ip, 'unknown-source') || '|' ||
      COALESCE(destination_ip, 'unknown-destination') || '|' ||
      COALESCE(filter_status, 'accepted')
    ) AS alert_group_key,
    COUNT(*) AS raw_alert_count,
    COALESCE(SUM(seen_count), 0) AS total_seen_count,
    MIN(first_seen) AS first_seen,
    MAX(last_seen) AS last_seen,
    MAX(triage_score) AS max_triage_score,
    rule_name,
    source_ip,
    destination_ip,
    triage_level,
    routing,
    filter_status,
    filter_reason,
    suppression_key
  FROM alerts
  GROUP BY alert_group_key
)
SELECT *
FROM grouped
ORDER BY max_triage_score DESC, last_seen DESC;
```

Destination port is now promoted into SQLite and can be added to the fallback
grouping key if analysis shows the same rule/source/destination should split by
service. Source port should still remain excluded:

```text
triage_level | rule_name | source_ip | destination_ip | destination_port | filter_status
```

Displayed duplicate count:

```text
sum(max(seen_count, total_seen_count, 1) for each grouped SQLite row)
```

The visible table row should use the newest SQLite row in the group as the
representative alert. This keeps the table's timestamp, title, endpoints, and
AI status aligned to the latest event while `Count` represents the whole
grouped detection.

The alert table column formerly labeled `Modified` now displays `Last Seen`.
The generated HTML stores the grouped row's newest `last_seen` timestamp as
UTC, not the Markdown file modification time. At render time, browser
JavaScript converts that UTC value into the viewer's local timezone while
keeping ISO 8601 format with an explicit offset, such as
`2026-07-02  11:58:49-06:00`. Mobile newest-first sorting uses the same grouped
`last_seen` value so table order, mobile cards, and the pinned row all reflect
the latest alert event.

The table also includes a `Log Source` column immediately after `Last Seen`.
For SQLite-backed rows this comes from `alerts.event_dataset`, which currently
renders source labels such as `suricata.alert`. The value is also included in
row search text and as `data-alert-source` in the generated HTML so future UI
filters can use it without another schema change.

Row details should still allow the analyst to inspect representative alert
content, first seen, last seen, total raw records, total seen count, filter
status, and suppression key. Grouped rows with more than one member render a
`Duplicate Alert Timeline` section in the Detailed Alert Report. The timeline
plots repeated alert members on a time rail and the table lists every member row
chronologically by alert firing timestamp, seen count, source IP, destination
IP, destination port, and short alert ID. Markdown reports remain optional
detail content: some grouped suppressed rows may have no Markdown report by
design.

As of 2026-07-02, row details also render `Enriched Alert Details` from SQLite
`alerts.alert_json`. The Security Onion exporter adds selected ECS/Security
Onion/Suricata metadata under `security_onion.raw_event`, and the dashboard
builder turns that JSON into readable sections for Security Onion detail fields,
network/flow context, DNS/HTTP/URL/TLS context, host/sensor context, and threat
context.

The Detailed Alert Report also includes `Complete Alert JSON`, which contains
every alert field available to the dashboard from SQLite. Full-fidelity mode
does not redact packet payload, packet blob, PCAP, or HTTP body fields.
`Complete Alert JSON` and `Raw Alert` are rendered at the bottom of the
Detailed Alert Report as closed-by-default collapsible sections so analysts can
open them only when they need full evidence.

The Detailed Alert Report also includes local AI analysis context:

New local AI outputs include `Alert Frequency Assessment` and `Recommended Tuning Actions`. These are grounded in grouped alert Count, total observations, duplicate timeline, first seen, and last seen from SQLite.


| Section | Source | Behavior |
| --- | --- | --- |
| `AI Model Used` | `$HOME/n8n-local/soc-alerts/ai-analysis/*-local-ai-analysis.json` | Shows analysis status, model path, model name, generation time, prompt package, and analysis artifact path |
| `AI Analysis Output` | Same JSON artifact `response` object | Shows summary, likely meaning, severity reasoning, false-positive possibilities, recommended next steps, evidence used, evidence gaps, tuning recommendation, escalation fields, and complete AI response JSON |

When the artifact `analysis_type` is `local-ai`, the dashboard displays the
model path as `Ollama local` so the UI clearly shows that the analysis ran via
the local Ollama runtime.

The scheduled AI trigger uses the same grouped-alert concept. It analyzes up to
three eligible accepted/escalated/unknown groups per 5-minute run across every
real severity level and skips the group after any member has an analysis
artifact. This prevents large repeated detections from consuming every model
run while ensuring every unique dashboard row eventually receives analysis.

The dashboard matches AI artifacts to alerts by `alert_id`. For grouped rows,
it also checks all member alert IDs in the group, so a repeated detection can
still display analysis even when the analyzed event is not the representative
row. If no matching artifact exists, the report says `Not analyzed yet`.

The SOC Alerts table also includes an `AI` status column:

| Status | Source |
| --- | --- |
| `Analyzing` | A live `run-local-ai-analysis.py` process references the alert's prompt package |
| `Analyzed` | A matching JSON artifact exists in `$HOME/n8n-local/soc-alerts/ai-analysis` |
| `Queued` | No analysis JSON exists yet. If a prompt package exists, the row is actively staged; otherwise it is scheduler backlog and the prompt will be generated just-in-time by the local AI worker. |
| `Not queued` | Reserved for fallback/error states where SQLite alert-store status cannot be resolved. Normal unique dashboard alerts should not remain in this state. |

Status precedence is `Analyzing -> Analyzed -> Queued -> Not queued`. Every unique grouped dashboard alert should resolve to `Analyzed`, `Analyzing`, or `Queued`.

alert-store stores detail/enrichment data in:

| SQLite column | Use |
| --- | --- |
| `alert_json` | Full scored alert object and complete source for the dashboard |
| `enrichment_json` | Focused protocol/threat/context bundle for faster UI and local-AI access |
| `raw_event_json` | Selected original Security Onion event context, available for alerts collected after exporter enrichment |

Full-fidelity storage warning:

```text
Packet blobs, packet payload fields, PCAP fields, and HTTP body fields are
retained when Security Onion provides them. This can increase SQLite size and
may store sensitive traffic contents in SQLite, Markdown, and dashboard HTML.
```

Validation command result on 2026-07-02:

```text
raw SQLite alert rows: 1138
grouped dashboard rows: 64
visible dashboard rows: 64
primary table repeat column: Count
primary table Source Port column: removed
```

## SOC Alerts Time-Window Filter

The SOC Alerts table uses a `Last seen` rolling time-window filter instead of
the older suppressed-repeat filter. The filter is evaluated against the grouped
dashboard row's newest `last_seen` timestamp, so a duplicate group remains
visible when its most recent member falls inside the selected window.

Supported windows:

```text
All time
Last 30 min
Last 1 hour
Last 2 hours
Last 3 hours
Last 4 hours
Last 5 hours
Last 6 hours
Last 12 hours
Last 24 hours
Last 36 hours
Last 72 hours
Last 7 days
```

## Markdown Corpus Recommendation

Continue generating Markdown, but only for alerts that deserve analyst or AI
attention:

```text
critical/high accepted alerts: generate Markdown
medium accepted alerts: generate Markdown unless suppressed
suppressed repeats: store in SQLite, no Markdown
low/store-only: SQLite only unless manually promoted
dropped policy noise: no Markdown
```

Markdown should continue to be generated by the n8n `Write SOC Markdown Report`
node for accepted alerts. The LAN Portal should link to Markdown when a report
exists, but should not require a Markdown file for an alert to appear in the
dashboard. Suppressed, duplicate, and dropped records should be visible from
SQLite even when they have no report file.

For local AI, build a corpus directory that contains:

- Alert Markdown reports.
- Daily rollups.
- Investigation notes.
- Tuning decisions.
- Suppression summaries.

This gives local AI stable files to reference without forcing the web UI to
parse Markdown for every table refresh.

## Suppression Model

Suppression should expire. Suppression reduces repeated notification/report
noise, but should not erase evidence.

Current policy direction:

```text
First event in a suppression window: accepted, stored, may report
Repeated event inside TTL: stored as suppressed, no Markdown report, no Telegram
Escalation threshold reached: accepted again despite suppression
Window expires: next event is accepted again
```

Dashboard visibility controls:

- **Acknowledge** hides the current grouped detection from the default table and records the repeat count at the time of acknowledgement. If a later matching detection increases that grouped count, the dashboard automatically reopens the row so the analyst sees the new evidence.
- **Suppress** opens a confirmation dialog that requires a typed suppression reason before the grouped detection is hidden. The reason is limited to 140 characters, is saved with the analyst status record, and is displayed in a **Suppression Note** inside that alert's detailed report.
- Confirmed suppressions write the grouped detection state through `/api/soc-alerts/<group_id>/ack`, then immediately refresh the active API table page. With **Show suppressed** off, the suppressed grouped detection disappears from the active table view right away. With **Show suppressed** on, it remains visible with the **Expose** action, which removes the analyst suppression and allows matching detections to appear again.
- Analyst-entered workflow state is persisted in SQLite in the `analyst_alert_group_state` table, keyed by grouped detection id. This keeps user decisions such as `acknowledged`, `suppressed`, repeat count at decision time, typed reason, and update timestamp separate from raw alert evidence while still keeping the complete state in the same backed-up alert store. The older `analyst_alert_status` table may exist for backward compatibility, but the grouped API path writes suppression comments to `analyst_alert_group_state.reason`.
- **Show acknowledged** and **Show suppressed** toggles reveal those hidden groups without deleting or rewriting alert evidence.

Recommended default TTLs:

| Alert Type | TTL | Escalation |
| --- | ---: | ---: |
| Known repeated high/critical lab pattern | 15 minutes | every 25 events |
| Medium repeated scan/noise pattern | 30 minutes | every 20 events |
| Low repeated pattern | 1-6 hours | every 50 events |

## Current Fast Read Path

The SQLite-backed SOC API, lazy detail fragments, SSE live-update channel, and
write-maintained grouped summary table are deployed.

`alert-store` maintains `alert_group_summary` inside
`~/n8n-local/alert_store_data/alerts.sqlite3`. Each row represents one grouped
detection and stores:

- Stable `group_id` and `group_key`.
- Newest representative alert id.
- First seen and last seen timestamps.
- Raw alert row count and total observed count.
- Rule name, log source, severity, triage level, routing, filter state, and
  common endpoint fields.

The LAN Portal API prefers this summary table for:

- `GET /api/soc-alerts`
- `GET /api/soc-alerts/metrics`
- navigation badge counts and live SSE metric snapshots

`GET /api/soc-alerts` supports page-number pagination for the dashboard:

```text
/api/soc-alerts?analyst_status=open&limit=25&page=2
```

The response includes `page`, `page_size`, `total_pages`, `total_matching`, and
the current page of grouped alerts. The SOC Alerts table uses those fields to
render a rows-per-page selector plus Previous, Next, and direct page selection.
The default rows-per-page value is 25. This keeps the browser loading only one
selected slice of the grouped summary table at a time.

The SOC Alerts toolbar includes a compact `Last Seen` time-window filter and a `Sorting Default` selector. The sorting default currently supports `Newest Alerts First` and `Highest Severity First`, persists in browser local storage, and resets the table to page 1 when changed.

Expanded **Detailed Alert Report** panels are constrained to the visible table viewport, not the full horizontally scrollable table width. Long report text, JSON, code blocks, IDs, URLs, and table cells wrap inside the visible panel with a small right-side gutter so analyst text does not run to the screen edge.

The **Latest Alert** metric is live-driven from `/api/soc-alerts/metrics`, using the SQLite `latest_seen` value and converting it to the analyst browser's local ISO-style timestamp. It updates from Server-Sent Events when available and falls back to periodic metrics polling while the page remains open.

The table headers now drive server-side sorting through allowlisted
`sort=<field>&direction=<asc|desc>` API parameters. Database-backed sort fields
include count, severity, last seen, alert title, source IP, destination IP,
destination port, log source, representative payload size, and risk score. `AI`
is exposed in the same UI pattern, but should become fully semantic only after
`ai_status` is promoted into `alert_group_summary`; until then the API keeps AI
sort requests safe and stable with deterministic timestamp tie-breaking.

If the summary table is missing or empty, the portal falls back to runtime
grouping over `alerts`, which keeps disaster recovery forgiving after DB
restore or partial migration.

The portal opens alert-store SQLite in read-only mode through a closing context
manager. This avoids leaking file handles under repeated API calls; Python's
native `sqlite3.Connection` context manager only commits or rolls back and does
not close the connection by itself.

Manual repair command from the Mac Studio:

```bash
curl -fsS -X POST http://127.0.0.1:8787/refresh-groups
```

Future scaling work should move Detailed Alert Report fragments to true
on-demand generation and add SQLite FTS for full raw JSON search. That keeps the
initial dashboard build small even when raw Security Onion evidence grows into
hundreds of thousands of rows.
