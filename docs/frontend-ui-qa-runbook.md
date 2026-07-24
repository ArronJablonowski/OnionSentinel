# Frontend UI QA Runbook

The Onion Sentinel UI regression suite combines static unit assertions with
two Playwright tracks:

- A read-only browser crawl against the independent Onion Sentinel dashboard. It intercepts mutating
  `/api/` requests and permits read-only API traffic only.
- A disposable mutation fixture generated under a temporary `HOME` and
  served on loopback. It uses TEST-NET alerts and exercises state-changing UI
  workflows without reading or writing production data.

## Install

```bash
cd operations/qa
npm ci
npx playwright install chromium
```

## Run

```bash
cd operations/qa
npm test
```

Run either track independently:

```bash
npm run test:read-only
npm run test:mutations
```

Override only the read-only deployment target when validating a restored
environment:

```bash
ONION_SENTINEL_BASE_URL=http://dashboard.example.test/view/site-id npm run test:read-only
```

The suite covers 320px and 480px mobile portrait, 844px phone landscape,
768px and 1024px tablets, and 1366px, 1440px, and 1920px desktop widths. Each
viewport repeats alert expansion, erratic scrolling, detail accordion toggles,
and collapse five times. It also crawls every internal navigation target,
checks document overflow and clipped interactive text, and captures traces,
screenshots, and video on failure. Short phone-landscape acceptance also
requires the first alert to begin in the initial viewport and the metric cards
to use a compact horizontal summary strip.

Mobile navigation acceptance opens the hamburger drawer at compact portrait,
modern iPhone portrait, and short phone-landscape sizes. It verifies that the
navigation list owns its vertical scroll, every menu row retains at least a
44px touch target, and the final `Flow` item can be scrolled into view and used
for navigation without creating page-level horizontal overflow.

Desktop acceptance additionally deep-scrolls an expanded Detailed Alert Report
and verifies that the selected-alert band is flush with the visible sticky
header or viewport top. The pinned band must copy the rendered source-table
column widths, keep all four action buttons on one line, and synchronize its
horizontal scroll position with the alert table. The regression suite pans the
pinned band with a vertical wheel gesture, repeats vertical report scrolling,
and rejects overlapping or clipped action controls. The Alert column measures
the current page's titles and expands between 420px and 960px so titles may
occupy no more than two lines in both the source row and its pinned clone.
Detailed Alert Report accordions use a compact 6px outer margin while retaining
touch-friendly section headers.
Sampled live reports must
each contain exactly one Duplicate Alert Timeline and one AI Analysis Output
section, including grouped detections with only one observation.

The read-only release gate also rebuilds the dashboard while repeatedly
requesting sampled detail endpoints. Every request must remain HTTP 200. A
transient 404 during publication indicates that the live detail directory was
cleared or a fragment was exposed before completion and blocks release.

Detail-renderer unit coverage also verifies nested packet-evidence accordions:
`TShark Findings` may live inside `Parsed PCAP Evidence`, while `Alert Summary`
and `Raw Logs` must remain independent top-level, closed-by-default dropdowns.
It also enforces Detailed Alert Report contract `2026-07-15.1`: all 15 required
sections must appear exactly once and in the documented order. Empty evidence
must render a placeholder, unknown legacy headings must be relocated beneath
`Raw Logs`, and malformed fragments must expose a layout error with the
expected version and specific validation failures.

When validating the live API, inspect both the rendered fragment and response
metadata:

```text
GET /api/soc-alerts/<group_id>/detail
layout_version = 2026-07-15.1
layout_valid = true
layout_issues = []
```

A `false` value is a release-blocking UI defect until the report is rebuilt or
the legacy field mapping is corrected. Do not suppress the error by hiding the
banner or modal.

The disposable fixture repeats acknowledge/restore and suppress/expose state
cycles five times, then verifies manual Analyze and PCAP queueing on desktop
and short phone-landscape layouts. Unexpected mutation routes fail the test.

## Safety Boundary

The read-only live suite must never submit acknowledge, suppress, expose,
analyze, or PCAP requests. Keep those workflows in the bundled disposable
fixture or exercise their API contracts through unit/integration tests. Never
replace the TEST-NET fixture with exported alerts or a production SQLite
database.
