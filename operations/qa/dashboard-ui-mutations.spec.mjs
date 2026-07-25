import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const GROUP_ID = 'a1b2c3d4e5f6';
const FIXTURE_REASON = 'Synthetic QA suppression reason';
const INCIDENT_CASE_ID = 'ir-synthetic-query-audit';
const EXACT_ALERT_CONTEXT_KQL = 'event.dataset: "synthetic.alert" AND source.ip: "192.0.2.10"';
const EXACT_NETWORK_FLOW_KQL = 'source.ip: "192.0.2.10" AND destination.ip: "198.51.100.20"';
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const SPEC_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SPEC_DIR, '../..');
const BUILDER = join(REPO_ROOT, 'onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py');
const CONTENT_TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};
let fixtureHome;
let fixtureRoot;
let fixtureServer;
let fixtureBaseUrl;

test.beforeAll(async () => {
  fixtureHome = mkdtempSync(join(tmpdir(), 'onion-sentinel-ui-qa-'));
  const build = spawnSync('python3', [BUILDER], {
    cwd: REPO_ROOT,
    env: { ...process.env, HOME: fixtureHome },
    encoding: 'utf8',
  });
  if (build.status !== 0) {
    throw new Error(`Synthetic dashboard build failed:\n${build.stderr || build.stdout}`);
  }
  fixtureRoot = join(fixtureHome, 'SOC Alerts Web');
  fixtureServer = createServer((request, response) => {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
    const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const target = resolve(fixtureRoot, relative);
    if (!target.startsWith(`${resolve(fixtureRoot)}${sep}`)) {
      response.writeHead(403).end('Forbidden');
      return;
    }
    try {
      if (!statSync(target).isFile()) throw new Error('not a file');
      response.writeHead(200, {
        'Content-Type': CONTENT_TYPES[extname(target).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': 'no-store',
      });
      response.end(readFileSync(target));
    } catch {
      response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
    }
  });
  await new Promise((accept, reject) => {
    fixtureServer.once('error', reject);
    fixtureServer.listen(0, '127.0.0.1', accept);
  });
  const address = fixtureServer.address();
  fixtureBaseUrl = `http://127.0.0.1:${address.port}`;
});

test.afterAll(async () => {
  if (fixtureServer) await new Promise(resolveClose => fixtureServer.close(resolveClose));
  if (fixtureHome) rmSync(fixtureHome, { recursive: true, force: true });
});

function fixtureAlert(state) {
  return {
    group_id: GROUP_ID,
    group_key: 'medium|Synthetic mutation QA alert|192.0.2.10|198.51.100.20|accepted',
    representative_alert_id: 'synthetic-alert-001',
    first_seen: '2026-07-15  08:00:00-06:00',
    last_seen: '2026-07-15  08:05:00-06:00',
    raw_alert_count: 3,
    seen_count: 3,
    timestamp: '2026-07-15  08:05:00-06:00',
    rule_name: 'Synthetic mutation QA alert',
    event_dataset: 'synthetic.alert',
    severity: 2,
    severity_label: 'medium',
    triage_score: 52,
    triage_level: 'medium',
    routing: 'store-and-notify',
    traffic_direction: 'outbound',
    source_ip: '192.0.2.10',
    source_port: 51515,
    destination_ip: '198.51.100.20',
    destination_port: 443,
    payload_size_bytes: 2048,
    transport_protocol: 'tcp',
    filter_status: 'accepted',
    analyst_status: state.status,
    analyst_status_reason: state.reason,
    analyst_status_updated_at: state.updatedAt,
    ai_status_key: state.aiStatus,
    ai_status_label: state.aiStatus === 'queued' ? 'Queued' : 'Not Queued',
    ai_status_detail: 'Synthetic browser-isolated QA state',
    enrichment_status_key: 'enriched',
    enrichment_status_label: 'Enriched',
    enrichment_status_detail: 'Synthetic TEST-NET enrichment fixture',
    pcap_status_key: state.pcapStatus,
    pcap_status_label: state.pcapStatus === 'queued' ? 'Queued' : 'None',
    pcap_status_detail: 'Synthetic browser-isolated QA state',
  };
}

function fixtureStatuses(state) {
  if (state.status === 'open') return {};
  return {
    [GROUP_ID]: {
      status: state.status,
      repeat_count: 3,
      reason: state.reason,
      updated_at: state.updatedAt,
      updated_by: 'playwright-fixture',
    },
  };
}

function escapeFixtureHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[character]));
}

function fixtureIncidentQueryRecord(position, pack, kql, totalHits, returnedHits, linkedFinding = '') {
  const dsl = JSON.stringify({
    query: { bool: { filter: [{ query_string: { query: kql } }] } },
    size: 25,
  }, null, 2);
  return `<article class="ir-query-record" data-query-finding="${escapeFixtureHtml(linkedFinding)}">`
    + `<h4>Query ${position}: ${pack}</h4>`
    + `<div class="ir-query-meta">`
    + `<span><b>Status:</b> ok</span>`
    + `<span><b>Digest:</b> <code>digest-${position}</code></span>`
    + `<span><b>Window:</b> 2026-07-15  08:00:00-06:00 to 2026-07-15  08:10:00-06:00</span>`
    + `<span><b>Hits:</b> ${totalHits} total / ${returnedHits} returned</span>`
    + `</div>`
    + `<h5>KQL (analyst-readable equivalent)</h5>`
    + `<pre class="ir-query-code"><code>${escapeFixtureHtml(kql)}</code></pre>`
    + `<h5>Elasticsearch Query DSL (exact executed request)</h5>`
    + `<pre class="ir-query-code"><code>${escapeFixtureHtml(dsl)}</code></pre>`
    + (position === 2
      ? `<h5>Bounded Result Preview</h5><pre class="ir-query-code"><code>[{"synthetic":true}]</code></pre>`
      : '')
    + `</article>`;
}

function fixtureInteractivePivotRecords() {
  const oql = '@timestamp:["2026-07-15T14:00:00.000Z" TO "2026-07-15T14:10:00.000Z"]'
    + ' AND source.ip:"192.0.2.10" | sortby @timestamp^';
  const dsl = JSON.stringify({
    size: 25,
    query: { bool: { filter: [{ term: { 'source.ip': '192.0.2.10' } }] } },
  }, null, 2);
  const structured = JSON.stringify({
    operation: 'dns',
    filters: { query: 'example.test' },
    limit: 10,
  }, null, 2);
  return `<section class="ir-query-audit"><h3>Interactive Investigation Pivot Audit</h3>`
    + `<article class="ir-query-record" data-query-purpose="Correlate an exact trusted observable."`
    + ` data-query-finding="One related flow was returned.">`
    + `<h4>Pivot 1 (round 1): OQL · network_flow</h4>`
    + `<div class="ir-query-meta"><span><b>Status:</b> ok</span>`
    + `<span><b>Hits:</b> 1 total / 1 returned</span></div>`
    + `<h5>OQL (analyst-readable equivalent)</h5>`
    + `<pre class="ir-query-code"><code>${escapeFixtureHtml(oql)}</code></pre>`
    + `<h5>Elasticsearch Query DSL (exact executed request)</h5>`
    + `<pre class="ir-query-code"><code>${escapeFixtureHtml(dsl)}</code></pre>`
    + `</article>`
    + `<article class="ir-query-record" data-query-purpose="Confirm the DNS answer."`
    + ` data-query-finding="">`
    + `<h4>Pivot 2 (round 1): ZEEK · dns</h4>`
    + `<div class="ir-query-meta"><span><b>Status:</b> ok</span>`
    + `<span><b>Records:</b> 4 scanned / 1 returned</span></div>`
    + `<h5>Structured PCAP/Zeek request (exact broker input)</h5>`
    + `<pre class="ir-query-code"><code>${escapeFixtureHtml(structured)}</code></pre>`
    + `</article></section>`;
}

function fixtureIncidentHtml() {
  return `<section class="ir-investigation-report"><h3>Incident Response Investigation</h3>`
    + `<p>Synthetic query-audit browser fixture.</p></section>`
    + `<section class="ir-query-audit"><h3>Security Onion Query Audit</h3>`
    + `<div class="ir-analysis-meta"><span><b>Source:</b> synthetic restricted wrapper</span></div>`
    + fixtureIncidentQueryRecord(
      1,
      'alert_context',
      EXACT_ALERT_CONTEXT_KQL,
      1,
      1,
      'The triggering synthetic detection was returned by the bounded query.',
    )
    + fixtureIncidentQueryRecord(2, 'network_flow', EXACT_NETWORK_FLOW_KQL, 7, 3)
    + `</section>`
    + fixtureInteractivePivotRecords();
}

function fixtureListPayload(state, requestUrl) {
  const analystStatus = new URL(requestUrl).searchParams.get('analyst_status') || '';
  const statusMatches = !state.escalated && (!analystStatus
    || (['open', 'new'].includes(analystStatus) && state.status === 'open')
    || analystStatus === state.status);
  const statusCounts = {
    total: state.escalated ? 0 : 1,
    open: !state.escalated && state.status === 'open' ? 1 : 0,
    active: !state.escalated && state.status === 'open' ? 1 : 0,
    acknowledged: !state.escalated && state.status === 'acknowledged' ? 1 : 0,
    suppressed: !state.escalated && state.status === 'suppressed' ? 1 : 0,
  };
  return {
    ok: true,
    source: 'synthetic-playwright-fixture',
    mode: 'grouped',
    count: statusMatches ? 1 : 0,
    total_matching: statusMatches ? 1 : 0,
    status_counts: statusCounts,
    severity_counts: {
      critical: 0,
      high: 0,
      medium: statusMatches ? 1 : 0,
      low: 0,
      informational: 0,
    },
    highest_severity: statusMatches ? 'medium' : 'none',
    top_endpoints: {
      source_ip: statusMatches ? '192.0.2.10' : 'n/a',
      destination_ip: statusMatches ? '198.51.100.20' : 'n/a',
      destination_port: statusMatches ? '443' : 'n/a',
    },
    limit: 25,
    page: 1,
    page_size: 25,
    total_pages: 1,
    sort: 'last_seen',
    direction: 'desc',
    next_cursor: null,
    alerts: statusMatches ? [fixtureAlert(state)] : [],
  };
}

async function installSyntheticApi(page, { failEscalation = false } = {}) {
  const state = {
    status: 'open',
    reason: '',
    updatedAt: '',
    aiStatus: 'not-queued',
    pcapStatus: 'none',
    escalated: false,
    delayNextListResponse: false,
    delayedListStarted: false,
    delayedListFinished: false,
    postEscalationListResponses: 0,
    mutations: [],
  };

  await page.route('**/api/**', async route => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());
    const path = url.pathname;
    const json = body => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });

    if (method === 'GET' && path === '/api/soc-incidents') {
      await json({
        ok: true,
        incidents: [{
          case_id: INCIDENT_CASE_ID,
          status: 'open',
          agent_status: 'analyzed',
          triage_level: 'medium',
          escalated_at: '2026-07-15  08:06:00-06:00',
          rule_name: 'Synthetic incident query audit',
          reason: 'Synthetic browser-only evidence review',
          source_ip: '192.0.2.10',
          destination_ip: '198.51.100.20',
          destination_port: 443,
          seen_count: 3,
        }],
        total: 1,
        page: 1,
        pages: 1,
        status_counts: { open: 1 },
        agent_status_counts: { analyzed: 1 },
      });
      return;
    }
    if (method === 'GET' && path === `/api/soc-incidents/${INCIDENT_CASE_ID}/detail`) {
      await json({
        ok: true,
        case_id: INCIDENT_CASE_ID,
        incident_html: fixtureIncidentHtml(),
        prior_ai_html: '<div class="ir-prior-analysis"><p>Synthetic prior analysis.</p></div>',
      });
      return;
    }
    if (method === 'GET' && path === '/api/soc-alerts') {
      const payload = fixtureListPayload(state, request.url());
      if (state.delayNextListResponse) {
        state.delayNextListResponse = false;
        state.delayedListStarted = true;
        await new Promise(resolveDelay => setTimeout(resolveDelay, 5500));
        state.delayedListFinished = true;
      } else if (state.escalated) {
        state.postEscalationListResponses += 1;
      }
      await json(payload);
      return;
    }
    if (method === 'GET' && path === '/api/soc-alerts/events') {
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        body: 'retry: 60000\n\n',
      });
      return;
    }
    if (method === 'GET' && path === '/api/soc-alerts/status') {
      await json({ ok: true, mode: 'grouped', statuses: fixtureStatuses(state) });
      return;
    }
    if (method === 'GET' && path === '/api/soc-alerts/metrics') {
      await json({
        ok: true,
        grouped_total: 1,
        by_analyst_status: fixtureListPayload(state, request.url()).status_counts,
      });
      return;
    }
    if (method === 'GET' && path === `/api/soc-alerts/${GROUP_ID}/detail`) {
      await json({
        ok: true,
        source: 'synthetic-playwright-fixture',
        group_id: GROUP_ID,
        detail_html: '<div class="markdown-body"><h2>Synthetic Detailed Alert Report</h2><p>TEST-NET fixture only.</p></div>',
      });
      return;
    }
    if (method === 'POST' && path === `/api/soc-alerts/${GROUP_ID}/ack`) {
      const payload = request.postDataJSON();
      state.status = payload.status || 'open';
      state.reason = payload.reason || '';
      state.updatedAt = '2026-07-15  08:06:00-06:00';
      state.mutations.push({ action: 'ack', payload });
      await json({ ok: true, statuses: fixtureStatuses(state) });
      return;
    }
    if (method === 'POST' && path === `/api/soc-alerts/${GROUP_ID}/analyze`) {
      const payload = request.postDataJSON();
      state.aiStatus = 'queued';
      state.mutations.push({ action: 'analyze', payload });
      await json({
        ok: true,
        ai_status_key: 'queued',
        ai_status_label: 'Queued',
        ai_status_detail: 'Synthetic fresh full-group analysis queued',
      });
      return;
    }
    if (method === 'POST' && path === `/api/soc-alerts/${GROUP_ID}/pcap`) {
      const payload = request.postDataJSON();
      state.pcapStatus = 'queued';
      state.mutations.push({ action: 'pcap', payload });
      await json({ ok: true, pcap_status_key: 'queued', pcap_status_label: 'Queued' });
      return;
    }
    if (method === 'POST' && path === `/api/soc-alerts/${GROUP_ID}/escalate`) {
      const payload = request.postDataJSON();
      state.mutations.push({ action: 'escalate', payload });
      if (failEscalation) {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, error: 'synthetic escalation failure' }),
        });
        return;
      }
      state.escalated = true;
      await json({ ok: true, case_id: 'ir-synthetic-ui', agent_status: 'queued' });
      return;
    }

    if (MUTATING_METHODS.has(method)) {
      state.mutations.push({ action: 'blocked', method, path });
      await route.fulfill({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({ ok: false, error: 'unhandled mutation blocked by synthetic QA fixture' }),
      });
      return;
    }
    await route.continue();
  });
  return state;
}

async function openSyntheticAlert(page) {
  await page.goto(`${fixtureBaseUrl}/index.html`, { waitUntil: 'domcontentloaded' });
  await expect(page.locator('strong:visible', { hasText: 'Synthetic mutation QA alert' }).first()).toBeVisible();
}

async function visibleAction(page, action) {
  return page.locator(`[data-${action}="${GROUP_ID}"]:visible`).first();
}

async function exposeAlertActions(page) {
  if (await page.locator('.mobile-alert-list').isVisible()) {
    const pill = page.locator(`.mobile-alert-card[data-mobile-report-id="${GROUP_ID}"] .mobile-alert-pill`);
    if ((await pill.getAttribute('aria-expanded')) !== 'true') await pill.click();
  }
}

async function toggleFilter(page, inputId, checked) {
  const input = page.locator(inputId);
  if ((await input.isChecked()) === checked) return;
  await page.locator('label.toggle-wrap', { has: input }).click();
  await expect(input).toBeChecked({ checked });
}

test('synthetic fixture safely validates every destructive alert action', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const state = await installSyntheticApi(page);
  await openSyntheticAlert(page);

  for (let cycle = 0; cycle < 5; cycle += 1) {
    await (await visibleAction(page, 'acknowledge')).click();
    await expect.poll(() => state.status).toBe('acknowledged');
    await expect(page.getByText('Synthetic mutation QA alert')).toHaveCount(0);

    await toggleFilter(page, '#show-acknowledged', true);
    await expect(page.locator('strong:visible', { hasText: 'Synthetic mutation QA alert' }).first()).toBeVisible();
    await expect(await visibleAction(page, 'acknowledge')).toHaveText('Unacknowledge');
    await (await visibleAction(page, 'acknowledge')).click();
    await expect.poll(() => state.status).toBe('open');
    await toggleFilter(page, '#show-acknowledged', false);
    await expect(page.locator('strong:visible', { hasText: 'Synthetic mutation QA alert' }).first()).toBeVisible();

    await (await visibleAction(page, 'suppress')).click();
    await expect(page.locator('#suppress-modal')).toBeVisible();
    await page.locator('#suppress-reason').fill(FIXTURE_REASON);
    await page.locator('#confirm-suppression').click();
    await expect.poll(() => state.status).toBe('suppressed');
    await expect(page.getByText('Synthetic mutation QA alert')).toHaveCount(0);

    await toggleFilter(page, '#show-suppressed', true);
    await expect(page.locator('strong:visible', { hasText: 'Synthetic mutation QA alert' }).first()).toBeVisible();
    await expect(await visibleAction(page, 'suppress')).toHaveText('Expose');
    await (await visibleAction(page, 'suppress')).click();
    await expect.poll(() => state.status).toBe('open');
    await toggleFilter(page, '#show-suppressed', false);
    await expect(page.locator('strong:visible', { hasText: 'Synthetic mutation QA alert' }).first()).toBeVisible();
  }

  await (await visibleAction(page, 'analyze')).click();
  await expect.poll(() => state.aiStatus).toBe('queued');
  await expect(page.locator(`tbody[data-report-id="${GROUP_ID}"] .ai-status-pill`)).toContainText('Queued');

  await (await visibleAction(page, 'pcap')).click();
  await expect.poll(() => state.pcapStatus).toBe('queued');
  await expect(page.locator(`tbody[data-report-id="${GROUP_ID}"] .pcap-status-cell .pcap-status-pill`).first())
    .toContainText('Queued');

  expect(state.mutations.filter(item => item.action === 'ack')).toHaveLength(20);
  expect(state.mutations.filter(item => item.action === 'analyze')).toHaveLength(1);
  expect(state.mutations.filter(item => item.action === 'pcap')).toHaveLength(1);
  expect(state.mutations.filter(item => item.action === 'blocked')).toEqual([]);
  expect(state.mutations.find(item => item.action === 'ack' && item.payload.status === 'suppressed')?.payload.reason)
    .toBe(FIXTURE_REASON);
});

test('short landscape mutation controls remain usable with synthetic state', async ({ page }) => {
  await page.setViewportSize({ width: 844, height: 390 });
  const state = await installSyntheticApi(page);
  await openSyntheticAlert(page);

  const firstPill = page.locator('.mobile-alert-pill:visible').first();
  const box = await firstPill.boundingBox();
  expect(box?.y).toBeLessThan(390);
  await exposeAlertActions(page);

  for (const action of ['analyze', 'acknowledge', 'suppress', 'pcap']) {
    const actionBox = await (await visibleAction(page, action)).boundingBox();
    expect(actionBox?.height, `${action} touch target`).toBeGreaterThanOrEqual(44);
  }

  await (await visibleAction(page, 'analyze')).click();
  await expect.poll(() => state.aiStatus).toBe('queued');
  await exposeAlertActions(page);
  await (await visibleAction(page, 'pcap')).click();
  await expect.poll(() => state.pcapStatus).toBe('queued');

  expect(state.mutations.filter(item => item.action === 'blocked')).toEqual([]);
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    page: document.documentElement.scrollWidth,
  }));
  expect(dimensions.page).toBeLessThanOrEqual(dimensions.viewport + 1);
});

test('incident query audits collapse by default and copy exact queries with accessible feedback', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => {
    window.__incidentQueryCopies = [];
    window.__incidentQueryCopyFailure = false;
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: async value => {
          if (window.__incidentQueryCopyFailure) throw new Error('synthetic clipboard failure');
          window.__incidentQueryCopies.push(value);
        },
      },
    });
    document.execCommand = command => command === 'copy' && !window.__incidentQueryCopyFailure;
  });
  await installSyntheticApi(page);
  await page.goto(`${fixtureBaseUrl}/investigations.html`, { waitUntil: 'domcontentloaded' });

  const incidentRow = page.locator(`[data-case-id="${INCIDENT_CASE_ID}"]`);
  await expect(incidentRow).toBeVisible();
  await incidentRow.click();

  const detail = page.locator(`.ir-detail-row[data-detail-for="${INCIDENT_CASE_ID}"]:not([hidden])`);
  const queries = detail.locator('details.ir-query-details');
  await expect(queries).toHaveCount(4);
  await expect(page.locator(`[data-mobile-case="${INCIDENT_CASE_ID}"] details.ir-query-details`)).toHaveCount(4);
  for (let index = 0; index < 4; index += 1) {
    await expect(queries.nth(index)).not.toHaveAttribute('open', '');
  }

  const alertContext = queries.nth(0);
  await expect(alertContext.locator('summary')).toContainText('Query 1: alert_context');
  await expect(alertContext.locator('summary')).toContainText('Review the triggering detection and its immediate alert context.');
  await expect(alertContext.locator('summary')).toContainText('1 total hits; 1 returned. Status: ok.');
  await expect(alertContext.locator('summary')).toContainText(
    'Responder finding: The triggering synthetic detection was returned by the bounded query.',
  );
  await alertContext.locator('summary').click();
  await expect(alertContext).toHaveAttribute('open', '');

  const queryCopyButtons = detail.locator('.ir-query-copy');
  await expect(queryCopyButtons).toHaveCount(7);
  const kqlCopy = alertContext.getByRole('button', {
    name: 'Copy KQL (analyst-readable equivalent) for Query 1: alert_context',
  });
  await kqlCopy.click();
  await expect(kqlCopy).toHaveText('Copied');
  await expect(alertContext.getByRole('status')).toHaveText('Copied exact query.');
  await expect.poll(() => page.evaluate(() => window.__incidentQueryCopies[0])).toBe(EXACT_ALERT_CONTEXT_KQL);

  const networkFlow = queries.nth(1);
  await expect(networkFlow.locator('summary')).toContainText('Review related network connections and traffic metadata.');
  await expect(networkFlow.locator('summary')).toContainText('7 total hits; 3 returned. Status: ok.');
  await expect(networkFlow.locator('summary')).toContainText(
    'No query-linked responder finding was recorded.',
  );
  await networkFlow.locator('summary').click();
  await page.evaluate(() => { window.__incidentQueryCopyFailure = true; });
  const failedCopy = networkFlow.getByRole('button', {
    name: 'Copy KQL (analyst-readable equivalent) for Query 2: network_flow',
  });
  await failedCopy.click();
  await expect(failedCopy).toHaveText('Try again');
  await expect(networkFlow.getByRole('status')).toHaveText('Copy failed — select and copy the query manually.');

  await page.evaluate(() => { window.__incidentQueryCopyFailure = false; });
  const oqlPivot = queries.nth(2);
  await expect(oqlPivot.locator('summary')).toContainText('Pivot 1 (round 1): OQL · network_flow');
  await expect(oqlPivot.locator('summary')).toContainText('One related flow was returned.');
  await oqlPivot.locator('summary').click();
  const oqlCopy = oqlPivot.getByRole('button', {
    name: 'Copy OQL (analyst-readable equivalent) for Pivot 1 (round 1): OQL · network_flow',
  });
  await oqlCopy.click();
  await expect(oqlCopy).toHaveText('Copied');

  const zeekPivot = queries.nth(3);
  await expect(zeekPivot.locator('summary')).toContainText('4 records scanned; 1 returned.');
  await zeekPivot.locator('summary').click();
  const structuredCopy = zeekPivot.getByRole('button', {
    name: 'Copy Structured PCAP/Zeek request (exact broker input) for Pivot 2 (round 1): ZEEK · dns',
  });
  await structuredCopy.click();
  await expect(structuredCopy).toHaveText('Copied');

  const copied = await page.evaluate(() => window.__incidentQueryCopies);
  expect(copied.some(value => value.includes('@timestamp:['))).toBeTruthy();
  expect(copied.some(value => value.includes('"operation": "dns"'))).toBeTruthy();
  await expect(detail.locator('.ir-query-copy')).toHaveCount(7);
});

test('successful escalation confirms for five seconds and removes desktop and mobile rows despite a stale list response', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const state = await installSyntheticApi(page);
  await openSyntheticAlert(page);

  const desktopGroup = page.locator(`tbody.report-row-group[data-report-id="${GROUP_ID}"]`);
  const mobileCard = page.locator(`[data-mobile-report-id="${GROUP_ID}"]`);
  state.delayNextListResponse = true;
  await page.locator('[data-sort-key="severity"]').click();
  await expect.poll(() => state.delayedListStarted).toBe(true);
  const escalate = await visibleAction(page, 'escalate');
  await escalate.click();

  await expect.poll(() => state.escalated).toBe(true);
  await expect(desktopGroup.locator('[data-escalate]')).toHaveText('Escalated');
  await expect(desktopGroup.locator('[data-escalate]')).toBeDisabled();
  await expect(mobileCard.locator('[data-escalate]')).toHaveText('Escalated');
  await page.waitForTimeout(4000);
  await expect(desktopGroup).toHaveCount(1);
  await expect(mobileCard).toHaveCount(1);
  await expect(desktopGroup).toHaveCount(0, { timeout: 2500 });
  await expect(mobileCard).toHaveCount(0);
  await expect.poll(() => state.delayedListFinished).toBe(true);
  await expect.poll(() => state.postEscalationListResponses).toBeGreaterThanOrEqual(1);
  await expect(desktopGroup).toHaveCount(0);
  await expect(mobileCard).toHaveCount(0);
  expect(state.mutations.filter(item => item.action === 'escalate')).toHaveLength(1);
  expect(state.mutations.filter(item => item.action === 'blocked')).toEqual([]);
});

test('failed escalation restores the action and keeps the alert visible', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const state = await installSyntheticApi(page, { failEscalation: true });
  await openSyntheticAlert(page);

  const desktopGroup = page.locator(`tbody.report-row-group[data-report-id="${GROUP_ID}"]`);
  const escalate = await visibleAction(page, 'escalate');
  await escalate.click();

  await expect(desktopGroup.locator('[data-escalate]')).toHaveText('Escalate');
  await expect(desktopGroup.locator('[data-escalate]')).toBeEnabled();
  await expect(desktopGroup).toHaveCount(1);
  expect(state.escalated).toBe(false);
  expect(state.mutations.filter(item => item.action === 'escalate')).toHaveLength(1);
});
