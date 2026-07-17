import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const GROUP_ID = 'a1b2c3d4e5f6';
const FIXTURE_REASON = 'Synthetic QA suppression reason';
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

function fixtureListPayload(state, requestUrl) {
  const analystStatus = new URL(requestUrl).searchParams.get('analyst_status') || '';
  const statusMatches = !analystStatus
    || (['open', 'new'].includes(analystStatus) && state.status === 'open')
    || analystStatus === state.status;
  const statusCounts = {
    total: 1,
    open: state.status === 'open' ? 1 : 0,
    active: state.status === 'open' ? 1 : 0,
    acknowledged: state.status === 'acknowledged' ? 1 : 0,
    suppressed: state.status === 'suppressed' ? 1 : 0,
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

async function installSyntheticApi(page) {
  const state = {
    status: 'open',
    reason: '',
    updatedAt: '',
    aiStatus: 'not-queued',
    pcapStatus: 'none',
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

    if (method === 'GET' && path === '/api/soc-alerts') {
      await json(fixtureListPayload(state, request.url()));
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
