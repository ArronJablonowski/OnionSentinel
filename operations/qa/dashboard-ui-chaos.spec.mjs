import { expect, test } from '@playwright/test';

const VIEWPORTS = [
  { name: 'mobile-portrait-320', width: 320, height: 568 },
  { name: 'mobile-portrait-480', width: 480, height: 800 },
  { name: 'mobile-landscape-844', width: 844, height: 390 },
  { name: 'tablet-portrait-768', width: 768, height: 1024 },
  { name: 'tablet-landscape-1024', width: 1024, height: 768 },
  { name: 'laptop-1366', width: 1366, height: 768 },
  { name: 'desktop-1440', width: 1440, height: 900 },
  { name: 'desktop-1920', width: 1920, height: 1080 },
];

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function collectRuntimeErrors(page) {
  const errors = [];
  page.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
  page.on('response', response => {
    if (response.status() >= 400) {
      errors.push(`http: ${response.status()} ${response.request().method()} ${response.url()}`);
    }
  });
  page.on('console', message => {
    if (message.type() === 'error' && !message.text().startsWith('Failed to load resource:')) {
      errors.push(`console: ${message.text()}`);
    }
  });
  return errors;
}

async function protectLiveState(page) {
  await page.route('**/api/**', async route => {
    if (!MUTATING_METHODS.has(route.request().method())) {
      await route.continue();
      return;
    }
    await route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({ ok: false, error: 'blocked by UI chaos QA' }),
    });
  });
}

async function openAlerts(page) {
  await page.goto('./index.html', { waitUntil: 'domcontentloaded' });
  await expect(page).toHaveTitle(/SOC Alerts/);
  await expect(page.locator('.report-row-group').first()).toBeAttached();
  await page.waitForTimeout(500);
}

async function assertContainedLayout(page) {
  const layout = await page.evaluate(() => ({
    viewportWidth: document.documentElement.clientWidth,
    pageWidth: document.documentElement.scrollWidth,
    clippedText: [...document.querySelectorAll('button,a,summary,label')]
      .filter(node => {
        const style = getComputedStyle(node);
        const rect = node.getBoundingClientRect();
        return style.display !== 'none'
          && style.visibility !== 'hidden'
          && rect.width > 0
          && node.scrollWidth > node.clientWidth + 2
          && !['auto', 'scroll'].includes(style.overflowX)
          && style.textOverflow !== 'ellipsis';
      })
      .slice(0, 10)
      .map(node => `${node.tagName}.${node.className}`),
  }));
  expect(layout.pageWidth, JSON.stringify(layout)).toBeLessThanOrEqual(layout.viewportWidth + 1);
  expect(layout.clippedText, JSON.stringify(layout)).toEqual([]);
}

async function erraticScroll(page) {
  for (const delta of [180, 640, -220, 980, -410, 260]) {
    await page.mouse.wheel(0, delta);
    await page.waitForTimeout(Math.abs(delta) % 3 === 0 ? 35 : 80);
  }
}

async function toggleFirstAlert(page, viewport) {
  const isCardLayout = await page.locator('.mobile-alert-list').isVisible();
  const trigger = isCardLayout
    ? page.locator('.mobile-alert-pill:visible').first()
    : page.locator('.report-row:visible').first();
  await expect(trigger).toBeVisible();
  await trigger.click();
  if (isCardLayout) {
    await expect(trigger.locator('xpath=..')).toHaveClass(/mobile-expanded/);
  } else {
    await expect(trigger.locator('xpath=ancestor::tbody[1]')).toHaveClass(/expanded/);
  }
  return { trigger, isCardLayout };
}

for (const viewport of VIEWPORTS) {
  test(`${viewport.name}: responsive chaos and report stability`, async ({ page }) => {
    const runtimeErrors = collectRuntimeErrors(page);
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await protectLiveState(page);
    await openAlerts(page);
    await assertContainedLayout(page);

    const controlsButton = page.locator('#mobile-controls-toggle:visible');
    if (await controlsButton.count()) {
      const box = await controlsButton.boundingBox();
      expect(box?.width).toBeGreaterThanOrEqual(44);
      expect(box?.height).toBeGreaterThanOrEqual(44);
      await controlsButton.click();
      await controlsButton.click();
    }

    if (viewport.width <= 960 && viewport.height <= 560) {
      const firstAlert = page.locator('.mobile-alert-pill:visible').first();
      const alertBox = await firstAlert.boundingBox();
      expect(alertBox, 'short landscape should render an alert in the first viewport').not.toBeNull();
      expect(alertBox.y, 'short landscape alert should begin before the viewport ends').toBeLessThan(viewport.height);
      await expect(page.locator('.metrics')).toHaveCSS('overflow-x', 'auto');
    }

    for (let loop = 0; loop < 5; loop += 1) {
      const { trigger, isCardLayout } = await toggleFirstAlert(page, viewport);
      await page.waitForTimeout(250);
      await erraticScroll(page);

      if (viewport.width <= 1180 || viewport.height < 600) {
        const pinned = page.locator('.pinned-alert-viewport');
        await expect(pinned).toBeHidden();
      }

      const summaries = page.locator('.report-row-group.expanded details > summary:visible');
      const summaryCount = Math.min(await summaries.count(), 3);
      for (let index = 0; index < summaryCount; index += 1) {
        await summaries.nth(index).click();
        await summaries.nth(index).click();
      }

      await trigger.evaluate(element => element.click());
      if (isCardLayout) {
        await expect(trigger.locator('xpath=..')).not.toHaveClass(/mobile-expanded/);
      } else {
        await expect(trigger.locator('xpath=ancestor::tbody[1]')).not.toHaveClass(/expanded/);
      }
      await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    }
    expect(runtimeErrors).toEqual([]);
  });
}

test('internal page crawl and safe interactive-state audit', async ({ page }) => {
  const runtimeErrors = collectRuntimeErrors(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await protectLiveState(page);
  await openAlerts(page);
  const hrefs = await page.locator('.nav a[href]').evaluateAll(links =>
    [...new Set(links.map(link => link.getAttribute('href')).filter(Boolean))]);

  for (const href of hrefs) {
    await page.goto(href, { waitUntil: 'domcontentloaded' });
    await expect(page.locator('main')).toBeVisible();
    await assertContainedLayout(page);
    await erraticScroll(page);

    const details = page.locator('main details > summary:visible');
    const detailsCount = Math.min(await details.count(), 8);
    for (let index = 0; index < detailsCount; index += 1) {
      await details.nth(index).click();
      await details.nth(index).click();
    }

    const focusables = page.locator(
      'main button:visible:not([data-analyze]):not([data-acknowledge]):not([data-suppress]):not([data-pcap]):not(#soc-alert-refresh), main select:visible, main input:visible',
    );
    const focusableCount = Math.min(await focusables.count(), 30);
    for (let index = 0; index < focusableCount; index += 1) {
      const control = focusables.nth(index);
      if (await control.isDisabled()) continue;
      await control.focus();
      await expect(control).toBeFocused();
    }
  }
  expect(runtimeErrors).toEqual([]);
});

test('desktop pinned alert stays flush with the visible header or viewport top', async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 });
  await protectLiveState(page);
  await openAlerts(page);

  const group = page.locator('.report-row-group:visible').first();
  await group.locator('.report-row').click();
  const detail = group.locator('.api-detail-content[data-detail-loaded="true"]');
  await expect(detail).toBeVisible();
  await detail.evaluate(element => {
    const target = window.scrollY + element.getBoundingClientRect().top + Math.min(1200, element.scrollHeight / 2);
    window.scrollTo({ top: target, behavior: 'instant' });
  });
  await page.waitForTimeout(150);

  const pinned = page.locator('.pinned-alert-viewport.visible');
  await expect(pinned).toBeVisible();
  const positions = await page.evaluate(() => {
    const pinnedRect = document.querySelector('.pinned-alert-viewport.visible')?.getBoundingClientRect();
    const headerRect = document.querySelector('.topbar')?.getBoundingClientRect();
    const headerVisible = Boolean(headerRect && headerRect.bottom > 0 && headerRect.top <= 1);
    return {
      pinnedTop: pinnedRect?.top ?? -1,
      expectedTop: headerVisible ? Math.max(0, Math.ceil(headerRect.bottom)) : 0,
    };
  });
  expect(Math.abs(positions.pinnedTop - positions.expectedTop), JSON.stringify(positions)).toBeLessThanOrEqual(1);
});

test('desktop pinned alert keeps action controls stable and synchronizes horizontal scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 900 });
  await protectLiveState(page);
  await openAlerts(page);

  const group = page.locator('.report-row-group:visible').first();
  await group.locator('.report-row').click();
  const detail = group.locator('.api-detail-content[data-detail-loaded="true"]');
  await expect(detail).toBeVisible();
  await detail.evaluate(element => {
    const target = window.scrollY + element.getBoundingClientRect().top + Math.min(1200, element.scrollHeight / 2);
    window.scrollTo({ top: target, behavior: 'instant' });
  });
  await page.waitForTimeout(200);

  const pinned = page.locator('.pinned-alert-viewport.visible');
  await expect(pinned).toBeVisible();
  const initial = await pinned.evaluate(element => ({
    clientWidth: element.clientWidth,
    scrollWidth: element.scrollWidth,
    scrollLeft: element.scrollLeft,
  }));
  expect(initial.scrollWidth).toBeGreaterThan(initial.clientWidth);

  await pinned.dispatchEvent('wheel', { deltaY: 480, deltaX: 0, deltaMode: 0 });
  await page.waitForTimeout(100);
  const synchronized = await page.evaluate(() => ({
    pinned: document.querySelector('.pinned-alert-viewport')?.scrollLeft ?? -1,
    table: document.querySelector('.table-card')?.scrollLeft ?? -1,
  }));
  expect(synchronized.pinned).toBeGreaterThan(initial.scrollLeft);
  expect(Math.abs(synchronized.pinned - synchronized.table), JSON.stringify(synchronized)).toBeLessThanOrEqual(1);

  await pinned.evaluate(element => { element.scrollLeft = element.scrollWidth; });
  await page.waitForTimeout(100);
  for (let index = 0; index < 5; index += 1) {
    await page.evaluate(() => window.scrollBy({ top: 120, behavior: 'instant' }));
    await page.evaluate(() => window.scrollBy({ top: -80, behavior: 'instant' }));
  }
  await page.waitForTimeout(150);

  const actionGeometry = await page.evaluate(() => {
    const viewport = document.querySelector('.pinned-alert-viewport.visible');
    const buttons = [...document.querySelectorAll('.pinned-alert-row .action-cell button')];
    const boxes = buttons.map(button => {
      const rect = button.getBoundingClientRect();
      return { left: rect.left, right: rect.right, width: rect.width, height: rect.height, text: button.textContent.trim() };
    });
    return {
      viewport: viewport ? { left: viewport.getBoundingClientRect().left, right: viewport.getBoundingClientRect().right } : null,
      labels: boxes.map(box => box.text),
      boxes,
      whiteSpace: buttons.map(button => getComputedStyle(button).whiteSpace),
    };
  });
  expect(actionGeometry.labels).toEqual(['Analyze', 'Acknowledge', 'Suppress', 'PCAP']);
  expect(actionGeometry.whiteSpace.every(value => value === 'nowrap')).toBe(true);
  expect(actionGeometry.boxes.every(box => box.width >= 48 && box.height >= 32), JSON.stringify(actionGeometry)).toBe(true);
  for (let index = 1; index < actionGeometry.boxes.length; index += 1) {
    expect(actionGeometry.boxes[index].left).toBeGreaterThanOrEqual(actionGeometry.boxes[index - 1].right);
  }
  expect(actionGeometry.boxes.at(-1).right).toBeLessThanOrEqual(actionGeometry.viewport.right + 1);

  const alertTitleGeometry = await page.evaluate(() => {
    const sourceCell = document.querySelector('tbody.report-row-group.expanded .report-row .alert-cell');
    const sourceTitle = sourceCell?.querySelector('strong');
    const pinnedCell = document.querySelector('.pinned-alert-row .alert-cell');
    const pinnedTitle = pinnedCell?.querySelector('strong');
    const metrics = element => {
      if (!element) return null;
      const style = getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      return {
        height: rect.height,
        lineHeight: Number.parseFloat(style.lineHeight),
        lineClamp: style.webkitLineClamp,
      };
    };
    return {
      dynamicWidth: Number.parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--soc-alert-title-column-width')),
      sourceCellWidth: sourceCell?.getBoundingClientRect().width ?? 0,
      pinnedCellWidth: pinnedCell?.getBoundingClientRect().width ?? 0,
      sourceTitle: metrics(sourceTitle),
      pinnedTitle: metrics(pinnedTitle),
      visibleTitles: [...document.querySelectorAll('tbody.report-row-group .report-row .alert-cell strong')]
        .filter(title => title.getClientRects().length)
        .map(metrics),
    };
  });
  expect(alertTitleGeometry.dynamicWidth).toBeGreaterThanOrEqual(420);
  expect(alertTitleGeometry.dynamicWidth).toBeLessThanOrEqual(960);
  expect(alertTitleGeometry.sourceCellWidth).toBeGreaterThanOrEqual(alertTitleGeometry.dynamicWidth - 1);
  expect(Math.abs(alertTitleGeometry.sourceCellWidth - alertTitleGeometry.pinnedCellWidth), JSON.stringify(alertTitleGeometry)).toBeLessThanOrEqual(1);
  expect(alertTitleGeometry.sourceTitle.lineClamp).toBe('2');
  expect(alertTitleGeometry.pinnedTitle.lineClamp).toBe('2');
  expect(alertTitleGeometry.sourceTitle.height).toBeLessThanOrEqual((alertTitleGeometry.sourceTitle.lineHeight * 2) + 1);
  expect(alertTitleGeometry.pinnedTitle.height).toBeLessThanOrEqual((alertTitleGeometry.pinnedTitle.lineHeight * 2) + 1);
  expect(alertTitleGeometry.visibleTitles.every(title => title.height <= (title.lineHeight * 2) + 1), JSON.stringify(alertTitleGeometry)).toBe(true);
});

test('sampled detailed reports always include Timeline and AI sections', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await protectLiveState(page);
  await openAlerts(page);

  const groups = page.locator('.report-row-group:visible');
  const sampleCount = Math.min(await groups.count(), 3);
  expect(sampleCount).toBeGreaterThan(0);
  for (let index = 0; index < sampleCount; index += 1) {
    const group = groups.nth(index);
    await group.locator('.report-row').click();
    const detail = group.locator('.api-detail-content[data-detail-loaded="true"]');
    await expect(detail.locator('.alert-timeline-section')).toHaveCount(1);
    await expect(detail.locator('.detail-section-ai-analysis-output')).toHaveCount(1);
    await group.locator('.report-row').click();
  }
});

test('detailed report accordions keep compact spacing and touch-friendly headers', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await protectLiveState(page);
  await openAlerts(page);

  const group = page.locator('.report-row-group:visible').first();
  await group.locator('.report-row').click();
  const detail = group.locator('.api-detail-content[data-detail-loaded="true"]');
  await expect(detail).toBeVisible();

  const geometry = await detail.evaluate(element =>
    [...element.querySelectorAll('.detail-collapsible-section')]
      .slice(0, 12)
      .map(section => {
        const style = getComputedStyle(section);
        const summary = section.querySelector(':scope > summary');
        return {
          marginTop: style.marginTop,
          marginBottom: style.marginBottom,
          summaryHeight: summary?.getBoundingClientRect().height ?? 0,
        };
      }));

  expect(geometry.length).toBeGreaterThan(0);
  expect(geometry.every(item => item.marginTop === '6px' && item.marginBottom === '6px'), JSON.stringify(geometry)).toBe(true);
  expect(geometry.every(item => item.summaryHeight >= 44), JSON.stringify(geometry)).toBe(true);
});

test('Settings memory files open in a read-only viewer', async ({ page }) => {
  const runtimeErrors = collectRuntimeErrors(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await protectLiveState(page);
  await page.goto('./settings.html', { waitUntil: 'domcontentloaded' });

  const memoryButton = page.locator('.settings-memory-link[data-memory-key="soc-analyst"]').first();
  const parentDetails = memoryButton.locator('xpath=ancestor::details[1]');
  await expect(memoryButton).toBeVisible();
  await expect(parentDetails).not.toHaveAttribute('open', '');
  await memoryButton.click();

  const modal = page.locator('#settings-memory-modal');
  await expect(modal).toBeVisible();
  await expect(page.locator('#settings-memory-title')).toHaveText('SOC Analyst Memory');
  await expect(page.locator('#settings-memory-content')).not.toBeEmpty();
  await expect(modal.locator('textarea,input,[contenteditable="true"]')).toHaveCount(0);
  await expect(parentDetails).not.toHaveAttribute('open', '');

  await page.keyboard.press('Escape');
  await expect(modal).toBeHidden();
  await expect(memoryButton).toBeFocused();

  await page.setViewportSize({ width: 390, height: 844 });
  const sharedButton = page.locator('.settings-memory-link[data-memory-key="shared"]').first();
  await sharedButton.scrollIntoViewIfNeeded();
  await sharedButton.click();
  await expect(modal).toBeVisible();
  await expect(page.locator('#settings-memory-title')).toHaveText('Shared Agent Memory');
  const mobileGeometry = await page.locator('.settings-memory-dialog').evaluate(element => {
    const rect = element.getBoundingClientRect();
    return {left: rect.left, right: rect.right, top: rect.top, bottom: rect.bottom};
  });
  expect(mobileGeometry.left).toBeGreaterThanOrEqual(0);
  expect(mobileGeometry.right).toBeLessThanOrEqual(390);
  expect(mobileGeometry.top).toBeGreaterThanOrEqual(0);
  expect(mobileGeometry.bottom).toBeLessThanOrEqual(844);
  await modal.locator('.settings-memory-close').click();
  await expect(modal).toBeHidden();
  expect(runtimeErrors).toEqual([]);
});

test('Settings prompt paths open the matching prompt editor', async ({ page }) => {
  const runtimeErrors = collectRuntimeErrors(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await protectLiveState(page);
  await page.goto('./settings.html', { waitUntil: 'domcontentloaded' });

  const promptTargets = [
    'soc-analyst-prompt',
    'incident-responder-prompt',
    'siem-engineer-prompt',
    'cyber-threat-intel-prompt',
    'threat-hunter-prompt',
  ];
  for (const promptTarget of promptTargets) {
    const button = page.locator(`.settings-prompt-link[data-prompt-target="${promptTarget}"]`);
    const panel = button.locator('xpath=ancestor::details[1]');
    await button.scrollIntoViewIfNeeded();
    await expect(button).toBeVisible();
    await button.click();
    await expect(panel).toHaveAttribute('open', '');
    await expect(page.locator(`#${promptTarget}`)).toBeFocused();
    await expect(page.locator('#settings-memory-modal')).toBeHidden();
    await panel.locator(':scope > summary').click();
    await expect(panel).not.toHaveAttribute('open', '');
  }

  await page.setViewportSize({ width: 390, height: 844 });
  const mobileButton = page.locator('.settings-prompt-link[data-prompt-target="soc-analyst-prompt"]');
  const mobilePanel = mobileButton.locator('xpath=ancestor::details[1]');
  await mobileButton.scrollIntoViewIfNeeded();
  await mobileButton.click();
  await expect(mobilePanel).toHaveAttribute('open', '');
  await expect(page.locator('#soc-analyst-prompt')).toBeFocused();
  const mobileLayout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(mobileLayout.scrollWidth).toBeLessThanOrEqual(mobileLayout.clientWidth + 1);
  expect(runtimeErrors).toEqual([]);
});

test('Settings agent icons use consistent source and rendered dimensions', async ({ page }) => {
  const runtimeErrors = collectRuntimeErrors(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('./settings.html', { waitUntil: 'domcontentloaded' });
  const agentIcons = page.locator('.settings-agent-section .settings-summary-icon img');
  await expect(agentIcons).toHaveCount(5);
  await expect.poll(() => agentIcons.evaluateAll(images =>
    images.every(image => image.complete && image.naturalWidth > 0)), {timeout: 10_000}).toBe(true);

  const desktopIcons = await agentIcons.evaluateAll(images =>
    images.map(image => {
      const rect = image.getBoundingClientRect();
      return {
        source: image.getAttribute('src'),
        width: rect.width,
        height: rect.height,
        naturalWidth: image.naturalWidth,
        naturalHeight: image.naturalHeight,
        complete: image.complete,
      };
    }));
  expect(desktopIcons).toHaveLength(5);
  expect(desktopIcons.every(icon => icon.complete && icon.naturalWidth === 512 && icon.naturalHeight === 512), JSON.stringify(desktopIcons)).toBe(true);
  expect(desktopIcons.every(icon => icon.width === 56 && icon.height === 56), JSON.stringify(desktopIcons)).toBe(true);
  expect(desktopIcons.some(icon => icon.source?.endsWith('settings-cyber-threat-intel-prompt.png'))).toBe(true);

  await page.setViewportSize({ width: 390, height: 844 });
  const mobileIcons = await agentIcons.evaluateAll(images =>
    images.map(image => {
      const rect = image.getBoundingClientRect();
      return {width: rect.width, height: rect.height};
    }));
  expect(mobileIcons.every(icon => icon.width === mobileIcons[0].width && icon.height === mobileIcons[0].height), JSON.stringify(mobileIcons)).toBe(true);
  expect(runtimeErrors).toEqual([]);
});
