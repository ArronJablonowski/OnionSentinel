import { defineConfig } from '@playwright/test';

const deploymentRoot = (process.env.ONION_SENTINEL_BASE_URL
  || 'http://10.77.7.225:8766').replace(/\/+$/, '');

export default defineConfig({
  testDir: '.',
  timeout: 120_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  outputDir: '.playwright-artifacts',
  use: {
    baseURL: `${deploymentRoot}/`,
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
    colorScheme: 'dark',
  },
});
