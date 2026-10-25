import { defineConfig, devices } from '@playwright/test'
import { requiredEnv } from './support/env'

const zone = process.env.E2E_ZONE ?? 'e2e.test'
const edgeIp = requiredEnv('E2E_EDGE_IP')
const baseURL = requiredEnv('E2E_BASE_URL')

export default defineConfig({
  testDir: './specs',
  // A unique directory per run keeps Playwright from bulk-deleting prior
  // traces, which also avoids the IDE safe-delete guard on large result sets.
  outputDir: process.env.E2E_OUTPUT_DIR ?? './test-results',
  timeout: 180_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'artifacts/html', open: 'never' }],
    ['json', { outputFile: 'artifacts/results.json' }],
  ],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    locale: 'en-US',
    timezoneId: 'UTC',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    launchOptions: {
      args: [`--host-resolver-rules=MAP *.${zone} ${edgeIp}`],
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    },
  ],
})
