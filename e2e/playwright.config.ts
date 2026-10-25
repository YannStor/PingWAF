import { defineConfig, devices } from '@playwright/test'

const zone = process.env.E2E_ZONE ?? 'e2e.test'
const edgeIp = process.env.E2E_EDGE_IP ?? '47.242.20.155'
const baseURL = process.env.E2E_BASE_URL ?? 'https://47.242.20.155:9080'

export default defineConfig({
  testDir: './specs',
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
