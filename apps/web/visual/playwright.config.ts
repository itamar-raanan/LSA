import { existsSync } from 'node:fs'
import { defineConfig, devices } from '@playwright/test'

const browserCandidates = [
  process.env.LSA_VISUAL_BROWSER,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
].filter((value): value is string => Boolean(value))
const executablePath = browserCandidates.find(existsSync)
if (!executablePath) throw new Error('No local Chromium browser found. Set LSA_VISUAL_BROWSER to its executable path.')

export default defineConfig({
  testDir: '.', testMatch: 'console.visual.ts', fullyParallel: true, forbidOnly: true, retries: 0, workers: 6,
  snapshotPathTemplate: '{testDir}/__screenshots__/{projectName}/{arg}{ext}',
  webServer: { command: 'npm exec vite -- --config visual/vite.config.ts', url: 'http://127.0.0.1:4174', reuseExistingServer: true, timeout: 30_000 },
  use: { baseURL: 'http://127.0.0.1:4174', launchOptions: { executablePath }, colorScheme: 'light', locale: 'en-US', timezoneId: 'UTC', screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } },
    { name: 'mobile', use: { ...devices['iPhone 13'], browserName: 'chromium', viewport: { width: 390, height: 844 } } },
  ],
})
