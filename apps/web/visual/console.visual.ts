import { expect, test } from '@playwright/test'

const surfaces = ['login', 'overview', 'assets', 'host-card', 'agents', 'administration'] as const

for (const surface of surfaces) {
  test(`${surface} visual baseline`, async ({ page }) => {
    await page.addInitScript(() => {
      const fixedNow = new Date('2026-08-20T12:05:00Z').getTime()
      Date.now = () => fixedNow
    })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto(`/?surface=${surface}`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(300)
    await page.evaluate(() => document.fonts.ready)
    await expect(page.locator('.skeleton')).toHaveCount(0)
    await expect(page).toHaveScreenshot(`${surface}.png`, { fullPage: true, animations: 'disabled', caret: 'hide', maxDiffPixelRatio: 0.002 })
  })
}
