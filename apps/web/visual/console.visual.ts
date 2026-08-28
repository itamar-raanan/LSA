import { expect, test } from '@playwright/test'

const surfaces = ['login', 'login-auth-methods', 'overview', 'assets', 'host-card', 'host-detail', 'agents', 'agents-policy', 'vulnerabilities', 'vulnerability-investigation', 'vulnerability-investigation-exposures', 'evidence', 'administration'] as const

for (const surface of surfaces) {
  test(`${surface} visual baseline`, async ({ page }) => {
    await page.addInitScript(() => {
      const fixedNow = new Date('2026-08-20T12:05:00Z').getTime()
      Date.now = () => fixedNow
    })
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto(`/?surface=${surface}`, { waitUntil: 'domcontentloaded' })
    await page.waitForTimeout(300)
    if (surface === 'agents-policy') {
      await page.getByRole('button', { name: /Default Linux Fleet/ }).click()
      await page.getByRole('button', { name: 'Policy', exact: true }).click()
    }
    if (surface === 'vulnerability-investigation' || surface === 'vulnerability-investigation-exposures') {
      await page.getByRole('button', { name: 'Investigate CVE-2026-1042' }).click()
    }
    if (surface === 'vulnerability-investigation-exposures') {
      await page.locator('.finding-detail-body').evaluate(element => { element.scrollTop = element.scrollHeight })
    }
    await page.evaluate(() => document.fonts.ready)
    await page.waitForFunction(() => Array.from(document.images).every(image => image.complete))
    await page.evaluate(() => Promise.all(Array.from(document.images).map(image => image.decode().catch(() => undefined))))
    await expect(page.locator('.skeleton')).toHaveCount(0)
    await expect(page).toHaveScreenshot(`${surface}.png`, { fullPage: true, animations: 'disabled', caret: 'hide', maxDiffPixelRatio: 0.002 })
  })
}
