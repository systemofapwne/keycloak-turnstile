import { test, expect } from '@playwright/test';
import { KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_REALM, KEYCLOAK_URL, getAuthedClient, setResetCredentialsAllowed, setResetCredentialsAuthBinding } from '../keycloak';

test.describe('keycloak default reset credentials', async () => {
  test.beforeEach(async () => {
    await setResetCredentialsAllowed(await getAuthedClient(), KEYCLOAK_REALM, true);
    await setResetCredentialsAuthBinding(await getAuthedClient(), KEYCLOAK_REALM, 'reset credentials');
  });

  test('can reset client account without turnstile widget', async ({ page }) => {
    await page.goto(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/login-actions/reset-credentials`);
    await page.waitForSelector('input#username');

    await expect(page.locator('.cf-turnstile')).toHaveCount(0);

    await page.fill('input#username', KEYCLOAK_ADMIN_USERNAME);
    await page.click('input[type="submit"]');

    const alertLocator = page.locator('.pf-c-alert');
    await alertLocator.waitFor();
    await expect(alertLocator).toHaveCount(1);

    await expect(page).toHaveURL(/.*\/login-actions\/authenticate.*/)
  });
});