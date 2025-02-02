import { test, expect } from '@playwright/test';
import { KEYCLOAK_ADMIN_USERNAME, KEYCLOAK_REALM, KEYCLOAK_URL, getAuthedClient, setResetCredentialsAllowed, setResetCredentialsAuthBinding, setResetCredentialsFlowTurnstileConfig } from '../keycloak';

test.describe('keycloak turnstile reset credentials', async () => {

    test.beforeEach(async () => {
        await setResetCredentialsAllowed(await getAuthedClient(), KEYCLOAK_REALM, true);
        await setResetCredentialsAuthBinding(await getAuthedClient(), KEYCLOAK_REALM, 'reset credentials-turnstile');
    });

    test.describe('client pass, server pass', () => {
        test.beforeEach(async () => {
            await setResetCredentialsFlowTurnstileConfig(await getAuthedClient(), KEYCLOAK_REALM, 'client-visible-pass-server-pass');
        });

        test('can reset credentials with turnstile widget', async ({ page }) => {
            await page.goto(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/login-actions/reset-credentials`);
            await page.waitForSelector('input#username');

            await expect(page.locator('.cf-turnstile')).toHaveCount(1);

            await page.fill('input#username', KEYCLOAK_ADMIN_USERNAME);

            await page.waitForFunction(() => {
                const resp = document.querySelector('input[name="cf-turnstile-response"]');
                return resp && resp.getAttribute('value') != null;
            });

            await page.click('input[type="submit"]');

            const alertLocator = page.locator('.pf-c-alert');
            await alertLocator.waitFor();
            await expect(alertLocator).toHaveCount(1);

            await expect(page).toHaveURL(/.*\/login-actions\/authenticate.*/)
        });
    });

    test.describe('client pass, server fail', () => {
        test.beforeEach(async () => {
            await setResetCredentialsFlowTurnstileConfig(await getAuthedClient(), KEYCLOAK_REALM, 'client-visible-pass-server-fail');
        });

        test('cannot reset credentials with turnstile widget when server-side validation fails', async ({ page }) => {
            await page.goto(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/login-actions/reset-credentials`);
            await page.waitForSelector('input#username');

            await expect(page.locator('.cf-turnstile')).toHaveCount(1);
            await page.fill('input#username', KEYCLOAK_ADMIN_USERNAME);

            await page.waitForFunction(() => {
                const resp = document.querySelector('input[name="cf-turnstile-response"]');
                return resp && resp.getAttribute('value') != null;
            });

            await page.click('input[type="submit"]');

            const alertLocator = page.locator('.pf-c-alert');
            const errorMessageLocator = page.locator('.pf-c-alert__title.kc-feedback-text');
            await errorMessageLocator.waitFor();
            expect(await errorMessageLocator.textContent()).toBe('Invalid Captcha');
        });
    });

    test.describe('client block', () => {
        test.beforeEach(async () => {
            await setResetCredentialsFlowTurnstileConfig(await getAuthedClient(), KEYCLOAK_REALM, 'client-visible-pass-server-fail');
        });

        test('cannot reset credentials with turnstile widget when turnstile client fails', async ({ page }) => {
            await page.goto(`${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/login-actions/reset-credentials`);
            await page.waitForSelector('input#username');

            await expect(page.locator('.cf-turnstile')).toHaveCount(1);
            await page.fill('input#username', KEYCLOAK_ADMIN_USERNAME);

            await page.waitForFunction(() => {
                const resp = document.querySelector('input[name="cf-turnstile-response"]');
                return resp && resp.getAttribute('value') != null;
            });

            await page.click('input[type="submit"]');

            const alertLocator = page.locator('.pf-c-alert');
            const errorMessageLocator = page.locator('.pf-c-alert__title.kc-feedback-text');
            await errorMessageLocator.waitFor();
            expect(await errorMessageLocator.textContent()).toBe('Invalid Captcha');
        });
    });
});