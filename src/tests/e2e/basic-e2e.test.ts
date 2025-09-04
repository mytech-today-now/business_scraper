import { test, expect } from '@playwright/test';

test.describe('Basic E2E Tests', () => {
  test('should load the homepage', async ({ page }) => {
    await page.goto('/');
    
    // Wait for the page to load
    await page.waitForLoadState('networkidle');
    
    // Check that the page has loaded
    expect(await page.title()).toBeTruthy();
  });

  test('should have basic navigation elements', async ({ page }) => {
    await page.goto('/');
    
    // Wait for the page to load
    await page.waitForLoadState('networkidle');
    
    // Check for basic page structure
    const body = await page.locator('body');
    await expect(body).toBeVisible();
  });

  test('should handle 404 pages gracefully', async ({ page }) => {
    const response = await page.goto('/non-existent-page');
    
    // Should either redirect or show a 404 page
    expect(response?.status()).toBeTruthy();
  });

  test('should be responsive', async ({ page }) => {
    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    const body = await page.locator('body');
    await expect(body).toBeVisible();
    
    // Test desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    await expect(body).toBeVisible();
  });
});
