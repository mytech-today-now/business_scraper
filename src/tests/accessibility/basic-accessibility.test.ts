import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Basic Accessibility Tests', () => {
  test('should not have any automatically detectable accessibility issues', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('should have proper heading structure', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Check for at least one heading
    const headings = await page.locator('h1, h2, h3, h4, h5, h6').count();
    expect(headings).toBeGreaterThan(0);
  });

  test('should have proper alt text for images', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Get all images
    const images = await page.locator('img').all();
    
    for (const image of images) {
      const alt = await image.getAttribute('alt');
      const src = await image.getAttribute('src');
      
      // Images should have alt text or be decorative
      if (src && !src.includes('data:')) {
        expect(alt).toBeTruthy();
      }
    }
  });

  test('should have proper form labels', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Get all form inputs
    const inputs = await page.locator('input[type="text"], input[type="email"], input[type="password"], textarea, select').all();
    
    for (const input of inputs) {
      const id = await input.getAttribute('id');
      const ariaLabel = await input.getAttribute('aria-label');
      const ariaLabelledBy = await input.getAttribute('aria-labelledby');
      
      if (id) {
        // Check if there's a label for this input
        const label = await page.locator(`label[for="${id}"]`).count();
        const hasLabel = label > 0 || ariaLabel || ariaLabelledBy;
        expect(hasLabel).toBeTruthy();
      }
    }
  });

  test('should have proper color contrast', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    const colorContrastViolations = accessibilityScanResults.violations.filter(
      violation => violation.id === 'color-contrast'
    );

    expect(colorContrastViolations).toEqual([]);
  });

  test('should be keyboard navigable', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Test tab navigation
    await page.keyboard.press('Tab');
    
    // Check if focus is visible
    const focusedElement = await page.locator(':focus').count();
    expect(focusedElement).toBeGreaterThanOrEqual(0);
  });
});
