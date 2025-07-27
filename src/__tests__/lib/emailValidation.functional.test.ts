/**
 * Functional tests for Email Validation Service
 * Tests the core functionality without complex mocking
 */

import { EmailValidationService } from '../../lib/emailValidationService';

// Mock DNS module with simple implementation
jest.mock('dns/promises', () => ({
  resolveMx: jest.fn().mockImplementation((domain: string) => {
    console.log('Mock DNS called for domain:', domain);
    // Simple mock that returns MX records for known domains
    if (domain.includes('gmail.com') || domain.includes('example.com') || domain.includes('company.com')) {
      return Promise.resolve([{ exchange: `mail.${domain}`, priority: 10 }]);
    }
    if (domain.includes('tempmail.org') || domain.includes('10minutemail.com')) {
      return Promise.resolve([{ exchange: `mail.${domain}`, priority: 10 }]);
    }
    return Promise.reject(new Error('No MX records found'));
  })
}));

// Mock logger
jest.mock('../../utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn()
  }
}));

describe('EmailValidationService Functional Tests', () => {
  let emailValidationService: EmailValidationService;

  beforeEach(() => {
    emailValidationService = EmailValidationService.getInstance();
    emailValidationService.clearCache();
  });

  describe('Core Functionality', () => {
    it('should validate a good business email', async () => {
      const result = await emailValidationService.validateEmail('contact@example.com');
      
      expect(result.email).toBe('contact@example.com');
      expect(result.domain).toBe('example.com');
      expect(result.isValid).toBe(true);
      expect(result.mxRecords).toBe(true);
      expect(result.isRoleBased).toBe(true);
      expect(result.isDisposable).toBe(false);
      expect(result.confidence).toBeGreaterThan(50);
      expect(result.deliverabilityScore).toBeGreaterThan(50);
    });

    it('should detect disposable emails', async () => {
      const result = await emailValidationService.validateEmail('test@tempmail.org');
      
      expect(result.email).toBe('test@tempmail.org');
      expect(result.isDisposable).toBe(true);
      expect(result.confidence).toBeLessThan(50); // Should be heavily penalized
      expect(result.errors).toContain('Disposable email domain detected');
    });

    it('should detect role-based emails', async () => {
      const result = await emailValidationService.validateEmail('info@example.com');
      
      expect(result.isRoleBased).toBe(true);
      expect(result.isValid).toBe(true);
    });

    it('should handle invalid syntax', async () => {
      const result = await emailValidationService.validateEmail('invalid-email');
      
      expect(result.isValid).toBe(false);
      expect(result.confidence).toBe(0);
      expect(result.errors).toContain('Invalid email syntax');
    });

    it('should handle empty emails', async () => {
      const result = await emailValidationService.validateEmail('');
      
      expect(result.isValid).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('should preserve original email case', async () => {
      const result = await emailValidationService.validateEmail('Test@Example.Com');
      
      expect(result.email).toBe('Test@Example.Com');
      expect(result.domain).toBe('example.com'); // Domain should be lowercase
    });

    it('should validate multiple emails in batch', async () => {
      const emails = [
        'good@example.com',
        'bad@tempmail.org',
        'invalid-email',
        'role@example.com'
      ];

      const results = await emailValidationService.validateEmails(emails);
      
      expect(results).toHaveLength(4);
      expect(results[0].isValid).toBe(true);
      expect(results[1].isDisposable).toBe(true);
      expect(results[2].isValid).toBe(false);
      expect(results[3].isRoleBased).toBe(true);
    });
  });

  describe('Confidence Scoring', () => {
    it('should give high confidence to valid business emails', async () => {
      const result = await emailValidationService.validateEmail('john.doe@example.com');
      
      expect(result.confidence).toBeGreaterThan(80);
      expect(result.deliverabilityScore).toBeGreaterThan(80);
    });

    it('should give low confidence to disposable emails', async () => {
      const result = await emailValidationService.validateEmail('temp@10minutemail.com');
      
      expect(result.confidence).toBeLessThan(40);
    });

    it('should give medium confidence to role-based emails', async () => {
      const result = await emailValidationService.validateEmail('support@example.com');
      
      expect(result.confidence).toBeGreaterThan(40);
      expect(result.confidence).toBeLessThan(90);
    });
  });

  describe('Error Handling', () => {
    it('should handle very long emails', async () => {
      const longEmail = 'a'.repeat(250) + '@example.com';
      const result = await emailValidationService.validateEmail(longEmail);
      
      expect(result.isValid).toBe(false);
      expect(result.confidence).toBe(0);
    });

    it('should handle emails with no domain MX records', async () => {
      const result = await emailValidationService.validateEmail('test@nonexistent-domain-xyz.com');
      
      expect(result.mxRecords).toBe(false);
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Domain has no valid MX records');
    });
  });

  describe('Utility Functions', () => {
    it('should provide cache statistics', () => {
      const stats = emailValidationService.getCacheStats();
      
      expect(stats).toHaveProperty('validationCacheSize');
      expect(stats).toHaveProperty('mxCacheSize');
      expect(typeof stats.validationCacheSize).toBe('number');
      expect(typeof stats.mxCacheSize).toBe('number');
    });

    it('should clear cache when requested', async () => {
      // Add something to cache
      await emailValidationService.validateEmail('test@example.com');
      
      let stats = emailValidationService.getCacheStats();
      expect(stats.validationCacheSize).toBeGreaterThan(0);
      
      // Clear cache
      emailValidationService.clearCache();
      
      stats = emailValidationService.getCacheStats();
      expect(stats.validationCacheSize).toBe(0);
      expect(stats.mxCacheSize).toBe(0);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle a realistic business email extraction scenario', async () => {
      const extractedEmails = [
        'info@company.com',
        'sales@company.com',
        'john.doe@company.com',
        'temp@tempmail.org',
        'invalid-email'
      ];

      const results = await emailValidationService.validateEmails(extractedEmails);

      // Debug output
      console.log('Validation results:', results.map(r => ({
        email: r.email,
        isValid: r.isValid,
        mxRecords: r.mxRecords,
        errors: r.errors
      })));

      // Should have validation results for all emails
      expect(results).toHaveLength(5);

      // Count valid emails
      const validEmails = results.filter(r => r.isValid);
      console.log('Valid emails count:', validEmails.length);
      expect(validEmails.length).toBe(3); // info, sales, john.doe
      
      // Check disposable detection
      const disposableEmails = results.filter(r => r.isDisposable);
      expect(disposableEmails.length).toBe(1); // temp@tempmail.org
      
      // Check role-based detection
      const roleBasedEmails = results.filter(r => r.isRoleBased);
      expect(roleBasedEmails.length).toBe(2); // info, sales
      
      // Find best email (should be john.doe - not role-based, not disposable)
      const bestEmail = results
        .filter(r => r.isValid && !r.isDisposable)
        .sort((a, b) => {
          if (!a.isRoleBased && b.isRoleBased) return -1;
          if (a.isRoleBased && !b.isRoleBased) return 1;
          return b.confidence - a.confidence;
        })[0];
      
      expect(bestEmail.email).toBe('john.doe@company.com');
    });
  });
});
