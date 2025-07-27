/**
 * Integration tests for ContactExtractor with EmailValidationService
 * Tests the integration between contact extraction and advanced email validation
 */

import { ContactExtractor } from '../../lib/contactExtractor';
import { EmailValidationService } from '../../lib/emailValidationService';

// Mock Puppeteer
const mockPage = {
  content: jest.fn(),
  evaluate: jest.fn(),
  $: jest.fn(),
  $$: jest.fn(),
  url: jest.fn()
};

// Mock DNS module
const mockResolveMx = jest.fn();
jest.mock('dns/promises', () => ({
  resolveMx: mockResolveMx
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

describe('ContactExtractor Integration with EmailValidationService', () => {
  let contactExtractor: ContactExtractor;
  let emailValidationService: EmailValidationService;

  beforeEach(() => {
    contactExtractor = new ContactExtractor();
    emailValidationService = EmailValidationService.getInstance();
    emailValidationService.clearCache();
    jest.clearAllMocks();
  });

  describe('Email Extraction and Validation Integration', () => {
    it('should extract and validate emails from page content', async () => {
      // Mock page content with various email formats
      const mockContent = `
        <html>
          <body>
            <div>Contact us at info@example.com</div>
            <div>Sales: sales@example.com</div>
            <div>Support: support@tempmail.org</div>
            <div>Invalid: not-an-email</div>
            <div>Personal: john.doe@example.com</div>
          </body>
        </html>
      `;

      const mockTextContent = `
        Contact us at info@example.com
        Sales: sales@example.com
        Support: support@tempmail.org
        Invalid: not-an-email
        Personal: john.doe@example.com
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve(mockTextContent);
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('Example Business');
        }
        return Promise.resolve([]);
      });

      // Mock MX record responses
      mockResolveMx.mockImplementation((domain) => {
        if (domain === 'example.com') {
          return Promise.resolve([{ exchange: 'mail.example.com', priority: 10 }]);
        }
        if (domain === 'tempmail.org') {
          return Promise.resolve([{ exchange: 'mail.tempmail.org', priority: 10 }]);
        }
        return Promise.reject(new Error('No MX records'));
      });

      const result = await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      // Verify email extraction
      expect(result.emails).toContain('info@example.com');
      expect(result.emails).toContain('sales@example.com');
      expect(result.emails).toContain('support@tempmail.org');
      expect(result.emails).toContain('john.doe@example.com');

      // Verify email validation metadata
      expect(result.emailValidation).toBeDefined();
      expect(result.emailValidation!.validationResults).toHaveLength(4);
      expect(result.emailValidation!.totalEmailCount).toBe(4);
      expect(result.emailValidation!.validEmailCount).toBeGreaterThan(0);

      // Check specific validation results
      const infoEmailResult = result.emailValidation!.validationResults.find(r => r.email === 'info@example.com');
      expect(infoEmailResult).toBeDefined();
      expect(infoEmailResult!.isValid).toBe(true);
      expect(infoEmailResult!.isRoleBased).toBe(true);
      expect(infoEmailResult!.isDisposable).toBe(false);

      const disposableEmailResult = result.emailValidation!.validationResults.find(r => r.email === 'support@tempmail.org');
      expect(disposableEmailResult).toBeDefined();
      expect(disposableEmailResult!.isDisposable).toBe(true);

      const personalEmailResult = result.emailValidation!.validationResults.find(r => r.email === 'john.doe@example.com');
      expect(personalEmailResult).toBeDefined();
      expect(personalEmailResult!.isRoleBased).toBe(false);

      // Verify best email selection (should prefer non-role-based, non-disposable)
      expect(result.emailValidation!.bestEmail).toBe('john.doe@example.com');
    });

    it('should handle pages with no emails gracefully', async () => {
      const mockContent = `
        <html>
          <body>
            <div>No email addresses here</div>
            <div>Just some text content</div>
          </body>
        </html>
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve('No email addresses here Just some text content');
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('Example Business');
        }
        return Promise.resolve([]);
      });

      const result = await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      expect(result.emails).toHaveLength(0);
      expect(result.emailValidation).toBeDefined();
      expect(result.emailValidation!.validationResults).toHaveLength(0);
      expect(result.emailValidation!.totalEmailCount).toBe(0);
      expect(result.emailValidation!.validEmailCount).toBe(0);
      expect(result.emailValidation!.overallConfidence).toBe(0);
      expect(result.emailValidation!.bestEmail).toBeUndefined();
    });

    it('should handle email validation errors gracefully', async () => {
      const mockContent = `
        <html>
          <body>
            <div>Contact: test@example.com</div>
          </body>
        </html>
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve('Contact: test@example.com');
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('Example Business');
        }
        return Promise.resolve([]);
      });

      // Mock email validation service to throw error
      const originalValidateEmails = emailValidationService.validateEmails;
      emailValidationService.validateEmails = jest.fn().mockRejectedValue(new Error('Validation service error'));

      const result = await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      expect(result.emails).toContain('test@example.com');
      expect(result.emailValidation).toBeDefined();
      expect(result.emailValidation!.validationResults).toHaveLength(0);
      expect(result.emailValidation!.overallConfidence).toBe(0);

      // Restore original method
      emailValidationService.validateEmails = originalValidateEmails;
    });

    it('should update confidence scores based on email validation', async () => {
      const mockContent = `
        <html>
          <body>
            <h1>High Quality Business</h1>
            <div>Email: john.doe@example.com</div>
            <div>Phone: (555) 123-4567</div>
            <div>Address: 123 Main St, City, State 12345</div>
          </body>
        </html>
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve('High Quality Business Email: john.doe@example.com Phone: (555) 123-4567 Address: 123 Main St, City, State 12345');
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('High Quality Business');
        }
        return Promise.resolve([]);
      });

      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }]);

      const result = await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      // Should have high confidence due to valid email with good validation scores
      expect(result.confidence.email).toBeGreaterThan(0.8);
      expect(result.confidence.overall).toBeGreaterThan(0.7);
      expect(result.emailValidation!.overallConfidence).toBeGreaterThan(80);
    });

    it('should prioritize emails correctly based on validation results', async () => {
      const mockContent = `
        <html>
          <body>
            <div>Info: info@example.com</div>
            <div>Personal: jane.smith@example.com</div>
            <div>Temp: temp@tempmail.org</div>
            <div>Sales: sales@example.com</div>
          </body>
        </html>
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve('Info: info@example.com Personal: jane.smith@example.com Temp: temp@tempmail.org Sales: sales@example.com');
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('Example Business');
        }
        return Promise.resolve([]);
      });

      mockResolveMx.mockImplementation((domain) => {
        if (domain === 'example.com') {
          return Promise.resolve([{ exchange: 'mail.example.com', priority: 10 }]);
        }
        if (domain === 'tempmail.org') {
          return Promise.resolve([{ exchange: 'mail.tempmail.org', priority: 10 }]);
        }
        return Promise.reject(new Error('No MX records'));
      });

      const result = await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      // Best email should be the personal one (non-role-based, non-disposable)
      expect(result.emailValidation!.bestEmail).toBe('jane.smith@example.com');

      // Validation results should correctly identify characteristics
      const validationResults = result.emailValidation!.validationResults;
      
      const infoResult = validationResults.find(r => r.email === 'info@example.com');
      expect(infoResult!.isRoleBased).toBe(true);
      expect(infoResult!.isDisposable).toBe(false);

      const personalResult = validationResults.find(r => r.email === 'jane.smith@example.com');
      expect(personalResult!.isRoleBased).toBe(false);
      expect(personalResult!.isDisposable).toBe(false);

      const tempResult = validationResults.find(r => r.email === 'temp@tempmail.org');
      expect(tempResult!.isDisposable).toBe(true);
    });
  });

  describe('Performance and Caching', () => {
    it('should cache email validation results across multiple extractions', async () => {
      const mockContent = `
        <html>
          <body>
            <div>Contact: test@example.com</div>
          </body>
        </html>
      `;

      mockPage.content.mockResolvedValue(mockContent);
      mockPage.evaluate.mockImplementation((fn) => {
        if (fn.toString().includes('document.body.innerText')) {
          return Promise.resolve('Contact: test@example.com');
        }
        if (fn.toString().includes('document.querySelector')) {
          return Promise.resolve('Example Business');
        }
        return Promise.resolve([]);
      });

      mockResolveMx.mockResolvedValue([{ exchange: 'mail.example.com', priority: 10 }]);

      // First extraction
      await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');
      
      // Second extraction with same email
      await contactExtractor.extractContactInfo(mockPage as any, 'https://example.com');

      // MX lookup should only happen once due to caching
      expect(mockResolveMx).toHaveBeenCalledTimes(1);
    });
  });
});
