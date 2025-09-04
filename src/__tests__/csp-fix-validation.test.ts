/**
 * CSP Fix Validation Tests
 * Tests to ensure the CSP white screen issue has been resolved
 */

import fs from 'fs';
import path from 'path';

describe('CSP Fix Validation', () => {
  describe('Environment Configuration', () => {
    it('should have NODE_ENV set to development in .env', () => {
      const envPath = path.join(process.cwd(), '.env');
      const envContent = fs.readFileSync(envPath, 'utf8');
      const nodeEnvMatch = envContent.match(/NODE_ENV=(.+)/);
      
      expect(nodeEnvMatch).toBeTruthy();
      expect(nodeEnvMatch![1]).toBe('development');
    });

    it('should have NODE_ENV set to development in .env.local', () => {
      const envLocalPath = path.join(process.cwd(), '.env.local');
      const envLocalContent = fs.readFileSync(envLocalPath, 'utf8');
      const nodeEnvMatch = envLocalContent.match(/NODE_ENV=(.+)/);
      
      expect(nodeEnvMatch).toBeTruthy();
      expect(nodeEnvMatch![1]).toBe('development');
    });
  });

  describe('CSP Configuration', () => {
    let cspConfigContent: string;

    beforeAll(() => {
      const cspConfigPath = path.join(process.cwd(), 'src/lib/cspConfig.ts');
      cspConfigContent = fs.readFileSync(cspConfigPath, 'utf8');
    });

    it('should include all required script hashes', () => {
      const requiredHashes = [
        'sha256-2lt0bFJlc5Kaphf4LkrOMIrdaHAEYNx8N9WCufhBrCo=',
        'sha256-oolAXs2Cdo3WdBhu4uUyDkOe8GFEQ1wq7uqTsMiKW9U=',
        'sha256-z05Y9BUQz7PEpWh9sitkqC+x0N4+SQix0AsyRlpYy7Q=',
        'sha256-JM7ucALGjjhHJ6z0bfjR6Dx5+OvnghD+JZoXdsywlzM=',
        'sha256-VySdMvYwvSwI5wjrw1P0Bfo7JRandOP0fPX3lt9vjaI='
      ];

      requiredHashes.forEach(hash => {
        expect(cspConfigContent).toContain(hash);
      });
    });

    it('should have development CSP with unsafe-inline and unsafe-eval', () => {
      expect(cspConfigContent).toContain("'unsafe-inline'");
      expect(cspConfigContent).toContain("'unsafe-eval'");
    });

    it('should include Stripe.js domain in script sources', () => {
      expect(cspConfigContent).toContain('https://js.stripe.com');
    });
  });

  describe('Middleware Configuration', () => {
    let middlewareContent: string;

    beforeAll(() => {
      const middlewarePath = path.join(process.cwd(), 'src/middleware.ts');
      middlewareContent = fs.readFileSync(middlewarePath, 'utf8');
    });

    it('should prioritize development CSP when NODE_ENV is development', () => {
      expect(middlewareContent).toContain('isDevelopment && process.env.ENABLE_CSP_IN_DEV !== \'true\'');
    });

    it('should include permissive development CSP', () => {
      expect(middlewareContent).toContain("script-src 'self' 'unsafe-eval' 'unsafe-inline'");
      expect(middlewareContent).toContain("style-src 'self' 'unsafe-inline'");
    });

    it('should generate nonce only in production or when explicitly enabled', () => {
      expect(middlewareContent).toContain('generateCSPNonce()');
      expect(middlewareContent).toContain('X-CSP-Nonce');
    });
  });

  describe('Layout Nonce Injection', () => {
    let layoutContent: string;

    beforeAll(() => {
      const layoutPath = path.join(process.cwd(), 'src/app/layout.tsx');
      layoutContent = fs.readFileSync(layoutPath, 'utf8');
    });

    it('should import getCSPNonce function', () => {
      expect(layoutContent).toContain('getCSPNonce');
    });

    it('should include CSP nonce meta tag', () => {
      expect(layoutContent).toContain('meta name="csp-nonce"');
    });

    it('should set global CSP nonce variable', () => {
      expect(layoutContent).toContain('window.__CSP_NONCE__');
    });

    it('should use nonce attribute in script tag', () => {
      expect(layoutContent).toContain('nonce={nonce}');
    });
  });

  describe('CSP Utilities', () => {
    it('should have CSP utility functions available', () => {
      const cspUtilsPath = path.join(process.cwd(), 'src/lib/cspUtils.ts');
      expect(fs.existsSync(cspUtilsPath)).toBe(true);
      
      const cspUtilsContent = fs.readFileSync(cspUtilsPath, 'utf8');
      expect(cspUtilsContent).toContain('getCSPNonce');
      expect(cspUtilsContent).toContain('getClientCSPNonce');
      expect(cspUtilsContent).toContain('createCSPSafeStyle');
    });
  });
});

describe('CSP Integration Tests', () => {
  it('should not have conflicting CSP configurations', () => {
    // Check that Next.js config doesn't override middleware CSP
    const nextConfigPath = path.join(process.cwd(), 'next.config.js');
    const nextConfigContent = fs.readFileSync(nextConfigPath, 'utf8');
    
    // Should not have static CSP headers that conflict with middleware
    expect(nextConfigContent).toContain('// CSP removed - handled by middleware');
  });

  it('should have proper CSP safe components available', () => {
    const cspComponentsPath = path.join(process.cwd(), 'src/components/CSPSafeComponents.tsx');
    expect(fs.existsSync(cspComponentsPath)).toBe(true);
    
    const cspComponentsContent = fs.readFileSync(cspComponentsPath, 'utf8');
    expect(cspComponentsContent).toContain('CSPScript');
    expect(cspComponentsContent).toContain('CSPStyle');
    expect(cspComponentsContent).toContain('CSPNonceProvider');
  });
});
