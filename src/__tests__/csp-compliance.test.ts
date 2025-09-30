/**
 * Comprehensive tests for CSP compliance and inline style handling
 * Tests the Content Security Policy configuration and middleware
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { NextRequest, NextResponse } from 'next/server'
import { getCSPHeader, getCSPConfig, buildCSPHeader } from '@/lib/cspConfig'
import { middleware } from '@/middleware'
import { mockNodeEnv } from './utils/mockTypeHelpers'

// Mock environment variables
const originalEnv = process.env

beforeEach(() => {
  jest.resetModules()
})

afterEach(() => {
  process.env = originalEnv
})

describe('CSP Compliance Fix', () => {
  describe('Development Environment CSP', () => {
    beforeEach(() => {
      process.env = {
        ...originalEnv,
        NODE_ENV: 'development',
      }
    })

    it('should use permissive CSP in development', () => {
      const config = getCSPConfig('development')
      
      expect(config.styleSrc).toContain("'unsafe-inline'")
      expect(config.scriptSrc).toContain("'unsafe-inline'")
      expect(config.scriptSrc).toContain("'unsafe-eval'")
    })

    it('should not include nonces in development CSP', () => {
      const config = getCSPConfig('development')
      const csp = buildCSPHeader(config)
      
      expect(csp).not.toContain('nonce-')
      expect(csp).toContain("'unsafe-inline'")
    })

    it('should allow inline styles in development', () => {
      const config = getCSPConfig('development')
      const csp = buildCSPHeader(config)
      
      expect(csp).toContain("style-src 'self' 'unsafe-inline'")
    })
  })

  describe('Production Environment CSP', () => {
    beforeEach(() => {
      process.env = {
        ...originalEnv,
        NODE_ENV: 'production',
      }
    })

    it('should use strict CSP in production', () => {
      const config = getCSPConfig('production')
      
      expect(config.styleSrc).toContain("'nonce-{nonce}'")
      expect(config.scriptSrc).toContain("'nonce-{nonce}'")
    })

    it('should include nonces in production CSP', () => {
      const config = getCSPConfig('production')
      const nonce = 'test-nonce-123'
      const csp = buildCSPHeader(config, nonce)
      
      expect(csp).toContain(`'nonce-${nonce}'`)
    })

    it('should have proper security directives', () => {
      const config = getCSPConfig('production')
      
      expect(config.objectSrc).toContain("'none'")
      expect(config.frameAncestors).toContain("'none'")
      expect(config.upgradeInsecureRequests).toBe(true)
      expect(config.blockAllMixedContent).toBe(true)
    })
  })

  describe('Middleware CSP Headers', () => {
    it('should set development CSP headers correctly', async () => {
      const restoreEnv = mockNodeEnv('development')
      
      const request = new NextRequest('http://localhost:3000/login', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1',
        },
      })

      const response = await middleware(request)
      const cspHeader = response.headers.get('Content-Security-Policy')
      
      expect(cspHeader).toContain("'unsafe-inline'")
      expect(cspHeader).not.toContain('nonce-')
      expect(response.headers.get('X-CSP-Nonce')).toBeNull()

      restoreEnv()
    })

    it('should set production CSP headers correctly', async () => {
      const restoreEnv = mockNodeEnv('production')
      
      const request = new NextRequest('http://localhost:3000/login', {
        method: 'GET',
        headers: {
          'x-forwarded-for': '127.0.0.1',
        },
      })

      const response = await middleware(request)
      const cspHeader = response.headers.get('Content-Security-Policy')
      const nonceHeader = response.headers.get('X-CSP-Nonce')
      
      expect(cspHeader).toContain('nonce-')
      expect(nonceHeader).toBeDefined()

      restoreEnv()
    })
  })

  describe('CSP Configuration Validation', () => {
    it('should have valid development configuration', () => {
      const config = getCSPConfig('development')
      
      expect(config.defaultSrc).toContain("'self'")
      expect(config.styleSrc).toContain("'self'")
      expect(config.styleSrc).toContain("'unsafe-inline'")
      expect(config.scriptSrc).toContain("'self'")
      expect(config.scriptSrc).toContain("'unsafe-inline'")
      expect(config.scriptSrc).toContain("'unsafe-eval'")
    })

    it('should have valid production configuration', () => {
      const config = getCSPConfig('production')
      
      expect(config.defaultSrc).toContain("'self'")
      expect(config.styleSrc).toContain("'self'")
      expect(config.styleSrc).toContain("'nonce-{nonce}'")
      expect(config.scriptSrc).toContain("'self'")
      expect(config.scriptSrc).toContain("'nonce-{nonce}'")
    })

    it('should include Stripe domains in all environments', () => {
      const devConfig = getCSPConfig('development')
      const prodConfig = getCSPConfig('production')
      
      expect(devConfig.scriptSrc).toContain('https://js.stripe.com')
      expect(devConfig.frameSrc).toContain('https://js.stripe.com')
      expect(prodConfig.scriptSrc).toContain('https://js.stripe.com')
      expect(prodConfig.frameSrc).toContain('https://js.stripe.com')
    })
  })

  describe('CSP Header Building', () => {
    it('should build proper CSP header without nonce in development', () => {
      const config = getCSPConfig('development')
      const csp = buildCSPHeader(config)
      
      expect(csp).toContain("default-src 'self'")
      expect(csp).toContain("style-src 'self' 'unsafe-inline'")
      expect(csp).toContain("script-src 'self' 'unsafe-eval' 'unsafe-inline'")
      expect(csp).not.toContain('nonce-')
    })

    it('should build proper CSP header with nonce in production', () => {
      const config = getCSPConfig('production')
      const nonce = 'abc123'
      const csp = buildCSPHeader(config, nonce)
      
      expect(csp).toContain("default-src 'self'")
      expect(csp).toContain(`style-src 'self' 'nonce-${nonce}'`)
      expect(csp).toContain(`script-src 'self'`)
      expect(csp).toContain(`'nonce-${nonce}'`)
    })

    it('should include security features in production', () => {
      const config = getCSPConfig('production')
      const csp = buildCSPHeader(config, 'test-nonce')
      
      expect(csp).toContain('upgrade-insecure-requests')
      expect(csp).toContain('block-all-mixed-content')
      expect(csp).toContain("object-src 'none'")
      expect(csp).toContain("frame-ancestors 'none'")
    })
  })
})
