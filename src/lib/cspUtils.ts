/**
 * CSP Utilities for React Components
 * Business Scraper Application - Client-side CSP Support
 */

import { headers } from 'next/headers'

/**
 * Get CSP nonce from headers (server-side)
 */
export function getCSPNonce(): string | null {
  try {
    const headersList = headers()
    return headersList.get('X-CSP-Nonce') || null
  } catch (error) {
    // Headers not available (client-side or static generation)
    return null
  }
}

/**
 * Create script tag with CSP nonce
 */
export function createNonceScript(content: string, nonce?: string): string {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''
  return `<script${nonceAttr}>${content}</script>`
}

/**
 * Create style tag with CSP nonce
 */
export function createNonceStyle(content: string, nonce?: string): string {
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''
  return `<style${nonceAttr}>${content}</style>`
}

/**
 * CSP-safe inline script component props
 */
export interface CSPScriptProps {
  children: string
  nonce?: string
  defer?: boolean
  async?: boolean
}

/**
 * CSP-safe inline style component props
 */
export interface CSPStyleProps {
  children: string
  nonce?: string
}

/**
 * Get CSP nonce from client-side (if available)
 */
export function getClientCSPNonce(): string | null {
  if (typeof window === 'undefined') {
    return null
  }

  // Try to get nonce from meta tag
  const metaTag = document.querySelector('meta[name="csp-nonce"]')
  if (metaTag) {
    return metaTag.getAttribute('content')
  }

  // Try to get from existing script tag
  const scriptTag = document.querySelector('script[nonce]')
  if (scriptTag) {
    return scriptTag.getAttribute('nonce')
  }

  return null
}

/**
 * Validate if content is CSP-safe
 */
export function isCSPSafe(content: string): boolean {
  // Check for potentially unsafe patterns
  const unsafePatterns = [
    /eval\s*\(/,
    /Function\s*\(/,
    /setTimeout\s*\(\s*["']/,
    /setInterval\s*\(\s*["']/,
    /javascript:/,
    /data:.*script/i,
    /vbscript:/i,
    /on\w+\s*=/i, // inline event handlers
  ]

  return !unsafePatterns.some(pattern => pattern.test(content))
}

/**
 * Sanitize content for CSP compliance
 */
export function sanitizeForCSP(content: string): string {
  // Remove potentially unsafe patterns
  const sanitized = content
    .replace(/eval\s*\(/g, '/* eval removed */')
    .replace(/Function\s*\(/g, '/* Function constructor removed */')
    .replace(/setTimeout\s*\(\s*["'][^"']*["']/g, '/* unsafe setTimeout removed */')
    .replace(/setInterval\s*\(\s*["'][^"']*["']/g, '/* unsafe setInterval removed */')
    .replace(/javascript:/gi, '/* javascript: removed */')
    .replace(/vbscript:/gi, '/* vbscript: removed */')
    .replace(/on\w+\s*=/gi, '/* inline handler removed */')

  return sanitized
}

/**
 * CSP reporting utilities
 */
export class CSPReporter {
  private static instance: CSPReporter
  private violations: Array<{
    directive: string
    blockedUri: string
    timestamp: number
  }> = []

  static getInstance(): CSPReporter {
    if (!CSPReporter.instance) {
      CSPReporter.instance = new CSPReporter()
    }
    return CSPReporter.instance
  }

  /**
   * Report CSP violation manually
   */
  reportViolation(directive: string, blockedUri: string): void {
    const violation = {
      directive,
      blockedUri,
      timestamp: Date.now(),
    }

    this.violations.push(violation)

    // Send to reporting endpoint (only in browser environment)
    if (typeof window !== 'undefined' && typeof fetch !== 'undefined') {
      try {
        fetch('/api/csp-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            'csp-report': {
              'document-uri': window.location.href,
              referrer: document.referrer,
              'violated-directive': directive,
              'effective-directive': directive,
              'original-policy': 'manual-report',
              disposition: 'enforce',
              'blocked-uri': blockedUri,
              'line-number': 0,
              'column-number': 0,
              'source-file': window.location.href,
              'status-code': 200,
              'script-sample': '',
            },
          }),
        }).catch(error => {
          console.warn('Failed to report CSP violation:', error)
        })
      } catch (error) {
        console.warn('Failed to send CSP violation report:', error)
      }
    }
  }

  /**
   * Get recent violations
   */
  getViolations(since?: number): Array<{
    directive: string
    blockedUri: string
    timestamp: number
  }> {
    const cutoff = since || Date.now() - 24 * 60 * 60 * 1000 // Last 24 hours
    return this.violations.filter(v => v.timestamp >= cutoff)
  }

  /**
   * Clear violation history
   */
  clearViolations(): void {
    this.violations = []
  }
}

/**
 * Initialize CSP reporting on client-side
 */
export function initializeCSPReporting(): void {
  if (typeof window === 'undefined') {
    return
  }

  // Listen for CSP violations
  document.addEventListener('securitypolicyviolation', event => {
    const reporter = CSPReporter.getInstance()
    reporter.reportViolation(event.violatedDirective, event.blockedURI)
  })
}

/**
 * CSP-safe dynamic script loading
 */
export function loadScriptSafely(src: string, nonce?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window === 'undefined') {
      reject(new Error('loadScriptSafely can only be used client-side'))
      return
    }

    const script = document.createElement('script')
    script.src = src

    if (nonce) {
      script.nonce = nonce
    }

    script.onload = () => resolve()
    script.onerror = () => reject(new Error(`Failed to load script: ${src}`))

    document.head.appendChild(script)
  })
}

/**
 * CSP-safe dynamic style loading
 */
export function loadStyleSafely(href: string, nonce?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (typeof window === 'undefined') {
      reject(new Error('loadStyleSafely can only be used client-side'))
      return
    }

    const link = document.createElement('link')
    link.rel = 'stylesheet'
    link.href = href

    if (nonce) {
      link.nonce = nonce
    }

    link.onload = () => resolve()
    link.onerror = () => reject(new Error(`Failed to load stylesheet: ${href}`))

    document.head.appendChild(link)
  })
}
