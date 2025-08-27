/**
 * CSP-Safe React Components
 * Business Scraper Application - Secure Script and Style Components
 */

'use client'

import React, { useEffect, useRef } from 'react'
import {
  getClientCSPNonce,
  isCSPSafe,
  sanitizeForCSP,
  CSPScriptProps,
  CSPStyleProps,
} from '@/lib/cspUtils'

/**
 * CSP-safe inline script component
 */
export function CSPScript({ children, nonce, defer = false, async = false }: CSPScriptProps) {
  const scriptRef = useRef<HTMLScriptElement>(null)
  const clientNonce = getClientCSPNonce()
  const effectiveNonce = nonce || clientNonce

  useEffect(() => {
    if (!scriptRef.current) return

    // Validate content is CSP-safe
    if (!isCSPSafe(children)) {
      console.warn('CSP Script: Potentially unsafe content detected, sanitizing...')
      const sanitized = sanitizeForCSP(children)
      scriptRef.current.textContent = sanitized
    } else {
      scriptRef.current.textContent = children
    }
  }, [children])

  return (
    <script
      ref={scriptRef}
      nonce={effectiveNonce || undefined}
      defer={defer}
      async={async}
      suppressHydrationWarning
    />
  )
}

/**
 * CSP-safe inline style component
 */
export function CSPStyle({ children, nonce }: CSPStyleProps) {
  const styleRef = useRef<HTMLStyleElement>(null)
  const clientNonce = getClientCSPNonce()
  const effectiveNonce = nonce || clientNonce

  useEffect(() => {
    if (!styleRef.current) return
    styleRef.current.textContent = children
  }, [children])

  return <style ref={styleRef} nonce={effectiveNonce || undefined} suppressHydrationWarning />
}

/**
 * CSP-safe external script loader
 */
interface CSPExternalScriptProps {
  src: string
  nonce?: string
  defer?: boolean
  async?: boolean
  onLoad?: () => void
  onError?: (error: Error) => void
}

export function CSPExternalScript({
  src,
  nonce,
  defer = false,
  async = false,
  onLoad,
  onError,
}: CSPExternalScriptProps) {
  const clientNonce = getClientCSPNonce()
  const effectiveNonce = nonce || clientNonce

  const handleLoad = () => {
    onLoad?.()
  }

  const handleError = () => {
    const error = new Error(`Failed to load script: ${src}`)
    onError?.(error)
  }

  return (
    <script
      src={src}
      nonce={effectiveNonce || undefined}
      defer={defer}
      async={async}
      onLoad={handleLoad}
      onError={handleError}
    />
  )
}

/**
 * CSP-safe external stylesheet loader
 */
interface CSPExternalStyleProps {
  href: string
  nonce?: string
  media?: string
  onLoad?: () => void
  onError?: (error: Error) => void
}

export function CSPExternalStyle({
  href,
  nonce,
  media = 'all',
  onLoad,
  onError,
}: CSPExternalStyleProps) {
  const clientNonce = getClientCSPNonce()
  const effectiveNonce = nonce || clientNonce

  const handleLoad = () => {
    onLoad?.()
  }

  const handleError = () => {
    const error = new Error(`Failed to load stylesheet: ${href}`)
    onError?.(error)
  }

  return (
    <link
      rel="stylesheet"
      href={href}
      nonce={effectiveNonce || undefined}
      media={media}
      onLoad={handleLoad}
      onError={handleError}
    />
  )
}

/**
 * CSP violation reporter component
 */
interface CSPViolationReporterProps {
  onViolation?: (violation: SecurityPolicyViolationEvent) => void
}

export function CSPViolationReporter({ onViolation }: CSPViolationReporterProps) {
  useEffect(() => {
    const handleViolation = (event: SecurityPolicyViolationEvent) => {
      console.warn('CSP Violation detected:', {
        directive: event.violatedDirective,
        blockedURI: event.blockedURI,
        documentURI: event.documentURI,
        sourceFile: event.sourceFile,
        lineNumber: event.lineNumber,
        columnNumber: event.columnNumber,
      })

      onViolation?.(event)
    }

    document.addEventListener('securitypolicyviolation', handleViolation)

    return () => {
      document.removeEventListener('securitypolicyviolation', handleViolation)
    }
  }, [onViolation])

  return null
}

/**
 * CSP nonce provider component
 */
interface CSPNonceProviderProps {
  nonce?: string
  children: React.ReactNode
}

const CSPNonceContext = React.createContext<string | null>(null)

export function CSPNonceProvider({ nonce, children }: CSPNonceProviderProps) {
  const clientNonce = getClientCSPNonce()
  const effectiveNonce = nonce || clientNonce

  return <CSPNonceContext.Provider value={effectiveNonce}>{children}</CSPNonceContext.Provider>
}

/**
 * Hook to get CSP nonce from context
 */
export function useCSPNonce(): string | null {
  return React.useContext(CSPNonceContext)
}

/**
 * CSP-safe dynamic content component
 */
interface CSPDynamicContentProps {
  html?: string
  script?: string
  style?: string
  nonce?: string
  sanitize?: boolean
}

export function CSPDynamicContent({
  html,
  script,
  style,
  nonce,
  sanitize = true,
}: CSPDynamicContentProps) {
  const contextNonce = useCSPNonce()
  const effectiveNonce = nonce || contextNonce

  return (
    <>
      {html && (
        <div
          dangerouslySetInnerHTML={{
            __html: sanitize ? sanitizeForCSP(html) : html,
          }}
        />
      )}

      {style && (
        <CSPStyle nonce={effectiveNonce || undefined}>
          {sanitize ? sanitizeForCSP(style) : style}
        </CSPStyle>
      )}

      {script && (
        <CSPScript nonce={effectiveNonce || undefined}>
          {sanitize ? sanitizeForCSP(script) : script}
        </CSPScript>
      )}
    </>
  )
}

/**
 * CSP status indicator component (for development)
 */
export function CSPStatusIndicator() {
  const [violations, setViolations] = React.useState<SecurityPolicyViolationEvent[]>([])
  const [nonce, setNonce] = React.useState<string | null>(null)

  useEffect(() => {
    // Get current nonce
    setNonce(getClientCSPNonce())

    // Listen for violations
    const handleViolation = (event: SecurityPolicyViolationEvent) => {
      setViolations(prev => [...prev, event])
    }

    document.addEventListener('securitypolicyviolation', handleViolation)

    return () => {
      document.removeEventListener('securitypolicyviolation', handleViolation)
    }
  }, [])

  // Only show in development
  if (process.env.NODE_ENV !== 'development') {
    return null
  }

  return (
    <div
      style={{
        position: 'fixed',
        bottom: '10px',
        right: '10px',
        background: violations.length > 0 ? '#ff4444' : '#44ff44',
        color: 'white',
        padding: '8px 12px',
        borderRadius: '4px',
        fontSize: '12px',
        zIndex: 9999,
        fontFamily: 'monospace',
      }}
    >
      CSP: {violations.length} violations
      {nonce && <div>Nonce: {nonce.substring(0, 8)}...</div>}
    </div>
  )
}
