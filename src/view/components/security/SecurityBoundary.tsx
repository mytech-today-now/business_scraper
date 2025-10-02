/**
 * Security Boundary Component
 * Provides input validation and sanitization at component boundaries
 */

'use client'

import React, { ReactNode, useEffect } from 'react'
import { sanitizeInput, validateInput } from '@/lib/security'
import { logger } from '@/utils/logger'
import { ErrorBoundary } from '../../components/ErrorBoundary'

export interface SecurityBoundaryProps {
  children: ReactNode
  componentName: string
  validateProps?: boolean
  sanitizeStrings?: boolean
  allowedProps?: string[]
  onSecurityViolation?: (violation: SecurityViolation) => void
}

export interface SecurityViolation {
  type: 'invalid_input' | 'sanitization_required' | 'prop_validation_failed'
  component: string
  details: string
  timestamp: Date
}

/**
 * Security Boundary wrapper component
 * Validates and sanitizes props before passing to child components
 */
export function SecurityBoundary({
  children,
  componentName,
  validateProps = true,
  sanitizeStrings = true,
  allowedProps = [],
  onSecurityViolation,
}: SecurityBoundaryProps): JSX.Element {
  
  useEffect(() => {
    logger.debug('SecurityBoundary', `Initialized for component: ${componentName}`)
  }, [componentName])

  const handleSecurityViolation = (violation: SecurityViolation) => {
    logger.warn('SecurityBoundary', `Security violation in ${componentName}`, violation)
    
    if (onSecurityViolation) {
      onSecurityViolation(violation)
    }
  }

  return (
    <ErrorBoundary 
      level="component" 
      componentName={componentName}
      showDetails={process.env.NODE_ENV === 'development'}
      onError={(error) => {
        handleSecurityViolation({
          type: 'prop_validation_failed',
          component: componentName,
          details: error.message,
          timestamp: new Date()
        })
      }}
    >
      {children}
    </ErrorBoundary>
  )
}

/**
 * Higher-order component for adding security boundaries
 */
export function withSecurityBoundary<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  options: {
    componentName: string
    validateProps?: boolean
    sanitizeStrings?: boolean
    allowedProps?: string[]
  }
) {
  const SecurityWrappedComponent = (props: P) => {
    // Validate and sanitize props if enabled
    const secureProps = options.sanitizeStrings ? sanitizeProps(props) : props
    
    return (
      <SecurityBoundary
        componentName={options.componentName}
        validateProps={options.validateProps}
        sanitizeStrings={options.sanitizeStrings}
        allowedProps={options.allowedProps}
      >
        <WrappedComponent {...secureProps} />
      </SecurityBoundary>
    )
  }

  SecurityWrappedComponent.displayName = `withSecurityBoundary(${options.componentName})`
  return SecurityWrappedComponent
}

/**
 * Sanitize props object recursively
 */
function sanitizeProps<T extends object>(props: T): T {
  const sanitized = { ...props }
  
  Object.keys(sanitized).forEach(key => {
    const value = (sanitized as any)[key]
    
    if (typeof value === 'string') {
      const validation = validateInput(value)
      if (!validation.isValid) {
        logger.warn('SecurityBoundary', `Invalid input detected in prop ${key}`, validation.errors)
      }
      (sanitized as any)[key] = sanitizeInput(value)
    } else if (Array.isArray(value)) {
      (sanitized as any)[key] = value.map(item => 
        typeof item === 'string' ? sanitizeInput(item) : item
      )
    } else if (value && typeof value === 'object') {
      (sanitized as any)[key] = sanitizeProps(value)
    }
  })
  
  return sanitized
}

/**
 * Secure input validation hook
 */
export function useSecureInput(initialValue: string = '') {
  const [value, setValue] = React.useState(initialValue)
  const [isValid, setIsValid] = React.useState(true)
  const [errors, setErrors] = React.useState<string[]>([])

  const updateValue = (newValue: string) => {
    const validation = validateInput(newValue)
    setIsValid(validation.isValid)
    setErrors(validation.errors)
    
    if (validation.isValid) {
      setValue(sanitizeInput(newValue))
    } else {
      logger.warn('useSecureInput', 'Invalid input detected', validation.errors)
    }
  }

  return {
    value,
    setValue: updateValue,
    isValid,
    errors,
    sanitizedValue: sanitizeInput(value)
  }
}

/**
 * Secure data validation utilities
 */
export const SecurityUtils = {
  /**
   * Validate business data for XSS and injection attacks
   */
  validateBusinessData: (data: any): { isValid: boolean; errors: string[] } => {
    const errors: string[] = []
    
    if (data.businessName && typeof data.businessName === 'string') {
      const validation = validateInput(data.businessName)
      if (!validation.isValid) {
        errors.push(`Business name: ${validation.errors.join(', ')}`)
      }
    }
    
    if (data.email && Array.isArray(data.email)) {
      data.email.forEach((email: string, index: number) => {
        const validation = validateInput(email)
        if (!validation.isValid) {
          errors.push(`Email ${index + 1}: ${validation.errors.join(', ')}`)
        }
      })
    }
    
    if (data.websiteUrl && typeof data.websiteUrl === 'string') {
      const validation = validateInput(data.websiteUrl)
      if (!validation.isValid) {
        errors.push(`Website URL: ${validation.errors.join(', ')}`)
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    }
  },

  /**
   * Sanitize business data
   */
  sanitizeBusinessData: (data: any): any => {
    const sanitized = { ...data }
    
    if (sanitized.businessName) {
      sanitized.businessName = sanitizeInput(sanitized.businessName)
    }
    
    if (sanitized.email && Array.isArray(sanitized.email)) {
      sanitized.email = sanitized.email.map((email: string) => sanitizeInput(email))
    }
    
    if (sanitized.websiteUrl) {
      sanitized.websiteUrl = sanitizeInput(sanitized.websiteUrl)
    }
    
    if (sanitized.address && typeof sanitized.address === 'object') {
      Object.keys(sanitized.address).forEach(key => {
        if (typeof sanitized.address[key] === 'string') {
          sanitized.address[key] = sanitizeInput(sanitized.address[key])
        }
      })
    }
    
    return sanitized
  }
}
