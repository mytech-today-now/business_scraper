import { renderHook, act } from '@testing-library/react'
import {
  useValidateEmail,
  useValidateURL,
  useRequiredField,
  useValidateCustomPattern,
  useValidatePhone,
  useValidateZipCode
} from '../../src/hooks/useValidation'

// Mock timers for debouncing tests
jest.useFakeTimers()

describe('useValidateEmail', () => {
  afterEach(() => {
    jest.clearAllTimers()
  })

  it('should validate correct email addresses', async () => {
    const { result } = renderHook(() => 
      useValidateEmail('test@example.com', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.success).toBe('Valid email address')
    expect(result.current.error).toBeUndefined()
  })

  it('should invalidate incorrect email addresses', async () => {
    const { result } = renderHook(() => 
      useValidateEmail('invalid-email', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Please enter a valid email address')
    expect(result.current.success).toBeUndefined()
  })

  it('should handle required validation', async () => {
    const { result } = renderHook(() => 
      useValidateEmail('', { required: true, debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Email is required')
  })

  it('should handle non-required empty values', async () => {
    const { result } = renderHook(() => 
      useValidateEmail('', { required: false, debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.error).toBeUndefined()
  })

  it('should debounce validation', async () => {
    const { result, rerender } = renderHook(
      ({ email }) => useValidateEmail(email, { debounceMs: 300 }),
      { initialProps: { email: '' } }
    )

    // Initially should be valid (empty)
    expect(result.current.isValid).toBe(true)

    // Update to invalid email
    rerender({ email: 'invalid' })
    
    // Should still be valid before debounce
    expect(result.current.isValid).toBe(true)

    // Fast-forward time
    act(() => {
      jest.advanceTimersByTime(300)
    })

    // Now should be invalid
    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Please enter a valid email address')
  })
})

describe('useValidateURL', () => {
  it('should validate correct URLs', async () => {
    const { result } = renderHook(() => 
      useValidateURL('https://example.com', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.success).toBe('Valid URL')
  })

  it('should warn about HTTP URLs', async () => {
    const { result } = renderHook(() => 
      useValidateURL('http://example.com', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.warning).toBe('Consider using HTTPS for better security')
  })

  it('should invalidate incorrect URLs', async () => {
    const { result } = renderHook(() => 
      useValidateURL('not-a-url', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Please enter a valid URL (e.g., https://example.com)')
  })

  it('should handle required validation', async () => {
    const { result } = renderHook(() => 
      useValidateURL('', { required: true, debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('URL is required')
  })
})

describe('useRequiredField', () => {
  it('should validate non-empty values', async () => {
    const { result } = renderHook(() => 
      useRequiredField('test value', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.success).toBe('Valid input')
  })

  it('should invalidate empty values', async () => {
    const { result } = renderHook(() => 
      useRequiredField('', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('This field is required')
  })

  it('should validate minimum length', async () => {
    const { result } = renderHook(() => 
      useRequiredField('ab', { minLength: 3, debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('This field requires at least 3 characters')
  })

  it('should handle custom required message', async () => {
    const { result } = renderHook(() => 
      useRequiredField('', { requiredMessage: 'Custom message', debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Custom message')
  })
})

describe('useValidateCustomPattern', () => {
  const phonePattern = /^\(\d{3}\) \d{3}-\d{4}$/

  it('should validate matching patterns', async () => {
    const { result } = renderHook(() => 
      useValidateCustomPattern(
        '(123) 456-7890',
        phonePattern,
        'Invalid phone format',
        { debounceMs: 0 }
      )
    )

    expect(result.current.isValid).toBe(true)
    expect(result.current.success).toBe('Valid input')
  })

  it('should invalidate non-matching patterns', async () => {
    const { result } = renderHook(() => 
      useValidateCustomPattern(
        '123-456-7890',
        phonePattern,
        'Invalid phone format',
        { debounceMs: 0 }
      )
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Invalid phone format')
  })
})

describe('useValidatePhone', () => {
  it('should validate correct phone numbers', async () => {
    const { result } = renderHook(() => 
      useValidatePhone('(123) 456-7890', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
  })

  it('should invalidate incorrect phone numbers', async () => {
    const { result } = renderHook(() => 
      useValidatePhone('123', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Please enter a valid phone number')
  })
})

describe('useValidateZipCode', () => {
  it('should validate correct ZIP codes', async () => {
    const { result } = renderHook(() => 
      useValidateZipCode('12345', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
  })

  it('should validate ZIP+4 codes', async () => {
    const { result } = renderHook(() => 
      useValidateZipCode('12345-6789', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(true)
  })

  it('should invalidate incorrect ZIP codes', async () => {
    const { result } = renderHook(() => 
      useValidateZipCode('123', { debounceMs: 0 })
    )

    expect(result.current.isValid).toBe(false)
    expect(result.current.error).toBe('Please enter a valid ZIP code')
  })
})
