import { useState, useEffect, useCallback, useMemo } from 'react'
import { EMAIL_REGEX, URL_REGEX, PHONE_REGEX, ZIP_REGEX } from '../utils/validation'

/**
 * Validation state for a single field
 */
export interface ValidationState {
  isValid: boolean
  error?: string
  warning?: string
  success?: string
  isValidating?: boolean
}

/**
 * Validation rule function type
 */
export type ValidationRule = (value: string) => ValidationState | Promise<ValidationState>

/**
 * Options for validation hooks
 */
export interface ValidationOptions {
  debounceMs?: number
  validateOnMount?: boolean
  required?: boolean
  requiredMessage?: string
}

/**
 * Hook for real-time email validation
 */
export function useValidateEmail(
  value: string,
  options: ValidationOptions = {}
): ValidationState {
  const {
    debounceMs = 300,
    validateOnMount = false,
    required = false,
    requiredMessage = 'Email is required'
  } = options

  const [state, setState] = useState<ValidationState>({ isValid: true })
  const [debouncedValue, setDebouncedValue] = useState(value)

  // Debounce the input value
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value)
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [value, debounceMs])

  // Validate the debounced value
  useEffect(() => {
    if (!validateOnMount && debouncedValue === '') {
      setState({ isValid: true })
      return
    }

    const validate = () => {
      // Check if required
      if (required && !debouncedValue.trim()) {
        setState({
          isValid: false,
          error: requiredMessage
        })
        return
      }

      // If not required and empty, it's valid
      if (!required && !debouncedValue.trim()) {
        setState({ isValid: true })
        return
      }

      // Validate email format
      if (!EMAIL_REGEX.test(debouncedValue)) {
        setState({
          isValid: false,
          error: 'Please enter a valid email address'
        })
        return
      }

      // Success state
      setState({
        isValid: true,
        success: 'Valid email address'
      })
    }

    validate()
  }, [debouncedValue, required, requiredMessage, validateOnMount])

  return state
}

/**
 * Hook for real-time URL validation
 */
export function useValidateURL(
  value: string,
  options: ValidationOptions = {}
): ValidationState {
  const {
    debounceMs = 300,
    validateOnMount = false,
    required = false,
    requiredMessage = 'URL is required'
  } = options

  const [state, setState] = useState<ValidationState>({ isValid: true })
  const [debouncedValue, setDebouncedValue] = useState(value)

  // Debounce the input value
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value)
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [value, debounceMs])

  // Validate the debounced value
  useEffect(() => {
    if (!validateOnMount && debouncedValue === '') {
      setState({ isValid: true })
      return
    }

    const validate = () => {
      // Check if required
      if (required && !debouncedValue.trim()) {
        setState({
          isValid: false,
          error: requiredMessage
        })
        return
      }

      // If not required and empty, it's valid
      if (!required && !debouncedValue.trim()) {
        setState({ isValid: true })
        return
      }

      // Validate URL format
      if (!URL_REGEX.test(debouncedValue)) {
        setState({
          isValid: false,
          error: 'Please enter a valid URL (e.g., https://example.com)'
        })
        return
      }

      // Check for insecure HTTP warning
      if (debouncedValue.startsWith('http://')) {
        setState({
          isValid: true,
          warning: 'Consider using HTTPS for better security'
        })
        return
      }

      // Success state
      setState({
        isValid: true,
        success: 'Valid URL'
      })
    }

    validate()
  }, [debouncedValue, required, requiredMessage, validateOnMount])

  return state
}

/**
 * Hook for required field validation
 */
export function useRequiredField(
  value: string,
  options: ValidationOptions & { minLength?: number } = {}
): ValidationState {
  const {
    debounceMs = 300,
    validateOnMount = false,
    requiredMessage = 'This field is required',
    minLength = 1
  } = options

  const [state, setState] = useState<ValidationState>({ isValid: true })
  const [debouncedValue, setDebouncedValue] = useState(value)

  // Debounce the input value
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value)
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [value, debounceMs])

  // Validate the debounced value
  useEffect(() => {
    if (!validateOnMount && debouncedValue === '') {
      setState({ isValid: true })
      return
    }

    const validate = () => {
      const trimmedValue = debouncedValue.trim()

      if (!trimmedValue || trimmedValue.length < minLength) {
        setState({
          isValid: false,
          error: minLength > 1 
            ? `This field requires at least ${minLength} characters`
            : requiredMessage
        })
        return
      }

      // Success state
      setState({
        isValid: true,
        success: 'Valid input'
      })
    }

    validate()
  }, [debouncedValue, requiredMessage, minLength, validateOnMount])

  return state
}

/**
 * Hook for custom pattern validation
 */
export function useValidateCustomPattern(
  value: string,
  pattern: RegExp,
  errorMessage: string,
  options: ValidationOptions = {}
): ValidationState {
  const {
    debounceMs = 300,
    validateOnMount = false,
    required = false,
    requiredMessage = 'This field is required'
  } = options

  const [state, setState] = useState<ValidationState>({ isValid: true })
  const [debouncedValue, setDebouncedValue] = useState(value)

  // Debounce the input value
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedValue(value)
    }, debounceMs)

    return () => clearTimeout(timer)
  }, [value, debounceMs])

  // Validate the debounced value
  useEffect(() => {
    if (!validateOnMount && debouncedValue === '') {
      setState({ isValid: true })
      return
    }

    const validate = () => {
      // Check if required
      if (required && !debouncedValue.trim()) {
        setState({
          isValid: false,
          error: requiredMessage
        })
        return
      }

      // If not required and empty, it's valid
      if (!required && !debouncedValue.trim()) {
        setState({ isValid: true })
        return
      }

      // Validate against pattern
      if (!pattern.test(debouncedValue)) {
        setState({
          isValid: false,
          error: errorMessage
        })
        return
      }

      // Success state
      setState({
        isValid: true,
        success: 'Valid input'
      })
    }

    validate()
  }, [debouncedValue, pattern, errorMessage, required, requiredMessage, validateOnMount])

  return state
}

/**
 * Hook for phone number validation
 */
export function useValidatePhone(
  value: string,
  options: ValidationOptions = {}
): ValidationState {
  return useValidateCustomPattern(
    value,
    PHONE_REGEX,
    'Please enter a valid phone number',
    options
  )
}

/**
 * Hook for ZIP code validation
 */
export function useValidateZipCode(
  value: string,
  options: ValidationOptions = {}
): ValidationState {
  return useValidateCustomPattern(
    value,
    ZIP_REGEX,
    'Please enter a valid ZIP code',
    options
  )
}
