/**
 * Login Page CSRF Integration Tests
 * Tests for the login page CSRF token integration and UI behavior
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { useRouter } from 'next/navigation'
import LoginPage from '@/app/login/page'

// Mock Next.js router
jest.mock('next/navigation', () => ({
  useRouter: jest.fn(),
}))

// Mock Image component
jest.mock('next/image', () => {
  return function MockImage({ src, alt, ...props }: any) {
    return <img src={src} alt={alt} {...props} />
  }
})

// Mock CSRF Protection hook
jest.mock('@/hooks/useCSRFProtection', () => ({
  useFormCSRFProtection: jest.fn(),
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

const mockPush = jest.fn()
const mockUseFormCSRFProtection = require('@/hooks/useCSRFProtection').useFormCSRFProtection

describe('Login Page CSRF Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })

    // Mock fetch for auth check
    global.fetch = jest.fn()
  })

  describe('CSRF Token Loading States', () => {
    it('should show loading message only during initial load', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: null,
        isLoading: true,
        error: null,
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => false,
      })

      render(<LoginPage />)

      // Should show loading message
      expect(screen.getByText('Loading security token...')).toBeInTheDocument()

      // Should not show error messages during loading
      expect(screen.queryByText(/Failed to fetch CSRF token/)).not.toBeInTheDocument()
    })

    it('should not show 401 errors to users', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: 'Failed to fetch CSRF token: 401',
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => false,
      })

      render(<LoginPage />)

      // Should not show 401 error to user
      expect(screen.queryByText(/Failed to fetch CSRF token: 401/)).not.toBeInTheDocument()

      // Should not show loading message when not loading
      expect(screen.queryByText('Loading security token...')).not.toBeInTheDocument()
    })

    it('should show non-401 errors to users', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: 'Network error occurred',
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => false,
      })

      render(<LoginPage />)

      // Should show non-401 errors
      expect(screen.getByText('Network error occurred')).toBeInTheDocument()
    })

    it('should not show loading and error simultaneously', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: null,
        isLoading: true,
        error: 'Some error',
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => false,
      })

      render(<LoginPage />)

      // Should show loading message
      expect(screen.getByText('Loading security token...')).toBeInTheDocument()

      // Should not show error message while loading
      expect(screen.queryByText('Some error')).not.toBeInTheDocument()
    })
  })

  describe('Successful CSRF Token Load', () => {
    it('should enable form submission when token is loaded', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'valid-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'valid-token',
        }),
        validateForm: jest.fn().mockResolvedValue(true),
        submitForm: jest.fn(),
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      // Fill in form
      fireEvent.change(screen.getByPlaceholderText('Username'), {
        target: { value: 'admin' },
      })
      fireEvent.change(screen.getByPlaceholderText('Password'), {
        target: { value: 'password' },
      })

      // Submit button should be enabled
      const submitButton = screen.getByRole('button', { name: /sign in/i })
      expect(submitButton).not.toBeDisabled()

      // Should not show any error or loading messages
      expect(screen.queryByText('Loading security token...')).not.toBeInTheDocument()
      expect(screen.queryByText(/Failed to fetch CSRF token/)).not.toBeInTheDocument()
    })

    it('should disable form submission without valid token', async () => {
      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => false,
      })

      render(<LoginPage />)

      // Fill in form
      fireEvent.change(screen.getByPlaceholderText('Username'), {
        target: { value: 'admin' },
      })
      fireEvent.change(screen.getByPlaceholderText('Password'), {
        target: { value: 'password' },
      })

      // Submit button should be disabled without token
      const submitButton = screen.getByRole('button', { name: /sign in/i })
      expect(submitButton).toBeDisabled()
    })
  })

  describe('Form Submission with CSRF Protection', () => {
    it('should submit form with CSRF token', async () => {
      const mockSubmitForm = jest.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      })

      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'submit-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'submit-token',
        }),
        validateForm: jest.fn().mockResolvedValue(true),
        submitForm: mockSubmitForm,
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      // Fill in form
      fireEvent.change(screen.getByPlaceholderText('Username'), {
        target: { value: 'admin' },
      })
      fireEvent.change(screen.getByPlaceholderText('Password'), {
        target: { value: 'password' },
      })

      // Submit form
      fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

      await waitFor(() => {
        expect(mockSubmitForm).toHaveBeenCalledWith('/api/auth', {
          username: 'admin',
          password: 'password',
        })
      })
    })

    it('should handle form submission errors gracefully', async () => {
      const mockSubmitForm = jest.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({ error: 'Invalid credentials' }),
      })

      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'error-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'error-token',
        }),
        validateForm: jest.fn().mockResolvedValue(true),
        submitForm: mockSubmitForm,
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      // Fill in form
      fireEvent.change(screen.getByPlaceholderText('Username'), {
        target: { value: 'admin' },
      })
      fireEvent.change(screen.getByPlaceholderText('Password'), {
        target: { value: 'wrong' },
      })

      // Submit form
      fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

      await waitFor(() => {
        expect(screen.getByText('Invalid credentials')).toBeInTheDocument()
      })
    })
  })

  describe('Rate Limiting Handling', () => {
    it('should show rate limit message and countdown', async () => {
      const mockSubmitForm = jest.fn().mockResolvedValue({
        ok: false,
        status: 429,
        json: () => Promise.resolve({ 
          error: 'Too many failed attempts. Please wait 60 seconds.',
          retryAfter: 60 
        }),
      })

      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'rate-limit-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'rate-limit-token',
        }),
        validateForm: jest.fn().mockResolvedValue(true),
        submitForm: mockSubmitForm,
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      // Fill in form
      fireEvent.change(screen.getByPlaceholderText('Username'), {
        target: { value: 'admin' },
      })
      fireEvent.change(screen.getByPlaceholderText('Password'), {
        target: { value: 'wrong' },
      })

      // Submit form
      fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

      await waitFor(() => {
        expect(screen.getByText(/Too many failed attempts/)).toBeInTheDocument()
        expect(screen.getByText(/Retry in 60 seconds/)).toBeInTheDocument()
      })

      // Form should be disabled during rate limit
      expect(screen.getByPlaceholderText('Username')).toBeDisabled()
      expect(screen.getByPlaceholderText('Password')).toBeDisabled()
      expect(screen.getByRole('button', { name: /sign in/i })).toBeDisabled()
    })
  })

  describe('Authentication Check', () => {
    it('should redirect if already authenticated', async () => {
      // Mock successful auth check
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ authenticated: true }),
      })

      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'auth-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      await waitFor(() => {
        expect(mockPush).toHaveBeenCalledWith('/')
      })
    })

    it('should stay on login page if not authenticated', async () => {
      // Mock failed auth check
      ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Not authenticated'))

      mockUseFormCSRFProtection.mockReturnValue({
        csrfToken: 'no-auth-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        validateForm: jest.fn(),
        submitForm: jest.fn(),
        isTokenValid: () => true,
      })

      render(<LoginPage />)

      // Should not redirect
      expect(mockPush).not.toHaveBeenCalled()

      // Should show login form
      expect(screen.getByPlaceholderText('Username')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Password')).toBeInTheDocument()
    })
  })
})
