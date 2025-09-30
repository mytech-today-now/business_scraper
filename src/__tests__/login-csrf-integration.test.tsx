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

// Mock Lightweight CSRF Protection hook (the one actually used by login page)
jest.mock('@/hooks/useLightweightCSRF', () => ({
  useLightweightFormCSRF: jest.fn(),
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
const mockUseLightweightFormCSRF = require('@/hooks/useLightweightCSRF').useLightweightFormCSRF

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
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: null,
        isLoading: true,
        error: null,
        getCSRFInput: () => null,
        submitForm: jest.fn(),
      })

      render(<LoginPage />)

      // Should show loading message
      expect(screen.getByText('Loading security token...')).toBeInTheDocument()

      // Should not show error messages during loading
      expect(screen.queryByText(/Failed to fetch CSRF token/)).not.toBeInTheDocument()
    })

    it('should not show 401 errors to users', async () => {
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: 'Failed to fetch CSRF token: 401',
        getCSRFInput: () => null,
        submitForm: jest.fn(),
      })

      render(<LoginPage />)

      // Should not show 401 error to user
      expect(screen.queryByText(/Failed to fetch CSRF token: 401/)).not.toBeInTheDocument()

      // Should not show loading message when not loading
      expect(screen.queryByText('Loading security token...')).not.toBeInTheDocument()
    })

    it('should show non-401 errors to users', async () => {
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: 'Network error occurred',
        getCSRFInput: () => null,
        submitForm: jest.fn(),
      })

      render(<LoginPage />)

      // Should show non-401 errors
      expect(screen.getByText('Network error occurred')).toBeInTheDocument()
    })

    it('should not show loading and error simultaneously', async () => {
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: null,
        isLoading: true,
        error: 'Some error',
        getCSRFInput: () => null,
        submitForm: jest.fn(),
      })

      render(<LoginPage />)

      // Should show loading message when loading is true
      expect(screen.getByText('Loading security token...')).toBeInTheDocument()

      // Should not show error message while loading (loading takes precedence)
      expect(screen.queryByText('Some error')).not.toBeInTheDocument()
    })
  })

  describe('Successful CSRF Token Load', () => {
    it('should enable form submission when token is loaded', async () => {
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'valid-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'valid-token',
        }),
        submitForm: jest.fn(),
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
      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: null,
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        submitForm: jest.fn(),
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

      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'submit-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'submit-token',
        }),
        submitForm: mockSubmitForm,
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

      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'error-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'error-token',
        }),
        submitForm: mockSubmitForm,
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

      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'rate-limit-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => ({
          name: 'csrf_token',
          type: 'hidden',
          value: 'rate-limit-token',
        }),
        submitForm: mockSubmitForm,
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
      // Button text changes to "Wait 60s" during rate limiting
      expect(screen.getByRole('button', { name: /wait 60s/i })).toBeDisabled()
    })
  })

  describe('Authentication Check', () => {
    it('should redirect if already authenticated', async () => {
      // Mock window.location.href since the component uses that instead of router.push
      const originalLocation = window.location
      delete (window as any).location
      window.location = { ...originalLocation, href: '' } as any

      // Mock successful auth check
      ;(global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ authenticated: true }),
      })

      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'auth-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        submitForm: jest.fn(),
      })

      render(<LoginPage />)

      await waitFor(() => {
        expect(window.location.href).toBe('/')
      })

      // Restore original location
      window.location = originalLocation
    })

    it('should stay on login page if not authenticated', async () => {
      // Mock failed auth check
      ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Not authenticated'))

      mockUseLightweightFormCSRF.mockReturnValue({
        csrfToken: 'no-auth-token',
        isLoading: false,
        error: null,
        getCSRFInput: () => null,
        submitForm: jest.fn(),
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
