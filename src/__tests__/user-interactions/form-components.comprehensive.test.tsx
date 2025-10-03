/**
 * Form Components - Comprehensive User Interaction Tests
 * 
 * Tests all form-related user interactions including:
 * - Form submission and validation
 * - Input field interactions
 * - Error handling and display
 * - Real-time validation feedback
 * - Form state management
 */

import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Form, FormField, FormControl } from '@/view/components/ui/Form'
import { Input } from '@/view/components/ui/Input'
import { Button } from '@/view/components/ui/Button'
import { useValidation } from '@/hooks/useValidation'
import { useZipCodeInput } from '@/hooks/useZipCodeInput'

// Mock dependencies
jest.mock('@/hooks/useValidation')
jest.mock('@/hooks/useZipCodeInput')
jest.mock('@/utils/logger')
jest.mock('@/utils/addressInputHandler')

const mockUseValidation = useValidation as jest.MockedFunction<typeof useValidation>
const mockUseZipCodeInput = useZipCodeInput as jest.MockedFunction<typeof useZipCodeInput>

describe('Form Components - Comprehensive User Interaction Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default validation hook mock
    mockUseValidation.mockReturnValue({
      isValid: true,
      error: null,
      warning: null,
      isValidating: false,
      validate: jest.fn(),
      reset: jest.fn(),
    })

    // Default ZIP code input hook mock
    mockUseZipCodeInput.mockReturnValue({
      state: {
        value: '',
        displayValue: '',
        isValid: false,
        parseResult: null,
        error: null,
        warning: null,
        isProcessing: false,
      },
      handleChange: jest.fn(),
      handleBlur: jest.fn(),
      handleFocus: jest.fn(),
      clearError: jest.fn(),
      reset: jest.fn(),
    })
  })

  describe('Form Component', () => {
    it('should render form with proper structure', () => {
      render(
        <Form data-testid="test-form">
          <FormField name="test" label="Test Field">
            <Input name="test" />
          </FormField>
        </Form>
      )

      expect(screen.getByTestId('test-form')).toBeInTheDocument()
      expect(screen.getByLabelText('Test Field')).toBeInTheDocument()
    })

    it('should handle form submission', async () => {
      const handleSubmit = jest.fn((e) => e.preventDefault())
      
      render(
        <Form onSubmit={handleSubmit} data-testid="test-form">
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
          <Button type="submit">Submit</Button>
        </Form>
      )

      const submitButton = screen.getByRole('button', { name: 'Submit' })
      fireEvent.click(submitButton)

      expect(handleSubmit).toHaveBeenCalledTimes(1)
    })

    it('should display form errors', () => {
      const errors = { email: 'Invalid email address' }
      const touched = { email: true }

      render(
        <Form errors={errors} touched={touched}>
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
        </Form>
      )

      expect(screen.getByText('Invalid email address')).toBeInTheDocument()
    })

    it('should handle field changes', async () => {
      const handleFieldChange = jest.fn()
      const user = userEvent.setup()

      render(
        <Form onFieldChange={handleFieldChange}>
          <FormField name="username" label="Username">
            <Input name="username" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Username')
      await user.type(input, 'testuser')

      expect(handleFieldChange).toHaveBeenCalled()
    })

    it('should handle field blur events', async () => {
      const handleFieldBlur = jest.fn()
      const user = userEvent.setup()

      render(
        <Form onFieldBlur={handleFieldBlur}>
          <FormField name="username" label="Username">
            <Input name="username" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Username')
      await user.click(input)
      await user.tab()

      expect(handleFieldBlur).toHaveBeenCalled()
    })

    it('should disable form during submission', () => {
      render(
        <Form isSubmitting={true}>
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
          <Button type="submit">Submit</Button>
        </Form>
      )

      const submitButton = screen.getByRole('button', { name: 'Submit' })
      expect(submitButton).toBeDisabled()
    })
  })

  describe('Input Component', () => {
    it('should render input with label', () => {
      render(<Input label="Test Input" name="test" />)
      
      expect(screen.getByLabelText('Test Input')).toBeInTheDocument()
    })

    it('should handle user input', async () => {
      const handleChange = jest.fn()
      const user = userEvent.setup()

      render(<Input label="Test Input" name="test" onChange={handleChange} />)
      
      const input = screen.getByLabelText('Test Input')
      await user.type(input, 'test value')

      expect(handleChange).toHaveBeenCalled()
      expect(input).toHaveValue('test value')
    })

    it('should display error state', () => {
      render(<Input label="Test Input" name="test" error="This field is required" />)
      
      expect(screen.getByText('This field is required')).toBeInTheDocument()
      expect(screen.getByLabelText('Test Input')).toHaveAttribute('aria-invalid', 'true')
    })

    it('should show validation icons', () => {
      render(
        <Input 
          label="Test Input" 
          name="test" 
          validationState="success"
          showValidationIcon={true}
        />
      )
      
      const input = screen.getByLabelText('Test Input')
      expect(input.parentElement).toContainHTML('svg')
    })

    it('should handle clearable input', async () => {
      const handleChange = jest.fn()
      const user = userEvent.setup()

      render(
        <Input 
          label="Test Input" 
          name="test" 
          clearable={true}
          value="test value"
          onChange={handleChange}
        />
      )
      
      const clearButton = screen.getByRole('button', { name: /clear/i })
      await user.click(clearButton)

      expect(handleChange).toHaveBeenCalledWith(expect.objectContaining({
        target: expect.objectContaining({ value: '' })
      }))
    })

    it('should show loading state', () => {
      render(<Input label="Test Input" name="test" loading={true} />)
      
      expect(screen.getByTestId('loading-spinner')).toBeInTheDocument()
    })
  })

  describe('Form Validation Integration', () => {
    it('should integrate with validation hooks', async () => {
      const mockValidate = jest.fn()
      mockUseValidation.mockReturnValue({
        isValid: false,
        error: 'Email is required',
        warning: null,
        isValidating: false,
        validate: mockValidate,
        reset: jest.fn(),
      })

      const user = userEvent.setup()

      render(
        <Form>
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Email')
      await user.type(input, 'invalid-email')
      await user.tab()

      expect(mockValidate).toHaveBeenCalled()
    })

    it('should handle real-time validation', async () => {
      const mockValidate = jest.fn()
      mockUseValidation.mockReturnValue({
        isValid: true,
        error: null,
        warning: null,
        isValidating: true,
        validate: mockValidate,
        reset: jest.fn(),
      })

      const user = userEvent.setup()

      render(
        <Form>
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Email')
      await user.type(input, 'test@example.com')

      await waitFor(() => {
        expect(mockValidate).toHaveBeenCalled()
      })
    })
  })

  describe('ZIP Code Input Integration', () => {
    it('should handle ZIP code input with validation', async () => {
      const mockHandleChange = jest.fn()
      mockUseZipCodeInput.mockReturnValue({
        state: {
          value: '90210',
          displayValue: '90210',
          isValid: true,
          parseResult: {
            zipCode: '90210',
            city: 'Beverly Hills',
            state: 'CA',
            isValid: true,
            confidence: 1.0,
          },
          error: null,
          warning: null,
          isProcessing: false,
        },
        handleChange: mockHandleChange,
        handleBlur: jest.fn(),
        handleFocus: jest.fn(),
        clearError: jest.fn(),
        reset: jest.fn(),
      })

      const user = userEvent.setup()

      const TestZipCodeForm = () => {
        const zipCodeInput = useZipCodeInput()
        
        return (
          <Form>
            <FormField name="zipCode" label="ZIP Code">
              <Input 
                name="zipCode" 
                value={zipCodeInput.state.displayValue}
                onChange={(e) => zipCodeInput.handleChange(e.target.value)}
                error={zipCodeInput.state.error}
                validationState={zipCodeInput.state.isValid ? 'success' : 'error'}
              />
            </FormField>
          </Form>
        )
      }

      render(<TestZipCodeForm />)

      const input = screen.getByLabelText('ZIP Code')
      await user.type(input, '90210')

      expect(mockHandleChange).toHaveBeenCalledWith('90210')
    })
  })

  describe('Form Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(
        <Form>
          <FormField name="email" label="Email" required>
            <Input name="email" type="email" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Email')
      expect(input).toHaveAttribute('aria-required', 'true')
    })

    it('should associate errors with inputs', () => {
      const errors = { email: 'Invalid email' }
      const touched = { email: true }

      render(
        <Form errors={errors} touched={touched}>
          <FormField name="email" label="Email">
            <Input name="email" type="email" />
          </FormField>
        </Form>
      )

      const input = screen.getByLabelText('Email')
      const errorMessage = screen.getByText('Invalid email')
      
      expect(input).toHaveAttribute('aria-describedby')
      expect(input).toHaveAttribute('aria-invalid', 'true')
      expect(errorMessage).toHaveAttribute('id')
    })

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup()

      render(
        <Form>
          <FormField name="firstName" label="First Name">
            <Input name="firstName" />
          </FormField>
          <FormField name="lastName" label="Last Name">
            <Input name="lastName" />
          </FormField>
          <Button type="submit">Submit</Button>
        </Form>
      )

      const firstInput = screen.getByLabelText('First Name')
      const lastInput = screen.getByLabelText('Last Name')
      const submitButton = screen.getByRole('button', { name: 'Submit' })

      await user.click(firstInput)
      expect(firstInput).toHaveFocus()

      await user.tab()
      expect(lastInput).toHaveFocus()

      await user.tab()
      expect(submitButton).toHaveFocus()
    })
  })
})
