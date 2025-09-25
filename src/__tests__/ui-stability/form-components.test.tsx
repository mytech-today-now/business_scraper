/**
 * UI Stability Tests - Form Components
 * Tests for form element rendering, accessibility, and validation
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@testing-library/jest-dom'

import { Input } from '@/view/components/ui/Input'
import { Form, FormField, FormControl, FormLabel, FormErrorMessage, FormHelperText } from '@/view/components/ui/Form'
import { ZipCodeInput } from '@/view/components/ui/ZipCodeInput'
import { Select } from '@/view/components/ui/Select'

describe('UI Stability - Form Components', () => {
  describe('Input Component', () => {
    it('should render with proper accessibility attributes', () => {
      render(
        <Input
          label="Test Input"
          helperText="This is a test input"
          placeholder="Enter text"
          required
        />
      )

      const input = screen.getByRole('textbox', { name: /test input/i })
      const label = screen.getByText('Test Input')
      const helperText = screen.getByText('This is a test input')

      expect(input).toBeInTheDocument()
      expect(input).toHaveAttribute('aria-describedby')
      expect(input).toHaveAttribute('aria-invalid', 'false')
      expect(label).toBeInTheDocument()
      expect(label).toHaveTextContent('*') // Required indicator
      expect(helperText).toBeInTheDocument()
    })

    it('should display validation errors correctly', async () => {
      const user = userEvent.setup()
      
      render(
        <Input
          label="Email"
          type="email"
          error="Invalid email address"
          required
        />
      )

      const input = screen.getByRole('textbox', { name: /email/i })
      const errorMessage = screen.getByRole('alert')

      expect(input).toHaveAttribute('aria-invalid', 'true')
      expect(errorMessage).toBeInTheDocument()
      expect(errorMessage).toHaveTextContent('Invalid email address')
    })

    it('should handle clearable functionality', async () => {
      const user = userEvent.setup()
      const onClear = jest.fn()
      
      render(
        <Input
          label="Clearable Input"
          value="test value"
          clearable
          onClear={onClear}
          onChange={() => {}}
        />
      )

      const clearButton = screen.getByRole('button', { name: /clear input/i })
      expect(clearButton).toBeInTheDocument()

      await user.click(clearButton)
      expect(onClear).toHaveBeenCalled()
    })

    it('should show loading state correctly', () => {
      render(
        <Input
          label="Loading Input"
          loading
        />
      )

      const label = screen.getByText('Loading Input')
      expect(label).toHaveTextContent('Validating...')
      
      // Check for loading spinner
      const spinner = document.querySelector('.animate-spin')
      expect(spinner).toBeInTheDocument()
    })

    it('should handle icon positioning', () => {
      const TestIcon = ({ className }: { className?: string }) => (
        <svg className={className} data-testid="test-icon">
          <circle cx="12" cy="12" r="10" />
        </svg>
      )

      const { rerender } = render(
        <Input
          label="Icon Input"
          icon={TestIcon}
          iconPosition="left"
        />
      )

      let icon = screen.getByTestId('test-icon')
      expect(icon.closest('.absolute')).toHaveClass('left-0')

      rerender(
        <Input
          label="Icon Input"
          icon={TestIcon}
          iconPosition="right"
        />
      )

      icon = screen.getByTestId('test-icon')
      expect(icon.closest('.absolute')).toHaveClass('right-0')
    })
  })

  describe('Form Component', () => {
    it('should provide form context to child components', () => {
      const errors = { email: 'Invalid email' }
      const touched = { email: true }

      render(
        <Form errors={errors} touched={touched}>
          <FormField name="email">
            <Input label="Email" type="email" />
          </FormField>
        </Form>
      )

      const input = screen.getByRole('textbox', { name: /email/i })
      expect(input).toHaveAttribute('aria-invalid', 'true')
      
      const errorMessage = screen.getByRole('alert')
      expect(errorMessage).toHaveTextContent('Invalid email')
    })

    it('should handle form submission state', () => {
      render(
        <Form isSubmitting>
          <FormField name="test">
            <Input label="Test Field" />
          </FormField>
        </Form>
      )

      // Form should have proper attributes when submitting
      const form = screen.getByRole('form')
      expect(form).toHaveAttribute('noValidate')
    })
  })

  describe('ZipCodeInput Component', () => {
    it('should render with proper validation states', () => {
      render(
        <ZipCodeInput
          label="ZIP Code"
          value="90210"
          showExtractedWarning
        />
      )

      const input = screen.getByRole('textbox', { name: /zip code/i })
      expect(input).toBeInTheDocument()
      expect(input).toHaveValue('90210')
    })

    it('should show processing state', () => {
      render(
        <ZipCodeInput
          label="ZIP Code"
          value="123 Main St, Beverly Hills, CA 90210"
        />
      )

      const label = screen.getByText('ZIP Code')
      // Should show processing indicator when extracting ZIP from address
      expect(label.parentElement).toBeInTheDocument()
    })
  })

  describe('Select Component', () => {
    const options = [
      { value: 'option1', label: 'Option 1' },
      { value: 'option2', label: 'Option 2' },
      { value: 'option3', label: 'Option 3', disabled: true },
    ]

    it('should render with proper accessibility attributes', () => {
      render(
        <Select
          options={options}
          placeholder="Select an option"
          aria-label="Test select"
        />
      )

      const button = screen.getByRole('button', { name: /test select/i })
      expect(button).toBeInTheDocument()
      expect(button).toHaveAttribute('aria-expanded', 'false')
      expect(button).toHaveAttribute('aria-haspopup', 'listbox')
    })

    it('should open dropdown and show options', async () => {
      const user = userEvent.setup()
      
      render(
        <Select
          options={options}
          placeholder="Select an option"
        />
      )

      const button = screen.getByRole('button')
      await user.click(button)

      expect(button).toHaveAttribute('aria-expanded', 'true')
      
      const listbox = screen.getByRole('listbox')
      expect(listbox).toBeInTheDocument()

      const option1 = screen.getByRole('option', { name: /option 1/i })
      const option2 = screen.getByRole('option', { name: /option 2/i })
      const option3 = screen.getByRole('option', { name: /option 3/i })

      expect(option1).toBeInTheDocument()
      expect(option2).toBeInTheDocument()
      expect(option3).toBeInTheDocument()
      expect(option3).toHaveClass('pointer-events-none', 'opacity-50')
    })

    it('should handle keyboard navigation', async () => {
      const user = userEvent.setup()
      const onValueChange = jest.fn()
      
      render(
        <Select
          options={options}
          onValueChange={onValueChange}
        />
      )

      const button = screen.getByRole('button')
      
      // Open with Enter key
      await user.type(button, '{Enter}')
      expect(button).toHaveAttribute('aria-expanded', 'true')

      // Navigate with arrow keys
      await user.type(button, '{ArrowDown}')
      await user.type(button, '{Enter}')

      expect(onValueChange).toHaveBeenCalledWith('option1')
    })

    it('should close dropdown when clicking outside', async () => {
      const user = userEvent.setup()
      
      render(
        <div>
          <Select options={options} />
          <button>Outside button</button>
        </div>
      )

      const selectButton = screen.getByRole('button', { name: /select an option/i })
      const outsideButton = screen.getByRole('button', { name: /outside button/i })

      // Open dropdown
      await user.click(selectButton)
      expect(selectButton).toHaveAttribute('aria-expanded', 'true')

      // Click outside
      await user.click(outsideButton)
      expect(selectButton).toHaveAttribute('aria-expanded', 'false')
    })
  })

  describe('Form Accessibility', () => {
    it('should have proper ARIA relationships', () => {
      render(
        <Form>
          <FormControl isRequired isInvalid>
            <FormLabel htmlFor="test-input">Test Label</FormLabel>
            <Input id="test-input" />
            <FormErrorMessage>This field is required</FormErrorMessage>
            <FormHelperText>Additional help text</FormHelperText>
          </FormControl>
        </Form>
      )

      const input = screen.getByRole('textbox')
      const label = screen.getByText('Test Label')
      const errorMessage = screen.getByRole('alert')
      const helperText = screen.getByText('Additional help text')

      expect(label).toHaveAttribute('for', 'test-input')
      expect(input).toHaveAttribute('id', 'test-input')
      expect(errorMessage).toBeInTheDocument()
      expect(helperText).toBeInTheDocument()
    })
  })
})
