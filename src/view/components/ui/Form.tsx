import React, { createContext, useContext, useId } from 'react'
import { clsx } from 'clsx'

/**
 * Form context for managing form state and validation
 */
interface FormContextValue {
  formId: string
  errors: Record<string, string>
  touched: Record<string, boolean>
  isSubmitting: boolean
  onFieldChange: (name: string, value: any) => void
  onFieldBlur: (name: string) => void
  onFieldFocus: (name: string) => void
}

const FormContext = createContext<FormContextValue | null>(null)

/**
 * Hook to access form context
 */
export function useFormContext() {
  const context = useContext(FormContext)
  if (!context) {
    throw new Error('useFormContext must be used within a Form component')
  }
  return context
}

/**
 * Form component props
 */
export interface FormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  children: React.ReactNode
  errors?: Record<string, string>
  touched?: Record<string, boolean>
  isSubmitting?: boolean
  onFieldChange?: (name: string, value: any) => void
  onFieldBlur?: (name: string) => void
  onFieldFocus?: (name: string) => void
}

/**
 * Enhanced Form component with context and validation support
 */
export const Form = React.forwardRef<HTMLFormElement, FormProps>(
  (
    {
      children,
      className,
      errors = {},
      touched = {},
      isSubmitting = false,
      onFieldChange = () => {},
      onFieldBlur = () => {},
      onFieldFocus = () => {},
      ...props
    },
    ref
  ) => {
    const formId = useId()

    const contextValue: FormContextValue = {
      formId,
      errors,
      touched,
      isSubmitting,
      onFieldChange,
      onFieldBlur,
      onFieldFocus,
    }

    return (
      <FormContext.Provider value={contextValue}>
        <form
          ref={ref}
          className={clsx('space-y-6', className)}
          noValidate
          {...props}
        >
          {children}
        </form>
      </FormContext.Provider>
    )
  }
)

Form.displayName = 'Form'

/**
 * Form field component props
 */
export interface FormFieldProps {
  name: string
  children: React.ReactNode
  className?: string
}

/**
 * Form field wrapper component
 */
export const FormField: React.FC<FormFieldProps> = ({ name, children, className }) => {
  const { errors, touched } = useFormContext()
  const error = touched[name] ? errors[name] : undefined

  return (
    <div className={clsx('form-field', className)} data-field={name}>
      {React.Children.map(children, child => {
        if (React.isValidElement(child)) {
          return React.cloneElement(child, {
            name,
            error,
            ...child.props,
          })
        }
        return child
      })}
    </div>
  )
}

FormField.displayName = 'FormField'

/**
 * Form control component props
 */
export interface FormControlProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
  isRequired?: boolean
  isInvalid?: boolean
  isDisabled?: boolean
}

/**
 * Form control wrapper component
 */
export const FormControl: React.FC<FormControlProps> = ({
  children,
  className,
  isRequired = false,
  isInvalid = false,
  isDisabled = false,
  ...props
}) => {
  return (
    <div
      className={clsx(
        'form-control',
        isRequired && 'required',
        isInvalid && 'invalid',
        isDisabled && 'disabled',
        className
      )}
      data-required={isRequired}
      data-invalid={isInvalid}
      data-disabled={isDisabled}
      {...props}
    >
      {children}
    </div>
  )
}

FormControl.displayName = 'FormControl'

/**
 * Form label component props
 */
export interface FormLabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  children: React.ReactNode
  isRequired?: boolean
}

/**
 * Form label component
 */
export const FormLabel = React.forwardRef<HTMLLabelElement, FormLabelProps>(
  ({ children, className, isRequired = false, ...props }, ref) => {
    return (
      <label
        ref={ref}
        className={clsx(
          'text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70',
          className
        )}
        {...props}
      >
        {children}
        {isRequired && <span className="text-red-500 ml-1">*</span>}
      </label>
    )
  }
)

FormLabel.displayName = 'FormLabel'

/**
 * Form error message component props
 */
export interface FormErrorMessageProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode
}

/**
 * Form error message component
 */
export const FormErrorMessage = React.forwardRef<HTMLParagraphElement, FormErrorMessageProps>(
  ({ children, className, ...props }, ref) => {
    return (
      <p
        ref={ref}
        className={clsx('text-sm text-red-600 dark:text-red-400 flex items-center gap-1', className)}
        role="alert"
        aria-live="polite"
        {...props}
      >
        <svg className="h-4 w-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        {children}
      </p>
    )
  }
)

FormErrorMessage.displayName = 'FormErrorMessage'

/**
 * Form helper text component props
 */
export interface FormHelperTextProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode
}

/**
 * Form helper text component
 */
export const FormHelperText = React.forwardRef<HTMLParagraphElement, FormHelperTextProps>(
  ({ children, className, ...props }, ref) => {
    return (
      <p
        ref={ref}
        className={clsx('text-sm text-muted-foreground', className)}
        {...props}
      >
        {children}
      </p>
    )
  }
)

FormHelperText.displayName = 'FormHelperText'

/**
 * Form section component for grouping related fields
 */
export interface FormSectionProps extends React.HTMLAttributes<HTMLFieldSetElement> {
  title?: string
  description?: string
  children: React.ReactNode
}

export const FormSection = React.forwardRef<HTMLFieldSetElement, FormSectionProps>(
  ({ title, description, children, className, ...props }, ref) => {
    return (
      <fieldset
        ref={ref}
        className={clsx('space-y-4 border border-border rounded-lg p-4', className)}
        {...props}
      >
        {title && (
          <legend className="text-lg font-semibold px-2 -ml-2">
            {title}
          </legend>
        )}
        {description && (
          <p className="text-sm text-muted-foreground -mt-2">
            {description}
          </p>
        )}
        <div className="space-y-4">
          {children}
        </div>
      </fieldset>
    )
  }
)

FormSection.displayName = 'FormSection'
