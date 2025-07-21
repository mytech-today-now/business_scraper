import React from 'react'
import { clsx } from 'clsx'

/**
 * Card component props
 */
export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

/**
 * Card header props
 */
export interface CardHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

/**
 * Card title props
 */
export interface CardTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
  children: React.ReactNode
}

/**
 * Card description props
 */
export interface CardDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode
}

/**
 * Card content props
 */
export interface CardContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

/**
 * Card footer props
 */
export interface CardFooterProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
}

/**
 * Card component
 */
export const Card = React.forwardRef<HTMLDivElement, CardProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={clsx(
        'rounded-lg border bg-card text-card-foreground shadow-sm',
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
)

Card.displayName = 'Card'

/**
 * Card header component
 */
export const CardHeader = React.forwardRef<HTMLDivElement, CardHeaderProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={clsx('flex flex-col space-y-1.5 p-6', className)}
      {...props}
    >
      {children}
    </div>
  )
)

CardHeader.displayName = 'CardHeader'

/**
 * Card title component
 */
export const CardTitle = React.forwardRef<HTMLParagraphElement, CardTitleProps>(
  ({ className, children, ...props }, ref) => (
    <h3
      ref={ref}
      className={clsx(
        'text-2xl font-semibold leading-none tracking-tight',
        className
      )}
      {...props}
    >
      {children}
    </h3>
  )
)

CardTitle.displayName = 'CardTitle'

/**
 * Card description component
 */
export const CardDescription = React.forwardRef<HTMLParagraphElement, CardDescriptionProps>(
  ({ className, children, ...props }, ref) => (
    <p
      ref={ref}
      className={clsx('text-sm text-muted-foreground', className)}
      {...props}
    >
      {children}
    </p>
  )
)

CardDescription.displayName = 'CardDescription'

/**
 * Card content component
 */
export const CardContent = React.forwardRef<HTMLDivElement, CardContentProps>(
  ({ className, children, ...props }, ref) => (
    <div ref={ref} className={clsx('p-6 pt-0', className)} {...props}>
      {children}
    </div>
  )
)

CardContent.displayName = 'CardContent'

/**
 * Card footer component
 */
export const CardFooter = React.forwardRef<HTMLDivElement, CardFooterProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={clsx('flex items-center p-6 pt-0', className)}
      {...props}
    >
      {children}
    </div>
  )
)

CardFooter.displayName = 'CardFooter'
