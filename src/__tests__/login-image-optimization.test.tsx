/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'

// Mock Next.js Image component for testing
jest.mock('next/image', () => {
  return function MockImage({ src, alt, width, height, priority, sizes, quality, ...props }: any) {
    return (
      <img
        src={src}
        alt={alt}
        width={width}
        height={height}
        data-priority={priority}
        data-sizes={sizes}
        data-quality={quality}
        {...props}
      />
    )
  }
})

// Mock Next.js router
jest.mock('next/navigation', () => ({
  useRouter: (): { push: jest.Mock; replace: jest.Mock; back: jest.Mock } => ({
    push: jest.fn(),
    replace: jest.fn(),
    back: jest.fn(),
  }),
}))

// Mock CSRF protection hook
jest.mock('@/hooks/useCSRFProtection', () => ({
  useFormCSRFProtection: (): { csrfToken: string; isLoading: boolean } => ({
    csrfToken: 'mock-token',
    isLoading: false,
  }),
}))

// Import component after mocking
import LoginPage from '@/app/login/page'

describe('Login Page Image Optimization', () => {
  test('should render optimized favicon image in login page', () => {
    render(<LoginPage />)

    const logoImage = screen.getByAltText('Business Scraper Logo')
    expect(logoImage).toBeInTheDocument()
    expect(logoImage).toHaveAttribute('src', '/favicon.ico')
    expect(logoImage).toHaveAttribute('width', '40')
    expect(logoImage).toHaveAttribute('height', '40')
    expect(logoImage).toHaveAttribute('data-priority', 'true')
    expect(logoImage).toHaveAttribute('data-sizes', '40px')
    expect(logoImage).toHaveAttribute('data-quality', '90')
  })

  test('should have proper alt text for accessibility', () => {
    render(<LoginPage />)

    const logoImage = screen.getByAltText('Business Scraper Logo')
    expect(logoImage).toHaveAttribute('alt', 'Business Scraper Logo')
  })

  test('should use priority loading for above-the-fold image', () => {
    render(<LoginPage />)

    const logoImage = screen.getByAltText('Business Scraper Logo')
    expect(logoImage).toHaveAttribute('data-priority', 'true')
  })
})
