/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'
import { useConfig } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'
import {
  mockConfigContext,
  mockScraperController,
  setupBrowserMocks
} from '@/test/testUtils'

// Mock Next.js Image component for testing
jest.mock('next/image', () => {
  return function MockImage({
    src,
    alt,
    width,
    height,
    priority,
    sizes,
    quality,
    ...props
  }: {
    src: string
    alt: string
    width?: number
    height?: number
    priority?: boolean
    sizes?: string
    quality?: number
    [key: string]: unknown
  }): JSX.Element {
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

// Import components after mocking
import { App } from '@/view/components/App'

// Mock the hooks
jest.mock('@/controller/ConfigContext', () => ({
  ...jest.requireActual('@/controller/ConfigContext'),
  useConfig: jest.fn(),
}))

jest.mock('@/controller/useScraperController')

const mockUseConfig = useConfig as jest.MockedFunction<typeof useConfig>
const mockUseScraperController = useScraperController as jest.MockedFunction<typeof useScraperController>

describe('Image Optimization', () => {
  beforeEach((): void => {
    // Setup browser mocks
    setupBrowserMocks()

    // Setup hook mocks
    mockUseConfig.mockReturnValue(mockConfigContext)
    mockUseScraperController.mockReturnValue(mockScraperController)
  })

  test('should render optimized favicon image in header', (): void => {
    render(<App />)

    const logoImage = screen.getByAltText('Business Scraper Logo')
    expect(logoImage).toBeInTheDocument()
    expect(logoImage).toHaveAttribute('src', '/favicon.ico')
    expect(logoImage).toHaveAttribute('width', '32')
    expect(logoImage).toHaveAttribute('height', '32')
    expect(logoImage).toHaveAttribute('data-priority', 'true')
    expect(logoImage).toHaveAttribute('data-sizes', '32px')
    expect(logoImage).toHaveAttribute('data-quality', '90')
  })

  test('should have proper alt text for accessibility', (): void => {
    render(<App />)

    const logoImage = screen.getByAltText('Business Scraper Logo')
    expect(logoImage).toHaveAttribute('alt', 'Business Scraper Logo')
  })

  test('should use Next.js Image component with optimization settings', (): void => {
    render(<App />)

    const logoImage = screen.getByAltText('Business Scraper Logo')

    // Verify optimization attributes are present
    expect(logoImage).toHaveAttribute('data-priority', 'true') // Above-the-fold image
    expect(logoImage).toHaveAttribute('data-sizes', '32px') // Responsive sizing
    expect(logoImage).toHaveAttribute('data-quality', '90') // High quality
  })
})
