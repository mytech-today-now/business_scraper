/**
 * Enhanced Test Helpers and Utilities
 * Comprehensive testing utilities for business scraper application
 */

import React from 'react'
import { jest } from '@jest/globals'
import { render, RenderOptions, RenderResult } from '@testing-library/react'
import { ReactElement, ReactNode } from 'react'
import userEvent from '@testing-library/user-event'
import { BusinessRecord, ScrapingConfig, IndustryCategory } from '@/types/business'

// Enhanced mock data generators
export const createMockBusinessRecord = (overrides: Partial<BusinessRecord> = {}): BusinessRecord => ({
  id: `business-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  businessName: 'Test Business',
  industry: 'Technology',
  email: ['test@testbusiness.com'],
  phone: '(555) 123-4567',
  websiteUrl: 'https://testbusiness.com',
  address: {
    street: '123 Test St',
    city: 'Test City',
    state: 'TC',
    zipCode: '12345'
  },
  contactPerson: 'Test Contact',
  coordinates: {
    lat: 40.7128,
    lng: -74.0060
  },
  scrapedAt: new Date(),
  ...overrides
})

export const createMockScrapingConfig = (overrides: Partial<ScrapingConfig> = {}): ScrapingConfig => ({
  industries: ['Technology', 'Healthcare'],
  zipCode: '12345',
  searchRadius: 10,
  searchDepth: 3,
  pagesPerSite: 5,
  ...overrides
})

export const createMockIndustryCategory = (overrides: Partial<IndustryCategory> = {}): IndustryCategory => ({
  id: `industry-${Date.now()}`,
  name: 'Test Industry',
  keywords: ['test', 'sample', 'mock'],
  isCustom: false,
  domainBlacklist: ['spam.com', 'unwanted.net'],
  ...overrides
})

// Mock data arrays for bulk testing
export const createMockBusinessRecords = (count: number = 5): BusinessRecord[] => {
  return Array.from({ length: count }, (_, index) => 
    createMockBusinessRecord({
      id: `business-${index + 1}`,
      businessName: `Test Business ${index + 1}`,
      email: [`test${index + 1}@business.com`],
      industry: index % 2 === 0 ? 'Technology' : 'Healthcare'
    })
  )
}

// Enhanced render function with providers
interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialState?: any
  theme?: 'light' | 'dark'
  mobile?: boolean
}

export const renderWithProviders = (
  ui: ReactElement,
  options: CustomRenderOptions = {}
): RenderResult => {
  const { initialState, theme = 'light', mobile = false, ...renderOptions } = options

  // Mock window.matchMedia for responsive testing
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation(query => ({
      matches: mobile ? query.includes('max-width') : query.includes('min-width'),
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  })

  // Mock IntersectionObserver
  global.IntersectionObserver = jest.fn().mockImplementation(() => ({
    observe: jest.fn(),
    unobserve: jest.fn(),
    disconnect: jest.fn(),
  }))

  const Wrapper = ({ children }: { children: ReactNode }) => {
    return (
      <div data-theme={theme} className={mobile ? 'mobile-viewport' : 'desktop-viewport'}>
        {children}
      </div>
    )
  }

  return render(ui, { wrapper: Wrapper, ...renderOptions })
}

// User interaction helpers
export const createUserEvent = () => userEvent.setup({
  advanceTimers: jest.advanceTimersByTime,
})

// Database and storage mocks
export const createMockStorage = () => ({
  initialize: jest.fn().mockResolvedValue(undefined),
  getAllBusinesses: jest.fn().mockResolvedValue([]),
  saveBusiness: jest.fn().mockResolvedValue(undefined),
  deleteBusiness: jest.fn().mockResolvedValue(undefined),
  getAllIndustries: jest.fn().mockResolvedValue([]),
  saveIndustry: jest.fn().mockResolvedValue(undefined),
  deleteIndustry: jest.fn().mockResolvedValue(undefined),
  getConfig: jest.fn().mockResolvedValue(null),
  saveConfig: jest.fn().mockResolvedValue(undefined),
  clearAll: jest.fn().mockResolvedValue(undefined),
})

// API mocks
export const createMockApiResponse = <T>(data: T, status: number = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  statusText: status === 200 ? 'OK' : 'Error',
  json: jest.fn().mockResolvedValue(data),
  text: jest.fn().mockResolvedValue(JSON.stringify(data)),
  headers: new Headers(),
})

// File system mocks
export const createMockFileSystem = () => ({
  readFile: jest.fn(),
  writeFile: jest.fn(),
  exists: jest.fn(),
  mkdir: jest.fn(),
  rmdir: jest.fn(),
  stat: jest.fn(),
})

// Environment variable helpers
export const mockEnvironmentVariables = (vars: Record<string, string>) => {
  const originalEnv = process.env
  beforeEach(() => {
    process.env = { ...originalEnv, ...vars }
  })
  afterEach(() => {
    process.env = originalEnv
  })
}

// Timer helpers
export const setupTimers = () => {
  beforeEach(() => {
    jest.useFakeTimers()
  })
  afterEach(() => {
    jest.runOnlyPendingTimers()
    jest.useRealTimers()
  })
}

// Network request mocks
export const mockFetch = (responses: Array<{ url: string; response: any; status?: number }>) => {
  const mockFn = jest.fn()
  
  responses.forEach(({ url, response, status = 200 }) => {
    mockFn.mockImplementationOnce((requestUrl: string) => {
      if (requestUrl.includes(url)) {
        return Promise.resolve(createMockApiResponse(response, status))
      }
      return Promise.reject(new Error(`Unexpected request to ${requestUrl}`))
    })
  })
  
  global.fetch = mockFn
  return mockFn
}

// Console mocks
export const mockConsole = () => {
  const originalConsole = console
  const mockConsole = {
    log: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  }
  
  beforeEach(() => {
    global.console = mockConsole as any
  })
  
  afterEach(() => {
    global.console = originalConsole
  })
  
  return mockConsole
}

// Performance testing helpers
export const measurePerformance = async (fn: () => Promise<void> | void): Promise<number> => {
  const start = performance.now()
  await fn()
  const end = performance.now()
  return end - start
}

// Memory leak detection
export const detectMemoryLeaks = () => {
  const initialMemory = process.memoryUsage()
  
  return {
    check: () => {
      const currentMemory = process.memoryUsage()
      const heapDiff = currentMemory.heapUsed - initialMemory.heapUsed
      return {
        heapDiff,
        isLeak: heapDiff > 10 * 1024 * 1024, // 10MB threshold
        initial: initialMemory,
        current: currentMemory,
      }
    }
  }
}

// Error boundary for testing
export class TestErrorBoundary extends React.Component<
  { children: ReactNode },
  { hasError: boolean }
> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Test Error Boundary caught an error:', error, errorInfo)
  }
  
  render() {
    if (this.state.hasError) {
      return <div data-testid="error-boundary">Something went wrong</div>
    }
    
    return this.props.children
  }
}

// Accessibility testing helpers
export const checkAccessibility = async (container: HTMLElement) => {
  // Mock axe-core for accessibility testing
  return {
    violations: [],
    passes: [],
    incomplete: [],
    inapplicable: [],
  }
}

// Test data cleanup
export const cleanupTestData = () => {
  // Clear all mocks
  jest.clearAllMocks()
  
  // Reset DOM
  document.body.innerHTML = ''
  
  // Clear local storage
  localStorage.clear()
  sessionStorage.clear()
  
  // Reset fetch
  if (global.fetch && jest.isMockFunction(global.fetch)) {
    global.fetch.mockRestore()
  }
}

// Test suite helpers
export const createTestSuite = (name: string, tests: () => void) => {
  describe(name, () => {
    beforeEach(() => {
      cleanupTestData()
    })
    
    afterEach(() => {
      cleanupTestData()
    })
    
    tests()
  })
}
