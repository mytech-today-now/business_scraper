/**
 * Test utilities for React component testing
 * Provides properly configured providers and mocks for testing
 */

import React from 'react'
import { render, RenderOptions, act } from '@testing-library/react'
import { ConfigProvider } from '@/controller/ConfigContext'

// Mock storage with proper initialization
export const mockStorage = {
  initialize: jest.fn().mockResolvedValue(undefined),
  getConfig: jest.fn().mockResolvedValue({
    id: 'default',
    industries: [],
    zipCode: '90210',
    searchRadius: 25,
    searchDepth: 2,
    pagesPerSite: 5,
  }),
  saveConfig: jest.fn().mockResolvedValue(undefined),
  getAllIndustries: jest.fn().mockResolvedValue([
    {
      id: 'law-firms',
      name: 'Law Firms & Legal Services',
      keywords: ['law firm near me', 'corporate law office'],
      isCustom: false,
    },
  ]),
  saveIndustries: jest.fn().mockResolvedValue(undefined),
  getAllSubCategories: jest.fn().mockResolvedValue([]),
  saveSubCategory: jest.fn().mockResolvedValue(undefined),
  getAllBusinesses: jest.fn().mockResolvedValue([]),
  saveBusiness: jest.fn().mockResolvedValue(undefined),
  deleteBusiness: jest.fn().mockResolvedValue(undefined),
  clearAllBusinesses: jest.fn().mockResolvedValue(undefined),
}

// Mock scraper controller
export const mockScraperController = {
  scrapingState: {
    isScrapingActive: false,
    results: [],
    errors: [],
    progress: { current: 0, total: 0, percentage: 0 },
    currentUrl: '',
    processingSteps: [],
  },
  startScraping: jest.fn(),
  stopScraping: jest.fn(),
  clearResults: jest.fn(),
  removeBusiness: jest.fn(),
  updateBusiness: jest.fn(),
  loadPreviousResults: jest.fn(),
  addProcessingStep: jest.fn(),
  updateProcessingStep: jest.fn(),
  clearProcessingSteps: jest.fn(),
  canStartScraping: true,
  hasResults: false,
  hasErrors: false,
}

// Mock localStorage
export const mockLocalStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}

// Setup browser environment mocks
export const setupBrowserMocks = () => {
  // Mock localStorage
  Object.defineProperty(window, 'localStorage', {
    value: mockLocalStorage,
    writable: true,
  })

  // Mock sessionStorage
  Object.defineProperty(window, 'sessionStorage', {
    value: {
      getItem: jest.fn(),
      setItem: jest.fn(),
      removeItem: jest.fn(),
      clear: jest.fn(),
    },
    writable: true,
  })

  // Mock document.documentElement.classList
  Object.defineProperty(document.documentElement, 'classList', {
    value: {
      toggle: jest.fn(),
      add: jest.fn(),
      remove: jest.fn(),
      contains: jest.fn(),
    },
    writable: true,
  })

  // Mock window.matchMedia if not already mocked
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    })
  }

  // Mock IndexedDB for storage tests
  const mockIDBRequest = {
    result: null,
    error: null,
    onsuccess: null,
    onerror: null,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
  }

  const mockIDBDatabase = {
    createObjectStore: jest.fn(),
    deleteObjectStore: jest.fn(),
    transaction: jest.fn(() => ({
      objectStore: jest.fn(() => ({
        add: jest.fn(() => mockIDBRequest),
        put: jest.fn(() => mockIDBRequest),
        get: jest.fn(() => mockIDBRequest),
        getAll: jest.fn(() => mockIDBRequest),
        delete: jest.fn(() => mockIDBRequest),
        clear: jest.fn(() => mockIDBRequest),
        createIndex: jest.fn(),
        deleteIndex: jest.fn(),
      })),
      oncomplete: null,
      onerror: null,
      onabort: null,
    })),
    close: jest.fn(),
  }

  if (!global.indexedDB) {
    global.indexedDB = {
      open: jest.fn(() => ({
        ...mockIDBRequest,
        result: mockIDBDatabase,
        onupgradeneeded: null,
      })),
      deleteDatabase: jest.fn(() => mockIDBRequest),
      databases: jest.fn(() => Promise.resolve([])),
    }
  }

  // Mock NextRequest and NextResponse for API tests
  if (!global.NextRequest) {
    global.NextRequest = jest.fn().mockImplementation((url, init) => ({
      url,
      method: init?.method || 'GET',
      headers: new Map(Object.entries(init?.headers || {})),
      body: init?.body,
      json: () => Promise.resolve(JSON.parse(init?.body || '{}')),
      text: () => Promise.resolve(init?.body || ''),
    }))
  }

  if (!global.NextResponse) {
    global.NextResponse = {
      json: jest.fn((data, init) => ({
        status: init?.status || 200,
        headers: new Map(Object.entries(init?.headers || {})),
        json: () => Promise.resolve(data),
      })),
      redirect: jest.fn((url, status) => ({
        status: status || 302,
        headers: new Map([['Location', url]]),
      })),
    }
  }

  // Mock fetch with better error handling
  if (!global.fetch) {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({}),
        text: () => Promise.resolve(''),
        blob: () => Promise.resolve(new Blob()),
      })
    )
  }

  // Mock ResizeObserver
  if (!global.ResizeObserver) {
    global.ResizeObserver = jest.fn().mockImplementation(() => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    }))
  }

  // Mock IntersectionObserver
  if (!global.IntersectionObserver) {
    global.IntersectionObserver = jest.fn().mockImplementation(() => ({
      observe: jest.fn(),
      unobserve: jest.fn(),
      disconnect: jest.fn(),
    }))
  }

  // Mock URL methods
  if (!global.URL.createObjectURL) {
    global.URL.createObjectURL = jest.fn(() => 'mocked-url')
    global.URL.revokeObjectURL = jest.fn()
  }

  // Mock crypto API
  if (!global.crypto) {
    Object.defineProperty(global, 'crypto', {
      value: {
        randomUUID: jest.fn(() => 'mocked-uuid'),
        getRandomValues: jest.fn(arr => {
          for (let i = 0; i < arr.length; i++) {
            arr[i] = Math.floor(Math.random() * 256)
          }
          return arr
        }),
      },
    })
  }

  // Mock performance API
  if (!window.performance) {
    Object.defineProperty(window, 'performance', {
      value: {
        now: jest.fn(() => Date.now()),
        mark: jest.fn(),
        measure: jest.fn(),
        getEntriesByType: jest.fn(() => []),
        getEntriesByName: jest.fn(() => []),
      },
    })
  }

  // Mock requestAnimationFrame
  if (!global.requestAnimationFrame) {
    global.requestAnimationFrame = jest.fn(cb => setTimeout(cb, 0))
    global.cancelAnimationFrame = jest.fn(id => clearTimeout(id))
  }
}

// Mock config state for testing
export const mockConfigState = {
  // Configuration object - this is what the App component expects
  config: {
    zipCode: '90210',
    searchRadius: 25,
    searchDepth: 2,
    pagesPerSite: 5,
  },

  // Industries
  industries: [
    {
      id: 'law-firms',
      name: 'Law Firms & Legal Services',
      keywords: ['law firm near me', 'corporate law office'],
      isCustom: false,
    },
  ],
  selectedIndustries: [],
  subCategories: [],

  // UI state
  isDarkMode: false,
  isLoading: false,

  // Application state - IMPORTANT: Set to true so App doesn't show loading screen
  isInitialized: true,

  // Edit state tracking
  industriesInEditMode: [],
}

export const mockConfigContext = {
  state: mockConfigState,
  updateConfig: jest.fn(),
  toggleDarkMode: jest.fn(),
  isConfigValid: jest.fn().mockReturnValue(true),
  resetApplicationData: jest.fn(),
  addIndustry: jest.fn(),
  updateIndustry: jest.fn(),
  deleteIndustry: jest.fn(),
  toggleIndustrySelection: jest.fn(),
  selectAllIndustries: jest.fn(),
  clearIndustrySelection: jest.fn(),
  startIndustryEdit: jest.fn(),
  stopIndustryEdit: jest.fn(),
  addSubCategory: jest.fn(),
  updateSubCategory: jest.fn(),
  deleteSubCategory: jest.fn(),
}

// Custom render function that includes providers
interface CustomRenderOptions extends Omit<RenderOptions, 'wrapper'> {
  initialConfigState?: Partial<any>
}

export const renderWithProviders = (ui: React.ReactElement, options: CustomRenderOptions = {}) => {
  const { initialConfigState, ...renderOptions } = options

  // Setup browser mocks
  setupBrowserMocks()

  const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    return <ConfigProvider>{children}</ConfigProvider>
  }

  return render(ui, { wrapper: AllTheProviders, ...renderOptions })
}

// Wait for ConfigProvider to initialize
export const waitForConfigInitialization = async () => {
  // Since we're using MockConfigProvider, initialization should be immediate
  // Just give a small delay for React to render
  await act(async () => {
    await new Promise(resolve => setTimeout(resolve, 50))
  })
}

// Reset all mocks
export const resetAllMocks = () => {
  jest.clearAllMocks()
  Object.values(mockStorage).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear()
    }
  })
  Object.values(mockLocalStorage).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockClear()
    }
  })
}

// Export everything from testing-library
export * from '@testing-library/react'
export { renderWithProviders as render }
