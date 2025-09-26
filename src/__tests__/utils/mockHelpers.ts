/**
 * Mock Helpers for Secure Testing
 * Utilities for mocking file operations and external dependencies safely
 */

import { jest } from '@jest/globals'

// Mock file system operations
export const createMockFileSystem = () => {
  const mockFiles: Record<string, string> = {}
  const mockDirectories: Set<string> = new Set()

  return {
    // Mock fs methods
    existsSync: jest.fn((path: string) => {
      return mockFiles[path] !== undefined || mockDirectories.has(path)
    }),

    readFileSync: jest.fn((path: string) => {
      if (mockFiles[path] === undefined) {
        throw new Error(`ENOENT: no such file or directory, open '${path}'`)
      }
      return mockFiles[path]
    }),

    writeFileSync: jest.fn((path: string, data: string) => {
      mockFiles[path] = data
    }),

    mkdirSync: jest.fn((path: string) => {
      mockDirectories.add(path)
    }),

    rmSync: jest.fn((path: string, options?: any) => {
      if (options?.recursive) {
        // Remove all files and directories that start with this path
        Object.keys(mockFiles).forEach(filePath => {
          if (filePath.startsWith(path)) {
            delete mockFiles[filePath]
          }
        })
        Array.from(mockDirectories).forEach(dirPath => {
          if (dirPath.startsWith(path)) {
            mockDirectories.delete(dirPath)
          }
        })
      } else {
        delete mockFiles[path]
        mockDirectories.delete(path)
      }
    }),

    // Helper methods for testing
    addMockFile: (path: string, content: string) => {
      mockFiles[path] = content
    },

    addMockDirectory: (path: string) => {
      mockDirectories.add(path)
    },

    getMockFiles: () => ({ ...mockFiles }),

    getMockDirectories: () => new Set(mockDirectories),

    reset: () => {
      Object.keys(mockFiles).forEach(key => delete mockFiles[key])
      mockDirectories.clear()
    },
  }
}

// Mock environment variables safely
export const createMockEnvironment = (initialEnv: Record<string, string> = {}) => {
  const originalEnv = { ...process.env }
  const mockEnv = { ...originalEnv, ...initialEnv }

  return {
    set: (key: string, value: string) => {
      mockEnv[key] = value
      process.env[key] = value
    },

    get: (key: string) => mockEnv[key],

    delete: (key: string) => {
      delete mockEnv[key]
      delete process.env[key]
    },

    restore: () => {
      // Restore original environment
      Object.keys(process.env).forEach(key => {
        if (!(key in originalEnv)) {
          delete process.env[key]
        }
      })
      Object.keys(originalEnv).forEach(key => {
        process.env[key] = originalEnv[key]
      })
    },

    getAll: () => ({ ...mockEnv }),
  }
}

// Mock logger for testing
export const createMockLogger = () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
  trace: jest.fn(),

  // Helper to check if specific messages were logged
  hasLoggedInfo: (message: string) => {
    return (createMockLogger().info as jest.Mock).mock.calls.some(call => call[0].includes(message))
  },

  hasLoggedError: (message: string) => {
    return (createMockLogger().error as jest.Mock).mock.calls.some(call =>
      call[0].includes(message)
    )
  },

  reset: () => {
    ;(createMockLogger().info as jest.Mock).mockClear()
    ;(createMockLogger().warn as jest.Mock).mockClear()
    ;(createMockLogger().error as jest.Mock).mockClear()
    ;(createMockLogger().debug as jest.Mock).mockClear()
    ;(createMockLogger().trace as jest.Mock).mockClear()
  },
})

// Mock database operations
export const createMockDatabase = () => {
  const mockData: Record<string, any[]> = {}

  return {
    query: jest.fn(async (sql: string, params?: any[]) => {
      // Simulate database response
      return {
        rows: mockData[sql] || [],
        rowCount: mockData[sql]?.length || 0,
        command: sql.split(' ')[0].toUpperCase(),
        executionTime: Math.random() * 100,
      }
    }),

    connect: jest.fn(async () => ({
      query: jest.fn(),
      release: jest.fn(),
    })),

    // Helper methods
    addMockData: (sql: string, data: any[]) => {
      mockData[sql] = data
    },

    reset: () => {
      Object.keys(mockData).forEach(key => delete mockData[key])
    },
  }
}

// Mock file upload objects
export const createMockFile = (
  content: string | Uint8Array,
  filename: string,
  mimeType: string = 'text/plain'
): File => {
  const blob = new Blob([content], { type: mimeType })
  return new File([blob], filename, { type: mimeType })
}

// Mock FormData for testing
export const createMockFormData = (files: Record<string, File>): FormData => {
  const formData = new FormData()
  Object.entries(files).forEach(([key, file]) => {
    formData.append(key, file)
  })
  return formData
}

// Mock NextRequest for API testing
export const createMockNextRequest = (
  url: string,
  options: {
    method?: string
    body?: FormData | string | null
    headers?: Record<string, string>
  } = {}
): NextRequest => {
  return new (global.NextRequest as any)(url, options)
}

// Import NextRequest type for TypeScript support
declare global {
  let NextRequest: any
}

// Re-export for convenience
export type { NextRequest } from 'next/server'

// Test isolation helper
export const createTestIsolation = () => {
  const mocks: Array<() => void> = []

  return {
    addMock: (resetFn: () => void) => {
      mocks.push(resetFn)
    },

    reset: () => {
      mocks.forEach(resetFn => resetFn())
      mocks.length = 0
    },
  }
}

// Safe test data generator
export const generateSafeTestData = {
  email: (index: number = 1) => `test${index}@example.com`,
  phone: (index: number = 1) => `+1-555-${String(index).padStart(4, '0')}`,
  url: (domain: string = 'example') => `https://${domain}.test`,
  businessName: (type: string = 'Tech') => `Test ${type} Company`,
  address: (index: number = 1) => ({
    street: `${index}00 Test Street`,
    city: 'Test City',
    state: 'TS',
    zipCode: String(10000 + index).padStart(5, '0'),
  }),
}
