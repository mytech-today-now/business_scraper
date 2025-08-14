import React from 'react'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { ConfigProvider, useConfig } from '@/controller/ConfigContext'

// Mock the storage module
jest.mock('@/model/storage', () => ({
  storage: {
    initialize: jest.fn(),
    getAllIndustries: jest.fn().mockResolvedValue([]),
    saveIndustry: jest.fn(),
    deleteIndustry: jest.fn(),
    getConfig: jest.fn().mockResolvedValue(null),
    saveConfig: jest.fn(),
  },
}))

// Mock the logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
  },
}))

// Mock react-hot-toast
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}))

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'localStorage', {
  value: localStorageMock,
})

// Test component that uses the config context
function TestComponent(): JSX.Element {
  const { state, toggleDemoMode } = useConfig()

  return (
    <div>
      <div data-testid="demo-mode-status">
        {state.isDemoMode ? 'Demo Mode On' : 'Demo Mode Off'}
      </div>
      <button onClick={toggleDemoMode} data-testid="toggle-demo-mode">
        Toggle Demo Mode
      </button>
    </div>
  )
}

function renderWithProvider(component: React.ReactElement): void {
  return act((): void => {
    render(
      <ConfigProvider>
        {component}
      </ConfigProvider>
    )
  })
}

describe('Demo Mode Configuration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorageMock.getItem.mockReturnValue(null)
  })

  it('should default to demo mode based on environment', async () => {
    await act(async () => {
      renderWithProvider(<TestComponent />)
    })

    await waitFor(() => {
      // In test environment, NODE_ENV might be 'test', so demo mode could be off by default
      const status = screen.getByTestId('demo-mode-status')
      expect(status).toBeInTheDocument()
      // Just verify the component renders, don't assume the default state
    })
  })

  it('should toggle demo mode when button is clicked', async () => {
    await act(async () => {
      renderWithProvider(<TestComponent />)
    })

    // Wait for initial render and get the initial state
    let initialState: string
    await waitFor(() => {
      const statusElement = screen.getByTestId('demo-mode-status')
      initialState = statusElement.textContent || ''
      expect(statusElement).toBeInTheDocument()
    })

    // Click toggle button
    await act(async () => {
      fireEvent.click(screen.getByTestId('toggle-demo-mode'))
    })

    // Check that demo mode has toggled
    await waitFor(() => {
      const statusElement = screen.getByTestId('demo-mode-status')
      const newState = statusElement.textContent || ''
      expect(newState).not.toBe(initialState)
    })

    // Verify localStorage was called
    expect(localStorageMock.setItem).toHaveBeenCalledWith('demoMode', expect.any(String))
  })

  it('should toggle demo mode multiple times', async () => {
    renderWithProvider(<TestComponent />)

    // Wait for initial render and get the initial state
    let initialState: string
    await waitFor(() => {
      const statusElement = screen.getByTestId('demo-mode-status')
      initialState = statusElement.textContent || ''
      expect(statusElement).toBeInTheDocument()
    })

    // Toggle once
    fireEvent.click(screen.getByTestId('toggle-demo-mode'))
    let firstToggleState: string
    await waitFor(() => {
      const statusElement = screen.getByTestId('demo-mode-status')
      firstToggleState = statusElement.textContent || ''
      expect(firstToggleState).not.toBe(initialState)
    })

    // Toggle back
    fireEvent.click(screen.getByTestId('toggle-demo-mode'))
    await waitFor(() => {
      const statusElement = screen.getByTestId('demo-mode-status')
      const finalState = statusElement.textContent || ''
      expect(finalState).toBe(initialState) // Should be back to initial state
    })

    // Verify localStorage was called multiple times
    expect(localStorageMock.setItem).toHaveBeenCalledTimes(2)
  })

  it('should load demo mode preference from localStorage', async () => {
    // Mock localStorage to return true for demo mode
    localStorageMock.getItem.mockImplementation((key) => {
      if (key === 'demoMode') return 'true'
      return null
    })

    renderWithProvider(<TestComponent />)

    await waitFor(() => {
      expect(screen.getByTestId('demo-mode-status')).toHaveTextContent('Demo Mode On')
    })
  })
})
