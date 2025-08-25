/**
 * Search Engine Controls Component Tests
 * 
 * Tests for the search engine management UI component
 */

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '@testing-library/jest-dom'
import { SearchEngineControls } from '@/view/components/SearchEngineControls'
import { searchEngineManager } from '@/lib/searchEngineManager'

// Mock the search engine manager
jest.mock('@/lib/searchEngineManager', () => ({
  searchEngineManager: {
    getAllEngines: jest.fn(),
    hasAvailableEngines: jest.fn(),
    setEngineEnabled: jest.fn(),
    resetAllEngines: jest.fn()
  }
}))

// Mock toast
jest.mock('react-hot-toast', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn()
  }
}))

// Mock logger
jest.mock('@/utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
  }
}))

const mockSearchEngineManager = searchEngineManager as jest.Mocked<typeof searchEngineManager>

describe('SearchEngineControls', () => {
  const mockEngines = [
    {
      id: 'google',
      name: 'Google Search',
      enabled: true,
      isDisabledForSession: false,
      duplicateCount: 0,
      lastResults: [],
      sessionId: null
    },
    {
      id: 'azure',
      name: 'Azure AI Search',
      enabled: true,
      isDisabledForSession: false,
      duplicateCount: 0,
      lastResults: [],
      sessionId: null
    },
    {
      id: 'duckduckgo',
      name: 'DuckDuckGo',
      enabled: false,
      isDisabledForSession: false,
      duplicateCount: 0,
      lastResults: [],
      sessionId: null
    }
  ]

  beforeEach(() => {
    jest.clearAllMocks()
    mockSearchEngineManager.getAllEngines.mockReturnValue(mockEngines)
    mockSearchEngineManager.hasAvailableEngines.mockReturnValue(true)
  })

  test('should render search engine controls', () => {
    render(<SearchEngineControls />)
    
    expect(screen.getByText('Search Engine Management')).toBeInTheDocument()
    expect(screen.getByText('Google Search')).toBeInTheDocument()
    expect(screen.getByText('Azure AI Search')).toBeInTheDocument()
    expect(screen.getByText('DuckDuckGo')).toBeInTheDocument()
  })

  test('should show warning when no engines are available', () => {
    mockSearchEngineManager.hasAvailableEngines.mockReturnValue(false)
    
    render(<SearchEngineControls />)
    
    expect(screen.getByText('Warning: No search engines are available')).toBeInTheDocument()
    expect(screen.getByText(/The application will not function properly/)).toBeInTheDocument()
  })

  test('should display correct status for each engine', () => {
    const enginesWithVariedStatus = [
      { ...mockEngines[0], enabled: true, isDisabledForSession: false },
      { ...mockEngines[1], enabled: false, isDisabledForSession: false },
      { ...mockEngines[2], enabled: true, isDisabledForSession: true, duplicateCount: 2 }
    ]
    
    mockSearchEngineManager.getAllEngines.mockReturnValue(enginesWithVariedStatus)
    
    render(<SearchEngineControls />)
    
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    expect(screen.getByText('Session Disabled (2 duplicates)')).toBeInTheDocument()
  })

  test('should handle engine toggle', async () => {
    render(<SearchEngineControls />)
    
    // Find the toggle button for DuckDuckGo (which is disabled)
    const toggleButtons = screen.getAllByRole('button')
    const duckduckgoToggle = toggleButtons.find(button => 
      button.getAttribute('title')?.includes('Enable DuckDuckGo')
    )
    
    expect(duckduckgoToggle).toBeInTheDocument()
    
    if (duckduckgoToggle) {
      fireEvent.click(duckduckgoToggle)
      
      await waitFor(() => {
        expect(mockSearchEngineManager.setEngineEnabled).toHaveBeenCalledWith('duckduckgo', true)
      })
    }
  })

  test('should handle reset all engines', async () => {
    render(<SearchEngineControls />)
    
    const resetButton = screen.getByText('Reset All')
    fireEvent.click(resetButton)
    
    await waitFor(() => {
      expect(mockSearchEngineManager.resetAllEngines).toHaveBeenCalled()
    })
  })

  test('should disable toggle for session-disabled engines', () => {
    const enginesWithSessionDisabled = [
      { ...mockEngines[0], enabled: true, isDisabledForSession: true, duplicateCount: 2 }
    ]
    
    mockSearchEngineManager.getAllEngines.mockReturnValue(enginesWithSessionDisabled)
    
    render(<SearchEngineControls />)
    
    const toggleButtons = screen.getAllByRole('button')
    const sessionDisabledToggle = toggleButtons.find(button => 
      button.getAttribute('title')?.includes('Cannot enable - disabled for current session')
    )
    
    expect(sessionDisabledToggle).toBeInTheDocument()
    expect(sessionDisabledToggle).toBeDisabled()
  })

  test('should call onEngineStateChange callback', () => {
    const mockCallback = jest.fn()
    
    render(<SearchEngineControls onEngineStateChange={mockCallback} />)
    
    expect(mockCallback).toHaveBeenCalledWith(mockEngines)
  })

  test('should show help text', () => {
    render(<SearchEngineControls />)
    
    expect(screen.getByText('How Search Engine Management Works:')).toBeInTheDocument()
    expect(screen.getByText(/Engines are automatically disabled if they return duplicate results twice/)).toBeInTheDocument()
    expect(screen.getByText(/Session-disabled engines are re-enabled when a new scraping session starts/)).toBeInTheDocument()
  })

  test('should apply correct styling based on engine availability', () => {
    // Test with available engines
    render(<SearchEngineControls />)
    let card = screen.getByText('Search Engine Management').closest('.border-blue-200')
    expect(card).toBeInTheDocument()

    // Test with no available engines
    mockSearchEngineManager.hasAvailableEngines.mockReturnValue(false)
    render(<SearchEngineControls />)
    card = screen.getByText('Search Engine Management').closest('.border-red-200')
    expect(card).toBeInTheDocument()
  })
})
