/**
 * @jest-environment jsdom
 */

import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { ProgressIndicator } from '../ProgressIndicator'
import { StreamingProgress } from '@/hooks/useSearchStreaming'

describe('ProgressIndicator', () => {
  const mockOnPause = jest.fn()
  const mockOnResume = jest.fn()
  const mockOnStop = jest.fn()

  const defaultProgress: StreamingProgress = {
    totalFound: 1000,
    processed: 250,
    currentBatch: 5,
    estimatedTimeRemaining: 120,
    status: 'streaming',
    connectionStatus: 'connected',
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders streaming status correctly', () => {
    render(
      <ProgressIndicator
        progress={defaultProgress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Streaming results in real-time')).toBeInTheDocument()
    expect(screen.getByText('250')).toBeInTheDocument()
    expect(screen.getByText('1,000')).toBeInTheDocument()
    expect(screen.getByText('2m 0s')).toBeInTheDocument()
  })

  it('shows pause button when streaming', () => {
    render(
      <ProgressIndicator
        progress={defaultProgress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    const pauseButton = screen.getByLabelText('Pause streaming')
    expect(pauseButton).toBeInTheDocument()

    fireEvent.click(pauseButton)
    expect(mockOnPause).toHaveBeenCalledTimes(1)
  })

  it('shows resume button when paused', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, status: 'paused' }}
        isStreaming={false}
        isPaused={true}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Stream paused')).toBeInTheDocument()

    const resumeButton = screen.getByLabelText('Resume streaming')
    expect(resumeButton).toBeInTheDocument()

    fireEvent.click(resumeButton)
    expect(mockOnResume).toHaveBeenCalledTimes(1)
  })

  it('shows stop button when streaming or paused', () => {
    render(
      <ProgressIndicator
        progress={defaultProgress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    const stopButton = screen.getByLabelText('Stop streaming')
    expect(stopButton).toBeInTheDocument()

    fireEvent.click(stopButton)
    expect(mockOnStop).toHaveBeenCalledTimes(1)
  })

  it('displays connection status correctly', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, connectionStatus: 'connected' }}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    // Connected status should show green wifi icon
    const wifiIcon = document.querySelector('.text-green-500')
    expect(wifiIcon).toBeInTheDocument()
  })

  it('displays reconnecting status', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, connectionStatus: 'reconnecting' }}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    // Reconnecting should show spinning icon
    const spinningIcon = document.querySelector('.animate-spin')
    expect(spinningIcon).toBeInTheDocument()
  })

  it('displays error message when error occurs', () => {
    const errorMessage = 'Connection failed'

    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, status: 'error' }}
        isStreaming={false}
        isPaused={false}
        error={errorMessage}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Search Error')).toBeInTheDocument()
    expect(screen.getByText(errorMessage)).toBeInTheDocument()
  })

  it('displays fallback notice', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, status: 'fallback' }}
        isStreaming={false}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Fallback Mode')).toBeInTheDocument()
    expect(
      screen.getByText('Streaming connection failed. Using standard search method.')
    ).toBeInTheDocument()
  })

  it('calculates progress percentage correctly', () => {
    const progress = {
      ...defaultProgress,
      totalFound: 400,
      processed: 100,
    }

    render(
      <ProgressIndicator
        progress={progress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('25%')).toBeInTheDocument()
  })

  it('formats time correctly', () => {
    const progress = {
      ...defaultProgress,
      estimatedTimeRemaining: 75, // 1 minute 15 seconds
    }

    render(
      <ProgressIndicator
        progress={progress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('1m 15s')).toBeInTheDocument()
  })

  it('shows ready state when idle', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, status: 'idle' }}
        isStreaming={false}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Ready to search')).toBeInTheDocument()
  })

  it('shows completed state', () => {
    render(
      <ProgressIndicator
        progress={{ ...defaultProgress, status: 'completed' }}
        isStreaming={false}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getByText('Search completed')).toBeInTheDocument()
  })

  it('provides accessibility announcements', () => {
    render(
      <ProgressIndicator
        progress={defaultProgress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    // Check for aria-live regions
    const liveRegions = document.querySelectorAll('[aria-live="polite"]')
    expect(liveRegions.length).toBeGreaterThan(0)
  })

  it('handles zero values gracefully', () => {
    const progress = {
      ...defaultProgress,
      totalFound: 0,
      processed: 0,
      estimatedTimeRemaining: 0,
    }

    render(
      <ProgressIndicator
        progress={progress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
      />
    )

    expect(screen.getAllByText('—')).toHaveLength(2) // Should show dash for zero values (Total Expected and Time Remaining)
  })

  it('applies custom className', () => {
    const { container } = render(
      <ProgressIndicator
        progress={defaultProgress}
        isStreaming={true}
        isPaused={false}
        error={null}
        onPause={mockOnPause}
        onResume={mockOnResume}
        onStop={mockOnStop}
        className="custom-class"
      />
    )

    expect(container.firstChild).toHaveClass('custom-class')
  })
})
