'use client'

import React from 'react'
import { AppShell } from './containers/AppShell'
import { SecurityBoundary } from './security/SecurityBoundary'
import { logger } from '@/utils/logger'

/**
 * Main App component - now using secure architecture
 * Orchestrates the entire application interface with security boundaries
 */
export function App(): JSX.Element {
  logger.info('App', 'Initializing secure application architecture')

  return (
    <SecurityBoundary componentName="App">
      <AppShell />
    </SecurityBoundary>
  )
}
