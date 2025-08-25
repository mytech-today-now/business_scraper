/**
 * Search Engine Controls Component
 * 
 * Provides UI controls for managing search engine state including
 * enabling/disabling engines and showing session status.
 */

'use client'

import React, { useState, useEffect } from 'react'
import { 
  Search, 
  ToggleLeft, 
  ToggleRight, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  RefreshCw,
  Info
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { searchEngineManager, SearchEngineConfig } from '@/lib/searchEngineManager'
import { logger } from '@/utils/logger'

interface SearchEngineControlsProps {
  onEngineStateChange?: (engines: SearchEngineConfig[]) => void
}

/**
 * Search Engine Controls Component
 */
export function SearchEngineControls({ onEngineStateChange }: SearchEngineControlsProps): JSX.Element {
  const [engines, setEngines] = useState<SearchEngineConfig[]>([])
  const [hasAvailableEngines, setHasAvailableEngines] = useState(true)

  /**
   * Load engine states
   */
  const loadEngines = () => {
    const allEngines = searchEngineManager.getAllEngines()
    const available = searchEngineManager.hasAvailableEngines()
    
    setEngines(allEngines)
    setHasAvailableEngines(available)
    
    // Notify parent component
    onEngineStateChange?.(allEngines)
    
    logger.info('SearchEngineControls', `Loaded ${allEngines.length} engines, ${available ? 'has' : 'no'} available engines`)
  }

  /**
   * Handle engine toggle
   */
  const handleEngineToggle = (engineId: string, enabled: boolean) => {
    searchEngineManager.setEngineEnabled(engineId, enabled)
    loadEngines()
  }

  /**
   * Reset all engines
   */
  const handleResetAll = () => {
    searchEngineManager.resetAllEngines()
    loadEngines()
  }

  /**
   * Get status icon for engine
   */
  const getEngineStatusIcon = (engine: SearchEngineConfig) => {
    if (!engine.enabled) {
      return <XCircle className="h-4 w-4 text-red-500" />
    }
    if (engine.isDisabledForSession) {
      return <AlertTriangle className="h-4 w-4 text-yellow-500" />
    }
    return <CheckCircle className="h-4 w-4 text-green-500" />
  }

  /**
   * Get status text for engine
   */
  const getEngineStatusText = (engine: SearchEngineConfig) => {
    if (!engine.enabled) {
      return 'Disabled'
    }
    if (engine.isDisabledForSession) {
      return `Session Disabled (${engine.duplicateCount} duplicates)`
    }
    return 'Active'
  }

  /**
   * Get status color class for engine
   */
  const getEngineStatusColor = (engine: SearchEngineConfig) => {
    if (!engine.enabled) {
      return 'text-red-600'
    }
    if (engine.isDisabledForSession) {
      return 'text-yellow-600'
    }
    return 'text-green-600'
  }

  // Load engines on mount
  useEffect(() => {
    loadEngines()
  }, [])

  return (
    <Card className={`${!hasAvailableEngines ? 'border-red-200 bg-red-50' : 'border-blue-200 bg-blue-50'}`}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Search className="h-5 w-5" />
            <span>Search Engine Management</span>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleResetAll}
            className="text-xs"
          >
            <RefreshCw className="h-3 w-3 mr-1" />
            Reset All
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Warning if no engines available */}
        {!hasAvailableEngines && (
          <div className="mb-4 p-3 bg-red-100 border border-red-200 rounded-md">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-red-600" />
              <span className="text-sm font-medium text-red-800">
                Warning: No search engines are available
              </span>
            </div>
            <p className="text-xs text-red-700 mt-1">
              The application will not function properly without at least one enabled search engine.
              Please enable at least one engine below.
            </p>
          </div>
        )}

        {/* Engine Controls */}
        <div className="space-y-3">
          {engines.map((engine) => (
            <div
              key={engine.id}
              className="flex items-center justify-between p-3 border rounded-md bg-white"
            >
              <div className="flex items-center space-x-3">
                {getEngineStatusIcon(engine)}
                <div>
                  <h4 className="text-sm font-medium text-gray-900">
                    {engine.name}
                  </h4>
                  <p className={`text-xs ${getEngineStatusColor(engine)}`}>
                    {getEngineStatusText(engine)}
                  </p>
                </div>
              </div>

              <div className="flex items-center space-x-2">
                {/* Session info */}
                {engine.isDisabledForSession && (
                  <div className="text-xs text-gray-500 mr-2">
                    <Info className="h-3 w-3 inline mr-1" />
                    Session disabled
                  </div>
                )}

                {/* Toggle switch */}
                <button
                  onClick={() => handleEngineToggle(engine.id, !engine.enabled)}
                  disabled={engine.isDisabledForSession}
                  className={`p-1 rounded transition-colors ${
                    engine.isDisabledForSession 
                      ? 'opacity-50 cursor-not-allowed' 
                      : 'hover:bg-gray-100'
                  }`}
                  title={
                    engine.isDisabledForSession 
                      ? 'Cannot enable - disabled for current session due to duplicate results'
                      : `${engine.enabled ? 'Disable' : 'Enable'} ${engine.name}`
                  }
                >
                  {engine.enabled ? (
                    <ToggleRight className="h-5 w-5 text-green-600" />
                  ) : (
                    <ToggleLeft className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>
          ))}
        </div>

        {/* Help text */}
        <div className="mt-4 p-3 bg-gray-50 rounded-md">
          <h5 className="text-xs font-medium text-gray-700 mb-1">
            How Search Engine Management Works:
          </h5>
          <ul className="text-xs text-gray-600 space-y-1">
            <li>• Engines are automatically disabled if they return duplicate results twice</li>
            <li>• Session-disabled engines are re-enabled when a new scraping session starts</li>
            <li>• Manually disabled engines remain disabled until you re-enable them</li>
            <li>• At least one engine must be enabled for the application to function</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  )
}

export default SearchEngineControls
