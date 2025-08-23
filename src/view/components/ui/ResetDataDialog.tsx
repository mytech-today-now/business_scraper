/**
 * Reset Data Confirmation Dialog
 * 
 * Provides a confirmation dialog for resetting all application data
 * with options and data statistics display.
 */

import React, { useState, useEffect } from 'react'
import { AlertTriangle, Database, Trash2, RefreshCw } from 'lucide-react'
import { Button } from './Button'
import { getApplicationDataStats, DataResetResult } from '@/utils/dataReset'

export interface ResetDataDialogProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: (options: { includeApiCredentials: boolean; useAggressiveReset: boolean }) => Promise<DataResetResult>
  isLoading?: boolean
}

interface DataStats {
  businesses: number
  configs: number
  industries: number
  sessions: number
  domainBlacklistEntries: number
  localStorageItems: number
}

/**
 * Reset Data Confirmation Dialog Component
 */
export const ResetDataDialog: React.FC<ResetDataDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  isLoading = false
}) => {
  const [stats, setStats] = useState<DataStats | null>(null)
  const [includeApiCredentials, setIncludeApiCredentials] = useState(false)
  const [useAggressiveReset, setUseAggressiveReset] = useState(false)
  const [isConfirming, setIsConfirming] = useState(false)

  // Load data statistics when dialog opens
  useEffect(() => {
    if (isOpen) {
      loadDataStats()
    }
  }, [isOpen])

  const loadDataStats = async () => {
    try {
      const dataStats = await getApplicationDataStats()
      setStats(dataStats)
    } catch (error) {
      console.error('Failed to load data statistics:', error)
      setStats(null)
    }
  }

  const handleConfirm = async () => {
    setIsConfirming(true)
    try {
      await onConfirm({ includeApiCredentials, useAggressiveReset })
      onClose()
    } catch (error) {
      console.error('Reset failed:', error)
    } finally {
      setIsConfirming(false)
    }
  }

  const handleClose = () => {
    if (!isConfirming && !isLoading) {
      onClose()
    }
  }

  if (!isOpen) return null

  const totalItems = stats ? 
    stats.businesses + stats.configs + stats.industries + stats.sessions + stats.domainBlacklistEntries + stats.localStorageItems : 0

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full mx-4">
        {/* Header */}
        <div className="flex items-center space-x-3 p-6 border-b">
          <div className="flex-shrink-0">
            <AlertTriangle className="h-6 w-6 text-red-600" />
          </div>
          <div>
            <h3 className="text-lg font-medium text-gray-900">
              Reset Application Data
            </h3>
            <p className="text-sm text-gray-500">
              This action cannot be undone
            </p>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {/* Warning */}
          <div className="bg-red-50 border border-red-200 rounded-md p-4">
            <div className="flex">
              <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
              <div className="ml-3">
                <h4 className="text-sm font-medium text-red-800">
                  Warning: Complete Data Reset
                </h4>
                <p className="text-sm text-red-700 mt-1">
                  This will permanently delete all your scraped business data, configurations, 
                  custom industries, and application settings. This action cannot be undone.
                </p>
              </div>
            </div>
          </div>

          {/* Data Statistics */}
          {stats && (
            <div className="bg-gray-50 border border-gray-200 rounded-md p-4">
              <div className="flex items-center space-x-2 mb-3">
                <Database className="h-4 w-4 text-gray-600" />
                <h4 className="text-sm font-medium text-gray-900">
                  Data to be deleted ({totalItems} items)
                </h4>
              </div>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Businesses:</span>
                  <span className="font-medium">{stats.businesses}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Configurations:</span>
                  <span className="font-medium">{stats.configs}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Industries:</span>
                  <span className="font-medium">{stats.industries}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Sessions:</span>
                  <span className="font-medium">{stats.sessions}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Blacklist entries:</span>
                  <span className="font-medium">{stats.domainBlacklistEntries}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Settings:</span>
                  <span className="font-medium">{stats.localStorageItems}</span>
                </div>
              </div>
            </div>
          )}

          {/* Options */}
          <div className="space-y-3">
            <h4 className="text-sm font-medium text-gray-900">Reset Options</h4>
            
            <label className="flex items-start space-x-3">
              <input
                type="checkbox"
                checked={includeApiCredentials}
                onChange={(e) => setIncludeApiCredentials(e.target.checked)}
                className="mt-1 h-4 w-4 text-red-600 border-gray-300 rounded focus:ring-red-500"
                disabled={isConfirming || isLoading}
              />
              <div>
                <span className="text-sm font-medium text-gray-900">
                  Include API Credentials
                </span>
                <p className="text-xs text-gray-500">
                  Also clear saved API keys and authentication data
                </p>
              </div>
            </label>

            <label className="flex items-start space-x-3">
              <input
                type="checkbox"
                checked={useAggressiveReset}
                onChange={(e) => setUseAggressiveReset(e.target.checked)}
                className="mt-1 h-4 w-4 text-red-600 border-gray-300 rounded focus:ring-red-500"
                disabled={isConfirming || isLoading}
              />
              <div>
                <span className="text-sm font-medium text-gray-900">
                  Aggressive Reset
                </span>
                <p className="text-xs text-gray-500">
                  Delete and recreate the entire database (use if having issues)
                </p>
              </div>
            </label>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end space-x-3 p-6 border-t bg-gray-50">
          <Button
            variant="outline"
            onClick={handleClose}
            disabled={isConfirming || isLoading}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={handleConfirm}
            disabled={isConfirming || isLoading}
            icon={isConfirming ? RefreshCw : Trash2}
            className={isConfirming ? 'animate-spin' : ''}
          >
            {isConfirming ? 'Resetting...' : 'Reset All Data'}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default ResetDataDialog
