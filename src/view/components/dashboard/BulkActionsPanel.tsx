/**
 * Bulk Actions Panel
 * Secure bulk operations interface with validation and confirmation
 */

'use client'

import React, { useState } from 'react'
import { Download, Tag, Trash2, Edit, AlertTriangle } from 'lucide-react'
import { SecurityBoundary } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { Card, CardContent } from '../ui/Card'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

export interface BulkActionsPanelProps {
  selectedCount: number
  onBulkAction: (action: string) => Promise<void>
  onClearSelection: () => void
}

/**
 * Bulk Actions Panel with security validation
 */
export function BulkActionsPanel({
  selectedCount,
  onBulkAction,
  onClearSelection,
}: BulkActionsPanelProps): JSX.Element {
  const [isProcessing, setIsProcessing] = useState(false)
  const [showConfirmation, setShowConfirmation] = useState<string | null>(null)

  /**
   * Secure bulk action handler with confirmation
   */
  const handleSecureBulkAction = async (action: string) => {
    try {
      // Validate action
      const allowedActions = ['export', 'tag', 'annotate', 'delete']
      if (!allowedActions.includes(action)) {
        logger.warn('BulkActionsPanel', 'Invalid bulk action attempted', { action })
        toast.error('Invalid action')
        return
      }

      // Validate selection count
      if (selectedCount <= 0) {
        logger.warn('BulkActionsPanel', 'No items selected for bulk action', { action })
        toast.error('No items selected')
        return
      }

      // Show confirmation for destructive actions
      if (action === 'delete') {
        setShowConfirmation(action)
        return
      }

      setIsProcessing(true)
      logger.info('BulkActionsPanel', `Starting bulk action: ${action}`, { selectedCount })

      await onBulkAction(action)
      
      logger.info('BulkActionsPanel', `Bulk action completed: ${action}`, { selectedCount })
      toast.success(`${action} completed for ${selectedCount} items`)
    } catch (error) {
      logger.error('BulkActionsPanel', `Bulk action failed: ${action}`, error)
      toast.error(`${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setIsProcessing(false)
      setShowConfirmation(null)
    }
  }

  /**
   * Confirm destructive action
   */
  const confirmDestructiveAction = async (action: string) => {
    try {
      setIsProcessing(true)
      await onBulkAction(action)
      
      logger.info('BulkActionsPanel', `Destructive action completed: ${action}`, { selectedCount })
      toast.success(`${action} completed for ${selectedCount} items`)
    } catch (error) {
      logger.error('BulkActionsPanel', `Destructive action failed: ${action}`, error)
      toast.error(`${action} failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setIsProcessing(false)
      setShowConfirmation(null)
    }
  }

  /**
   * Secure clear selection handler
   */
  const handleClearSelection = () => {
    try {
      onClearSelection()
      logger.debug('BulkActionsPanel', 'Selection cleared')
    } catch (error) {
      logger.error('BulkActionsPanel', 'Failed to clear selection', error)
      toast.error('Failed to clear selection')
    }
  }

  return (
    <SecurityBoundary componentName="BulkActionsPanel">
      <Card className="p-4 bg-blue-50 border-blue-200">
        <CardContent className="p-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <span className="text-sm font-medium">
                {selectedCount} businesses selected
              </span>
              <Button
                size="sm"
                variant="outline"
                onClick={handleClearSelection}
                disabled={isProcessing}
                aria-label="Clear selection"
              >
                Clear Selection
              </Button>
            </div>

            <div className="flex items-center space-x-2">
              <Button
                size="sm"
                onClick={() => handleSecureBulkAction('export')}
                disabled={isProcessing}
                icon={Download}
                aria-label="Export selected businesses"
              >
                Export Selected
              </Button>
              
              <Button
                size="sm"
                onClick={() => handleSecureBulkAction('tag')}
                disabled={isProcessing}
                icon={Tag}
                aria-label="Add tags to selected businesses"
              >
                Add Tags
              </Button>
              
              <Button
                size="sm"
                onClick={() => handleSecureBulkAction('annotate')}
                disabled={isProcessing}
                icon={Edit}
                aria-label="Annotate selected businesses"
              >
                Annotate
              </Button>
              
              <Button
                size="sm"
                variant="destructive"
                onClick={() => handleSecureBulkAction('delete')}
                disabled={isProcessing}
                icon={Trash2}
                aria-label="Delete selected businesses"
              >
                Delete
              </Button>
            </div>
          </div>

          {/* Confirmation Dialog */}
          {showConfirmation && (
            <SecurityBoundary componentName="ConfirmationDialog">
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                <div className="flex items-start space-x-3">
                  <AlertTriangle className="h-5 w-5 text-red-600 mt-0.5" />
                  <div className="flex-1">
                    <h4 className="text-sm font-medium text-red-800">
                      Confirm Destructive Action
                    </h4>
                    <p className="text-sm text-red-700 mt-1">
                      Are you sure you want to {showConfirmation} {selectedCount} selected businesses? 
                      This action cannot be undone.
                    </p>
                    <div className="flex items-center space-x-2 mt-3">
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => confirmDestructiveAction(showConfirmation)}
                        disabled={isProcessing}
                      >
                        {isProcessing ? 'Processing...' : `Yes, ${showConfirmation}`}
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setShowConfirmation(null)}
                        disabled={isProcessing}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </SecurityBoundary>
          )}

          {/* Processing Indicator */}
          {isProcessing && (
            <div className="mt-4 p-3 bg-blue-100 border border-blue-200 rounded-lg">
              <div className="flex items-center space-x-2">
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-blue-600 border-t-transparent" />
                <span className="text-sm text-blue-800">
                  Processing bulk action for {selectedCount} businesses...
                </span>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </SecurityBoundary>
  )
}
