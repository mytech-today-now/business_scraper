/**
 * Scraping Container
 * Secure scraping control panel with input validation and error handling
 */

'use client'

import React, { useState } from 'react'
import { Play, Pause, Square, RefreshCw, Trash2, StopCircle } from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'
import { useSearchStreaming } from '@/hooks/useSearchStreaming'
import { useErrorHandling } from '@/hooks/useErrorHandling'
import { SecurityBoundary, SecurityUtils } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card'
import { ProgressIndicator } from '../ProgressIndicator'
import { ProcessingWindow } from '../ProcessingWindow'
import { ResultsContainer } from './ResultsContainer'
import { ExportService, ExportFormat, ExportTemplate } from '@/utils/exportService'
import { createCSPSafeStyle } from '@/lib/cspUtils'
import { logger } from '@/utils/logger'
import toast from 'react-hot-toast'

/**
 * Scraping Container with security boundaries
 */
export function ScrapingContainer(): JSX.Element {
  const { state: configState } = useConfig()
  const {
    scrapingState,
    startScraping,
    stopScraping,
    stopEarly,
    clearResults,
    loadPreviousResults,
    removeBusiness,
    updateBusiness,
    canStartScraping,
    hasResults,
    hasErrors,
    clearProcessingSteps,
    shouldShowResults,
  } = useScraperController()

  const [showExportOptions, setShowExportOptions] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [showProcessingWindow, setShowProcessingWindow] = useState(true)
  const [useStreamingSearch, setUseStreamingSearch] = useState(true)

  // Streaming search hook
  const {
    results: streamingResults,
    progress: streamingProgress,
    isStreaming,
    isPaused,
    error: streamingError,
    startStreaming,
    pauseStreaming,
    resumeStreaming,
    stopStreaming,
    clearResults: clearStreamingResults,
  } = useSearchStreaming()

  // Error handling for the scraping panel
  const exportErrorHandling = useErrorHandling({
    component: 'ScrapingContainer-Export',
    maxRetries: 2,
    onError: (error, errorId) => {
      toast.error(`Export failed: ${error.message}`, {
        id: errorId,
        duration: 5000,
      })
    },
  })

  /**
   * Secure export handler with validation
   */
  const handleSecureExport = async (
    format: string,
    selectedIds?: string[],
    template?: ExportTemplate
  ): Promise<void> => {
    try {
      if (!scrapingState.results.length) {
        logger.warn('ScrapingContainer', 'No data to export')
        toast.error('No data available to export')
        return
      }

      // Validate and sanitize business data before export
      const validatedResults = scrapingState.results.map(business => {
        const validation = SecurityUtils.validateBusinessData(business)
        if (!validation.isValid) {
          logger.warn('ScrapingContainer', 'Invalid business data detected', validation.errors)
        }
        return SecurityUtils.sanitizeBusinessData(business)
      })

      setIsExporting(true)
      setShowExportOptions(false)

      const exportService = new ExportService()
      const selectedIndustryNames = configState.selectedIndustries.map(industryId => {
        const industry = configState.industries.find(ind => ind.id === industryId)
        return industry?.name || industryId
      })

      const { blob, filename } = await exportService.exportBusinesses(
        validatedResults,
        format as ExportFormat,
        {
          includeHeaders: true,
          dateFormat: 'YYYY-MM-DD HH:mm:ss',
          context: {
            selectedIndustries: selectedIndustryNames,
            searchLocation: configState.config.zipCode,
            searchRadius: configState.config.searchRadius,
            totalResults: validatedResults.length,
          },
          selectedBusinesses: selectedIds,
          template: template,
        }
      )

      // Create secure download
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      const exportCount = selectedIds ? selectedIds.length : validatedResults.length
      const exportType = selectedIds ? 'selected' : 'all'
      const templateInfo = template ? ` using template "${template.name}"` : ''

      logger.info('ScrapingContainer', `Successfully exported ${exportCount} ${exportType} businesses as ${format}${templateInfo}`)
      toast.success(`Successfully exported ${exportCount} ${exportType} businesses as ${format.toUpperCase()}${templateInfo}`)
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      exportErrorHandling.handleError(err, { format, resultCount: scrapingState.results.length })
    } finally {
      setIsExporting(false)
    }
  }

  /**
   * Secure streaming start handler
   */
  const handleSecureStreamingStart = async () => {
    try {
      if (!canStartScraping) {
        toast.error('Cannot start scraping. Please check configuration.')
        return
      }

      const selectedIndustryNames = configState.selectedIndustries
        .map(industryId => {
          const industry = configState.industries.find(ind => ind.id === industryId)
          return industry?.name || industryId
        })
        .join(', ')

      logger.info('ScrapingContainer', 'Starting streaming search', {
        industries: selectedIndustryNames,
        location: configState.config.zipCode
      })

      await startStreaming(
        selectedIndustryNames || 'business',
        configState.config.zipCode,
        {
          maxResults: 1000,
          enableFallback: true,
        }
      )
    } catch (error) {
      logger.error('ScrapingContainer', 'Failed to start streaming search', error)
      toast.error('Failed to start streaming search. Please try again.')
    }
  }

  return (
    <SecurityBoundary componentName="ScrapingContainer">
      <div className="space-y-6">
        {/* Control Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold">Scraping Control</h2>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              icon={RefreshCw}
              onClick={loadPreviousResults}
              disabled={scrapingState.isScrapingActive}
            >
              Load Previous
            </Button>
            {hasResults && (
              <Button
                variant="outline"
                size="sm"
                icon={Trash2}
                onClick={clearResults}
                disabled={scrapingState.isScrapingActive}
              >
                Clear Results
              </Button>
            )}
          </div>
        </div>

        {/* Search Mode Toggle */}
        <SecurityBoundary componentName="SearchModeToggle">
          <Card>
            <CardHeader>
              <CardTitle>Search Mode</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="searchMode"
                    checked={useStreamingSearch}
                    onChange={() => setUseStreamingSearch(true)}
                    className="rounded"
                  />
                  <span className="text-sm font-medium">Real-time Streaming</span>
                  <span className="text-xs text-muted-foreground">(Recommended)</span>
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="searchMode"
                    checked={!useStreamingSearch}
                    onChange={() => setUseStreamingSearch(false)}
                    className="rounded"
                  />
                  <span className="text-sm font-medium">Traditional Batch</span>
                </label>
              </div>
            </CardContent>
          </Card>
        </SecurityBoundary>

        {/* Scraping Controls */}
        <SecurityBoundary componentName="ScrapingControls">
          <Card>
            <CardHeader>
              <CardTitle>Controls</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-4">
                {useStreamingSearch ? (
                  // Streaming controls
                  <>
                    {!isStreaming ? (
                      <Button
                        icon={Play}
                        onClick={handleSecureStreamingStart}
                        disabled={!canStartScraping}
                      >
                        Start Streaming Search
                      </Button>
                    ) : (
                      <>
                        {!isPaused ? (
                          <Button variant="outline" icon={Pause} onClick={pauseStreaming}>
                            Pause
                          </Button>
                        ) : (
                          <Button
                            icon={Play}
                            onClick={resumeStreaming}
                            className="bg-blue-600 hover:bg-blue-700"
                          >
                            Resume
                          </Button>
                        )}
                        <Button
                          variant="destructive"
                          icon={Square}
                          onClick={stopStreaming}
                          className="animate-pulse"
                        >
                          Stop Streaming
                        </Button>
                      </>
                    )}
                  </>
                ) : (
                  // Traditional scraping controls
                  <>
                    {scrapingState.isScrapingActive ? (
                      <>
                        <Button
                          variant="destructive"
                          icon={Square}
                          onClick={stopScraping}
                          className="animate-pulse"
                        >
                          Stop Scraping
                        </Button>
                        {scrapingState.canStopEarly && (
                          <Button
                            variant="outline"
                            icon={StopCircle}
                            onClick={stopEarly}
                            className="border-orange-500 text-orange-600 hover:bg-orange-50"
                          >
                            Stop Early ({scrapingState.results.length} found)
                          </Button>
                        )}
                      </>
                    ) : (
                      <Button icon={Play} onClick={startScraping} disabled={!canStartScraping}>
                        Start Scraping
                      </Button>
                    )}
                  </>
                )}

                {/* Status Indicator */}
                <div className="flex items-center gap-2 text-sm">
                  {useStreamingSearch ? (
                    <>
                      {isStreaming ? (
                        <>
                          <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                          <span className="text-blue-600 font-medium">
                            {isPaused ? 'Paused' : 'Streaming'}
                          </span>
                        </>
                      ) : streamingProgress.status === 'completed' ? (
                        <>
                          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                          <span className="text-green-600 font-medium">Completed</span>
                        </>
                      ) : streamingError ? (
                        <>
                          <div className="w-2 h-2 bg-red-500 rounded-full"></div>
                          <span className="text-red-600 font-medium">Error</span>
                        </>
                      ) : (
                        <>
                          <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
                          <span className="text-gray-500">Ready</span>
                        </>
                      )}
                    </>
                  ) : (
                    <>
                      {scrapingState.isScrapingActive ? (
                        <>
                          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                          <span className="text-green-600 font-medium">Active</span>
                        </>
                      ) : (
                        <>
                          <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
                          <span className="text-gray-500">Idle</span>
                        </>
                      )}
                    </>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </SecurityBoundary>

        {/* Streaming Progress Indicator */}
        {useStreamingSearch && (isStreaming || streamingResults.length > 0 || streamingError) && (
          <SecurityBoundary componentName="ProgressIndicator">
            <ProgressIndicator
              progress={streamingProgress}
              isStreaming={isStreaming}
              isPaused={isPaused}
              error={streamingError}
              onPause={pauseStreaming}
              onResume={resumeStreaming}
              onStop={stopStreaming}
            />
          </SecurityBoundary>
        )}

        {/* Processing Window */}
        <SecurityBoundary componentName="ProcessingWindow">
          <ProcessingWindow
            isVisible={showProcessingWindow}
            isActive={scrapingState.isScrapingActive}
            currentStep={scrapingState.currentUrl}
            steps={scrapingState.processingSteps}
            onToggleVisibility={() => setShowProcessingWindow(!showProcessingWindow)}
            onClear={clearProcessingSteps}
            progress={scrapingState.progress}
            currentUrl={scrapingState.currentUrl}
          />
        </SecurityBoundary>

        {/* Results Container */}
        {(shouldShowResults || (useStreamingSearch && streamingResults.length > 0)) && (
          <SecurityBoundary componentName="ResultsContainer">
            <ResultsContainer
              businesses={useStreamingSearch ? streamingResults : scrapingState.results}
              onEdit={updateBusiness}
              onDelete={removeBusiness}
              onExport={handleSecureExport}
              isLoading={useStreamingSearch ? isStreaming : scrapingState.isScrapingActive}
              isExporting={isExporting}
              useStreamingSearch={useStreamingSearch}
            />
          </SecurityBoundary>
        )}
      </div>
    </SecurityBoundary>
  )
}
