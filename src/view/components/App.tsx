'use client'

import React, { useState } from 'react'
import Image from 'next/image'
import {
  Play,
  Square,
  Settings,
  Moon,
  Sun,
  FileText,
  Trash2,
  RefreshCw,
  RotateCcw,
  Search,
  Info,
  Brain,
  StopCircle,
} from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { PerformanceProvider } from '@/controller/PerformanceContext'
import { useScraperController } from '@/controller/useScraperController'
import { CategorySelector } from './CategorySelector'
import { ResultsTable } from './ResultsTable'
import { VirtualizedResultsTable } from './VirtualizedResultsTable'
import { ProcessingWindow } from './ProcessingWindow'
import { ApiConfigurationPage } from './ApiConfigurationPage'
import { MobileNavigation } from './MobileNavigation'
import { AIInsightsPanel } from './AIInsightsPanel'
import { MemoryDashboard } from './MemoryDashboard'
import { BusinessIntelligenceDashboard } from './BusinessIntelligenceDashboard'
import { ProgressIndicator } from './ProgressIndicator'
import { StreamingResultsDisplay } from './StreamingResultsDisplay'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { ZipCodeInput } from './ui/ZipCodeInput'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Breadcrumb, useBreadcrumbItems } from './ui/Breadcrumb'
import { ExportService, ExportFormat, ExportTemplate } from '@/utils/exportService'
import { logger } from '@/utils/logger'
import { clsx } from 'clsx'
import { clientScraperService } from '@/model/clientScraperService'
import { ErrorBoundary } from '../../components/ErrorBoundary'
import { useErrorHandling } from '@/hooks/useErrorHandling'
import { useResponsive } from '@/hooks/useResponsive'
import { useSearchStreaming } from '@/hooks/useSearchStreaming'
import ResetDataDialog from './ui/ResetDataDialog'
import { DataResetResult } from '@/utils/dataReset'
import toast from 'react-hot-toast'

/**
 * Configuration panel component
 */
function ConfigurationPanel(): JSX.Element {
  const { state, updateConfig, toggleDarkMode, isConfigValid } = useConfig()
  const { scrapingState } = useScraperController()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Configuration</h2>
        <Button variant="ghost" size="icon" onClick={toggleDarkMode} className="h-9 w-9">
          {state.isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>

      {/* Scraping Active Banner */}
      {scrapingState.isScrapingActive && (
        <Card className="border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-950">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="h-2 w-2 bg-orange-500 rounded-full animate-pulse" />
              <div>
                <h3 className="font-medium text-orange-900 dark:text-orange-100">
                  🔒 Configuration Locked - Scraping in Progress
                </h3>
                <p className="text-sm text-orange-700 dark:text-orange-300 mt-1">
                  Configuration settings are locked while scraping is active. Stop the scraping
                  process to make changes.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Location Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Location Settings</CardTitle>
          {scrapingState.isScrapingActive && (
            <p className="text-sm text-muted-foreground">
              🔒 Configuration is locked while scraping is active
            </p>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ZipCodeInput
              label="ZIP Code"
              placeholder="e.g., 90210 or 123 Main St, Beverly Hills, CA 90210"
              value={state.config.zipCode}
              onChange={zipCode => updateConfig({ zipCode })}
              onValidZipCode={zipCode => {
                logger.info('App', `Valid ZIP code entered: ${zipCode}`)
                toast.success(`ZIP code "${zipCode}" is valid`)
              }}
              onInvalidInput={error => {
                logger.warn('App', `Invalid ZIP code input: ${error}`)
              }}
              helperText="Enter ZIP code or full address - we'll extract the ZIP code"
              disabled={scrapingState.isScrapingActive}
              showExtractedWarning={true}
              debounceMs={300}
            />
            <Input
              label="Search Radius (miles)"
              type="number"
              min="1"
              max="100"
              value={state.config.searchRadius}
              onChange={e => updateConfig({ searchRadius: parseInt(e.target.value) || 25 })}
              helperText="How far to search from ZIP code"
              disabled={scrapingState.isScrapingActive}
            />
          </div>
        </CardContent>
      </Card>

      {/* Scraping Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Scraping Settings</CardTitle>
          {scrapingState.isScrapingActive && (
            <p className="text-sm text-muted-foreground">
              🔒 Settings cannot be changed during active scraping
            </p>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Search Depth"
              type="number"
              min="1"
              max="5"
              value={state.config.searchDepth}
              onChange={e => updateConfig({ searchDepth: parseInt(e.target.value) || 2 })}
              helperText="How deep to crawl each website"
              disabled={scrapingState.isScrapingActive}
            />
            <Input
              label="Pages per Site"
              type="number"
              min="1"
              max="20"
              value={state.config.pagesPerSite}
              onChange={e => updateConfig({ pagesPerSite: parseInt(e.target.value) || 5 })}
              helperText="Maximum pages to scrape per website"
              disabled={scrapingState.isScrapingActive}
            />
          </div>
        </CardContent>
      </Card>

      {/* Search Configuration */}
      <Card className="border-blue-200 bg-blue-50">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Search className="h-5 w-5" />
            <span>Search Configuration</span>
          </CardTitle>
          {scrapingState.isScrapingActive && (
            <p className="text-sm text-muted-foreground">
              🔒 Settings cannot be changed during active scraping
            </p>
          )}
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                DuckDuckGo SERP Pages
              </label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={state.config.duckduckgoSerpPages || 2}
                onChange={e => updateConfig({ duckduckgoSerpPages: parseInt(e.target.value) })}
                aria-label="DuckDuckGo SERP Pages"
                disabled={scrapingState.isScrapingActive}
              >
                <option value={1}>1 page (~30 results)</option>
                <option value={2}>2 pages (~60 results)</option>
                <option value={3}>3 pages (~90 results)</option>
                <option value={4}>4 pages (~120 results)</option>
                <option value={5}>5 pages (~150 results)</option>
              </select>
              <p className="text-xs text-gray-600 mt-1">
                Number of DuckDuckGo search result pages to scrape per query
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Max Results Per Search
              </label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={state.config.maxSearchResults || 1000}
                onChange={e => updateConfig({ maxSearchResults: parseInt(e.target.value) })}
                aria-label="Max Results Per Search"
                disabled={scrapingState.isScrapingActive}
              >
                <option value={50}>50 results</option>
                <option value={100}>100 results</option>
                <option value={500}>500 results</option>
                <option value={1000}>1000 results</option>
                <option value={10000}>Unlimited (10,000+)</option>
              </select>
              <p className="text-xs text-gray-600 mt-1">
                Maximum number of business websites to find per search (higher values gather more
                comprehensive results)
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-blue-200">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                BBB Search Type
              </label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={state.config.bbbAccreditedOnly ? 'accredited' : 'all'}
                onChange={e => updateConfig({ bbbAccreditedOnly: e.target.value === 'accredited' })}
                aria-label="BBB Search Type"
                disabled={scrapingState.isScrapingActive}
              >
                <option value="accredited">BBB Accredited Businesses Only</option>
                <option value="all">All Businesses</option>
              </select>
              <p className="text-xs text-gray-600 mt-1">
                Choose whether to search only BBB accredited businesses or all businesses
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                ZIP Code Radius (miles)
              </label>
              <select
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                value={state.config.zipRadius || 10}
                onChange={e => updateConfig({ zipRadius: parseInt(e.target.value) })}
                aria-label="ZIP Code Radius"
                disabled={scrapingState.isScrapingActive}
              >
                <option value={5}>5 miles</option>
                <option value={10}>10 miles</option>
                <option value={15}>15 miles</option>
                <option value={25}>25 miles</option>
                <option value={50}>50 miles</option>
              </select>
              <p className="text-xs text-gray-600 mt-1">
                Radius around the ZIP code to include businesses
              </p>
            </div>
          </div>
          <div className="mt-4 p-3 bg-blue-100 rounded-md">
            <div className="flex items-start space-x-2">
              <Info className="h-4 w-4 text-blue-600 mt-0.5" />
              <div className="text-sm text-blue-800">
                <p className="font-medium">Comprehensive Search Strategy:</p>
                <ul className="mt-1 space-y-1 text-xs">
                  <li>• Scrapes actual DuckDuckGo search result pages (SERP)</li>
                  <li>
                    • Searches each industry criteria individually (medical, healthcare, clinic,
                    etc.)
                  </li>
                  <li>• Uses BBB as business discovery platform to find real business websites</li>
                  <li>• Validates ZIP code radius and extracts "Visit Website" URLs from BBB</li>
                  <li>• Scrapes actual business websites for contact information</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Industry Categories */}
      <CategorySelector disabled={scrapingState.isScrapingActive} />

      {/* Configuration Status */}
      <div
        className={clsx(
          'p-4 rounded-lg border',
          isConfigValid()
            ? 'bg-green-50 border-green-200 dark:bg-green-950 dark:border-green-800'
            : 'bg-yellow-50 border-yellow-200 dark:bg-yellow-950 dark:border-yellow-800'
        )}
      >
        <div className="flex items-center gap-2">
          <div
            className={clsx(
              'w-2 h-2 rounded-full',
              isConfigValid() ? 'bg-green-500' : 'bg-yellow-500'
            )}
          />
          <span className="text-sm font-medium">
            {isConfigValid() ? 'Configuration Complete' : 'Configuration Incomplete'}
          </span>
        </div>
        {!isConfigValid() && (
          <p className="text-sm text-muted-foreground mt-1">
            Please select at least one industry and enter a ZIP code to continue.
          </p>
        )}
      </div>
    </div>
  )
}

/**
 * Scraping control panel component
 */
function ScrapingPanel(): JSX.Element {
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

  // Virtual scrolling toggle
  const [useVirtualScrolling, setUseVirtualScrolling] = useState(true)

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
    component: 'ScrapingPanel-Export',
    maxRetries: 2,
    onError: (error, errorId) => {
      toast.error(`Export failed: ${error.message}`, {
        id: errorId,
        duration: 5000,
      })
    },
  })

  /**
   * Handle export functionality with improved error handling and context
   */
  const handleExport = async (
    format: string,
    selectedIds?: string[],
    template?: ExportTemplate
  ): Promise<void> => {
    if (!scrapingState.results.length) {
      logger.warn('Export', 'No data to export')
      toast.error('No data available to export')
      return
    }

    setIsExporting(true)
    setShowExportOptions(false)

    try {
      const exportService = new ExportService()

      // Get selected industry names for context
      const selectedIndustryNames = configState.selectedIndustries.map(industryId => {
        const industry = configState.industries.find(ind => ind.id === industryId)
        return industry?.name || industryId
      })

      const { blob, filename } = await exportService.exportBusinesses(
        scrapingState.results,
        format as ExportFormat,
        {
          includeHeaders: true,
          dateFormat: 'YYYY-MM-DD HH:mm:ss',
          context: {
            selectedIndustries: selectedIndustryNames,
            searchLocation: configState.config.zipCode,
            searchRadius: configState.config.searchRadius,
            totalResults: scrapingState.results.length,
          },
          selectedBusinesses: selectedIds,
          template: template,
        }
      )

      // Create download link
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)

      const exportCount = selectedIds ? selectedIds.length : scrapingState.results.length
      const exportType = selectedIds ? 'selected' : 'all'
      const templateInfo = template ? ` using template "${template.name}"` : ''

      logger.info(
        'Export',
        `Successfully exported ${exportCount} ${exportType} businesses as ${format}${templateInfo}`
      )
      toast.success(
        `Successfully exported ${exportCount} ${exportType} businesses as ${format.toUpperCase()}${templateInfo}`
      )
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error))
      exportErrorHandling.handleError(err, { format, resultCount: scrapingState.results.length })
    } finally {
      setIsExporting(false)
    }
  }

  return (
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

      {/* Scraping Controls */}
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
                    onClick={async () => {
                      const selectedIndustryNames = configState.selectedIndustries
                        .map(industryId => {
                          const industry = configState.industries.find(ind => ind.id === industryId)
                          return industry?.name || industryId
                        })
                        .join(', ')

                      await startStreaming(
                        selectedIndustryNames || 'business',
                        configState.config.zipCode,
                        {
                          maxResults: 1000,
                          enableFallback: true,
                        }
                      )
                    }}
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
                ) : scrapingState.currentUrl === 'Stopping scraping...' ? (
                  <Button variant="outline" icon={Square} disabled className="opacity-75">
                    Stopping...
                  </Button>
                ) : (
                  <>
                    <Button icon={Play} onClick={startScraping} disabled={!canStartScraping}>
                      Start Scraping
                    </Button>
                  </>
                )}
              </>
            )}

            {/* Status Indicator */}
            <div className="flex items-center gap-2 text-sm">
              {useStreamingSearch ? (
                // Streaming status
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
                // Traditional scraping status
                <>
                  {scrapingState.isScrapingActive ? (
                    <>
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                      <span className="text-green-600 font-medium">Active</span>
                    </>
                  ) : scrapingState.currentUrl === 'Stopping scraping...' ? (
                    <>
                      <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div>
                      <span className="text-yellow-600 font-medium">Stopping</span>
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

          {/* Progress Display */}
          {(scrapingState.isScrapingActive ||
            scrapingState.currentUrl === 'Stopping scraping...') && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>
                  {scrapingState.currentUrl === 'Stopping scraping...'
                    ? 'Stopping'
                    : 'Real-Time Progress'}
                </span>
                <span>
                  {scrapingState.currentUrl === 'Stopping scraping...'
                    ? 'Finalizing...'
                    : `${scrapingState.progress.percentage}%`}
                </span>
              </div>

              {/* Real-time results counter */}
              {scrapingState.isStreamingEnabled && scrapingState.results.length > 0 && (
                <div className="flex items-center justify-between text-xs text-green-600 dark:text-green-400">
                  <span className="flex items-center gap-1">
                    <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse" />
                    Live Results Streaming
                  </span>
                  <span className="font-medium">
                    {scrapingState.results.length} businesses found
                  </span>
                </div>
              )}
              <div className="w-full bg-secondary rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all duration-300 ${
                    scrapingState.currentUrl === 'Stopping scraping...'
                      ? 'bg-yellow-500 animate-pulse'
                      : 'bg-primary'
                  }`}
                  style={{
                    width:
                      scrapingState.currentUrl === 'Stopping scraping...'
                        ? '100%'
                        : `${scrapingState.progress.percentage}%`,
                  }}
                />
              </div>
              {scrapingState.currentUrl && (
                <p
                  className={`text-xs truncate ${
                    scrapingState.currentUrl === 'Stopping scraping...'
                      ? 'text-yellow-600 font-medium'
                      : 'text-muted-foreground'
                  }`}
                >
                  {scrapingState.currentUrl}
                </p>
              )}
            </div>
          )}

          {/* Completion Summary - shown when scraping is stopped */}
          {!scrapingState.isScrapingActive &&
            scrapingState.currentUrl === '' &&
            scrapingState.results.length > 0 && (
              <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                  <span className="text-green-700 font-medium">Scraping Completed</span>
                </div>
                <div className="text-sm text-green-600">
                  Found {scrapingState.results.length} businesses.
                  {scrapingState.errors.length > 0 && (
                    <span className="ml-1">{scrapingState.errors.length} errors encountered.</span>
                  )}
                </div>
              </div>
            )}

          {/* Statistics */}
          {scrapingState.stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-muted/50 rounded-lg">
              <div className="text-center">
                <div className="text-2xl font-bold text-primary">
                  {scrapingState.stats.totalBusinesses}
                </div>
                <div className="text-xs text-muted-foreground">Businesses Found</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {scrapingState.stats.successfulScrapes}
                </div>
                <div className="text-xs text-muted-foreground">Successful</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">
                  {scrapingState.stats.failedScrapes}
                </div>
                <div className="text-xs text-muted-foreground">Failed</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-600">
                  {scrapingState.stats.totalSites}
                </div>
                <div className="text-xs text-muted-foreground">Sites Scraped</div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Streaming Progress Indicator */}
      {useStreamingSearch && (isStreaming || streamingResults.length > 0 || streamingError) && (
        <ProgressIndicator
          progress={streamingProgress}
          isStreaming={isStreaming}
          isPaused={isPaused}
          error={streamingError}
          onPause={pauseStreaming}
          onResume={resumeStreaming}
          onStop={stopStreaming}
        />
      )}

      {/* Error Display */}
      {hasErrors && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-destructive">
              Errors ({scrapingState.errors.length})
            </CardTitle>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                // Clear errors if there's a method for it
                logger.info('ScrapingPanel', 'User cleared error display')
                toast.success('Error display cleared')
              }}
              className="text-muted-foreground hover:text-foreground"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </CardHeader>
          <CardContent>
            <div className="max-h-40 overflow-y-auto space-y-2">
              {scrapingState.errors.slice(-10).map((error, index) => (
                <div
                  key={index}
                  className="text-sm text-destructive bg-destructive/10 p-3 rounded-lg border border-destructive/20"
                >
                  <div className="flex items-start justify-between gap-2">
                    <span className="flex-1">{error}</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        navigator.clipboard?.writeText(error)
                        toast.success('Error copied to clipboard')
                      }}
                      className="h-6 w-6 p-0 text-destructive/60 hover:text-destructive"
                    >
                      <FileText className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
              ))}
              {scrapingState.errors.length > 10 && (
                <div className="text-xs text-muted-foreground text-center py-2">
                  Showing last 10 errors. Total: {scrapingState.errors.length}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Processing Window */}
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

      {/* Results Table */}
      {(shouldShowResults || (useStreamingSearch && streamingResults.length > 0)) && (
        <div className="space-y-4">
          {/* Table Mode Toggle */}
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold">
              Business Results (
              {useStreamingSearch
                ? streamingResults.length.toLocaleString()
                : scrapingState.results.length.toLocaleString()}
              )
            </h3>
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Table Mode:</span>
              <Button
                variant={useVirtualScrolling ? 'default' : 'outline'}
                size="sm"
                onClick={() => setUseVirtualScrolling(true)}
              >
                Virtual (High Performance)
              </Button>
              <Button
                variant={!useVirtualScrolling ? 'default' : 'outline'}
                size="sm"
                onClick={() => setUseVirtualScrolling(false)}
              >
                Traditional
              </Button>
            </div>
          </div>

          {/* Smart Performance Mode Table Rendering */}
          <PerformanceProvider
            datasetSize={
              useStreamingSearch ? streamingResults.length : scrapingState.results.length
            }
          >
            <ResultsTable
              businesses={useStreamingSearch ? streamingResults : scrapingState.results}
              onEdit={updateBusiness}
              onDelete={removeBusiness}
              onExport={handleExport}
              isLoading={useStreamingSearch ? isStreaming : scrapingState.isScrapingActive}
              isExporting={isExporting}
            />
          </PerformanceProvider>
        </div>
      )}
    </div>
  )
}

/**
 * Breadcrumb Navigation component
 * Provides contextual navigation breadcrumbs
 */
interface BreadcrumbNavigationProps {
  activeTab: 'config' | 'scraping' | 'ai-insights'
  hasResults: boolean
  onNavigate: (path: string) => void
}

function BreadcrumbNavigation({
  activeTab,
  hasResults,
  onNavigate,
}: BreadcrumbNavigationProps): JSX.Element {
  // Generate breadcrumb items based on current state
  const breadcrumbItems = useBreadcrumbItems(
    activeTab === 'ai-insights' ? 'scraping' : activeTab, // Treat AI insights as part of scraping flow
    hasResults
  )

  const handleBreadcrumbClick = (item: any, index: number) => {
    if (item.path && item.clickable !== false) {
      onNavigate(item.path)
    }
  }

  return (
    <Breadcrumb
      items={breadcrumbItems}
      onItemClick={handleBreadcrumbClick}
      showHomeIcon={true}
      maxItems={5}
      className="text-sm"
    />
  )
}

/**
 * Main App component
 * Orchestrates the entire application interface
 */
export function App(): JSX.Element {
  const { state, resetApplicationData, toggleDarkMode } = useConfig()
  const { scrapingState, hasResults } = useScraperController()
  const { isMobile } = useResponsive()
  const [activeTab, setActiveTab] = useState<
    'config' | 'scraping' | 'ai-insights' | 'bi-dashboard'
  >('config')
  const [showApiConfig, setShowApiConfig] = useState(false)
  const [showResetDialog, setShowResetDialog] = useState(false)
  const [isResetting, setIsResetting] = useState(false)

  /**
   * Handle application data reset
   */
  const handleResetData = async (options: {
    includeApiCredentials: boolean
    useAggressiveReset: boolean
  }): Promise<DataResetResult> => {
    setIsResetting(true)
    try {
      const result = await resetApplicationData(options)
      return result
    } catch (error) {
      logger.error('App', 'Failed to reset application data', error)
      toast.error('Failed to reset application data')
      return {
        success: false,
        clearedStores: [],
        clearedLocalStorage: [],
        errors: [error instanceof Error ? error.message : 'Unknown error'],
        fallbackUsed: false,
      }
    } finally {
      setIsResetting(false)
    }
  }

  // Show loading screen while initializing
  if (!state.isInitialized) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Initializing application...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b bg-card sticky top-0 z-40">
        <div className="container mx-auto px-4 py-3 md:py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 md:gap-4">
              <div className="flex items-center gap-2 md:gap-3">
                <Image
                  src="/favicon.ico"
                  alt="Business Scraper Logo"
                  width={isMobile ? 24 : 32}
                  height={isMobile ? 24 : 32}
                  className="object-contain"
                  priority
                  sizes={isMobile ? '24px' : '32px'}
                  quality={90}
                />
                <h1 className="text-lg md:text-2xl font-bold truncate">
                  {isMobile ? 'Scraper' : 'Business Scraper'}
                </h1>
              </div>
              {/* Desktop Navigation - Hidden on mobile */}
              {!isMobile && (
                <div className="flex items-center gap-1 bg-muted rounded-lg p-1">
                  <Button
                    variant={activeTab === 'config' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => {
                      if (scrapingState.isScrapingActive) {
                        toast.error(
                          'Configuration cannot be changed while scraping is active. Please stop scraping first.'
                        )
                        return
                      }
                      setActiveTab('config')
                    }}
                    disabled={scrapingState.isScrapingActive}
                    title={
                      scrapingState.isScrapingActive
                        ? 'Configuration cannot be changed while scraping is active. Please stop scraping first.'
                        : undefined
                    }
                    className={clsx(
                      'min-h-touch',
                      scrapingState.isScrapingActive && 'opacity-50 cursor-not-allowed'
                    )}
                  >
                    Configuration
                    {scrapingState.isScrapingActive && (
                      <span className="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-red-500 rounded-full">
                        🔒
                      </span>
                    )}
                  </Button>
                  <Button
                    variant={activeTab === 'scraping' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('scraping')}
                    disabled={state.industriesInEditMode.length > 0}
                    title={
                      state.industriesInEditMode.length > 0
                        ? `Please save or cancel edits for: ${state.industriesInEditMode
                            .map(id => state.industries.find(industry => industry.id === id)?.name)
                            .filter(Boolean)
                            .join(', ')}`
                        : undefined
                    }
                    className={clsx(
                      'min-h-touch',
                      state.industriesInEditMode.length > 0 && 'opacity-50 cursor-not-allowed'
                    )}
                  >
                    Scraping
                    {state.industriesInEditMode.length > 0 && (
                      <span className="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-yellow-500 rounded-full">
                        !
                      </span>
                    )}
                  </Button>
                  <Button
                    variant={activeTab === 'ai-insights' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('ai-insights')}
                    className="min-h-touch"
                  >
                    AI Insights
                  </Button>
                  <Button
                    variant={activeTab === 'bi-dashboard' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('bi-dashboard')}
                    className="min-h-touch"
                  >
                    <Brain className="h-4 w-4 mr-1" />
                    BI Dashboard
                  </Button>
                  <Button
                    variant={activeTab === 'memory' ? 'default' : 'ghost'}
                    size="sm"
                    onClick={() => setActiveTab('memory')}
                    className="min-h-touch"
                  >
                    Memory
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowResetDialog(true)}
                    disabled={scrapingState.isScrapingActive || isResetting}
                    title={
                      scrapingState.isScrapingActive
                        ? 'Cannot reset data while scraping is active. Please stop scraping first.'
                        : 'Reset all application data to start fresh'
                    }
                    className={clsx(
                      'ml-2 text-red-600 border-red-200 hover:bg-red-50 hover:border-red-300 min-h-touch',
                      (scrapingState.isScrapingActive || isResetting) &&
                        'opacity-50 cursor-not-allowed'
                    )}
                  >
                    <RotateCcw className="h-4 w-4 mr-1" />
                    Reset Data
                  </Button>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 md:gap-4">
              <MemoryDashboard compact className="hidden lg:flex" />

              {/* Mobile Navigation */}
              <MobileNavigation
                activeTab={activeTab as 'config' | 'scraping'}
                onTabChange={tab => {
                  if (tab === 'config') {
                    if (scrapingState.isScrapingActive) {
                      toast.error(
                        'Configuration cannot be changed while scraping is active. Please stop scraping first.'
                      )
                      return
                    }
                    setActiveTab('config')
                  } else if (tab === 'scraping') {
                    if (state.industriesInEditMode.length > 0) {
                      toast.error(
                        `Please save or cancel edits for: ${state.industriesInEditMode
                          .map(id => state.industries.find(industry => industry.id === id)?.name)
                          .filter(Boolean)
                          .join(', ')}`
                      )
                      return
                    }
                    setActiveTab('scraping')
                  }
                }}
                onApiConfigOpen={() => setShowApiConfig(true)}
                isDarkMode={state.isDarkMode}
                onToggleDarkMode={toggleDarkMode}
              />
            </div>
          </div>
        </div>
      </header>

      {/* Breadcrumb Navigation */}
      <div className="border-b bg-muted/30">
        <div className="container mx-auto px-4 py-3">
          <BreadcrumbNavigation
            activeTab={activeTab}
            hasResults={hasResults}
            onNavigate={path => {
              if (path === 'config') {
                if (scrapingState.isScrapingActive) {
                  toast.error(
                    'Configuration cannot be changed while scraping is active. Please stop scraping first.'
                  )
                  return
                }
                setActiveTab('config')
              } else if (path === 'scraping') {
                if (state.industriesInEditMode.length > 0) {
                  toast.error(
                    `Please save or cancel edits for: ${state.industriesInEditMode
                      .map(id => state.industries.find(industry => industry.id === id)?.name)
                      .filter(Boolean)
                      .join(', ')}`
                  )
                  return
                }
                setActiveTab('scraping')
              }
            }}
          />
        </div>
      </div>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-4 md:py-8 pb-safe-bottom">
        <ErrorBoundary level="section" showDetails={process.env.NODE_ENV === 'development'}>
          {activeTab === 'config' ? (
            <ConfigurationPanel />
          ) : activeTab === 'scraping' ? (
            <ScrapingPanel />
          ) : activeTab === 'memory' ? (
            <MemoryDashboard />
          ) : activeTab === 'bi-dashboard' ? (
            <BusinessIntelligenceDashboard
              businesses={scrapingState.results}
              scores={new Map()} // This will be populated with actual scores
            />
          ) : (
            <AIInsightsPanel />
          )}
        </ErrorBoundary>
      </main>

      {/* Footer */}
      <footer className="border-t bg-card mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <p>Business Scraper App v3.10.1 - Navigation Enhancement & Breadcrumb Implementation</p>
            <p>Built with Next.js, React, and TypeScript</p>
          </div>
        </div>
      </footer>

      {/* API Configuration Modal */}
      {showApiConfig && (
        <ApiConfigurationPage
          onClose={() => setShowApiConfig(false)}
          onCredentialsUpdated={async credentials => {
            // Refresh the scraper service with new credentials
            await clientScraperService.refreshCredentials()
            logger.info('App', 'API credentials updated and refreshed', {
              hasGoogleSearch: !!credentials.googleSearchApiKey,
              hasAzureSearch: !!credentials.azureSearchApiKey,
            })
          }}
        />
      )}

      {/* Reset Data Confirmation Dialog */}
      <ResetDataDialog
        isOpen={showResetDialog}
        onClose={() => setShowResetDialog(false)}
        onConfirm={handleResetData}
        isLoading={isResetting}
      />
    </div>
  )
}
