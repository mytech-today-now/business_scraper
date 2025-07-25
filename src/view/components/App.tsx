'use client'

import React, { useState } from 'react'
import { 
  Play, 
  Square, 
  Settings, 
  Moon, 
  Sun, 
  FileText,
  Download,
  Trash2,
  RefreshCw
} from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'
import { CategorySelector } from './CategorySelector'
import { ResultsTable } from './ResultsTable'
import { ProcessingWindow } from './ProcessingWindow'
import { ApiConfigurationPage } from './ApiConfigurationPage'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { ExportService, ExportFormat } from '@/utils/exportService'
import { logger } from '@/utils/logger'
import { clsx } from 'clsx'
import { clientScraperService } from '@/model/clientScraperService'

/**
 * Configuration panel component
 */
function ConfigurationPanel() {
  const { state, updateConfig, toggleDarkMode, toggleDemoMode, isConfigValid } = useConfig()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Configuration</h2>
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleDarkMode}
          className="h-9 w-9"
        >
          {state.isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </Button>
      </div>



      {/* Location Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Location Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="ZIP Code"
              placeholder="e.g., 90210"
              value={state.config.zipCode}
              onChange={(e) => updateConfig({ zipCode: e.target.value })}
              helperText="Center point for business search"
            />
            <Input
              label="Search Radius (miles)"
              type="number"
              min="1"
              max="100"
              value={state.config.searchRadius}
              onChange={(e) => updateConfig({ searchRadius: parseInt(e.target.value) || 25 })}
              helperText="How far to search from ZIP code"
            />
          </div>
        </CardContent>
      </Card>

      {/* Industry Categories */}
      <CategorySelector />

      {/* Scraping Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Scraping Settings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Input
              label="Search Depth"
              type="number"
              min="1"
              max="5"
              value={state.config.searchDepth}
              onChange={(e) => updateConfig({ searchDepth: parseInt(e.target.value) || 2 })}
              helperText="How deep to crawl each website"
            />
            <Input
              label="Pages per Site"
              type="number"
              min="1"
              max="20"
              value={state.config.pagesPerSite}
              onChange={(e) => updateConfig({ pagesPerSite: parseInt(e.target.value) || 5 })}
              helperText="Maximum pages to scrape per website"
            />
          </div>
        </CardContent>
      </Card>

      {/* Configuration Status */}
      <div className={clsx(
        'p-4 rounded-lg border',
        isConfigValid() 
          ? 'bg-green-50 border-green-200 dark:bg-green-950 dark:border-green-800'
          : 'bg-yellow-50 border-yellow-200 dark:bg-yellow-950 dark:border-yellow-800'
      )}>
        <div className="flex items-center gap-2">
          <div className={clsx(
            'w-2 h-2 rounded-full',
            isConfigValid() ? 'bg-green-500' : 'bg-yellow-500'
          )} />
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
function ScrapingPanel() {
  const { state: configState } = useConfig()
  const {
    scrapingState,
    startScraping,
    stopScraping,
    clearResults,
    loadPreviousResults,
    removeBusiness,
    updateBusiness,
    canStartScraping,
    hasResults,
    hasErrors,
    clearProcessingSteps
  } = useScraperController()

  const [showExportOptions, setShowExportOptions] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [showProcessingWindow, setShowProcessingWindow] = useState(true)

  /**
   * Handle export functionality
   */
  const handleExport = async (format: string) => {
    if (!scrapingState.results.length) {
      logger.warn('Export', 'No data to export')
      return
    }

    setIsExporting(true)
    setShowExportOptions(false)

    try {
      const exportService = new ExportService()
      const { blob, filename } = await exportService.exportBusinesses(
        scrapingState.results,
        format as ExportFormat,
        {
          includeHeaders: true,
          dateFormat: 'YYYY-MM-DD HH:mm:ss'
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

      logger.info('Export', `Successfully exported ${scrapingState.results.length} businesses as ${format}`)
    } catch (error) {
      logger.error('Export', `Failed to export data as ${format}`, error)
      // You could show a toast notification here
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

      {/* Scraping Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Controls</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            {scrapingState.isScrapingActive ? (
              <Button
                variant="destructive"
                icon={Square}
                onClick={stopScraping}
              >
                Stop Scraping
              </Button>
            ) : (
              <>
                <Button
                  icon={Play}
                  onClick={startScraping}
                  disabled={!canStartScraping}
                >
                  Start Scraping
                </Button>
              </>
            )}
          </div>

          {/* Progress Display */}
          {scrapingState.isScrapingActive && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Progress</span>
                <span>{scrapingState.progress.percentage}%</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div
                  className="bg-primary h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scrapingState.progress.percentage}%` }}
                />
              </div>
              {scrapingState.currentUrl && (
                <p className="text-xs text-muted-foreground truncate">
                  {scrapingState.currentUrl}
                </p>
              )}
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

      {/* Error Display */}
      {hasErrors && (
        <Card>
          <CardHeader>
            <CardTitle className="text-destructive">Errors ({scrapingState.errors.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="max-h-40 overflow-y-auto space-y-2">
              {scrapingState.errors.slice(-10).map((error, index) => (
                <div key={index} className="text-sm text-destructive bg-destructive/10 p-2 rounded">
                  {error}
                </div>
              ))}
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
        isDemoMode={configState.isDemoMode}
        onToggleVisibility={() => setShowProcessingWindow(!showProcessingWindow)}
        onClear={clearProcessingSteps}
        progress={scrapingState.progress}
        currentUrl={scrapingState.currentUrl}
      />

      {/* Results Table */}
      {hasResults && (
        <ResultsTable
          businesses={scrapingState.results}
          onEdit={updateBusiness}
          onDelete={removeBusiness}
          onExport={handleExport}
          isLoading={scrapingState.isScrapingActive}
          isExporting={isExporting}
        />
      )}
    </div>
  )
}

/**
 * Main App component
 * Orchestrates the entire application interface
 */
export function App() {
  const { state, toggleDemoMode } = useConfig()
  const [activeTab, setActiveTab] = useState<'config' | 'scraping'>('config')
  const [showApiConfig, setShowApiConfig] = useState(false)

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
      <header className="border-b bg-card">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3">
                <img
                  src="/favicon.ico"
                  alt="Business Scraper Logo"
                  className="h-8 w-8 object-contain"
                />
                <h1 className="text-2xl font-bold">Business Scraper</h1>
              </div>
              <div className="flex items-center gap-1 bg-muted rounded-lg p-1">
                <Button
                  variant={activeTab === 'config' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('config')}
                >
                  Configuration
                </Button>
                <Button
                  variant={activeTab === 'scraping' ? 'default' : 'ghost'}
                  size="sm"
                  onClick={() => setActiveTab('scraping')}
                >
                  Scraping
                </Button>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="icon">
                <FileText className="h-4 w-4" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setShowApiConfig(true)}
                title="API Configuration"
              >
                <Settings className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {activeTab === 'config' ? <ConfigurationPanel /> : <ScrapingPanel />}
      </main>

      {/* Footer */}
      <footer className="border-t bg-card mt-16">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <p>Business Scraper App v1.0.0</p>
            <p>Built with Next.js, React, and TypeScript</p>
          </div>
        </div>
      </footer>

      {/* API Configuration Modal */}
      {showApiConfig && (
        <ApiConfigurationPage
          onClose={() => setShowApiConfig(false)}
          onCredentialsUpdated={async (credentials) => {
            // Refresh the scraper service with new credentials
            await clientScraperService.refreshCredentials()
            logger.info('App', 'API credentials updated and refreshed', {
              hasGoogleSearch: !!credentials.googleSearchApiKey,
              hasAzureSearch: !!credentials.azureSearchApiKey
            })
          }}
          isDemoMode={state.isDemoMode}
          onToggleDemoMode={toggleDemoMode}
        />
      )}
    </div>
  )
}
