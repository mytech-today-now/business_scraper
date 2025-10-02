/**
 * Configuration Container
 * Secure configuration panel with input validation and sanitization
 */

'use client'

import React from 'react'
import { Moon, Sun, Info } from 'lucide-react'
import { useConfig } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'
import { SecurityBoundary, useSecureInput } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { Input } from '../ui/Input'
import { ZipCodeInput } from '../ui/ZipCodeInput'
import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card'
import { CategorySelector } from '../CategorySelector'
import { showDeduplicatedSuccessToast } from '@/utils/toastDeduplication'
import { logger } from '@/utils/logger'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'

/**
 * Configuration Container with security boundaries
 */
export function ConfigurationContainer(): JSX.Element {
  const { state, updateConfig, toggleDarkMode, isConfigValid } = useConfig()
  const { scrapingState } = useScraperController()

  /**
   * Secure configuration update handler
   */
  const handleSecureConfigUpdate = (updates: any) => {
    try {
      // Validate that scraping is not active
      if (scrapingState.isScrapingActive) {
        toast.error('Configuration cannot be changed while scraping is active')
        logger.warn('ConfigurationContainer', 'Blocked config update during scraping', updates)
        return
      }

      // Log configuration change
      logger.info('ConfigurationContainer', 'Configuration updated', updates)
      updateConfig(updates)
    } catch (error) {
      logger.error('ConfigurationContainer', 'Configuration update failed', error)
      toast.error('Configuration update failed. Please try again.')
    }
  }

  /**
   * Secure ZIP code validation handler
   */
  const handleZipCodeValidation = (zipCode: string) => {
    try {
      logger.debug('ConfigurationContainer', `Valid ZIP code entered: ${zipCode}`)
      showDeduplicatedSuccessToast(
        (message) => toast.success(message),
        `ZIP code "${zipCode}" is valid`
      )
    } catch (error) {
      logger.error('ConfigurationContainer', 'ZIP code validation failed', error)
    }
  }

  /**
   * Secure input error handler
   */
  const handleInputError = (error: string) => {
    logger.debug('ConfigurationContainer', `Invalid input: ${error}`)
  }

  return (
    <SecurityBoundary componentName="ConfigurationContainer">
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
        <SecurityBoundary componentName="LocationSettings">
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
                  onChange={zipCode => handleSecureConfigUpdate({ zipCode })}
                  onValidZipCode={handleZipCodeValidation}
                  onInvalidInput={handleInputError}
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
                  onChange={e => handleSecureConfigUpdate({ 
                    searchRadius: parseInt(e.target.value) || 25 
                  })}
                  helperText="How far to search from ZIP code"
                  disabled={scrapingState.isScrapingActive}
                />
              </div>
            </CardContent>
          </Card>
        </SecurityBoundary>

        {/* Scraping Settings */}
        <SecurityBoundary componentName="ScrapingSettings">
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
                  onChange={e => handleSecureConfigUpdate({ 
                    searchDepth: parseInt(e.target.value) || 2 
                  })}
                  helperText="How deep to crawl each website"
                  disabled={scrapingState.isScrapingActive}
                />
                <Input
                  label="Pages per Site"
                  type="number"
                  min="1"
                  max="20"
                  value={state.config.pagesPerSite}
                  onChange={e => handleSecureConfigUpdate({ 
                    pagesPerSite: parseInt(e.target.value) || 5 
                  })}
                  helperText="Maximum pages to scrape per website"
                  disabled={scrapingState.isScrapingActive}
                />
              </div>
            </CardContent>
          </Card>
        </SecurityBoundary>

        {/* Search Configuration */}
        <SecurityBoundary componentName="SearchConfiguration">
          <Card className="border-blue-200 bg-blue-50">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
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
                    Search Result Pages
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={state.config.searchResultPages || state.config.duckduckgoSerpPages || 2}
                    onChange={e => handleSecureConfigUpdate({ 
                      searchResultPages: parseInt(e.target.value) 
                    })}
                    aria-label="Search Result Pages"
                    disabled={scrapingState.isScrapingActive}
                  >
                    <option value={1}>1 page (~30 results)</option>
                    <option value={2}>2 pages (~60 results)</option>
                    <option value={3}>3 pages (~90 results)</option>
                    <option value={4}>4 pages (~120 results)</option>
                    <option value={5}>5 pages (~150 results)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Max Results Per Search
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={state.config.maxSearchResults || 1000}
                    onChange={e => handleSecureConfigUpdate({ 
                      maxSearchResults: parseInt(e.target.value) 
                    })}
                    aria-label="Max Results Per Search"
                    disabled={scrapingState.isScrapingActive}
                  >
                    <option value={50}>50 results</option>
                    <option value={100}>100 results</option>
                    <option value={500}>500 results</option>
                    <option value={1000}>1000 results</option>
                    <option value={10000}>Unlimited (10,000+)</option>
                  </select>
                </div>
              </div>

              <div className="mt-4 p-3 bg-blue-100 rounded-md">
                <div className="flex items-start space-x-2">
                  <Info className="h-4 w-4 text-blue-600 mt-0.5" />
                  <div className="text-sm text-blue-800">
                    <p className="font-medium">Comprehensive Search Strategy:</p>
                    <ul className="mt-1 space-y-1 text-xs">
                      <li>• Scrapes actual DuckDuckGo search result pages (SERP)</li>
                      <li>• Searches each industry criteria individually</li>
                      <li>• Uses BBB as business discovery platform</li>
                      <li>• Validates ZIP code radius and extracts business URLs</li>
                      <li>• Scrapes actual business websites for contact information</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </SecurityBoundary>

        {/* Industry Categories */}
        <SecurityBoundary componentName="CategorySelector">
          <CategorySelector disabled={scrapingState.isScrapingActive} />
        </SecurityBoundary>

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
    </SecurityBoundary>
  )
}
