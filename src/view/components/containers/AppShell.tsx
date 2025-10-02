/**
 * App Shell Container
 * Main application container with security boundaries and navigation
 */

'use client'

import React, { useState, useEffect } from 'react'
import Image from 'next/image'
import { useConfig } from '@/controller/ConfigContext'
import { useScraperController } from '@/controller/useScraperController'
import { useResponsive } from '@/hooks/useResponsive'
import { analyticsService } from '@/model/analyticsService'
import { ErrorBoundary } from '../../components/ErrorBoundary'
import { SecurityBoundary } from '../security/SecurityBoundary'
import { NavigationContainer } from './NavigationContainer'
import { ConfigurationContainer } from './ConfigurationContainer'
import { ScrapingContainer } from './ScrapingContainer'
import { ResultsContainer } from './ResultsContainer'
import { AdminDashboard } from '../AdminDashboard'
import { AnalyticsDashboard } from '../analytics/AnalyticsDashboard'
import { AIInsightsPanel } from '../AIInsightsPanel'
import { BusinessIntelligenceDashboard } from '../BusinessIntelligenceDashboard'
import { MemoryDashboard } from '../MemoryDashboard'
import { logger } from '@/utils/logger'

export type AppTab = 'config' | 'scraping' | 'ai-insights' | 'bi-dashboard' | 'analytics' | 'dashboard' | 'memory'

export interface AppShellProps {
  initialTab?: AppTab
}

/**
 * Main App Shell component with security boundaries
 */
export function AppShell({ initialTab = 'config' }: AppShellProps): JSX.Element {
  const { state } = useConfig()
  const { scrapingState, hasResults } = useScraperController()
  const { isMobile } = useResponsive()
  const [activeTab, setActiveTab] = useState<AppTab>(initialTab)

  // Analytics tracking for app initialization and tab changes
  useEffect(() => {
    analyticsService.trackEvent('app_initialized', {
      timestamp: new Date().toISOString(),
      isMobile,
      hasResults,
    })
  }, [isMobile, hasResults])

  useEffect(() => {
    analyticsService.trackEvent('navigation_tab_change', {
      activeTab,
      timestamp: new Date().toISOString(),
      isMobile,
    })
  }, [activeTab, isMobile])

  /**
   * Handle tab change with security validation
   */
  const handleTabChange = (tab: AppTab) => {
    // Validate tab change is allowed
    if (scrapingState.isScrapingActive && tab === 'config') {
      logger.warn('AppShell', 'Configuration access blocked during active scraping')
      return
    }

    if (state.industriesInEditMode.length > 0 && tab === 'scraping') {
      logger.warn('AppShell', 'Scraping access blocked with unsaved industry edits')
      return
    }

    setActiveTab(tab)
    analyticsService.trackEvent('feature_tab_navigation', {
      fromTab: activeTab,
      toTab: tab,
      timestamp: new Date().toISOString(),
    })
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
    <SecurityBoundary componentName="AppShell">
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
                
                {/* Navigation */}
                <NavigationContainer
                  activeTab={activeTab}
                  onTabChange={handleTabChange}
                  isMobile={isMobile}
                  scrapingState={scrapingState}
                  industriesInEditMode={state.industriesInEditMode}
                  industries={state.industries}
                  isDarkMode={state.isDarkMode}
                />
              </div>

              <div className="flex items-center gap-2 md:gap-4">
                <MemoryDashboard compact className="hidden lg:flex" />
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-4 md:py-8 pb-safe-bottom">
          <ErrorBoundary level="section" showDetails={process.env.NODE_ENV === 'development'}>
            {activeTab === 'config' && (
              <SecurityBoundary componentName="ConfigurationContainer">
                <ConfigurationContainer />
              </SecurityBoundary>
            )}
            
            {activeTab === 'scraping' && (
              <SecurityBoundary componentName="ScrapingContainer">
                <ScrapingContainer />
              </SecurityBoundary>
            )}
            
            {activeTab === 'memory' && (
              <SecurityBoundary componentName="MemoryDashboard">
                <MemoryDashboard />
              </SecurityBoundary>
            )}
            
            {activeTab === 'bi-dashboard' && (
              <SecurityBoundary componentName="BusinessIntelligenceDashboard">
                <BusinessIntelligenceDashboard
                  businesses={scrapingState.results}
                  scores={new Map()}
                />
              </SecurityBoundary>
            )}
            
            {activeTab === 'analytics' && (
              <SecurityBoundary componentName="AnalyticsDashboard">
                <AnalyticsDashboard />
              </SecurityBoundary>
            )}
            
            {activeTab === 'dashboard' && (
              <SecurityBoundary componentName="AdminDashboard">
                <AdminDashboard />
              </SecurityBoundary>
            )}
            
            {activeTab === 'ai-insights' && (
              <SecurityBoundary componentName="AIInsightsPanel">
                <AIInsightsPanel />
              </SecurityBoundary>
            )}
          </ErrorBoundary>
        </main>

        {/* Footer */}
        <footer className="border-t bg-card mt-16">
          <div className="container mx-auto px-4 py-6">
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <p>Business Scraper App v3.10.1 - Security Enhanced Architecture</p>
              <p>Built with Next.js, React, and TypeScript</p>
            </div>
          </div>
        </footer>
      </div>
    </SecurityBoundary>
  )
}
