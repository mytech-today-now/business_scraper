/**
 * Navigation Container
 * Secure navigation component with input validation and access control
 */

'use client'

import React from 'react'
import { Settings, Brain, BarChart3, RotateCcw } from 'lucide-react'
import { Button } from '../ui/Button'
import { MobileNavigation } from '../MobileNavigation'
import { SecurityBoundary } from '../security/SecurityBoundary'
import { useConfig } from '@/controller/ConfigContext'
import { clsx } from 'clsx'
import toast from 'react-hot-toast'
import { logger } from '@/utils/logger'

export type AppTab = 'config' | 'scraping' | 'ai-insights' | 'bi-dashboard' | 'analytics' | 'dashboard' | 'memory'

export interface NavigationContainerProps {
  activeTab: AppTab
  onTabChange: (tab: AppTab) => void
  isMobile: boolean
  scrapingState: any
  industriesInEditMode: string[]
  industries: any[]
  isDarkMode: boolean
}

/**
 * Navigation Container with security boundaries
 */
export function NavigationContainer({
  activeTab,
  onTabChange,
  isMobile,
  scrapingState,
  industriesInEditMode,
  industries,
  isDarkMode,
}: NavigationContainerProps): JSX.Element {
  const { toggleDarkMode } = useConfig()

  /**
   * Secure tab change handler with validation
   */
  const handleSecureTabChange = (tab: AppTab) => {
    try {
      // Validate tab change permissions
      if (scrapingState.isScrapingActive && tab === 'config') {
        toast.error(
          'Configuration cannot be changed while scraping is active. Please stop scraping first.'
        )
        logger.warn('NavigationContainer', 'Blocked config access during scraping', { tab, activeTab })
        return
      }

      if (industriesInEditMode.length > 0 && tab === 'scraping') {
        const editingIndustries = industriesInEditMode
          .map(id => industries.find(industry => industry.id === id)?.name)
          .filter(Boolean)
          .join(', ')
        
        toast.error(`Please save or cancel edits for: ${editingIndustries}`)
        logger.warn('NavigationContainer', 'Blocked scraping access with unsaved edits', { 
          tab, 
          activeTab, 
          editingIndustries 
        })
        return
      }

      // Log successful navigation
      logger.info('NavigationContainer', 'Tab change', { from: activeTab, to: tab })
      onTabChange(tab)
    } catch (error) {
      logger.error('NavigationContainer', 'Tab change failed', error)
      toast.error('Navigation failed. Please try again.')
    }
  }

  /**
   * Secure reset data handler
   */
  const handleResetData = () => {
    try {
      if (scrapingState.isScrapingActive) {
        toast.error('Cannot reset data while scraping is active. Please stop scraping first.')
        logger.warn('NavigationContainer', 'Blocked reset during scraping')
        return
      }

      // This would trigger the reset dialog in the parent component
      logger.info('NavigationContainer', 'Reset data requested')
      // Implementation would be handled by parent component
    } catch (error) {
      logger.error('NavigationContainer', 'Reset data failed', error)
      toast.error('Reset operation failed. Please try again.')
    }
  }

  if (isMobile) {
    return (
      <SecurityBoundary componentName="MobileNavigation">
        <MobileNavigation
          activeTab={activeTab as 'config' | 'scraping'}
          onTabChange={(tab) => handleSecureTabChange(tab)}
          onApiConfigOpen={() => {
            // Handle API config opening
            logger.info('NavigationContainer', 'API config opened')
          }}
          isDarkMode={isDarkMode}
          onToggleDarkMode={toggleDarkMode}
        />
      </SecurityBoundary>
    )
  }

  return (
    <SecurityBoundary componentName="DesktopNavigation">
      <div className="flex items-center gap-1 bg-muted rounded-lg p-1">
        <Button
          variant={activeTab === 'config' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('config')}
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
          onClick={() => handleSecureTabChange('scraping')}
          disabled={industriesInEditMode.length > 0}
          title={
            industriesInEditMode.length > 0
              ? `Please save or cancel edits for: ${industriesInEditMode
                  .map(id => industries.find(industry => industry.id === id)?.name)
                  .filter(Boolean)
                  .join(', ')}`
              : undefined
          }
          className={clsx(
            'min-h-touch',
            industriesInEditMode.length > 0 && 'opacity-50 cursor-not-allowed'
          )}
        >
          Scraping
          {industriesInEditMode.length > 0 && (
            <span className="ml-1 inline-flex items-center justify-center w-4 h-4 text-xs font-bold text-white bg-yellow-500 rounded-full">
              !
            </span>
          )}
        </Button>

        <Button
          variant={activeTab === 'ai-insights' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('ai-insights')}
          className="min-h-touch"
        >
          AI Insights
        </Button>

        <Button
          variant={activeTab === 'bi-dashboard' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('bi-dashboard')}
          className="min-h-touch"
        >
          <Brain className="h-4 w-4 mr-1" />
          BI Dashboard
        </Button>

        <Button
          variant={activeTab === 'analytics' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('analytics')}
          className="min-h-touch"
        >
          <BarChart3 className="h-4 w-4 mr-1" />
          Analytics
        </Button>

        <Button
          variant={activeTab === 'dashboard' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('dashboard')}
          className="min-h-touch"
        >
          <Settings className="h-4 w-4 mr-1" />
          Dashboard
        </Button>

        <Button
          variant={activeTab === 'memory' ? 'default' : 'ghost'}
          size="sm"
          onClick={() => handleSecureTabChange('memory')}
          className="min-h-touch"
        >
          Memory
        </Button>

        <Button
          variant="outline"
          size="sm"
          onClick={handleResetData}
          disabled={scrapingState.isScrapingActive}
          title={
            scrapingState.isScrapingActive
              ? 'Cannot reset data while scraping is active. Please stop scraping first.'
              : 'Reset all application data to start fresh'
          }
          className={clsx(
            'ml-2 text-red-600 border-red-200 hover:bg-red-50 hover:border-red-300 min-h-touch',
            scrapingState.isScrapingActive && 'opacity-50 cursor-not-allowed'
          )}
        >
          <RotateCcw className="h-4 w-4 mr-1" />
          Reset Data
        </Button>
      </div>
    </SecurityBoundary>
  )
}
