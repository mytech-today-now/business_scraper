'use client'

import React, { useState, useEffect } from 'react'
import { X, Menu, Settings, FileText, Moon, Sun } from 'lucide-react'
import { Button } from './ui/Button'
import { useResponsive } from '@/hooks/useResponsive'
import { clsx } from 'clsx'

interface MobileNavigationProps {
  activeTab: 'config' | 'scraping'
  onTabChange: (tab: 'config' | 'scraping') => void
  onApiConfigOpen: () => void
  isDarkMode: boolean
  onToggleDarkMode: () => void
}

/**
 * Mobile-optimized navigation component
 * Features collapsible drawer, touch-friendly targets, and accessibility support
 */
export function MobileNavigation({
  activeTab,
  onTabChange,
  onApiConfigOpen,
  isDarkMode,
  onToggleDarkMode,
}: MobileNavigationProps): JSX.Element {
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const { isMobile, isTouchDevice } = useResponsive()

  // Close drawer when switching to desktop
  useEffect(() => {
    if (!isMobile && isDrawerOpen) {
      setIsDrawerOpen(false)
    }
  }, [isMobile, isDrawerOpen])

  // Close drawer on escape key
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isDrawerOpen) {
        setIsDrawerOpen(false)
      }
    }

    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [isDrawerOpen])

  // Prevent body scroll when drawer is open
  useEffect(() => {
    if (isDrawerOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }

    return () => {
      document.body.style.overflow = ''
    }
  }, [isDrawerOpen])

  const handleTabChange = (tab: 'config' | 'scraping') => {
    onTabChange(tab)
    setIsDrawerOpen(false) // Close drawer after selection
  }

  const handleActionAndClose = (action: () => void) => {
    action()
    setIsDrawerOpen(false)
  }

  if (!isMobile) {
    // Desktop navigation - horizontal layout
    return (
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1 bg-muted rounded-lg p-1">
          <Button
            variant={activeTab === 'config' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => onTabChange('config')}
            className="min-h-touch"
          >
            Configuration
          </Button>
          <Button
            variant={activeTab === 'scraping' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => onTabChange('scraping')}
            className="min-h-touch"
          >
            Scraping
          </Button>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="icon"
            className="min-h-touch min-w-touch"
            title="Documentation"
          >
            <FileText className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={onApiConfigOpen}
            title="API Configuration"
            className="min-h-touch min-w-touch"
          >
            <Settings className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={onToggleDarkMode}
            title={isDarkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            className="min-h-touch min-w-touch"
          >
            {isDarkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </div>
      </div>
    )
  }

  return (
    <>
      {/* Mobile Menu Button */}
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setIsDrawerOpen(true)}
        className="min-h-touch min-w-touch"
        aria-label="Open navigation menu"
        aria-expanded={isDrawerOpen}
      >
        <Menu className="h-5 w-5" />
      </Button>

      {/* Mobile Drawer Overlay */}
      {isDrawerOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-50"
          onClick={() => setIsDrawerOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Mobile Drawer */}
      <div
        className={clsx(
          'fixed top-0 right-0 h-full w-80 max-w-mobile bg-card border-l shadow-xl z-50 transform transition-transform duration-300 ease-in-out',
          isDrawerOpen ? 'translate-x-0' : 'translate-x-full'
        )}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation menu"
      >
        {/* Drawer Header */}
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Navigation</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsDrawerOpen(false)}
            className="min-h-touch min-w-touch"
            aria-label="Close navigation menu"
          >
            <X className="h-5 w-5" />
          </Button>
        </div>

        {/* Drawer Content */}
        <div className="p-4 space-y-6">
          {/* Tab Navigation */}
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
              Sections
            </h3>
            <div className="space-y-1">
              <Button
                variant={activeTab === 'config' ? 'default' : 'ghost'}
                className="w-full justify-start min-h-touch"
                onClick={() => handleTabChange('config')}
              >
                Configuration
              </Button>
              <Button
                variant={activeTab === 'scraping' ? 'default' : 'ghost'}
                className="w-full justify-start min-h-touch"
                onClick={() => handleTabChange('scraping')}
              >
                Scraping
              </Button>
            </div>
          </div>

          {/* Actions */}
          <div className="space-y-2">
            <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
              Actions
            </h3>
            <div className="space-y-1">
              <Button
                variant="ghost"
                className="w-full justify-start min-h-touch"
                onClick={() => handleActionAndClose(onApiConfigOpen)}
              >
                <Settings className="h-4 w-4 mr-2" />
                API Configuration
              </Button>
              <Button
                variant="ghost"
                className="w-full justify-start min-h-touch"
                title="Documentation"
              >
                <FileText className="h-4 w-4 mr-2" />
                Documentation
              </Button>
              <Button
                variant="ghost"
                className="w-full justify-start min-h-touch"
                onClick={() => handleActionAndClose(onToggleDarkMode)}
              >
                {isDarkMode ? (
                  <>
                    <Sun className="h-4 w-4 mr-2" />
                    Light Mode
                  </>
                ) : (
                  <>
                    <Moon className="h-4 w-4 mr-2" />
                    Dark Mode
                  </>
                )}
              </Button>
            </div>
          </div>
        </div>

        {/* Drawer Footer */}
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t bg-muted/30">
          <p className="text-xs text-muted-foreground text-center">Business Scraper v1.0.0</p>
        </div>
      </div>
    </>
  )
}
