'use client'

import { ConfigProvider } from '@/controller/ConfigContext'
import { PerformanceProvider } from '@/controller/PerformanceContext'
import { App } from '@/view/components/App'

/**
 * Main page component that serves as the entry point for the application
 * Wraps the App component with necessary providers
 */
export default function HomePage(): JSX.Element {
  return (
    <ConfigProvider>
      <PerformanceProvider>
        <App />
      </PerformanceProvider>
    </ConfigProvider>
  )
}
