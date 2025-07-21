'use client'

import { ConfigProvider } from '@/controller/ConfigContext'
import { App } from '@/view/components/App'

/**
 * Main page component that serves as the entry point for the application
 * Wraps the App component with necessary providers
 */
export default function HomePage() {
  return (
    <ConfigProvider>
      <App />
    </ConfigProvider>
  )
}
