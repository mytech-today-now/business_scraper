import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from 'react-hot-toast'
import { ErrorBoundary } from '../components/ErrorBoundary'
import { ServiceWorkerRegistration } from '../components/ServiceWorkerRegistration'
import { StripeProvider } from '@/view/components/payments/StripeProvider'
import { PaymentSystemInitializer } from '../components/PaymentSystemInitializer'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Business Scraper App',
  description: 'A comprehensive business web scraping application for contact data collection',
  keywords: ['business scraping', 'contact data', 'web scraping', 'lead generation'],
  authors: [{ name: 'Business Scraper Team' }],
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: '16x16 32x32', type: 'image/x-icon' },
      { url: '/favicon.png', sizes: '32x32', type: 'image/png' },
    ],
    shortcut: '/favicon.ico',
    apple: '/favicon.png',
  },
}

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: [
    { media: '(prefers-color-scheme: light)', color: 'white' },
    { media: '(prefers-color-scheme: dark)', color: 'black' },
  ],
}

export default function RootLayout({ children }: { children: React.ReactNode }): JSX.Element {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <meta name="color-scheme" content="light dark" />
        <meta
          name="viewport"
          content="width=device-width, initial-scale=1, maximum-scale=5, user-scalable=yes, viewport-fit=cover"
        />
        <meta name="mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-capable" content="yes" />
        <meta name="apple-mobile-web-app-status-bar-style" content="default" />
        <meta name="apple-mobile-web-app-title" content="Business Scraper" />
        <meta name="format-detection" content="telephone=no" />
        <meta name="msapplication-TileColor" content="#2563eb" />
        <link rel="preload" href="/favicon.ico" as="image" type="image/x-icon" />
        <link rel="dns-prefetch" href="https://js.stripe.com" />
        <link rel="preconnect" href="https://js.stripe.com" crossOrigin="anonymous" />
        <meta name="theme-color" content="#2563eb" />
        <link rel="manifest" href="/manifest.json" />
        <link rel="apple-touch-icon" href="/favicon.png" />
      </head>
      <body className={inter.className}>
        <ErrorBoundary level="page" showDetails={process.env.NODE_ENV === 'development'}>
          <StripeProvider>
            <PaymentSystemInitializer />
            <div className="min-h-screen bg-background font-sans antialiased">{children}</div>
            <ServiceWorkerRegistration />
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 4000,
                style: {
                  background: 'hsl(var(--card))',
                  color: 'hsl(var(--card-foreground))',
                  border: '1px solid hsl(var(--border))',
                },
              }}
            />
          </StripeProvider>
        </ErrorBoundary>
      </body>
    </html>
  )
}
