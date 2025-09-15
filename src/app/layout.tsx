import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from 'react-hot-toast'
import { ErrorBoundary } from '../components/ErrorBoundary'
import { ServiceWorkerRegistration } from '../components/ServiceWorkerRegistration'
import { ClientOnlyStripeProvider } from '../components/ClientOnlyStripeProvider'
import { PaymentSystemInitializer } from '../components/PaymentSystemInitializer'
import { getCSPNonce } from '@/lib/cspUtils'
import { DebugSystemInitializer } from '../components/DebugSystemInitializer'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Business Scraper App',
  description: 'A comprehensive business web scraping application for contact data collection',
  keywords: ['business scraping', 'contact data', 'web scraping', 'lead generation'],
  authors: [{ name: 'Business Scraper Team' }],
  icons: {
    icon: [
      { url: '/favicon.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon.ico', sizes: '16x16 32x32', type: 'image/x-icon' },
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
  // Get CSP nonce for this request (server-side only)
  const nonce = getCSPNonce()

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
        {/* CSP nonce for client-side access */}
        {nonce && <meta name="csp-nonce" content={nonce} />}
        {/* Removed favicon preload to prevent unused resource warning - favicon is loaded via metadata.icons */}
        <link rel="dns-prefetch" href="https://js.stripe.com" />
        <link rel="preconnect" href="https://js.stripe.com" crossOrigin="anonymous" />
        <meta name="theme-color" content="#2563eb" />
        <link rel="manifest" href="/manifest.json" />
        <link rel="apple-touch-icon" href="/favicon.png" />
        {/* Set global CSP nonce for client-side access */}
        {nonce && (
          <script
            nonce={nonce}
            dangerouslySetInnerHTML={{
              __html: `window.__CSP_NONCE__ = '${nonce}';`,
            }}
          />
        )}
      </head>
      <body className={inter.className}>
        <ErrorBoundary level="page" showDetails={process.env.NODE_ENV === 'development'}>
          <ClientOnlyStripeProvider>
            <DebugSystemInitializer />
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
          </ClientOnlyStripeProvider>
        </ErrorBoundary>
      </body>
    </html>
  )
}
