// Service Worker for Business Scraper
// Provides offline caching and performance optimization

const CACHE_NAME = 'business-scraper-v1.0.0'
const STATIC_CACHE_NAME = 'business-scraper-static-v1.0.0'
const DYNAMIC_CACHE_NAME = 'business-scraper-dynamic-v1.0.0'

// Static assets to cache immediately (only include assets that definitely exist)
const STATIC_ASSETS = [
  '/manifest.json',
  '/favicon.png', // Use PNG favicon as primary (more reliable than ICO)
  // Note: favicon.ico removed temporarily due to server errors
  // Root path '/' removed to prevent caching failures during development
]

// API endpoints to cache
const API_CACHE_PATTERNS = [
  /^\/api\/ping$/,
  /^\/api\/health$/,
]

// Assets to cache dynamically
const DYNAMIC_CACHE_PATTERNS = [
  /\/_next\/static\//,
  /\.(?:js|css|woff2?|png|jpg|jpeg|gif|svg|ico)$/,
]

// Maximum cache size (number of items)
const MAX_CACHE_SIZE = 100

/**
 * Install event - cache static assets
 */
self.addEventListener('install', (event) => {
  console.log('[SW] Installing service worker...')

  event.waitUntil(
    caches.open(STATIC_CACHE_NAME)
      .then(async (cache) => {
        console.log('[SW] Caching static assets')

        // Cache assets individually to handle 404s gracefully
        const cachePromises = STATIC_ASSETS.map(async (asset) => {
          try {
            // Add timeout to prevent hanging requests
            const controller = new AbortController()
            const timeoutId = setTimeout(() => controller.abort(), 5000)

            const response = await fetch(asset, {
              signal: controller.signal,
              cache: 'no-cache' // Ensure fresh fetch during development
            })
            clearTimeout(timeoutId)

            if (response.ok) {
              await cache.put(asset, response)
              console.log(`[SW] Cached: ${asset}`)
            } else {
              // Only log warnings for unexpected errors (not 404s for optional assets)
              if (response.status !== 404 || !asset.includes('favicon')) {
                console.warn(`[SW] Skipped caching ${asset}: ${response.status}`)
              }
            }
          } catch (error) {
            // Reduce console noise for expected development server issues
            if (error.name !== 'AbortError') {
              // Only log errors for critical assets, not favicons
              if (!asset.includes('favicon')) {
                console.warn(`[SW] Failed to cache ${asset}:`, error.message)
              }
            }
          }
        })

        await Promise.allSettled(cachePromises)
        console.log('[SW] Static asset caching completed')
        return self.skipWaiting()
      })
      .catch((error) => {
        console.error('[SW] Cache initialization failed:', error)
        // Continue installation even if caching fails
        return self.skipWaiting()
      })
  )
})

/**
 * Activate event - clean up old caches
 */
self.addEventListener('activate', (event) => {
  console.log('[SW] Activating service worker...')
  
  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            if (cacheName !== STATIC_CACHE_NAME && 
                cacheName !== DYNAMIC_CACHE_NAME &&
                cacheName !== CACHE_NAME) {
              console.log('[SW] Deleting old cache:', cacheName)
              return caches.delete(cacheName)
            }
          })
        )
      })
      .then(() => {
        console.log('[SW] Service worker activated')
        return self.clients.claim()
      })
  )
})

/**
 * Fetch event - handle network requests with caching strategy
 */
self.addEventListener('fetch', (event) => {
  const { request } = event
  const url = new URL(request.url)

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return
  }

  // Skip chrome-extension and other non-http(s) requests
  if (!url.protocol.startsWith('http')) {
    return
  }

  event.respondWith(handleFetch(request))
})

/**
 * Handle fetch requests with appropriate caching strategy
 */
async function handleFetch(request) {
  const url = new URL(request.url)

  try {
    // Strategy 1: Static assets - Cache First
    if (STATIC_ASSETS.some(asset => url.pathname === asset)) {
      const response = await cacheFirst(request, STATIC_CACHE_NAME)
      if (response instanceof Response) return response
    }

    // Strategy 2: API endpoints - Network First with cache fallback
    if (API_CACHE_PATTERNS.some(pattern => pattern.test(url.pathname))) {
      const response = await networkFirst(request, DYNAMIC_CACHE_NAME)
      if (response instanceof Response) return response
    }

    // Strategy 3: Dynamic assets - Stale While Revalidate
    if (DYNAMIC_CACHE_PATTERNS.some(pattern => pattern.test(url.pathname))) {
      const response = await staleWhileRevalidate(request, DYNAMIC_CACHE_NAME)
      if (response instanceof Response) return response
    }

    // Strategy 4: HTML pages - Network First
    if (request.headers.get('accept')?.includes('text/html')) {
      const response = await networkFirst(request, DYNAMIC_CACHE_NAME)
      if (response instanceof Response) return response
    }

    // Default: Network only
    const networkResponse = await fetch(request)
    if (networkResponse instanceof Response) {
      return networkResponse
    }

    // If we get here, something went wrong - return fallback
    return await getOfflineFallback(request)

  } catch (error) {
    // Only log errors for critical resources or unexpected failures
    // Reduce console noise for expected network failures during development
    const url = new URL(request.url)
    const isDevServer = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
    const isNextJSChunk = url.pathname.includes('/_next/static/')

    // Only log errors for non-development or critical resources
    if (!isDevServer || (!isNextJSChunk && !url.pathname.includes('/api/'))) {
      console.warn('[SW] Network request failed:', {
        url: request.url,
        method: request.method,
        error: error.message
      })
    }

    // Always return a valid Response object
    try {
      const fallback = await getOfflineFallback(request)
      if (fallback instanceof Response) {
        return fallback
      }
    } catch (fallbackError) {
      // Only log fallback errors for critical resources
      if (!isDevServer || !isNextJSChunk) {
        console.warn('[SW] Fallback failed:', fallbackError.message)
      }
    }

    // Last resort: return a basic error response
    return new Response(
      JSON.stringify({ error: 'Service unavailable' }),
      {
        status: 503,
        statusText: 'Service Unavailable',
        headers: { 'Content-Type': 'application/json' }
      }
    )
  }
}

/**
 * Cache First strategy - check cache first, fallback to network
 */
async function cacheFirst(request, cacheName) {
  const cache = await caches.open(cacheName)
  const cachedResponse = await cache.match(request)
  
  if (cachedResponse) {
    return cachedResponse
  }

  const networkResponse = await fetch(request)
  
  if (networkResponse.ok) {
    cache.put(request, networkResponse.clone())
  }
  
  return networkResponse
}

/**
 * Network First strategy - try network first, fallback to cache
 */
async function networkFirst(request, cacheName) {
  const cache = await caches.open(cacheName)
  
  try {
    const networkResponse = await fetch(request)
    
    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone())
      await limitCacheSize(cacheName, MAX_CACHE_SIZE)
    }
    
    return networkResponse
  } catch (error) {
    const cachedResponse = await cache.match(request)
    
    if (cachedResponse) {
      return cachedResponse
    }
    
    throw error
  }
}

/**
 * Stale While Revalidate strategy - return cache immediately, update in background
 */
async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName)
  const cachedResponse = await cache.match(request)

  // Start network request in background
  const networkPromise = fetch(request)
    .then((networkResponse) => {
      if (networkResponse && networkResponse.ok) {
        cache.put(request, networkResponse.clone())
        limitCacheSize(cacheName, MAX_CACHE_SIZE)
      }
      return networkResponse
    })
    .catch((error) => {
      // Reduce console noise for expected development server failures
      const url = new URL(request.url)
      const isDevServer = url.hostname === 'localhost' || url.hostname === '127.0.0.1'
      const isNextJSChunk = url.pathname.includes('/_next/static/')
      const isFavicon = url.pathname.includes('favicon')

      // Only log network failures for critical resources or production
      if (!isDevServer || (!isNextJSChunk && !url.pathname.includes('/api/') && !isFavicon)) {
        console.warn('[SW] Network request failed in staleWhileRevalidate:', {
          url: request.url,
          error: error.message,
          timestamp: new Date().toISOString()
        })
      }

      // For Stripe.js failures, provide more helpful context without excessive logging
      if (url.hostname === 'js.stripe.com') {
        // Only log Stripe.js failures once per session to avoid spam
        if (!self.stripeFailureLogged) {
          console.info('[SW] Stripe.js temporarily unavailable - this is expected during service outages:', {
            url: request.url,
            error: error.message,
            timestamp: new Date().toISOString(),
            note: 'Payment features will retry automatically when service is restored'
          })
          self.stripeFailureLogged = true
        }
      }

      // Return null to indicate network failure
      return null
    })

  // Return cached version immediately if available
  if (cachedResponse) {
    return cachedResponse
  }

  // Wait for network if no cache available
  try {
    const networkResponse = await networkPromise
    if (networkResponse && networkResponse instanceof Response) {
      return networkResponse
    }
    // If network failed and no cache, return offline fallback
    return await getOfflineFallback(request)
  } catch (error) {
    console.error('[SW] Failed to get network response:', error)
    return await getOfflineFallback(request)
  }
}

/**
 * Get offline fallback response
 */
async function getOfflineFallback(request) {
  const url = new URL(request.url)
  
  // For HTML requests, try to return cached main page
  if (request.headers.get('accept')?.includes('text/html')) {
    const cache = await caches.open(STATIC_CACHE_NAME)
    const fallback = await cache.match('/')
    
    if (fallback) {
      return fallback
    }
  }

  // Return a basic offline response
  return new Response(
    JSON.stringify({
      error: 'Offline',
      message: 'This request requires an internet connection'
    }),
    {
      status: 503,
      statusText: 'Service Unavailable',
      headers: {
        'Content-Type': 'application/json'
      }
    }
  )
}

/**
 * Limit cache size by removing oldest entries
 */
async function limitCacheSize(cacheName, maxSize) {
  const cache = await caches.open(cacheName)
  const keys = await cache.keys()
  
  if (keys.length > maxSize) {
    const keysToDelete = keys.slice(0, keys.length - maxSize)
    await Promise.all(keysToDelete.map(key => cache.delete(key)))
  }
}

/**
 * Handle background sync for offline actions
 */
self.addEventListener('sync', (event) => {
  if (event.tag === 'background-sync') {
    event.waitUntil(handleBackgroundSync())
  }
})

/**
 * Handle background sync operations
 */
async function handleBackgroundSync() {
  console.log('[SW] Handling background sync')
  
  // Implement background sync logic here
  // This could include syncing offline data when connection is restored
}

/**
 * Handle push notifications (if needed in the future)
 */
self.addEventListener('push', (event) => {
  if (event.data) {
    const data = event.data.json()
    
    event.waitUntil(
      self.registration.showNotification(data.title, {
        body: data.body,
        icon: '/favicon.png',
        badge: '/favicon.png',
        data: data.data
      })
    )
  }
})

/**
 * Handle notification clicks
 */
self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  
  event.waitUntil(
    self.clients.openWindow('/')
  )
})
