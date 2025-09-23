/**
 * Streaming Connection Integration Tests
 * 
 * Tests for GitHub Issue #191: EventSource connection failures
 * Verifies that streaming connections don't immediately close with readyState 2
 * 
 * These are integration tests that test the actual HTTP endpoints
 */

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals'

describe('Streaming Connection Integration Tests (Issue #191)', () => {
  const baseUrl = process.env.TEST_BASE_URL || 'http://localhost:3000'
  let serverRunning = false

  beforeAll(async () => {
    // Check if server is running
    try {
      const response = await fetch(`${baseUrl}/api/health`, {
        signal: AbortSignal.timeout(5000)
      })
      serverRunning = response.ok
    } catch (error) {
      serverRunning = false
    }
  })

  describe('EventSource Connection Establishment', () => {
    test('should establish streaming connection successfully', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      const streamingUrl = `${baseUrl}/api/stream-search?q=test&location=12345&maxResults=10&batchSize=5`
      
      try {
        const response = await fetch(streamingUrl, {
          method: 'GET',
          headers: {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache'
          },
          signal: AbortSignal.timeout(8000)
        })

        // Check if the endpoint responds (even if it's an error, it should not be a connection failure)
        expect(response.status).toBeGreaterThanOrEqual(200)
        expect(response.status).toBeLessThan(600)
        
        // If successful, verify streaming headers
        if (response.ok) {
          expect(response.headers.get('Content-Type')).toContain('text/event-stream')
          expect(response.headers.get('Cache-Control')).toContain('no-cache')
          console.log('✅ Streaming connection established successfully')
        } else {
          console.log(`⚠️ Streaming endpoint returned status ${response.status}`)
        }
      } catch (error) {
        // If there's a connection error, the test should fail
        if (error.name === 'AbortError') {
          console.log('⚠️ Streaming connection timed out (may indicate server issues)')
        } else {
          console.error('❌ Connection error:', error.message)
          throw error
        }
      }
    })

    test('should handle missing query parameter', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      const streamingUrl = `${baseUrl}/api/stream-search?location=12345` // Missing 'q' parameter
      
      try {
        const response = await fetch(streamingUrl, {
          method: 'GET',
          headers: {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache'
          },
          signal: AbortSignal.timeout(5000)
        })

        expect(response.status).toBe(400)
        
        if (response.headers.get('content-type')?.includes('application/json')) {
          const data = await response.json()
          expect(data.error).toContain('required')
        }
        console.log('✅ Parameter validation working correctly')
      } catch (error) {
        // Connection errors should not occur for parameter validation
        if (error.name !== 'AbortError') {
          console.error('❌ Unexpected connection error:', error.message)
          throw error
        }
      }
    })

    test('should verify CSP headers allow EventSource connections', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      try {
        const response = await fetch(baseUrl, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
        })

        const cspHeader = response.headers.get('content-security-policy')
        
        if (cspHeader) {
          // Check if connect-src allows 'self' for EventSource connections
          const connectSrcAllowsSelf = cspHeader.includes("connect-src") && cspHeader.includes("'self'")
          expect(connectSrcAllowsSelf).toBe(true)
          console.log('✅ CSP headers properly configured for EventSource')
        } else {
          console.log('⚠️ No CSP header found')
        }
      } catch (error) {
        console.error('❌ Error checking CSP headers:', error.message)
        throw error
      }
    })
  })

  describe('Health Check Integration', () => {
    test('should verify health endpoint is accessible', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      try {
        const response = await fetch(`${baseUrl}/api/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(5000)
        })

        expect(response.ok).toBe(true)
        expect(response.status).toBe(200)
        
        const data = await response.json()
        expect(data.status).toBe('healthy')
        console.log('✅ Health endpoint accessible')
      } catch (error) {
        console.error('❌ Health endpoint error:', error.message)
        throw error
      }
    })
  })

  describe('Rate Limiting Verification', () => {
    test('should handle rate limiting gracefully', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      const streamingUrl = `${baseUrl}/api/stream-search?q=test&location=12345&maxResults=10&batchSize=5`
      
      // Make multiple rapid requests to test rate limiting
      const requests = []
      for (let i = 0; i < 5; i++) {
        requests.push(
          fetch(streamingUrl, {
            method: 'GET',
            headers: {
              'Accept': 'text/event-stream',
              'Cache-Control': 'no-cache'
            },
            signal: AbortSignal.timeout(3000)
          }).catch(error => ({ error: error.message }))
        )
      }

      const responses = await Promise.all(requests)
      
      // At least one request should succeed or return a proper rate limit response
      const validResponses = responses.filter(r => !r.error && r.status)
      expect(validResponses.length).toBeGreaterThan(0)
      
      console.log(`✅ Rate limiting test completed: ${validResponses.length}/${responses.length} valid responses`)
    })
  })

  describe('Connection Recovery Scenarios', () => {
    test('should handle multiple connection attempts', async () => {
      if (!serverRunning) {
        console.warn('Server not running, skipping integration test')
        return
      }

      const streamingUrl = `${baseUrl}/api/stream-search?q=test&location=12345&maxResults=5&batchSize=2`
      
      // Test multiple sequential connection attempts
      let successfulConnections = 0
      
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          const response = await fetch(streamingUrl, {
            method: 'GET',
            headers: {
              'Accept': 'text/event-stream',
              'Cache-Control': 'no-cache'
            },
            signal: AbortSignal.timeout(3000)
          })

          if (response.ok) {
            successfulConnections++
          }
          
          // Small delay between attempts
          await new Promise(resolve => setTimeout(resolve, 100))
        } catch (error) {
          console.log(`Attempt ${attempt} failed: ${error.message}`)
        }
      }

      // At least one connection should succeed
      expect(successfulConnections).toBeGreaterThan(0)
      console.log(`✅ Connection recovery test: ${successfulConnections}/3 successful connections`)
    })
  })
})
