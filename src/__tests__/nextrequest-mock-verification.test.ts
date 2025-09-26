/**
 * Verification test for NextRequest mocking fix
 * This test verifies that the NextRequest mock properly handles read-only properties
 */

import { NextRequest } from 'next/server'
import { createMockNextRequest } from './utils/mockHelpers'

describe('NextRequest Mocking Verification', () => {
  it('should create NextRequest without TypeError on read-only properties', () => {
    expect(() => {
      const request = new NextRequest('http://localhost:3000/api/test')
      expect(request.url).toBe('http://localhost:3000/api/test')
      expect(request.method).toBe('GET')
      expect(request.headers).toBeDefined()
      expect(request.nextUrl).toBeDefined()
    }).not.toThrow()
  })

  it('should create NextRequest with options', () => {
    expect(() => {
      const request = new NextRequest('http://localhost:3000/api/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: 'data' })
      })
      expect(request.url).toBe('http://localhost:3000/api/test')
      expect(request.method).toBe('POST')
      expect(request.headers.get('Content-Type')).toBe('application/json')
    }).not.toThrow()
  })

  it('should work with createMockNextRequest helper', () => {
    expect(() => {
      const request = createMockNextRequest('http://localhost:3000/api/test', {
        method: 'PUT',
        headers: { 'Authorization': 'Bearer token' }
      })
      expect(request.url).toBe('http://localhost:3000/api/test')
      expect(request.method).toBe('PUT')
      expect(request.headers.get('Authorization')).toBe('Bearer token')
    }).not.toThrow()
  })

  it('should handle URL parsing correctly', () => {
    const request = new NextRequest('http://localhost:3000/api/test?q=search&location=city')
    expect(request.url).toBe('http://localhost:3000/api/test?q=search&location=city')
    expect(request.nextUrl.pathname).toBe('/api/test')
    expect(request.nextUrl.searchParams.get('q')).toBe('search')
    expect(request.nextUrl.searchParams.get('location')).toBe('city')
  })

  it('should implement required methods', async () => {
    const request = new NextRequest('http://localhost:3000/api/test', {
      method: 'POST',
      body: JSON.stringify({ test: 'data' })
    })

    // Test json() method
    const jsonData = await request.json()
    expect(jsonData).toEqual({ test: 'data' })

    // Test clone() method
    const clonedRequest = request.clone()
    expect(clonedRequest.url).toBe(request.url)
    expect(clonedRequest.method).toBe(request.method)
  })

  it('should handle cookies mock', () => {
    const request = new NextRequest('http://localhost:3000/api/test')
    expect(request.cookies).toBeDefined()
    expect(typeof request.cookies.get).toBe('function')
    expect(typeof request.cookies.set).toBe('function')
  })

  it('should prevent modification of read-only properties', () => {
    const request = new NextRequest('http://localhost:3000/api/test')

    // Attempting to modify read-only properties should throw an error
    expect(() => {
      // @ts-expect-error - Testing runtime behavior
      request.url = 'http://different.com'
    }).toThrow('Cannot assign to read only property')

    // URL should remain unchanged due to read-only property
    expect(request.url).toBe('http://localhost:3000/api/test')
  })
})
