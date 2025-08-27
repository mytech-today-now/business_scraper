/**
 * Address Parser Tests
 *
 * Tests for enhanced address parsing functionality
 */

import { describe, it, expect, beforeEach } from '@jest/globals'
import { AddressParser } from '@/utils/addressParser'

describe('AddressParser', () => {
  let parser: AddressParser

  beforeEach(() => {
    parser = new AddressParser()
  })

  describe('parseAddress', () => {
    it('should parse complete structured address', () => {
      const result = parser.parseAddress('123 Main St, Anytown, CA 90210')

      expect(result.streetNumber).toBe('123')
      expect(result.streetName).toBe('Main St')
      expect(result.city).toBe('Anytown')
      expect(result.state).toBe('CA')
      expect(result.zipCode).toBe('90210')
      expect(result.confidence).toBeGreaterThan(0.8)
    })

    it('should parse address with suite information', () => {
      const result = parser.parseAddress('456 Oak Ave Suite 200, Springfield, IL 62701')

      expect(result.streetNumber).toBe('456')
      expect(result.streetName).toBe('Oak Ave')
      expect(result.suite).toBe('Suite 200')
      expect(result.city).toBe('Springfield')
      expect(result.state).toBe('IL')
      expect(result.zipCode).toBe('62701')
    })

    it('should parse address with ZIP+4', () => {
      const result = parser.parseAddress('789 Pine Rd, Boston, MA 02101-1234')

      expect(result.streetNumber).toBe('789')
      expect(result.streetName).toBe('Pine Rd')
      expect(result.city).toBe('Boston')
      expect(result.state).toBe('MA')
      expect(result.zipCode).toBe('02101-1234')
    })

    it('should handle full state names', () => {
      const result = parser.parseAddress('321 Elm St, Dallas, Texas 75201')

      expect(result.streetNumber).toBe('321')
      expect(result.streetName).toBe('Elm St')
      expect(result.city).toBe('Dallas')
      expect(result.state).toBe('TX')
      expect(result.zipCode).toBe('75201')
    })

    it('should parse address with apartment number', () => {
      const result = parser.parseAddress('555 Broadway Apt 3B, New York, NY 10012')

      expect(result.streetNumber).toBe('555')
      expect(result.streetName).toBe('Broadway')
      expect(result.suite).toBe('Apt 3B')
      expect(result.city).toBe('New York')
      expect(result.state).toBe('NY')
      expect(result.zipCode).toBe('10012')
    })

    it('should handle addresses with building numbers', () => {
      const result = parser.parseAddress('100A First St, San Francisco, CA 94105')

      expect(result.streetNumber).toBe('100A')
      expect(result.streetName).toBe('First St')
      expect(result.city).toBe('San Francisco')
      expect(result.state).toBe('CA')
      expect(result.zipCode).toBe('94105')
    })

    it('should parse partial addresses', () => {
      const result = parser.parseAddress('123 Main St, CA 90210', { allowPartialMatches: true })

      expect(result.streetNumber).toBe('123')
      expect(result.streetName).toBe('Main St')
      expect(result.state).toBe('CA')
      expect(result.zipCode).toBe('90210')
      expect(result.confidence).toBeGreaterThan(0.4)
    })

    it('should handle malformed addresses gracefully', () => {
      const result = parser.parseAddress('Not a real address')

      expect(result.confidence).toBeLessThan(0.5)
    })

    it('should return empty result for invalid input', () => {
      const result = parser.parseAddress('')

      expect(result.streetNumber).toBe('')
      expect(result.streetName).toBe('')
      expect(result.city).toBe('')
      expect(result.state).toBe('')
      expect(result.zipCode).toBe('')
      expect(result.confidence).toBe(0)
    })

    it('should handle addresses with different separators', () => {
      const result = parser.parseAddress('123 Main St\nAnytown, CA 90210')

      expect(result.streetNumber).toBe('123')
      expect(result.streetName).toBe('Main St')
      expect(result.city).toBe('Anytown')
      expect(result.state).toBe('CA')
      expect(result.zipCode).toBe('90210')
    })

    it('should parse addresses with various street types', () => {
      const testCases = [
        { input: '123 Main Street, City, CA 90210', expected: 'Main Street' },
        { input: '456 Oak Avenue, City, CA 90210', expected: 'Oak Avenue' },
        { input: '789 Pine Boulevard, City, CA 90210', expected: 'Pine Boulevard' },
        { input: '321 Elm Drive, City, CA 90210', expected: 'Elm Drive' },
        { input: '654 First Lane, City, CA 90210', expected: 'First Lane' },
      ]

      testCases.forEach(({ input, expected }) => {
        const result = parser.parseAddress(input)
        expect(result.streetName).toBe(expected)
      })
    })

    it('should handle addresses with extra whitespace', () => {
      const result = parser.parseAddress('  123   Main   St  ,  Anytown  ,  CA   90210  ')

      expect(result.streetNumber).toBe('123')
      expect(result.streetName).toBe('Main St')
      expect(result.city).toBe('Anytown')
      expect(result.state).toBe('CA')
      expect(result.zipCode).toBe('90210')
    })

    it('should parse addresses with unit indicators', () => {
      const testCases = [
        '123 Main St Unit 5, City, CA 90210',
        '123 Main St Ste 5, City, CA 90210',
        '123 Main St #5, City, CA 90210',
        '123 Main St Floor 5, City, CA 90210',
        '123 Main St Bldg 5, City, CA 90210',
      ]

      testCases.forEach(address => {
        const result = parser.parseAddress(address)
        expect(result.streetNumber).toBe('123')
        expect(result.streetName).toBe('Main St')
        expect(result.suite).toContain('5')
      })
    })
  })

  describe('edge cases', () => {
    it('should handle null input', () => {
      const result = parser.parseAddress(null as any)
      expect(result.confidence).toBe(0)
    })

    it('should handle undefined input', () => {
      const result = parser.parseAddress(undefined as any)
      expect(result.confidence).toBe(0)
    })

    it('should handle non-string input', () => {
      const result = parser.parseAddress(123 as any)
      expect(result.confidence).toBe(0)
    })
  })
})
