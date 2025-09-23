/**
 * Unit Tests for Toast Deduplication Utility
 * Tests the enhanced toast deduplication system to prevent duplicate notifications
 */

import { 
  toastDeduplication, 
  showDeduplicatedToast, 
  showDeduplicatedSuccessToast,
  showDeduplicatedErrorToast 
} from '@/utils/toastDeduplication'

// Mock logger to prevent console output during tests
jest.mock('@/utils/logger', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  },
}))

describe('ToastDeduplication', () => {
  beforeEach(() => {
    // Clear all toast records before each test
    toastDeduplication.clear()
    jest.clearAllMocks()
  })

  describe('Basic Deduplication', () => {
    it('should allow the first toast', () => {
      const mockToastFunction = jest.fn()
      const result = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith('Test message')
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
    })

    it('should suppress duplicate toasts within the deduplication window', () => {
      const mockToastFunction = jest.fn()
      
      // First toast should be allowed
      const result1 = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      expect(result1).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
      
      // Second identical toast should be suppressed
      const result2 = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      expect(result2).toBe(false)
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
    })

    it('should allow different messages', () => {
      const mockToastFunction = jest.fn()
      
      const result1 = showDeduplicatedToast(mockToastFunction, 'Message 1', 'info')
      const result2 = showDeduplicatedToast(mockToastFunction, 'Message 2', 'info')
      
      expect(result1).toBe(true)
      expect(result2).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledTimes(2)
    })

    it('should allow same message with different types', () => {
      const mockToastFunction = jest.fn()
      
      const result1 = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      const result2 = showDeduplicatedToast(mockToastFunction, 'Test message', 'error')
      
      expect(result1).toBe(true)
      expect(result2).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledTimes(2)
    })
  })

  describe('ZIP Code Specific Deduplication', () => {
    it('should use longer deduplication window for ZIP code toasts', () => {
      const mockToastFunction = jest.fn()
      const zipCodeMessage = 'ZIP code "60047" is valid'
      
      // First ZIP code toast should be allowed
      const result1 = showDeduplicatedSuccessToast(mockToastFunction, zipCodeMessage)
      expect(result1).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
      
      // Second identical ZIP code toast should be suppressed for longer period
      const result2 = showDeduplicatedSuccessToast(mockToastFunction, zipCodeMessage)
      expect(result2).toBe(false)
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
    })

    it('should identify ZIP code toasts correctly', () => {
      const mockToastFunction = jest.fn()
      
      // ZIP code related messages
      const zipMessages = [
        'ZIP code "60047" is valid',
        'zip code "90210" is valid',
        'ZIP Code validation successful',
        'Valid ZIP code entered'
      ]
      
      zipMessages.forEach(message => {
        mockToastFunction.mockClear()
        
        // First call should be allowed
        const result1 = showDeduplicatedSuccessToast(mockToastFunction, message)
        expect(result1).toBe(true)
        
        // Second call should be suppressed
        const result2 = showDeduplicatedSuccessToast(mockToastFunction, message)
        expect(result2).toBe(false)
      })
    })
  })

  describe('Time-based Expiration', () => {
    it('should allow toast after deduplication window expires', async () => {
      const mockToastFunction = jest.fn()
      
      // Mock Date.now to control time
      const originalDateNow = Date.now
      let currentTime = 1000000
      Date.now = jest.fn(() => currentTime)
      
      try {
        // First toast
        const result1 = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
        expect(result1).toBe(true)
        
        // Advance time by 6 seconds (beyond 5 second window)
        currentTime += 6000
        
        // Second toast should now be allowed
        const result2 = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
        expect(result2).toBe(true)
        expect(mockToastFunction).toHaveBeenCalledTimes(2)
      } finally {
        Date.now = originalDateNow
      }
    })

    it('should clean up old records automatically', () => {
      const mockToastFunction = jest.fn()
      
      // Mock Date.now to control time
      const originalDateNow = Date.now
      let currentTime = 1000000
      Date.now = jest.fn(() => currentTime)
      
      try {
        // Add multiple toasts
        for (let i = 0; i < 10; i++) {
          showDeduplicatedToast(mockToastFunction, `Message ${i}`, 'info')
          currentTime += 1000 // Advance 1 second each time
        }

        const initialCount = toastDeduplication.getRecordCount()
        expect(initialCount).toBeGreaterThan(0)
        
        // Advance time significantly to trigger cleanup
        currentTime += 10000
        
        // Trigger cleanup by adding a new toast
        showDeduplicatedToast(mockToastFunction, 'New message', 'info')
        
        // Old records should be cleaned up
        const finalCount = toastDeduplication.getRecordCount()
        expect(finalCount).toBeLessThan(initialCount)
      } finally {
        Date.now = originalDateNow
      }
    })
  })

  describe('Helper Functions', () => {
    it('should work with showDeduplicatedSuccessToast', () => {
      const mockToastFunction = jest.fn()
      
      const result = showDeduplicatedSuccessToast(mockToastFunction, 'Success message')
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith('Success message')
    })

    it('should work with showDeduplicatedErrorToast', () => {
      const mockToastFunction = jest.fn()
      
      const result = showDeduplicatedErrorToast(mockToastFunction, 'Error message')
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith('Error message')
    })
  })

  describe('Force Show Toast', () => {
    it('should allow forcing a toast even if it would be deduplicated', () => {
      const mockToastFunction = jest.fn()
      
      // First toast
      showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      expect(mockToastFunction).toHaveBeenCalledTimes(1)
      
      // Force show the same toast
      toastDeduplication.forceShowToast('Test message', 'info')
      const result = showDeduplicatedToast(mockToastFunction, 'Test message', 'info')
      
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledTimes(2)
    })
  })

  describe('Memory Management', () => {
    it('should not exceed maximum record count', () => {
      const mockToastFunction = jest.fn()
      
      // Add more toasts than the maximum
      for (let i = 0; i < 60; i++) {
        showDeduplicatedToast(mockToastFunction, `Message ${i}`, 'info')
      }

      // Should not exceed maximum by much (allow some buffer for cleanup timing)
      expect(toastDeduplication.getRecordCount()).toBeLessThanOrEqual(55)
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty messages', () => {
      const mockToastFunction = jest.fn()
      
      const result = showDeduplicatedToast(mockToastFunction, '', 'info')
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith('')
    })

    it('should handle very long messages', () => {
      const mockToastFunction = jest.fn()
      const longMessage = 'A'.repeat(1000)
      
      const result = showDeduplicatedToast(mockToastFunction, longMessage, 'info')
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith(longMessage)
    })

    it('should handle special characters in messages', () => {
      const mockToastFunction = jest.fn()
      const specialMessage = 'Message with "quotes" and symbols: !@#$%^&*()'
      
      const result = showDeduplicatedToast(mockToastFunction, specialMessage, 'info')
      expect(result).toBe(true)
      expect(mockToastFunction).toHaveBeenCalledWith(specialMessage)
    })
  })
})
