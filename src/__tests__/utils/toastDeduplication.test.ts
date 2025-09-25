/**
 * Toast Deduplication Utility Tests
 * 
 * Tests for the toast deduplication mechanism to prevent duplicate notifications.
 */

import { 
  toastDeduplication, 
  showDeduplicatedToast, 
  showDeduplicatedSuccessToast,
  showDeduplicatedErrorToast 
} from '@/utils/toastDeduplication'

describe('ToastDeduplication', () => {
  beforeEach(() => {
    // Clear any existing toast records before each test
    toastDeduplication.clear()
    jest.clearAllMocks()
  })

  describe('shouldShowToast', () => {
    it('should allow the first toast with a message', () => {
      const result = toastDeduplication.shouldShowToast('Test message', 'success')
      expect(result).toBe(true)
    })

    it('should prevent duplicate toasts within the deduplication window', () => {
      const message = 'ZIP code "60047" is valid'
      
      // First toast should be allowed
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
      
      // Immediate duplicate should be prevented
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(false)
      
      // Another immediate duplicate should also be prevented
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(false)
    })

    it('should allow the same message after the deduplication window expires', async () => {
      const message = 'Test message'
      
      // Mock Date.now to control time
      const originalDateNow = Date.now
      let currentTime = 1000000
      Date.now = jest.fn(() => currentTime)
      
      try {
        // First toast should be allowed
        expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
        
        // Immediate duplicate should be prevented
        expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(false)
        
        // Advance time beyond deduplication window (5000ms)
        currentTime += 6000
        
        // Should now allow the toast again
        expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
      } finally {
        Date.now = originalDateNow
      }
    })

    it('should treat different message types as separate', () => {
      const message = 'Same message'
      
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
      expect(toastDeduplication.shouldShowToast(message, 'error')).toBe(true)
      expect(toastDeduplication.shouldShowToast(message, 'warning')).toBe(true)
      expect(toastDeduplication.shouldShowToast(message, 'info')).toBe(true)
    })

    it('should treat different messages as separate', () => {
      expect(toastDeduplication.shouldShowToast('Message 1', 'success')).toBe(true)
      expect(toastDeduplication.shouldShowToast('Message 2', 'success')).toBe(true)
      expect(toastDeduplication.shouldShowToast('Message 3', 'success')).toBe(true)
    })
  })

  describe('memory management', () => {
    it('should clean up old records', () => {
      const originalDateNow = Date.now
      let currentTime = 1000000
      Date.now = jest.fn(() => currentTime)
      
      try {
        // Add some toasts
        toastDeduplication.shouldShowToast('Message 1', 'success')
        toastDeduplication.shouldShowToast('Message 2', 'success')
        
        expect(toastDeduplication.getRecordCount()).toBe(2)
        
        // Advance time beyond cleanup threshold (5000ms)
        currentTime += 6000
        
        // Trigger cleanup by adding a new toast
        toastDeduplication.shouldShowToast('Message 3', 'success')
        
        // Old records should be cleaned up
        expect(toastDeduplication.getRecordCount()).toBe(1)
      } finally {
        Date.now = originalDateNow
      }
    })

    it('should limit the number of records to prevent memory leaks', () => {
      // Add more than MAX_RECORDS (50) toasts
      for (let i = 0; i < 60; i++) {
        toastDeduplication.shouldShowToast(`Message ${i}`, 'success')
      }

      // Should not exceed the maximum by much (allowing for some buffer during cleanup)
      expect(toastDeduplication.getRecordCount()).toBeLessThanOrEqual(52)
    })
  })

  describe('forceShowToast', () => {
    it('should allow a toast even if it would normally be deduplicated', () => {
      const message = 'Test message'
      
      // First toast should be allowed
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
      
      // Duplicate should be prevented
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(false)
      
      // Force allow the toast
      toastDeduplication.forceShowToast(message, 'success')
      
      // Should now be allowed again
      expect(toastDeduplication.shouldShowToast(message, 'success')).toBe(true)
    })
  })

  describe('clear', () => {
    it('should clear all toast records', () => {
      toastDeduplication.shouldShowToast('Message 1', 'success')
      toastDeduplication.shouldShowToast('Message 2', 'error')
      
      expect(toastDeduplication.getRecordCount()).toBe(2)
      
      toastDeduplication.clear()
      
      expect(toastDeduplication.getRecordCount()).toBe(0)
    })
  })
})

describe('showDeduplicatedToast', () => {
  const mockToastFunction = jest.fn()

  beforeEach(() => {
    toastDeduplication.clear()
    mockToastFunction.mockClear()
  })

  it('should call the toast function for the first occurrence', () => {
    const result = showDeduplicatedToast(mockToastFunction, 'Test message', 'success')
    
    expect(result).toBe(true)
    expect(mockToastFunction).toHaveBeenCalledWith('Test message')
    expect(mockToastFunction).toHaveBeenCalledTimes(1)
  })

  it('should not call the toast function for duplicates', () => {
    showDeduplicatedToast(mockToastFunction, 'Test message', 'success')
    mockToastFunction.mockClear()
    
    const result = showDeduplicatedToast(mockToastFunction, 'Test message', 'success')
    
    expect(result).toBe(false)
    expect(mockToastFunction).not.toHaveBeenCalled()
  })
})

describe('showDeduplicatedSuccessToast', () => {
  const mockToastFunction = jest.fn()

  beforeEach(() => {
    toastDeduplication.clear()
    mockToastFunction.mockClear()
  })

  it('should call the toast function for success toasts', () => {
    const result = showDeduplicatedSuccessToast(mockToastFunction, 'Success message')
    
    expect(result).toBe(true)
    expect(mockToastFunction).toHaveBeenCalledWith('Success message')
  })

  it('should prevent duplicate success toasts', () => {
    showDeduplicatedSuccessToast(mockToastFunction, 'Success message')
    mockToastFunction.mockClear()
    
    const result = showDeduplicatedSuccessToast(mockToastFunction, 'Success message')
    
    expect(result).toBe(false)
    expect(mockToastFunction).not.toHaveBeenCalled()
  })
})

describe('showDeduplicatedErrorToast', () => {
  const mockToastFunction = jest.fn()

  beforeEach(() => {
    toastDeduplication.clear()
    mockToastFunction.mockClear()
  })

  it('should call the toast function for error toasts', () => {
    const result = showDeduplicatedErrorToast(mockToastFunction, 'Error message')
    
    expect(result).toBe(true)
    expect(mockToastFunction).toHaveBeenCalledWith('Error message')
  })

  it('should prevent duplicate error toasts', () => {
    showDeduplicatedErrorToast(mockToastFunction, 'Error message')
    mockToastFunction.mockClear()
    
    const result = showDeduplicatedErrorToast(mockToastFunction, 'Error message')
    
    expect(result).toBe(false)
    expect(mockToastFunction).not.toHaveBeenCalled()
  })
})
