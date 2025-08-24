/**
 * Unit Tests for Advanced Email Validation Service
 * Comprehensive test suite for advanced email validation features
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals'
import { EmailValidationService } from '@/lib/emailValidationService'
import { EmailValidationResult } from '@/types/business'

// Mock DNS module
jest.mock('dns/promises', () => ({
  resolveMx: jest.fn()
}))

// Mock net module for SMTP testing
jest.mock('net', () => ({
  Socket: jest.fn().mockImplementation(() => ({
    connect: jest.fn(),
    write: jest.fn(),
    end: jest.fn(),
    destroy: jest.fn(),
    on: jest.fn()
  }))
}))

describe('EmailValidationService - Advanced Features', () => {
  let emailValidationService: EmailValidationService
  const mockResolveMx = require('dns/promises').resolveMx as jest.MockedFunction<any>

  beforeEach(() => {
    emailValidationService = EmailValidationService.getInstance()
    emailValidationService.clearCache()
    jest.clearAllMocks()
  })

  afterEach(() => {
    emailValidationService.clearCache()
  })

  describe('Basic Email Validation', () => {
    it('should validate correct email format', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result.email).toBe('test@example.com')
      expect(result.isValid).toBe(true)
      expect(result.domain).toBe('example.com')
      expect(result.mxRecords).toBe(true)
    })

    it('should reject invalid email format', async () => {
      const result = await emailValidationService.validateEmail('invalid-email')
      
      expect(result.isValid).toBe(false)
      expect(result.errors).toContain('Invalid email syntax')
    })

    it('should detect disposable email domains', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.10minutemail.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@10minutemail.com')
      
      expect(result.isDisposable).toBe(true)
      expect(result.isValid).toBe(false)
    })

    it('should detect role-based emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('info@example.com')
      
      expect(result.isRoleBased).toBe(true)
    })
  })

  describe('Advanced Email Validation Features', () => {
    it('should include SMTP verification results', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result).toHaveProperty('smtpVerified')
      expect(result).toHaveProperty('mailServerResponse')
      expect(result).toHaveProperty('greylisted')
    })

    it('should include catch-all domain detection', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result).toHaveProperty('catchAllDomain')
      expect(typeof result.catchAllDomain).toBe('boolean')
    })

    it('should include reputation scoring', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.gmail.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@gmail.com')
      
      expect(result).toHaveProperty('reputationScore')
      expect(typeof result.reputationScore).toBe('number')
      expect(result.reputationScore).toBeGreaterThanOrEqual(0)
      expect(result.reputationScore).toBeLessThanOrEqual(100)
    })

    it('should include bounce rate prediction', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result).toHaveProperty('bounceRatePrediction')
      expect(typeof result.bounceRatePrediction).toBe('number')
      expect(result.bounceRatePrediction).toBeGreaterThanOrEqual(0)
      expect(result.bounceRatePrediction).toBeLessThanOrEqual(100)
    })

    it('should give higher reputation scores to trusted providers', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.gmail.com', priority: 10 }])
      
      const gmailResult = await emailValidationService.validateEmail('test@gmail.com')
      
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.unknown-domain.com', priority: 10 }])
      
      const unknownResult = await emailValidationService.validateEmail('test@unknown-domain.com')
      
      expect(gmailResult.reputationScore).toBeGreaterThan(unknownResult.reputationScore!)
    })
  })

  describe('Batch Email Validation', () => {
    it('should validate multiple emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const emails = ['test1@example.com', 'test2@example.com', 'invalid-email']
      const results = await emailValidationService.validateEmails(emails)
      
      expect(results).toHaveLength(3)
      expect(results[0].isValid).toBe(true)
      expect(results[1].isValid).toBe(true)
      expect(results[2].isValid).toBe(false)
    })
  })

  describe('Caching', () => {
    it('should cache validation results', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      // First call
      await emailValidationService.validateEmail('test@example.com')
      
      // Second call should use cache
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result.email).toBe('test@example.com')
      // DNS should only be called once due to caching
      expect(mockResolveMx).toHaveBeenCalledTimes(1)
    })

    it('should provide cache statistics', () => {
      const stats = emailValidationService.getCacheStats()
      
      expect(stats).toHaveProperty('validationCacheSize')
      expect(stats).toHaveProperty('mxCacheSize')
      expect(stats).toHaveProperty('smtpCacheSize')
      expect(stats).toHaveProperty('catchAllCacheSize')
      expect(stats).toHaveProperty('reputationCacheSize')
    })

    it('should clear all caches', () => {
      emailValidationService.clearCache()
      
      const stats = emailValidationService.getCacheStats()
      expect(stats.validationCacheSize).toBe(0)
      expect(stats.mxCacheSize).toBe(0)
      expect(stats.smtpCacheSize).toBe(0)
      expect(stats.catchAllCacheSize).toBe(0)
      expect(stats.reputationCacheSize).toBe(0)
    })
  })

  describe('Error Handling', () => {
    it('should handle DNS resolution failures gracefully', async () => {
      mockResolveMx.mockRejectedValue(new Error('DNS resolution failed'))
      
      const result = await emailValidationService.validateEmail('test@nonexistent.com')
      
      expect(result.isValid).toBe(false)
      expect(result.mxRecords).toBe(false)
    })

    it('should handle SMTP connection failures gracefully', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      // Should still provide a result even if SMTP fails
      expect(result).toHaveProperty('smtpVerified')
      expect(result).toHaveProperty('reputationScore')
    })
  })

  describe('Confidence Scoring', () => {
    it('should provide higher confidence for valid emails with good reputation', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.gmail.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('john.doe@gmail.com')
      
      expect(result.confidence).toBeGreaterThan(70)
    })

    it('should provide lower confidence for disposable emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.10minutemail.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@10minutemail.com')
      
      expect(result.confidence).toBeLessThan(50)
    })

    it('should provide zero confidence for invalid syntax', async () => {
      const result = await emailValidationService.validateEmail('invalid-email')
      
      expect(result.confidence).toBe(0)
    })
  })

  describe('Deliverability Scoring', () => {
    it('should calculate deliverability score based on multiple factors', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.example.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@example.com')
      
      expect(result.deliverabilityScore).toBeGreaterThanOrEqual(0)
      expect(result.deliverabilityScore).toBeLessThanOrEqual(100)
    })

    it('should give higher deliverability scores to verified emails', async () => {
      mockResolveMx.mockResolvedValue([{ exchange: 'mx.gmail.com', priority: 10 }])
      
      const result = await emailValidationService.validateEmail('test@gmail.com')
      
      expect(result.deliverabilityScore).toBeGreaterThan(50)
    })
  })
})
