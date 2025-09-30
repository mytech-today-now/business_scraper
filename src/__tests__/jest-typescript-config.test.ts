/**
 * Jest TypeScript Configuration Validation Test
 * 
 * Tests to validate that our Jest TypeScript configuration enhancements
 * are working correctly, including custom matchers and type helpers.
 */

import { jest } from '@jest/globals'
import {
  createMockFunction,
  createMockResolvedFunction,
  createMockObject,
  createMockResponse,
  MockedFunction,
  MockedObject,
} from './utils/mockTypeHelpers'

import {
  createMockBusinessRecord,
  createMockUser,
  createMockSearchResult,
} from './utils/commonMocks'

describe('Jest TypeScript Configuration', () => {
  describe('Custom Matchers', () => {
    it('should validate business records with toBeValidBusinessRecord', () => {
      const validBusiness = createMockBusinessRecord()
      expect(validBusiness).toBeValidBusinessRecord()

      const invalidBusiness = { id: 'test' }
      expect(invalidBusiness).not.toBeValidBusinessRecord()
    })

    it('should validate email addresses with toBeValidEmailAddress', () => {
      expect('test@example.com').toBeValidEmailAddress()
      expect('invalid-email').not.toBeValidEmailAddress()
    })

    it('should validate phone numbers with toBeValidPhoneNumber', () => {
      expect('+1-555-123-4567').toBeValidPhoneNumber()
      expect('555-123-4567').toBeValidPhoneNumber()
      expect('invalid-phone').not.toBeValidPhoneNumber()
    })

    it('should validate URLs with toBeValidUrl', () => {
      expect('https://example.com').toBeValidUrl()
      expect('http://test.org').toBeValidUrl()
      expect('invalid-url').not.toBeValidUrl()
    })

    it('should validate addresses with toHaveValidAddress', () => {
      const businessWithAddress = createMockBusinessRecord({
        address: {
          street: '123 Main St',
          city: 'Test City',
          state: 'TS',
          zipCode: '12345',
        },
      })
      expect(businessWithAddress).toHaveValidAddress()

      const businessWithoutAddress = createMockBusinessRecord({
        address: {
          street: '',
          city: '',
          state: '',
          zipCode: '',
        },
      })
      expect(businessWithoutAddress).not.toHaveValidAddress()
    })

    it('should validate time ranges with toBeWithinTimeRange', () => {
      const now = new Date()
      const start = new Date(now.getTime() - 1000)
      const end = new Date(now.getTime() + 1000)
      
      expect(now).toBeWithinTimeRange(start, end)
      
      const pastDate = new Date(now.getTime() - 2000)
      expect(pastDate).not.toBeWithinTimeRange(start, end)
    })

    it('should validate business schema with toMatchBusinessSchema', () => {
      const validBusiness = createMockBusinessRecord()
      expect(validBusiness).toMatchBusinessSchema()

      const invalidBusiness = { id: 'test' }
      expect(invalidBusiness).not.toMatchBusinessSchema()
    })

    it('should validate industry categories with toHaveValidIndustryCategory', () => {
      const techBusiness = createMockBusinessRecord({ industry: 'Technology' })
      expect(techBusiness).toHaveValidIndustryCategory()

      const invalidBusiness = createMockBusinessRecord({ industry: 'InvalidIndustry' })
      expect(invalidBusiness).not.toHaveValidIndustryCategory()
    })

    it('should validate search results with toBeValidSearchResult', () => {
      const validResult = createMockSearchResult()
      expect(validResult).toBeValidSearchResult()

      const invalidResult = { title: 'test' }
      expect(invalidResult).not.toBeValidSearchResult()
    })

    it('should validate contact info with toHaveValidContactInfo', () => {
      const businessWithEmail = createMockBusinessRecord({
        email: ['test@example.com'],
        phone: '',
      })
      expect(businessWithEmail).toHaveValidContactInfo()

      const businessWithPhone = createMockBusinessRecord({
        email: [],
        phone: '555-123-4567',
      })
      expect(businessWithPhone).toHaveValidContactInfo()

      const businessWithoutContact = createMockBusinessRecord({
        email: [],
        phone: '',
      })
      expect(businessWithoutContact).not.toHaveValidContactInfo()
    })
  })

  describe('Mock Type Helpers', () => {
    it('should create properly typed mock functions', () => {
      const mockFn = createMockFunction<(x: number) => string>()
      mockFn.mockReturnValue('test')
      
      const result = mockFn(42)
      expect(result).toBe('test')
      expect(mockFn).toHaveBeenCalledWith(42)
    })

    it('should create properly typed resolved mock functions', () => {
      const mockAsyncFn = createMockResolvedFunction<() => Promise<string>>('resolved')
      
      return expect(mockAsyncFn()).resolves.toBe('resolved')
    })

    it('should create properly typed mock objects', () => {
      interface TestService {
        getData: () => Promise<string>
        processData: (data: string) => boolean
      }

      const mockService = createMockObject<TestService>({
        getData: createMockResolvedFunction<() => Promise<string>>('test-data'),
        processData: createMockFunction<(data: string) => boolean>(),
      })

      mockService.processData.mockReturnValue(true)

      expect(mockService.processData('test')).toBe(true)
      return expect(mockService.getData()).resolves.toBe('test-data')
    })

    it('should create properly typed mock responses', () => {
      const mockResponse = createMockResponse({ success: true, data: 'test' })
      
      expect(mockResponse.ok).toBe(true)
      expect(mockResponse.status).toBe(200)
      return expect(mockResponse.json()).resolves.toEqual({ success: true, data: 'test' })
    })
  })

  describe('Global Mock Utilities', () => {
    it('should have global mock utilities available', () => {
      expect(global.createMockFunction).toBeDefined()
      expect(global.createMockResolvedFunction).toBeDefined()
      expect(global.createMockObject).toBeDefined()
      expect(global.createMockResponse).toBeDefined()
      expect(global.createMockBusinessRecord).toBeDefined()
      expect(global.createMockUser).toBeDefined()
      expect(global.createMockSearchResult).toBeDefined()
    })

    it('should use global mock utilities', () => {
      const mockFn = global.createMockFunction<() => string>()
      mockFn.mockReturnValue('global-test')
      
      expect(mockFn()).toBe('global-test')
    })

    it('should create mock data using global factories', () => {
      const business = global.createMockBusinessRecord({ businessName: 'Global Test Business' })
      expect(business.businessName).toBe('Global Test Business')
      expect(business).toBeValidBusinessRecord()

      const user = global.createMockUser({ username: 'globaluser' })
      expect(user.username).toBe('globaluser')

      const searchResult = global.createMockSearchResult({ title: 'Global Search Result' })
      expect(searchResult.title).toBe('Global Search Result')
      expect(searchResult).toBeValidSearchResult()
    })
  })

  describe('TypeScript Type Safety', () => {
    it('should provide proper type inference for mock functions', () => {
      // This test validates that TypeScript types are working correctly
      const typedMockFn: MockedFunction<(input: { id: string; name: string }) => Promise<boolean>> = 
        createMockResolvedFunction<(input: { id: string; name: string }) => Promise<boolean>>(true)

      typedMockFn.mockResolvedValue(false)
      
      return expect(typedMockFn({ id: 'test', name: 'test' })).resolves.toBe(false)
    })

    it('should provide proper type inference for mock objects', () => {
      interface ComplexService {
        method1: (param: string) => number
        method2: (param: number) => Promise<string>
        property: boolean
      }

      const mockService: MockedObject<ComplexService> = createMockObject<ComplexService>({
        method1: createMockFunction<(param: string) => number>(),
        method2: createMockResolvedFunction<(param: number) => Promise<string>>('result'),
        property: true,
      })

      mockService.method1.mockReturnValue(42)
      
      expect(mockService.method1('test')).toBe(42)
      expect(mockService.property).toBe(true)
      return expect(mockService.method2(123)).resolves.toBe('result')
    })
  })

  describe('Jest Configuration Features', () => {
    it('should have proper test environment setup', () => {
      expect(process.env.NODE_ENV).toBe('test')
      expect(global.__TEST_ENV__).toBe('jest')
      expect(global.__MOCK_ENABLED__).toBe(true)
    })

    it('should have proper mock cleanup between tests', () => {
      const mockFn = jest.fn()
      mockFn('test-call')
      
      expect(mockFn).toHaveBeenCalledWith('test-call')
      
      // Mock should be cleared in beforeEach
      // This validates our global setup is working
    })

    it('should have access to enhanced Jest globals', () => {
      expect(jest.fn).toBeDefined()
      expect(jest.clearAllMocks).toBeDefined()
      expect(jest.resetAllMocks).toBeDefined()
      expect(jest.restoreAllMocks).toBeDefined()
    })
  })
})
