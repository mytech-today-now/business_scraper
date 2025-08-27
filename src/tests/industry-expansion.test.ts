import { clientSearchEngine } from '@/model/clientSearchEngine'

describe('Industry Expansion Tests', () => {
  test('should expand Professional Services into individual keywords', () => {
    // Access the private method through reflection for testing
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('Professional Services businesses')

    expect(result).toEqual(['consulting', 'legal', 'accounting', 'financial', 'insurance'])
  })

  test('should expand Healthcare into individual keywords', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('Healthcare & Medical')

    expect(result).toEqual(['medical', 'healthcare', 'clinic', 'hospital', 'dental'])
  })

  test('should expand Restaurants into individual keywords', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('Restaurants & Food Service')

    expect(result).toEqual(['restaurant', 'cafe', 'food service', 'catering', 'dining'])
  })

  test('should expand Automotive into individual keywords', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('Automotive businesses')

    expect(result).toEqual(['automotive', 'car repair', 'auto service', 'mechanic', 'tire service'])
  })

  test('should handle comma-separated terms when no industry expansion applies', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('plumber, electrician, carpenter')

    expect(result).toEqual(['plumber', 'electrician', 'carpenter'])
  })

  test('should handle quoted phrases', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('"medical clinic", "dental office"')

    // Should contain both quoted phrases
    expect(result).toContain('medical clinic')
    expect(result).toContain('dental office')
    expect(result.length).toBe(2)
  })

  test('should handle mixed industry and specific terms', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    // When no industry expansion applies, should parse as comma-separated
    const result = parseMethod('dentist, lawyer, accountant')

    expect(result).toEqual(['dentist', 'lawyer', 'accountant'])
  })

  test('should handle case insensitive industry matching', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('PROFESSIONAL SERVICES')

    expect(result).toEqual(['consulting', 'legal', 'accounting', 'financial', 'insurance'])
  })

  test('should handle partial industry matches', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('professional')

    expect(result).toEqual(['consulting', 'legal', 'accounting', 'financial', 'insurance'])
  })

  test('should fallback to original query when no parsing applies', () => {
    const parseMethod = (clientSearchEngine as any).parseIndustryCriteria.bind(clientSearchEngine)

    const result = parseMethod('unique business type')

    expect(result).toEqual(['unique business type'])
  })
})
