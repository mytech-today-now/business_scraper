/**
 * Advanced Duplicate Detection System
 * Sophisticated algorithms for identifying and managing duplicate business records
 */

import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface DuplicateMatch {
  record1: BusinessRecord
  record2: BusinessRecord
  confidence: number
  matchType: DuplicateMatchType
  matchedFields: string[]
  similarity: SimilarityScores
}

export interface SimilarityScores {
  businessName: number
  address: number
  phone: number
  email: number
  website: number
  overall: number
}

export type DuplicateMatchType = 
  | 'exact' 
  | 'high_confidence' 
  | 'medium_confidence' 
  | 'low_confidence' 
  | 'potential'

export interface DuplicateCluster {
  id: string
  records: BusinessRecord[]
  primaryRecord: BusinessRecord
  confidence: number
  mergeRecommendation: MergeRecommendation
}

export interface MergeRecommendation {
  shouldMerge: boolean
  confidence: number
  suggestedPrimary: BusinessRecord
  fieldsToMerge: Record<string, any>
  conflictingFields: string[]
}

export interface DuplicateDetectionConfig {
  enableFuzzyMatching: boolean
  enablePhoneticMatching: boolean
  enableGeographicClustering: boolean
  thresholds: {
    exact: number
    highConfidence: number
    mediumConfidence: number
    lowConfidence: number
  }
  weights: {
    businessName: number
    address: number
    phone: number
    email: number
    website: number
  }
}

/**
 * Advanced Duplicate Detection System
 */
export class DuplicateDetectionSystem {
  private config: DuplicateDetectionConfig
  private phoneticCache = new Map<string, string>()
  private similarityCache = new Map<string, number>()

  constructor(config?: Partial<DuplicateDetectionConfig>) {
    this.config = {
      enableFuzzyMatching: true,
      enablePhoneticMatching: true,
      enableGeographicClustering: true,
      thresholds: {
        exact: 0.95,
        highConfidence: 0.85,
        mediumConfidence: 0.70,
        lowConfidence: 0.55,
      },
      weights: {
        businessName: 0.3,
        address: 0.25,
        phone: 0.2,
        email: 0.15,
        website: 0.1,
      },
      ...config,
    }
  }

  /**
   * Find all duplicate matches in a dataset
   */
  async findDuplicates(records: BusinessRecord[]): Promise<DuplicateMatch[]> {
    logger.info('DuplicateDetection', `Analyzing ${records.length} records for duplicates`)

    const matches: DuplicateMatch[] = []
    const processedPairs = new Set<string>()

    for (let i = 0; i < records.length; i++) {
      for (let j = i + 1; j < records.length; j++) {
        const recordA = records[i]
        const recordB = records[j]

        if (!recordA || !recordB) continue

        const pairKey = `${recordA.id}-${recordB.id}`
        if (processedPairs.has(pairKey)) continue

        processedPairs.add(pairKey)

        const match = await this.compareRecords(recordA, recordB)
        if (match.confidence >= this.config.thresholds.lowConfidence) {
          matches.push(match)
        }
      }
    }

    logger.info('DuplicateDetection', `Found ${matches.length} potential duplicate matches`)
    return matches.sort((a, b) => b.confidence - a.confidence)
  }

  /**
   * Create duplicate clusters from matches
   */
  createClusters(matches: DuplicateMatch[]): DuplicateCluster[] {
    const clusters: DuplicateCluster[] = []
    const recordToCluster = new Map<string, DuplicateCluster>()

    // Group matches into clusters
    for (const match of matches) {
      const cluster1 = recordToCluster.get(match.record1.id)
      const cluster2 = recordToCluster.get(match.record2.id)

      if (!cluster1 && !cluster2) {
        // Create new cluster
        const cluster = this.createNewCluster([match.record1, match.record2], match.confidence)
        clusters.push(cluster)
        recordToCluster.set(match.record1.id, cluster)
        recordToCluster.set(match.record2.id, cluster)
      } else if (cluster1 && !cluster2) {
        // Add record2 to cluster1
        cluster1.records.push(match.record2)
        recordToCluster.set(match.record2.id, cluster1)
        this.updateClusterConfidence(cluster1)
      } else if (!cluster1 && cluster2) {
        // Add record1 to cluster2
        cluster2.records.push(match.record1)
        recordToCluster.set(match.record1.id, cluster2)
        this.updateClusterConfidence(cluster2)
      } else if (cluster1 && cluster2 && cluster1 !== cluster2) {
        // Merge clusters
        this.mergeClusters(cluster1, cluster2, clusters)
        
        // Update record mappings
        for (const record of cluster2.records) {
          recordToCluster.set(record.id, cluster1)
        }
      }
    }

    // Generate merge recommendations for each cluster
    clusters.forEach(cluster => {
      cluster.mergeRecommendation = this.generateMergeRecommendation(cluster.records)
    })

    logger.info('DuplicateDetection', `Created ${clusters.length} duplicate clusters`)
    return clusters
  }

  /**
   * Compare two business records for similarity
   */
  async compareRecords(record1: BusinessRecord, record2: BusinessRecord): Promise<DuplicateMatch> {
    const similarity = await this.calculateSimilarity(record1, record2)
    const matchedFields = this.getMatchedFields(record1, record2, similarity)
    const matchType = this.determineMatchType(similarity.overall)

    return {
      record1,
      record2,
      confidence: similarity.overall,
      matchType,
      matchedFields,
      similarity,
    }
  }

  /**
   * Calculate similarity scores between two records
   */
  private async calculateSimilarity(record1: BusinessRecord, record2: BusinessRecord): Promise<SimilarityScores> {
    const businessNameSim = this.calculateBusinessNameSimilarity(record1.businessName, record2.businessName)
    const addressSim = this.calculateAddressSimilarity(record1.address, record2.address)
    const phoneSim = this.calculatePhoneSimilarity(record1.phone, record2.phone)
    const emailSim = this.calculateEmailSimilarity(record1.email, record2.email)
    const websiteSim = this.calculateWebsiteSimilarity(record1.websiteUrl, record2.websiteUrl)

    const overall = (
      businessNameSim * this.config.weights.businessName +
      addressSim * this.config.weights.address +
      phoneSim * this.config.weights.phone +
      emailSim * this.config.weights.email +
      websiteSim * this.config.weights.website
    )

    return {
      businessName: businessNameSim,
      address: addressSim,
      phone: phoneSim,
      email: emailSim,
      website: websiteSim,
      overall,
    }
  }

  /**
   * Calculate business name similarity
   */
  private calculateBusinessNameSimilarity(name1: string, name2: string): number {
    if (!name1 || !name2) return 0

    // Exact match
    if (name1.toLowerCase() === name2.toLowerCase()) return 1.0

    // Normalize names
    const normalized1 = this.normalizeBusinessName(name1)
    const normalized2 = this.normalizeBusinessName(name2)

    if (normalized1 === normalized2) return 0.95

    // Fuzzy matching
    if (this.config.enableFuzzyMatching) {
      const fuzzyScore = this.calculateLevenshteinSimilarity(normalized1, normalized2)
      
      // Phonetic matching
      if (this.config.enablePhoneticMatching) {
        const phonetic1 = this.getPhoneticCode(normalized1)
        const phonetic2 = this.getPhoneticCode(normalized2)
        
        if (phonetic1 === phonetic2) {
          return Math.max(fuzzyScore, 0.8)
        }
      }
      
      return fuzzyScore
    }

    return 0
  }

  /**
   * Calculate address similarity
   */
  private calculateAddressSimilarity(addr1: BusinessRecord['address'], addr2: BusinessRecord['address']): number {
    if (!addr1 || !addr2) return 0

    // Exact match
    if (this.formatAddress(addr1) === this.formatAddress(addr2)) return 1.0

    let score = 0
    let components = 0

    // Compare street addresses
    if (addr1.street && addr2.street) {
      components++
      const streetSim = this.calculateLevenshteinSimilarity(
        this.normalizeAddress(addr1.street),
        this.normalizeAddress(addr2.street)
      )
      score += streetSim * 0.4
    }

    // Compare cities
    if (addr1.city && addr2.city) {
      components++
      score += (addr1.city.toLowerCase() === addr2.city.toLowerCase() ? 1 : 0) * 0.3
    }

    // Compare states
    if (addr1.state && addr2.state) {
      components++
      score += (addr1.state.toLowerCase() === addr2.state.toLowerCase() ? 1 : 0) * 0.2
    }

    // Compare ZIP codes
    if (addr1.zipCode && addr2.zipCode) {
      components++
      const zip1 = addr1.zipCode.split('-')[0]
      const zip2 = addr2.zipCode.split('-')[0]
      score += (zip1 === zip2 ? 1 : 0) * 0.1
    }

    return components > 0 ? score : 0
  }

  /**
   * Calculate phone similarity
   */
  private calculatePhoneSimilarity(phone1?: string, phone2?: string): number {
    if (!phone1 || !phone2) return 0

    const normalized1 = this.normalizePhone(phone1)
    const normalized2 = this.normalizePhone(phone2)

    return normalized1 === normalized2 ? 1.0 : 0
  }

  /**
   * Calculate email similarity
   */
  private calculateEmailSimilarity(emails1: string[], emails2: string[]): number {
    if (!emails1?.length || !emails2?.length) return 0

    const set1 = new Set(emails1.map(e => e.toLowerCase()))
    const set2 = new Set(emails2.map(e => e.toLowerCase()))

    const intersection = new Set(Array.from(set1).filter(x => set2.has(x)))
    const union = new Set([...Array.from(set1), ...Array.from(set2)])

    return intersection.size / union.size
  }

  /**
   * Calculate website similarity
   */
  private calculateWebsiteSimilarity(website1?: string, website2?: string): number {
    if (!website1 || !website2) return 0

    const domain1 = this.extractDomain(website1)
    const domain2 = this.extractDomain(website2)

    return domain1 === domain2 ? 1.0 : 0
  }

  /**
   * Calculate Levenshtein similarity
   */
  private calculateLevenshteinSimilarity(str1: string, str2: string): number {
    const cacheKey = `${str1}|${str2}`
    if (this.similarityCache.has(cacheKey)) {
      return this.similarityCache.get(cacheKey)!
    }

    const distance = this.levenshteinDistance(str1, str2)
    const maxLength = Math.max(str1.length, str2.length)
    const similarity = maxLength === 0 ? 1 : 1 - (distance / maxLength)

    this.similarityCache.set(cacheKey, similarity)
    return similarity
  }

  /**
   * Calculate Levenshtein distance
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(0))

    for (let i = 0; i <= str1.length; i++) {
      matrix[0]![i] = i
    }
    for (let j = 0; j <= str2.length; j++) {
      matrix[j]![0] = j
    }

    for (let j = 1; j <= str2.length; j++) {
      for (let i = 1; i <= str1.length; i++) {
        const indicator = str1[i - 1] === str2[j - 1] ? 0 : 1
        matrix[j]![i] = Math.min(
          matrix[j]![i - 1]! + 1,
          matrix[j - 1]![i]! + 1,
          matrix[j - 1]![i - 1]! + indicator
        )
      }
    }

    return matrix[str2.length]?.[str1.length] ?? 0
  }

  /**
   * Normalize business name for comparison
   */
  private normalizeBusinessName(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^\w\s]/g, '')
      .replace(/\b(inc|llc|corp|ltd|company|co)\b/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  }

  /**
   * Normalize address for comparison
   */
  private normalizeAddress(address: string): string {
    return address
      .toLowerCase()
      .replace(/\b(street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln)\b/g, '')
      .replace(/[^\w\s]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  }

  /**
   * Normalize phone number
   */
  private normalizePhone(phone: string): string {
    return phone.replace(/[^\d]/g, '')
  }

  /**
   * Get phonetic code for a string (simplified Soundex)
   */
  private getPhoneticCode(str: string): string {
    if (this.phoneticCache.has(str)) {
      return this.phoneticCache.get(str)!
    }

    const code = this.soundex(str)
    this.phoneticCache.set(str, code)
    return code
  }

  /**
   * Simplified Soundex algorithm
   */
  private soundex(str: string): string {
    const cleaned = str.toLowerCase().replace(/[^a-z]/g, '')
    if (!cleaned) return '0000'

    const firstLetter = cleaned[0]!
    const mapping: Record<string, string> = {
      'bfpv': '1', 'cgjkqsxz': '2', 'dt': '3',
      'l': '4', 'mn': '5', 'r': '6'
    }

    let code = firstLetter
    for (let i = 1; i < cleaned.length && code.length < 4; i++) {
      const char = cleaned[i]!
      for (const [chars, digit] of Object.entries(mapping)) {
        if (chars.includes(char) && code[code.length - 1] !== digit) {
          code += digit
          break
        }
      }
    }

    return code.padEnd(4, '0').substring(0, 4)
  }

  /**
   * Extract domain from URL
   */
  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname.replace('www.', '')
    } catch {
      return url
    }
  }

  /**
   * Format address as string
   */
  private formatAddress(address: BusinessRecord['address']): string {
    return [address.street, address.city, address.state, address.zipCode]
      .filter(Boolean)
      .join(', ')
      .toLowerCase()
  }

  /**
   * Determine match type based on confidence
   */
  private determineMatchType(confidence: number): DuplicateMatchType {
    if (confidence >= this.config.thresholds.exact) return 'exact'
    if (confidence >= this.config.thresholds.highConfidence) return 'high_confidence'
    if (confidence >= this.config.thresholds.mediumConfidence) return 'medium_confidence'
    if (confidence >= this.config.thresholds.lowConfidence) return 'low_confidence'
    return 'potential'
  }

  /**
   * Get matched fields between two records
   */
  private getMatchedFields(record1: BusinessRecord, record2: BusinessRecord, similarity: SimilarityScores): string[] {
    const matched: string[] = []
    
    if (similarity.businessName > 0.8) matched.push('businessName')
    if (similarity.address > 0.8) matched.push('address')
    if (similarity.phone > 0.8) matched.push('phone')
    if (similarity.email > 0.8) matched.push('email')
    if (similarity.website > 0.8) matched.push('website')

    return matched
  }

  /**
   * Create a new duplicate cluster
   */
  private createNewCluster(records: BusinessRecord[], confidence: number): DuplicateCluster {
    const primaryRecord = this.selectPrimaryRecord(records)
    
    return {
      id: `cluster-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      records,
      primaryRecord,
      confidence,
      mergeRecommendation: this.generateMergeRecommendation(records),
    }
  }

  /**
   * Update cluster confidence
   */
  private updateClusterConfidence(cluster: DuplicateCluster): void {
    // Recalculate confidence based on all records in cluster
    // For now, use a simple average
    cluster.confidence = 0.8 // Simplified
  }

  /**
   * Merge two clusters
   */
  private mergeClusters(cluster1: DuplicateCluster, cluster2: DuplicateCluster, clusters: DuplicateCluster[]): void {
    cluster1.records.push(...cluster2.records)
    cluster1.primaryRecord = this.selectPrimaryRecord(cluster1.records)
    
    const index = clusters.indexOf(cluster2)
    if (index > -1) {
      clusters.splice(index, 1)
    }
  }

  /**
   * Select primary record from a group
   */
  private selectPrimaryRecord(records: BusinessRecord[]): BusinessRecord {
    // Select record with most complete data
    return records.reduce((best, current) => {
      const bestScore = this.calculateCompletenessScore(best)
      const currentScore = this.calculateCompletenessScore(current)
      return currentScore > bestScore ? current : best
    })
  }

  /**
   * Calculate completeness score for a record
   */
  private calculateCompletenessScore(record: BusinessRecord): number {
    let score = 0
    if (record.businessName) score += 1
    if (record.email?.length) score += 1
    if (record.phone) score += 1
    if (record.websiteUrl) score += 1
    if (record.address?.street) score += 1
    return score
  }

  /**
   * Generate merge recommendation for a cluster
   */
  private generateMergeRecommendation(records: BusinessRecord[]): MergeRecommendation {
    const primaryRecord = this.selectPrimaryRecord(records)
    const fieldsToMerge: Record<string, any> = {}
    const conflictingFields: string[] = []

    // Merge email addresses
    const allEmails = new Set<string>()
    records.forEach(record => {
      record.email?.forEach(email => allEmails.add(email.toLowerCase()))
    })
    fieldsToMerge.email = Array.from(allEmails)

    // Check for conflicts in other fields
    const fields = ['businessName', 'phone', 'website', 'industry']
    fields.forEach(field => {
      const values = new Set(records.map(r => (r as any)[field]).filter(Boolean))
      if (values.size > 1) {
        conflictingFields.push(field)
      }
    })

    return {
      shouldMerge: conflictingFields.length <= 2,
      confidence: conflictingFields.length === 0 ? 0.9 : 0.7,
      suggestedPrimary: primaryRecord,
      fieldsToMerge,
      conflictingFields,
    }
  }
}

/**
 * Default duplicate detection system instance
 */
export const duplicateDetectionSystem = new DuplicateDetectionSystem()
