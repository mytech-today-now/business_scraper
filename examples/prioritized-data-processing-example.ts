/**
 * Example: Prioritized Data Processing for Business Contact Exports
 *
 * This example demonstrates the new prioritized data processing system that:
 * 1. Prioritizes email addresses, phone numbers, and address information
 * 2. Eliminates duplicates based on key contact fields
 * 3. Produces clean, high-quality export files
 */

import { BusinessRecord } from '../src/types/business'
import { prioritizedDataProcessor } from '../src/lib/prioritizedDataProcessor'
import { prioritizedExportFormatter } from '../src/utils/prioritizedExportFormatter'

async function demonstratePrioritizedProcessing() {
  console.log('🎯 Prioritized Data Processing Example\n')

  // Example raw scraped data with duplicates and quality issues
  const rawScrapedData: BusinessRecord[] = [
    {
      id: '1',
      businessName: 'ABC Financial Services',
      email: ['noreply@abc-financial.com', 'info@abc-financial.com', 'contact@abc-financial.com'],
      phone: '555-123-4567',
      websiteUrl: 'https://abc-financial.com',
      address: {
        street: '123 Main Street',
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
      },
      contactPerson: 'John Smith',
      coordinates: { lat: 40.7128, lng: -74.006 },
      industry: 'Financial Services',
      scrapedAt: new Date(),
    },
    {
      id: '2',
      businessName: 'ABC Financial Services LLC', // Slight variation
      email: ['info@abc-financial.com'], // Same primary email
      phone: '555-123-4567', // Same phone
      websiteUrl: 'https://abc-financial.com/about',
      address: {
        street: '123 Main Street', // Same address
        city: 'New York',
        state: 'NY',
        zipCode: '10001',
      },
      contactPerson: 'Jane Doe', // Different contact
      industry: 'Financial Services',
      scrapedAt: new Date(),
    },
    {
      id: '3',
      businessName: 'XYZ Event Planning',
      email: ['hello@xyzeventplanning.com', 'events@xyzeventplanning.com'],
      phone: '555-987-6543',
      websiteUrl: 'https://xyzeventplanning.com',
      address: {
        street: '456 Broadway',
        city: 'New York',
        state: 'NY',
        zipCode: '10002',
      },
      contactPerson: 'Sarah Johnson',
      industry: 'Event Planning',
      scrapedAt: new Date(),
    },
    {
      id: '4',
      businessName: 'Low Quality Business',
      email: [], // No email
      phone: '', // No phone
      websiteUrl: 'https://lowquality.com',
      address: {
        street: '', // No address
        city: '',
        state: '',
        zipCode: '',
      },
      industry: 'Unknown',
      scrapedAt: new Date(),
    },
    {
      id: '5',
      businessName: '  MESSY   DATA   COMPANY  ',
      email: ['  CONTACT@MESSY.COM  ', 'Info@Messy.Com'],
      phone: '(555) 555-1234',
      websiteUrl: 'https://messy.com',
      address: {
        street: '  789   Oak   Street  ',
        city: '  Los   Angeles  ',
        state: 'ca',
        zipCode: '90210-1234',
      },
      contactPerson: '  Bob   Wilson  ',
      industry: 'Technology',
      scrapedAt: new Date(),
    },
  ]

  console.log(`📊 Original Data: ${rawScrapedData.length} records`)
  console.log('Issues with original data:')
  console.log('- Duplicate businesses with slight variations')
  console.log('- Mixed email priorities (noreply vs info vs contact)')
  console.log('- Inconsistent data formatting')
  console.log('- Records without valuable contact information\n')

  // Process data with prioritized system
  console.log('🔄 Processing with prioritized data processor...')
  const { processedRecords, stats } =
    await prioritizedDataProcessor.processBusinessRecords(rawScrapedData)

  console.log('\n📈 Processing Results:')
  console.log(`- Original records: ${stats.totalRecords}`)
  console.log(`- Records with email: ${stats.recordsWithEmail}`)
  console.log(`- Records with phone: ${stats.recordsWithPhone}`)
  console.log(`- Records with address: ${stats.recordsWithAddress}`)
  console.log(`- Duplicates removed: ${stats.duplicatesRemoved}`)
  console.log(`- Final high-quality records: ${stats.finalRecords}\n`)

  // Show prioritized data structure
  console.log('🎯 Prioritized Data Structure:')
  processedRecords.forEach((record, index) => {
    console.log(`\nRecord ${index + 1}:`)
    console.log(`  📧 Primary Email: ${record.email}`)
    console.log(`  📞 Phone: ${record.phone}`)
    console.log(
      `  🏠 Address: ${record.streetAddress}, ${record.city}, ${record.state} ${record.zipCode}`
    )
    console.log(`  🏢 Business: ${record.businessName}`)
    console.log(`  👤 Contact: ${record.contactName}`)
    console.log(`  ⭐ Quality Score: ${Math.round(record.confidence * 100)}%`)
    if (record.additionalEmails.length > 0) {
      console.log(`  📧 Additional Emails: ${record.additionalEmails.join(', ')}`)
    }
    if (record.sources.length > 1) {
      console.log(`  🔗 Sources: ${record.sources.length} URLs`)
    }
  })

  // Generate export formats
  console.log('\n📄 Export Examples:')

  // CSV Export
  console.log('\n1. CSV Export (Priority-based columns):')
  const csvContent = prioritizedExportFormatter.formatForCSV(processedRecords)
  const csvLines = csvContent.split('\n').slice(0, 3) // Show header + 2 data rows
  csvLines.forEach(line => console.log(`   ${line}`))
  if (processedRecords.length > 2) {
    console.log(`   ... and ${processedRecords.length - 2} more records`)
  }

  // Export Summary
  console.log('\n2. Export Summary:')
  const summary = prioritizedExportFormatter.generateExportSummary(processedRecords)
  console.log(`   - Total Records: ${summary.totalRecords}`)
  console.log(`   - With Email: ${summary.recordsWithEmail}`)
  console.log(`   - With Phone: ${summary.recordsWithPhone}`)
  console.log(`   - With Complete Address: ${summary.recordsWithAddress}`)
  console.log(`   - With Contact Name: ${summary.recordsWithContact}`)
  console.log(`   - Average Quality: ${Math.round(summary.averageConfidence * 100)}%`)

  // Filename Generation
  console.log('\n3. Smart Filename Generation:')
  const filename = prioritizedExportFormatter.generateFilename({
    industries: ['Financial Services', 'Event Planning'],
    location: 'New York, NY',
    totalRecords: processedRecords.length,
  })
  console.log(`   Generated filename: ${filename}.xlsx`)

  console.log('\n✅ Key Benefits of Prioritized Processing:')
  console.log('   🎯 Email Priority: info@ and contact@ emails prioritized over noreply@')
  console.log('   🔄 Smart Deduplication: Merges duplicate businesses based on key contact fields')
  console.log('   🧹 Data Cleaning: Standardizes formatting and removes low-quality records')
  console.log('   📊 Quality Scoring: Assigns confidence scores based on data completeness')
  console.log('   📋 Priority Columns: Email, Phone, Address fields come first in exports')
  console.log('   📈 Export Analytics: Provides detailed statistics about data quality')

  console.log('\n🎉 Prioritized data processing complete!')
  console.log('Your export files will now contain high-quality, deduplicated business contacts')
  console.log('with the most valuable information prioritized and properly formatted.')
}

// Export for use in other files
export { demonstratePrioritizedProcessing }

// Run if called directly
if (require.main === module) {
  demonstratePrioritizedProcessing().catch(console.error)
}
