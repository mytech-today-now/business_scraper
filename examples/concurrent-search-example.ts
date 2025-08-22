/**
 * Example: Using Concurrent Search in SearchOrchestrator
 * 
 * This example demonstrates how to use the new concurrent search functionality
 * to improve search performance by running multiple providers simultaneously.
 */

import { searchOrchestrator, SearchOptions } from '../src/lib/searchProviderAbstraction'

async function demonstrateConcurrentSearch() {
  console.log('🚀 Concurrent Search Example\n')

  // Example search options
  const searchOptions: SearchOptions = {
    query: 'restaurants',
    location: 'New York, NY',
    maxResults: 50
  }

  console.log('📊 Current Configuration:')
  const config = searchOrchestrator.getConfig()
  console.log(`- Concurrent searches: ${config.enableConcurrentSearches}`)
  console.log(`- Max concurrent providers: ${config.maxConcurrentProviders}`)
  console.log(`- Search timeout: ${config.searchTimeout}ms\n`)

  // Demonstrate concurrent search (default mode)
  console.log('🔄 Running concurrent search...')
  const concurrentStart = Date.now()
  
  try {
    const concurrentResults = await searchOrchestrator.searchBusinesses(searchOptions)
    const concurrentDuration = Date.now() - concurrentStart
    
    console.log(`✅ Concurrent search completed in ${concurrentDuration}ms`)
    console.log(`📈 Found ${concurrentResults.length} unique businesses`)
    console.log(`🎯 Sources: ${[...new Set(concurrentResults.map(r => r.source))].join(', ')}\n`)
  } catch (error) {
    console.error('❌ Concurrent search failed:', error)
  }

  // Demonstrate sequential search for comparison
  console.log('🔄 Running sequential search for comparison...')
  searchOrchestrator.updateConfig({ enableConcurrentSearches: false })
  
  const sequentialStart = Date.now()
  
  try {
    const sequentialResults = await searchOrchestrator.searchBusinesses(searchOptions)
    const sequentialDuration = Date.now() - sequentialStart
    
    console.log(`✅ Sequential search completed in ${sequentialDuration}ms`)
    console.log(`📈 Found ${sequentialResults.length} unique businesses`)
    console.log(`🎯 Sources: ${[...new Set(sequentialResults.map(r => r.source))].join(', ')}\n`)
  } catch (error) {
    console.error('❌ Sequential search failed:', error)
  }

  // Restore concurrent mode
  searchOrchestrator.updateConfig({ enableConcurrentSearches: true })
  console.log('🔧 Restored concurrent search mode')
}

async function demonstrateConfigurationOptions() {
  console.log('\n⚙️  Configuration Options Example\n')

  // Example 1: High-performance configuration
  console.log('🚀 High-performance configuration:')
  searchOrchestrator.updateConfig({
    enableConcurrentSearches: true,
    maxConcurrentProviders: 8,
    searchTimeout: 60000 // 1 minute
  })
  
  let config = searchOrchestrator.getConfig()
  console.log(`- Concurrent: ${config.enableConcurrentSearches}`)
  console.log(`- Max providers: ${config.maxConcurrentProviders}`)
  console.log(`- Timeout: ${config.searchTimeout}ms`)

  // Example 2: Conservative configuration
  console.log('\n🛡️  Conservative configuration:')
  searchOrchestrator.updateConfig({
    enableConcurrentSearches: true,
    maxConcurrentProviders: 3,
    searchTimeout: 30000 // 30 seconds
  })
  
  config = searchOrchestrator.getConfig()
  console.log(`- Concurrent: ${config.enableConcurrentSearches}`)
  console.log(`- Max providers: ${config.maxConcurrentProviders}`)
  console.log(`- Timeout: ${config.searchTimeout}ms`)

  // Example 3: Debug/development configuration
  console.log('\n🔍 Debug/development configuration:')
  searchOrchestrator.updateConfig({
    enableConcurrentSearches: false, // Sequential for easier debugging
    maxConcurrentProviders: 1,
    searchTimeout: 120000 // 2 minutes
  })
  
  config = searchOrchestrator.getConfig()
  console.log(`- Concurrent: ${config.enableConcurrentSearches}`)
  console.log(`- Max providers: ${config.maxConcurrentProviders}`)
  console.log(`- Timeout: ${config.searchTimeout}ms`)
}

async function demonstrateErrorHandling() {
  console.log('\n🛡️  Error Handling Example\n')

  // Configure with very short timeout to demonstrate timeout handling
  searchOrchestrator.updateConfig({
    enableConcurrentSearches: true,
    searchTimeout: 1 // 1ms - will cause timeouts
  })

  const searchOptions: SearchOptions = {
    query: 'test timeout',
    location: 'Test City',
    maxResults: 10
  }

  console.log('⏱️  Testing timeout handling with 1ms timeout...')
  
  try {
    const results = await searchOrchestrator.searchBusinesses(searchOptions)
    console.log(`📊 Results despite timeouts: ${results.length}`)
    console.log('✅ Error handling working - search completed gracefully')
  } catch (error) {
    console.error('❌ Unexpected error:', error)
  }

  // Restore normal timeout
  searchOrchestrator.updateConfig({ searchTimeout: 120000 })
  console.log('🔧 Restored normal timeout')
}

// Main execution
async function main() {
  try {
    await demonstrateConcurrentSearch()
    await demonstrateConfigurationOptions()
    await demonstrateErrorHandling()
    
    console.log('\n🎉 Concurrent search examples completed!')
    console.log('\n💡 Key Benefits:')
    console.log('- Faster search results through parallel execution')
    console.log('- Graceful handling of provider failures')
    console.log('- Configurable timeouts and concurrency limits')
    console.log('- Backward compatibility with sequential mode')
    console.log('- Respects existing rate limiting per provider')
    
  } catch (error) {
    console.error('❌ Example failed:', error)
  }
}

// Export for use in other files
export {
  demonstrateConcurrentSearch,
  demonstrateConfigurationOptions,
  demonstrateErrorHandling
}

// Run if called directly
if (require.main === module) {
  main()
}
