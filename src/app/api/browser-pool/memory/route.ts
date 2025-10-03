/**
 * Browser Pool Memory Monitoring API
 * Provides real-time memory statistics and leak detection for the browser pool
 */

import { NextRequest, NextResponse } from 'next/server'
import { browserPool } from '@/lib/browserPool'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryLeakDetector } from '@/lib/memory-leak-detector'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { logger } from '@/utils/logger'

/**
 * GET /api/browser-pool/memory - Get browser pool memory statistics
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url)
    const includeHistory = searchParams.get('history') === 'true'
    const includeDetails = searchParams.get('details') === 'true'

    // Get browser pool memory stats
    const poolStats = browserPool.getMemoryStats()
    const poolHealth = browserPool.getPoolHealthStats()
    
    // Get system memory stats
    const systemMemory = memoryMonitor.getCurrentStats()
    const memoryHistory = includeHistory ? memoryMonitor.getMemoryHistory() : []
    
    // Get leak detection status
    const leakDetectionStatus = memoryLeakDetector.getStatus()
    
    // Get cleanup service status
    const cleanupStatus = memoryCleanup.getStatus()

    const response = {
      timestamp: new Date().toISOString(),
      browserPool: {
        memory: poolStats,
        health: poolHealth,
        config: browserPool.getConfig(),
      },
      system: {
        memory: systemMemory,
        history: memoryHistory,
      },
      leakDetection: leakDetectionStatus,
      cleanup: cleanupStatus,
    }

    // Add detailed information if requested
    if (includeDetails) {
      const detailedStats = await browserPool.getStats()
      response.browserPool.detailed = detailedStats
    }

    return NextResponse.json(response)
  } catch (error) {
    logger.error('BrowserPoolMemoryAPI', 'Failed to get memory statistics', error)
    return NextResponse.json(
      { error: 'Failed to retrieve memory statistics' },
      { status: 500 }
    )
  }
}

/**
 * POST /api/browser-pool/memory/cleanup - Trigger memory cleanup
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { type = 'automatic', force = false } = body

    let cleanupResult

    if (type === 'emergency' || force) {
      // Trigger emergency cleanup
      await browserPool.performEmergencyCleanup()
      cleanupResult = await memoryCleanup.performManualCleanup({
        clearSearchResults: true,
        clearProcessingSteps: true,
        clearErrorLogs: true,
        clearCachedData: true,
        forceGarbageCollection: true,
      })
    } else {
      // Trigger automatic cleanup
      cleanupResult = await memoryCleanup.performAutomaticCleanup()
    }

    // Get updated stats after cleanup
    const updatedStats = {
      browserPool: browserPool.getMemoryStats(),
      system: memoryMonitor.getCurrentStats(),
      cleanup: cleanupResult,
    }

    logger.info('BrowserPoolMemoryAPI', `Memory cleanup completed: ${type}`, cleanupResult)

    return NextResponse.json({
      success: true,
      type,
      result: cleanupResult,
      updatedStats,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('BrowserPoolMemoryAPI', 'Failed to perform memory cleanup', error)
    return NextResponse.json(
      { error: 'Failed to perform memory cleanup' },
      { status: 500 }
    )
  }
}

/**
 * PUT /api/browser-pool/memory/thresholds - Update memory thresholds
 */
export async function PUT(request: NextRequest) {
  try {
    const body = await request.json()
    const { memoryThresholds, cleanupPolicy } = body

    // Update memory monitor thresholds
    if (memoryThresholds) {
      memoryMonitor.updateThresholds(memoryThresholds)
    }

    // Update cleanup policy
    if (cleanupPolicy) {
      memoryCleanup.updateRetentionPolicy(cleanupPolicy)
    }

    const updatedConfig = {
      memoryThresholds: memoryMonitor.getThresholds(),
      cleanupPolicy: memoryCleanup.getRetentionPolicy(),
    }

    logger.info('BrowserPoolMemoryAPI', 'Memory configuration updated', updatedConfig)

    return NextResponse.json({
      success: true,
      updatedConfig,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('BrowserPoolMemoryAPI', 'Failed to update memory configuration', error)
    return NextResponse.json(
      { error: 'Failed to update memory configuration' },
      { status: 500 }
    )
  }
}

/**
 * DELETE /api/browser-pool/memory/leaks - Clear memory leak alerts
 */
export async function DELETE(request: NextRequest) {
  try {
    // Clear all memory trackers
    memoryLeakDetector.clearAllTrackers()
    
    // Reset browser pool memory leak counter
    const poolStats = browserPool.getMemoryStats()
    poolStats.memoryLeakAlerts = 0

    logger.info('BrowserPoolMemoryAPI', 'Memory leak alerts cleared')

    return NextResponse.json({
      success: true,
      message: 'Memory leak alerts cleared',
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    logger.error('BrowserPoolMemoryAPI', 'Failed to clear memory leak alerts', error)
    return NextResponse.json(
      { error: 'Failed to clear memory leak alerts' },
      { status: 500 }
    )
  }
}
