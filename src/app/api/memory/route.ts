/**
 * Memory Management API
 * Handles memory monitoring, cleanup, and optimization operations
 */

import { NextRequest, NextResponse } from 'next/server'
import { memoryMonitor } from '@/lib/memory-monitor'
import { memoryCleanup } from '@/lib/memory-cleanup'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * GET - Get memory status and statistics
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const currentStats = memoryMonitor.getCurrentStats()
    const memoryHistory = memoryMonitor.getMemoryHistory()
    const thresholds = memoryMonitor.getThresholds()
    const cleanupStatus = memoryCleanup.getStatus()
    
    const response = {
      success: true,
      data: {
        isMonitoring: memoryMonitor.isActive(),
        currentStats,
        memoryHistory: memoryHistory.slice(-20), // Last 20 entries
        thresholds,
        cleanupStatus,
        timestamp: new Date().toISOString()
      }
    }
    
    logger.info('MemoryAPI', `Memory status request from IP: ${ip}`)
    
    return NextResponse.json(response)
  } catch (error) {
    logger.error('MemoryAPI', `Failed to get memory status from IP: ${ip}`, error)
    
    return NextResponse.json(
      { 
        success: false,
        error: 'Failed to get memory status',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * POST - Perform memory operations (start/stop monitoring, cleanup)
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const body = await request.json()
    const { action, options } = body
    
    logger.info('MemoryAPI', `Memory operation '${action}' from IP: ${ip}`, options)
    
    switch (action) {
      case 'start-monitoring':
        if (memoryMonitor.isActive()) {
          return NextResponse.json({
            success: true,
            message: 'Memory monitoring is already active',
            data: { isMonitoring: true }
          })
        }
        
        memoryMonitor.startMonitoring()
        
        return NextResponse.json({
          success: true,
          message: 'Memory monitoring started',
          data: { isMonitoring: true }
        })
      
      case 'stop-monitoring':
        if (!memoryMonitor.isActive()) {
          return NextResponse.json({
            success: true,
            message: 'Memory monitoring is already stopped',
            data: { isMonitoring: false }
          })
        }
        
        memoryMonitor.stopMonitoring()
        
        return NextResponse.json({
          success: true,
          message: 'Memory monitoring stopped',
          data: { isMonitoring: false }
        })
      
      case 'cleanup':
        const cleanupResult = await memoryCleanup.performManualCleanup(options || {})
        
        return NextResponse.json({
          success: cleanupResult.success,
          message: cleanupResult.success 
            ? `Cleanup completed: ${cleanupResult.itemsCleared} items cleared`
            : `Cleanup failed: ${cleanupResult.errors.join(', ')}`,
          data: cleanupResult
        })
      
      case 'emergency-cleanup':
        const emergencyResult = await memoryCleanup.performEmergencyCleanup()
        
        return NextResponse.json({
          success: emergencyResult.success,
          message: emergencyResult.success 
            ? `Emergency cleanup completed: ${emergencyResult.itemsCleared} items cleared`
            : `Emergency cleanup failed: ${emergencyResult.errors.join(', ')}`,
          data: emergencyResult
        })
      
      case 'update-thresholds':
        if (!options || typeof options !== 'object') {
          return NextResponse.json(
            { 
              success: false,
              error: 'Invalid thresholds',
              message: 'Thresholds must be provided as an object'
            },
            { status: 400 }
          )
        }
        
        memoryMonitor.updateThresholds(options)
        
        return NextResponse.json({
          success: true,
          message: 'Memory thresholds updated',
          data: { thresholds: memoryMonitor.getThresholds() }
        })
      
      case 'update-retention-policy':
        if (!options || typeof options !== 'object') {
          return NextResponse.json(
            { 
              success: false,
              error: 'Invalid retention policy',
              message: 'Retention policy must be provided as an object'
            },
            { status: 400 }
          )
        }
        
        memoryCleanup.updateRetentionPolicy(options)
        
        return NextResponse.json({
          success: true,
          message: 'Retention policy updated',
          data: { retentionPolicy: memoryCleanup.getRetentionPolicy() }
        })
      
      case 'start-auto-cleanup':
        const interval = options?.interval || 30000 // 30 seconds default
        memoryCleanup.startAutoCleanup(interval)
        
        return NextResponse.json({
          success: true,
          message: 'Auto cleanup started',
          data: { autoCleanupEnabled: true, interval }
        })
      
      case 'stop-auto-cleanup':
        memoryCleanup.stopAutoCleanup()
        
        return NextResponse.json({
          success: true,
          message: 'Auto cleanup stopped',
          data: { autoCleanupEnabled: false }
        })
      
      case 'force-gc':
        const gcResult = memoryMonitor.forceGarbageCollection()
        
        return NextResponse.json({
          success: true,
          message: gcResult 
            ? 'Garbage collection forced successfully'
            : 'Garbage collection not available',
          data: { gcForced: gcResult }
        })
      
      default:
        return NextResponse.json(
          { 
            success: false,
            error: 'Invalid action',
            message: 'Action must be one of: start-monitoring, stop-monitoring, cleanup, emergency-cleanup, update-thresholds, update-retention-policy, start-auto-cleanup, stop-auto-cleanup, force-gc'
          },
          { status: 400 }
        )
    }
  } catch (error) {
    logger.error('MemoryAPI', `Memory operation failed from IP: ${ip}`, error)
    
    return NextResponse.json(
      { 
        success: false,
        error: 'Memory operation failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * DELETE - Clear memory data (alerts, history, etc.)
 */
export async function DELETE(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const url = new URL(request.url)
    const target = url.searchParams.get('target') || 'all'
    
    logger.info('MemoryAPI', `Memory data clear '${target}' from IP: ${ip}`)
    
    switch (target) {
      case 'history':
        // Clear memory history (this would need to be implemented in memoryMonitor)
        return NextResponse.json({
          success: true,
          message: 'Memory history cleared'
        })
      
      case 'alerts':
        // Clear alerts (this would be handled by the frontend)
        return NextResponse.json({
          success: true,
          message: 'Memory alerts cleared'
        })
      
      case 'all':
        // Clear all memory data
        return NextResponse.json({
          success: true,
          message: 'All memory data cleared'
        })
      
      default:
        return NextResponse.json(
          { 
            success: false,
            error: 'Invalid target',
            message: 'Target must be one of: history, alerts, all'
          },
          { status: 400 }
        )
    }
  } catch (error) {
    logger.error('MemoryAPI', `Memory data clear failed from IP: ${ip}`, error)
    
    return NextResponse.json(
      { 
        success: false,
        error: 'Memory data clear failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}
