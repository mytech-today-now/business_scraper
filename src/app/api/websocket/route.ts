/**
 * WebSocket Server Management API
 * Handles starting, stopping, and monitoring the WebSocket server
 */

import { NextRequest, NextResponse } from 'next/server'
import { webSocketServer } from '@/lib/websocket-server'
import { logger } from '@/utils/logger'
import { getClientIP } from '@/lib/security'

/**
 * GET - Get WebSocket server status
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const status = webSocketServer.getStatus()
    
    logger.info('WebSocketAPI', `Status request from IP: ${ip}`, status)
    
    return NextResponse.json({
      success: true,
      status,
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    logger.error('WebSocketAPI', `Failed to get status from IP: ${ip}`, error)
    
    return NextResponse.json(
      { 
        success: false,
        error: 'Failed to get WebSocket server status',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}

/**
 * POST - Start or stop WebSocket server
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  const ip = getClientIP(request)
  
  try {
    const body = await request.json()
    const { action } = body
    
    logger.info('WebSocketAPI', `${action} request from IP: ${ip}`)
    
    switch (action) {
      case 'start':
        if (webSocketServer.getStatus().isRunning) {
          return NextResponse.json({
            success: true,
            message: 'WebSocket server is already running',
            status: webSocketServer.getStatus()
          })
        }
        
        await webSocketServer.start()
        
        return NextResponse.json({
          success: true,
          message: 'WebSocket server started successfully',
          status: webSocketServer.getStatus()
        })
      
      case 'stop':
        if (!webSocketServer.getStatus().isRunning) {
          return NextResponse.json({
            success: true,
            message: 'WebSocket server is already stopped',
            status: webSocketServer.getStatus()
          })
        }
        
        await webSocketServer.stop()
        
        return NextResponse.json({
          success: true,
          message: 'WebSocket server stopped successfully',
          status: webSocketServer.getStatus()
        })
      
      case 'restart':
        await webSocketServer.stop()
        await new Promise(resolve => setTimeout(resolve, 1000)) // Wait 1 second
        await webSocketServer.start()
        
        return NextResponse.json({
          success: true,
          message: 'WebSocket server restarted successfully',
          status: webSocketServer.getStatus()
        })
      
      default:
        return NextResponse.json(
          { 
            success: false,
            error: 'Invalid action',
            message: 'Action must be one of: start, stop, restart'
          },
          { status: 400 }
        )
    }
  } catch (error) {
    logger.error('WebSocketAPI', `WebSocket operation failed from IP: ${ip}`, error)
    
    return NextResponse.json(
      { 
        success: false,
        error: 'WebSocket operation failed',
        message: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    )
  }
}
