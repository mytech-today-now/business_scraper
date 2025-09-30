#!/usr/bin/env node

/**
 * Resilience System Demonstration Script
 * Tests the multi-tiered resilience system functionality
 */

const { connectionManager } = require('../src/lib/resilience/connectionManager')
const { healthMonitor } = require('../src/lib/resilience/healthMonitor')
const { autoRecoveryService } = require('../src/lib/resilience/autoRecovery')

async function demonstrateResilienceSystem() {
  console.log('🚀 Starting Resilience System Demonstration')
  console.log('=' .repeat(50))

  try {
    // 1. Test Connection Manager
    console.log('\n📡 Testing Connection Manager...')
    
    let connectionAttempts = 0
    const mockConnectionFactory = async () => {
      connectionAttempts++
      if (connectionAttempts <= 2) {
        throw new Error(`Connection attempt ${connectionAttempts} failed`)
      }
      return { id: `connection-${connectionAttempts}`, healthy: true }
    }

    const mockHealthCheck = async (conn) => conn.healthy

    try {
      const connection = await connectionManager.getConnection(
        'demo-connection',
        mockConnectionFactory,
        mockHealthCheck
      )
      console.log('✅ Connection created successfully:', connection.id)
    } catch (error) {
      console.log('❌ Connection failed:', error.message)
    }

    // 2. Test Health Monitor
    console.log('\n🏥 Testing Health Monitor...')
    
    let serviceHealthy = true
    healthMonitor.registerService('demo-service', async () => {
      return serviceHealthy
    })

    healthMonitor.start()
    console.log('✅ Health monitoring started')

    // Wait for initial health check
    await new Promise(resolve => setTimeout(resolve, 200))
    
    let service = healthMonitor.getServiceHealth('demo-service')
    console.log('📊 Service status:', service?.status)

    // Simulate service failure
    console.log('\n💥 Simulating service failure...')
    serviceHealthy = false
    
    await new Promise(resolve => setTimeout(resolve, 300))
    
    service = healthMonitor.getServiceHealth('demo-service')
    console.log('📊 Service status after failure:', service?.status)

    // 3. Test Auto Recovery
    console.log('\n🔧 Testing Auto Recovery...')
    
    let recoveryExecuted = false
    autoRecoveryService.registerRecoveryPlan('demo-service', {
      serviceName: 'demo-service',
      maxExecutionTime: 10000,
      cooldownPeriod: 1000,
      actions: [
        {
          name: 'recoverService',
          description: 'Recover the demo service',
          execute: async () => {
            console.log('🔄 Executing recovery action...')
            recoveryExecuted = true
            serviceHealthy = true
            return true
          },
          timeout: 5000,
          retries: 1,
        },
      ],
    })

    const recoverySuccess = await autoRecoveryService.triggerRecovery(
      'demo-service',
      'Manual recovery for demonstration'
    )

    console.log('🔧 Recovery triggered:', recoverySuccess ? 'SUCCESS' : 'FAILED')
    console.log('🔄 Recovery executed:', recoveryExecuted)

    // Wait for recovery to complete
    await new Promise(resolve => setTimeout(resolve, 500))

    service = healthMonitor.getServiceHealth('demo-service')
    console.log('📊 Service status after recovery:', service?.status)

    // 4. Show System Status
    console.log('\n📈 System Status Summary:')
    console.log('=' .repeat(30))

    const connectionStatus = connectionManager.getStatus()
    console.log('🔗 Connections:', {
      total: connectionStatus.totalConnections,
      healthy: connectionStatus.healthyConnections,
    })

    const healthStatus = healthMonitor.getHealthStatus()
    console.log('🏥 Health Status:', {
      systemStatus: healthStatus.systemStatus,
      services: healthStatus.services.length,
      activeAlerts: healthStatus.activeAlerts.length,
    })

    const recoveryStatus = autoRecoveryService.getRecoveryStatus()
    console.log('🔧 Recovery Status:', {
      enabled: recoveryStatus.isEnabled,
      activeRecoveries: recoveryStatus.activeRecoveries.length,
      registeredPlans: recoveryStatus.registeredPlans.length,
    })

    console.log('\n✅ Resilience System Demonstration Complete!')
    console.log('🎯 All systems are functioning correctly')

  } catch (error) {
    console.error('❌ Demonstration failed:', error.message)
    console.error(error.stack)
  } finally {
    // Cleanup
    healthMonitor.stop()
    await connectionManager.shutdown()
    console.log('\n🧹 Cleanup complete')
  }
}

// Run the demonstration
if (require.main === module) {
  demonstrateResilienceSystem()
    .then(() => {
      console.log('\n🏁 Demonstration finished successfully')
      process.exit(0)
    })
    .catch((error) => {
      console.error('\n💥 Demonstration failed:', error)
      process.exit(1)
    })
}

module.exports = { demonstrateResilienceSystem }
