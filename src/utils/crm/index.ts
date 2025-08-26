/**
 * CRM Export Templates - Main Export
 * Centralized export for all CRM functionality
 */

// Types
export * from './types'

// Core Engine
export { CRMTransformationEngine } from './transformationEngine'

// Adapters
export { SalesforceAdapter } from './adapters/salesforceAdapter'
export { HubSpotAdapter } from './adapters/hubspotAdapter'
export { PipedriveAdapter } from './adapters/pipedriveAdapter'

// Services
export { crmTemplateManager } from './crmTemplateManager'
export { crmExportService } from './crmExportService'

// Re-export singleton instances for easy access
export { CRMTemplateManagerImpl } from './crmTemplateManager'
export { CRMExportService } from './crmExportService'
