/**
 * Database Security Validation Module
 * Business Scraper Application - Security Compliance Checker
 */

import { Pool } from 'pg'
import { logger } from '@/utils/logger'
import { getDatabaseConfig } from './database'

/**
 * Security check result
 */
export interface SecurityCheckResult {
  checkName: string
  status: 'PASS' | 'FAIL' | 'WARNING'
  message: string
  recommendation?: string
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

/**
 * Database security validation service
 */
export class DatabaseSecurityValidator {
  private pool: Pool | null = null

  /**
   * Initialize database connection for validation
   */
  async initialize(): Promise<void> {
    try {
      const config = getDatabaseConfig()
      if (config.type === 'postgresql') {
        this.pool = new Pool({
          host: config.host,
          port: config.port,
          database: config.database,
          user: config.username,
          password: config.password,
          ssl: config.ssl,
          max: 1, // Only need one connection for validation
        })
      }
    } catch (error) {
      logger.error('DatabaseSecurityValidator', 'Failed to initialize', error)
      throw error
    }
  }

  /**
   * Run comprehensive security validation
   */
  async validateSecurity(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Database Connection',
        status: 'FAIL',
        message: 'No database connection available for validation',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Run all security checks
      results.push(...(await this.checkUserPermissions()))
      results.push(...(await this.checkSSLConfiguration()))
      results.push(...(await this.checkPasswordSecurity()))
      results.push(...(await this.checkRowLevelSecurity()))
      results.push(...(await this.checkAuditLogging()))
      results.push(...(await this.checkConnectionLimits()))
      results.push(...(await this.checkDangerousExtensions()))
      results.push(...(await this.checkTablePermissions()))
      results.push(...(await this.checkSensitiveDataProtection()))
    } catch (error) {
      logger.error('DatabaseSecurityValidator', 'Validation failed', error)
      results.push({
        checkName: 'Security Validation',
        status: 'FAIL',
        message: `Validation failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'HIGH',
      })
    }

    return results
  }

  /**
   * Check user permissions and roles
   */
  private async checkUserPermissions(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'User Permissions Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Check for superuser privileges
      const superuserQuery = `
        SELECT rolname, rolsuper
        FROM pg_roles
        WHERE rolname = current_user
      `
      const superuserResult = await this.pool.query(superuserQuery)

      if (superuserResult.rows[0]?.rolsuper) {
        results.push({
          checkName: 'Superuser Privileges',
          status: 'FAIL',
          message: 'Application is running with superuser privileges',
          recommendation: 'Create dedicated application user with minimal required permissions',
          severity: 'CRITICAL',
        })
      } else {
        results.push({
          checkName: 'Superuser Privileges',
          status: 'PASS',
          message: 'Application is not running with superuser privileges',
          severity: 'LOW',
        })
      }

      // Check for dedicated application user
      const appUserQuery = `
        SELECT COUNT(*) as count
        FROM pg_roles
        WHERE rolname IN ('business_scraper_app', 'business_scraper_readonly')
      `
      const appUserResult = await this.pool.query(appUserQuery)

      if (appUserResult.rows[0]?.count < 2) {
        results.push({
          checkName: 'Dedicated Application Users',
          status: 'WARNING',
          message: 'Dedicated application users not found',
          recommendation:
            'Create dedicated users: business_scraper_app and business_scraper_readonly',
          severity: 'MEDIUM',
        })
      } else {
        results.push({
          checkName: 'Dedicated Application Users',
          status: 'PASS',
          message: 'Dedicated application users are configured',
          severity: 'LOW',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'User Permissions Check',
        status: 'FAIL',
        message: `Failed to check user permissions: ${error}`,
        severity: 'HIGH',
      })
    }

    return results
  }

  /**
   * Check SSL configuration
   */
  private async checkSSLConfiguration(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'SSL Configuration Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      const sslQuery = `SHOW ssl`
      const sslResult = await this.pool.query(sslQuery)

      if (sslResult.rows[0]?.ssl === 'on') {
        results.push({
          checkName: 'SSL Configuration',
          status: 'PASS',
          message: 'SSL is enabled',
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'SSL Configuration',
          status: 'FAIL',
          message: 'SSL is not enabled',
          recommendation: 'Enable SSL for encrypted connections',
          severity: 'HIGH',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'SSL Configuration Check',
        status: 'WARNING',
        message: `Could not verify SSL configuration: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check password security
   */
  private async checkPasswordSecurity(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Password Security Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Check for default passwords
      const weakPasswordQuery = `
        SELECT rolname
        FROM pg_roles
        WHERE rolname IN ('postgres', 'business_scraper_app', 'business_scraper_readonly')
          AND rolpassword IS NOT NULL
      `
      const weakPasswordResult = await this.pool.query(weakPasswordQuery)

      // Note: We can't actually check password content, but we can check if passwords are set
      if (weakPasswordResult.rows.length > 0) {
        results.push({
          checkName: 'Password Security',
          status: 'WARNING',
          message: 'Ensure strong passwords are set for all database users',
          recommendation: 'Use strong, unique passwords for all database accounts',
          severity: 'HIGH',
        })
      }

      // Check password encryption
      const encryptionQuery = `SHOW password_encryption`
      const encryptionResult = await this.pool.query(encryptionQuery)

      if (encryptionResult.rows[0]?.password_encryption === 'scram-sha-256') {
        results.push({
          checkName: 'Password Encryption',
          status: 'PASS',
          message: 'Strong password encryption (SCRAM-SHA-256) is enabled',
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'Password Encryption',
          status: 'WARNING',
          message: 'Consider upgrading to SCRAM-SHA-256 password encryption',
          recommendation: 'Set password_encryption = scram-sha-256',
          severity: 'MEDIUM',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Password Security Check',
        status: 'WARNING',
        message: `Could not verify password security: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check Row Level Security (RLS)
   */
  private async checkRowLevelSecurity(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Row Level Security Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      const rlsQuery = `
        SELECT schemaname, tablename, rowsecurity
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN ('businesses', 'app_settings')
      `
      const rlsResult = await this.pool.query(rlsQuery)

      const tablesWithRLS = rlsResult.rows.filter(row => row.rowsecurity).length
      const totalSensitiveTables = rlsResult.rows.length

      if (tablesWithRLS === totalSensitiveTables && totalSensitiveTables > 0) {
        results.push({
          checkName: 'Row Level Security',
          status: 'PASS',
          message: 'RLS is enabled on sensitive tables',
          severity: 'LOW',
        })
      } else if (tablesWithRLS > 0) {
        results.push({
          checkName: 'Row Level Security',
          status: 'WARNING',
          message: `RLS enabled on ${tablesWithRLS}/${totalSensitiveTables} sensitive tables`,
          recommendation: 'Enable RLS on all sensitive tables',
          severity: 'MEDIUM',
        })
      } else {
        results.push({
          checkName: 'Row Level Security',
          status: 'FAIL',
          message: 'RLS is not enabled on sensitive tables',
          recommendation: 'Enable Row Level Security on tables containing sensitive data',
          severity: 'HIGH',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Row Level Security Check',
        status: 'WARNING',
        message: `Could not verify RLS configuration: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check audit logging
   */
  private async checkAuditLogging(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Audit Logging Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Check if audit log table exists
      const auditTableQuery = `
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_schema = 'public'
            AND table_name = 'security_audit_log'
        ) as exists
      `
      const auditTableResult = await this.pool.query(auditTableQuery)

      if (auditTableResult.rows[0]?.exists) {
        results.push({
          checkName: 'Audit Logging',
          status: 'PASS',
          message: 'Security audit logging is configured',
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'Audit Logging',
          status: 'FAIL',
          message: 'Security audit logging is not configured',
          recommendation: 'Create security_audit_log table and implement audit triggers',
          severity: 'HIGH',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Audit Logging Check',
        status: 'WARNING',
        message: `Could not verify audit logging: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check connection limits and timeouts
   */
  private async checkConnectionLimits(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Connection Limits Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      const settingsQuery = `
        SELECT name, setting
        FROM pg_settings
        WHERE name IN ('max_connections', 'statement_timeout', 'idle_in_transaction_session_timeout')
      `
      const settingsResult = await this.pool.query(settingsQuery)

      const settings = settingsResult.rows.reduce(
        (acc, row) => {
          acc[row.name] = row.setting
          return acc
        },
        {} as Record<string, string>
      )

      // Check max_connections
      const maxConnections = parseInt(settings.max_connections || '0')
      if (maxConnections > 0 && maxConnections <= 200) {
        results.push({
          checkName: 'Connection Limits',
          status: 'PASS',
          message: `Connection limit is appropriately set to ${maxConnections}`,
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'Connection Limits',
          status: 'WARNING',
          message: `Connection limit may be too high: ${maxConnections}`,
          recommendation: 'Set reasonable connection limits to prevent resource exhaustion',
          severity: 'MEDIUM',
        })
      }

      // Check statement timeout
      const statementTimeout = settings.statement_timeout
      if (statementTimeout && statementTimeout !== '0') {
        results.push({
          checkName: 'Statement Timeout',
          status: 'PASS',
          message: `Statement timeout is configured: ${statementTimeout}`,
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'Statement Timeout',
          status: 'WARNING',
          message: 'Statement timeout is not configured',
          recommendation: 'Set statement_timeout to prevent long-running queries',
          severity: 'MEDIUM',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Connection Limits Check',
        status: 'WARNING',
        message: `Could not verify connection settings: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check for dangerous extensions
   */
  private async checkDangerousExtensions(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Dangerous Extensions Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      const extensionsQuery = `
        SELECT extname
        FROM pg_extension
        WHERE extname IN ('dblink', 'postgres_fdw', 'file_fdw', 'plpythonu', 'plperlu')
      `
      const extensionsResult = await this.pool.query(extensionsQuery)

      if (extensionsResult.rows.length === 0) {
        results.push({
          checkName: 'Dangerous Extensions',
          status: 'PASS',
          message: 'No potentially dangerous extensions detected',
          severity: 'LOW',
        })
      } else {
        const dangerousExtensions = extensionsResult.rows.map(row => row.extname).join(', ')
        results.push({
          checkName: 'Dangerous Extensions',
          status: 'WARNING',
          message: `Potentially dangerous extensions found: ${dangerousExtensions}`,
          recommendation: 'Review and remove unnecessary extensions that could pose security risks',
          severity: 'MEDIUM',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Dangerous Extensions Check',
        status: 'WARNING',
        message: `Could not check extensions: ${error}`,
        severity: 'LOW',
      })
    }

    return results
  }

  /**
   * Check table permissions
   */
  private async checkTablePermissions(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Table Permissions Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Check for overly permissive public permissions
      const publicPermsQuery = `
        SELECT COUNT(*) as count
        FROM information_schema.table_privileges
        WHERE grantee = 'PUBLIC'
          AND table_schema = 'public'
          AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE')
      `
      const publicPermsResult = await this.pool.query(publicPermsQuery)

      if (publicPermsResult.rows[0]?.count === 0) {
        results.push({
          checkName: 'Public Table Permissions',
          status: 'PASS',
          message: 'No dangerous public permissions found',
          severity: 'LOW',
        })
      } else {
        results.push({
          checkName: 'Public Table Permissions',
          status: 'FAIL',
          message: 'Dangerous public permissions detected',
          recommendation: 'Revoke unnecessary public permissions on tables',
          severity: 'HIGH',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Table Permissions Check',
        status: 'WARNING',
        message: `Could not verify table permissions: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Check sensitive data protection
   */
  private async checkSensitiveDataProtection(): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = []

    if (!this.pool) {
      results.push({
        checkName: 'Sensitive Data Protection Check',
        status: 'FAIL',
        message: 'No database connection available',
        severity: 'CRITICAL',
      })
      return results
    }

    try {
      // Check if sensitive columns are properly protected
      const sensitiveColumnsQuery = `
        SELECT table_name, column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND column_name IN ('email', 'phone', 'password', 'api_key', 'secret')
      `
      const sensitiveColumnsResult = await this.pool.query(sensitiveColumnsQuery)

      if (sensitiveColumnsResult.rows.length > 0) {
        results.push({
          checkName: 'Sensitive Data Protection',
          status: 'WARNING',
          message: `Found ${sensitiveColumnsResult.rows.length} potentially sensitive columns`,
          recommendation: 'Ensure sensitive data is properly encrypted and access is logged',
          severity: 'MEDIUM',
        })
      } else {
        results.push({
          checkName: 'Sensitive Data Protection',
          status: 'PASS',
          message: 'No obviously sensitive column names detected',
          severity: 'LOW',
        })
      }
    } catch (error) {
      results.push({
        checkName: 'Sensitive Data Protection Check',
        status: 'WARNING',
        message: `Could not check sensitive data protection: ${error}`,
        severity: 'MEDIUM',
      })
    }

    return results
  }

  /**
   * Close database connection
   */
  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end()
      this.pool = null
    }
  }

  /**
   * Generate security report
   */
  generateSecurityReport(results: SecurityCheckResult[]): string {
    const summary = {
      total: results.length,
      passed: results.filter(r => r.status === 'PASS').length,
      warnings: results.filter(r => r.status === 'WARNING').length,
      failed: results.filter(r => r.status === 'FAIL').length,
    }

    let report = '=== DATABASE SECURITY VALIDATION REPORT ===\n\n'
    report += `Total Checks: ${summary.total}\n`
    report += `Passed: ${summary.passed}\n`
    report += `Warnings: ${summary.warnings}\n`
    report += `Failed: ${summary.failed}\n\n`

    // Group by severity
    const critical = results.filter(r => r.severity === 'CRITICAL')
    const high = results.filter(r => r.severity === 'HIGH')
    const medium = results.filter(r => r.severity === 'MEDIUM')
    const low = results.filter(r => r.severity === 'LOW')

    if (critical.length > 0) {
      report += '🚨 CRITICAL ISSUES:\n'
      critical.forEach(r => {
        report += `  ❌ ${r.checkName}: ${r.message}\n`
        if (r.recommendation) report += `     💡 ${r.recommendation}\n`
      })
      report += '\n'
    }

    if (high.length > 0) {
      report += '⚠️  HIGH PRIORITY ISSUES:\n'
      high.forEach(r => {
        report += `  ${r.status === 'FAIL' ? '❌' : '⚠️'} ${r.checkName}: ${r.message}\n`
        if (r.recommendation) report += `     💡 ${r.recommendation}\n`
      })
      report += '\n'
    }

    if (medium.length > 0) {
      report += '⚠️  MEDIUM PRIORITY ISSUES:\n'
      medium.forEach(r => {
        report += `  ⚠️ ${r.checkName}: ${r.message}\n`
        if (r.recommendation) report += `     💡 ${r.recommendation}\n`
      })
      report += '\n'
    }

    if (low.length > 0) {
      report += '✅ PASSED CHECKS:\n'
      low.forEach(r => {
        if (r.status === 'PASS') {
          report += `  ✅ ${r.checkName}: ${r.message}\n`
        }
      })
    }

    return report
  }
}

// Export singleton instance
export const databaseSecurityValidator = new DatabaseSecurityValidator()
