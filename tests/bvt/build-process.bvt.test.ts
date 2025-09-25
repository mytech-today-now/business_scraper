/**
 * Build Process BVT Test
 * Validates that the build process works without PostgreSQL connection errors
 */

import { exec } from 'child_process'
import { promisify } from 'util'
import path from 'path'

const execAsync = promisify(exec)

describe('Build Process BVT', () => {
  const timeout = 300000 // 5 minutes for build process

  beforeAll(() => {
    // Set build-time environment variables
    process.env.IS_BUILD_TIME = 'true'
    process.env.DISABLE_DATABASE = 'true'
    process.env.SKIP_RETENTION_POLICIES = 'true'
    process.env.SKIP_BACKGROUND_JOBS = 'true'
    process.env.BUILD_LOG_LEVEL = 'warn'
  })

  afterAll(() => {
    // Clean up environment variables
    delete process.env.IS_BUILD_TIME
    delete process.env.DISABLE_DATABASE
    delete process.env.SKIP_RETENTION_POLICIES
    delete process.env.SKIP_BACKGROUND_JOBS
    delete process.env.BUILD_LOG_LEVEL
  })

  it('should build successfully without PostgreSQL connection errors', async () => {
    const projectRoot = path.resolve(__dirname, '../..')
    
    try {
      const { stdout, stderr } = await execAsync('npm run build', {
        cwd: projectRoot,
        env: {
          ...process.env,
          IS_BUILD_TIME: 'true',
          DISABLE_DATABASE: 'true',
          SKIP_RETENTION_POLICIES: 'true',
          SKIP_BACKGROUND_JOBS: 'true',
          BUILD_LOG_LEVEL: 'warn'
        }
      })

      // Check that build completed successfully
      expect(stdout).toContain('✓ Compiled successfully')
      expect(stdout).toContain('✓ Collecting page data')
      expect(stdout).toContain('✓ Generating static pages')
      expect(stdout).toContain('✓ Finalizing page optimization')

      // Check that no PostgreSQL connection errors occurred
      expect(stderr).not.toContain('ECONNREFUSED')
      expect(stderr).not.toContain('Failed to load retention schedules')
      expect(stderr).not.toContain('Failed to create/update retention policy')
      expect(stderr).not.toContain('Failed to initialize default policies')

      // Check that build-time guards are working
      expect(stdout).toContain('Build-time environment detected') || 
      expect(stderr).toContain('Build-time environment detected') ||
      expect(stdout).toContain('Skipping') ||
      expect(stderr).toContain('Skipping')

    } catch (error) {
      console.error('Build process failed:', error)
      throw error
    }
  }, timeout)

  it('should generate all expected static pages', async () => {
    const projectRoot = path.resolve(__dirname, '../..')
    
    try {
      const { stdout } = await execAsync('npm run build', {
        cwd: projectRoot,
        env: {
          ...process.env,
          IS_BUILD_TIME: 'true',
          DISABLE_DATABASE: 'true',
          SKIP_RETENTION_POLICIES: 'true',
          SKIP_BACKGROUND_JOBS: 'true'
        }
      })

      // Check that key pages are generated
      expect(stdout).toContain('/')
      expect(stdout).toContain('/login')
      expect(stdout).toContain('/pricing')
      expect(stdout).toContain('/payment/success')
      expect(stdout).toContain('/payment/cancel')

      // Check that API routes are processed
      expect(stdout).toContain('/api/')

    } catch (error) {
      console.error('Static page generation failed:', error)
      throw error
    }
  }, timeout)

  it('should not attempt database connections during build', async () => {
    const projectRoot = path.resolve(__dirname, '../..')
    
    try {
      const { stdout, stderr } = await execAsync('npm run build', {
        cwd: projectRoot,
        env: {
          ...process.env,
          IS_BUILD_TIME: 'true',
          DISABLE_DATABASE: 'true',
          SKIP_RETENTION_POLICIES: 'true',
          SKIP_BACKGROUND_JOBS: 'true',
          BUILD_LOG_LEVEL: 'debug' // Enable debug logging to see guard messages
        }
      })

      const output = stdout + stderr

      // Check for build-time guard messages
      expect(output).toContain('Skipping') || 
      expect(output).toContain('Build-time environment') ||
      expect(output).toContain('Database connection not allowed')

      // Ensure no actual database connection attempts
      expect(output).not.toContain('PostgreSQL connection created')
      expect(output).not.toContain('Connection test successful')

    } catch (error) {
      console.error('Build database connection test failed:', error)
      throw error
    }
  }, timeout)

  it('should handle API route static analysis without errors', async () => {
    const projectRoot = path.resolve(__dirname, '../..')
    
    try {
      const { stdout, stderr } = await execAsync('npm run build', {
        cwd: projectRoot,
        env: {
          ...process.env,
          IS_BUILD_TIME: 'true',
          DISABLE_DATABASE: 'true'
        }
      })

      // Check that API routes don't cause build failures
      expect(stderr).not.toContain('Dynamic server usage')
      expect(stderr).not.toContain("couldn't be rendered statically")

      // Check that build completed without critical errors
      expect(stdout).toContain('✓ Compiled successfully')

    } catch (error) {
      console.error('API route static analysis failed:', error)
      throw error
    }
  }, timeout)

  it('should respect build-time environment variables', async () => {
    const projectRoot = path.resolve(__dirname, '../..')
    
    try {
      const { stdout, stderr } = await execAsync('npm run build', {
        cwd: projectRoot,
        env: {
          ...process.env,
          IS_BUILD_TIME: 'true',
          DISABLE_DATABASE: 'true',
          SKIP_RETENTION_POLICIES: 'true',
          SKIP_BACKGROUND_JOBS: 'true',
          SKIP_DATA_MIGRATIONS: 'true'
        }
      })

      const output = stdout + stderr

      // Check that environment variables are respected
      expect(output).not.toContain('Retention policy initialization')
      expect(output).not.toContain('Background job scheduling')
      expect(output).not.toContain('Data migration execution')

    } catch (error) {
      console.error('Environment variable test failed:', error)
      throw error
    }
  }, timeout)
})
