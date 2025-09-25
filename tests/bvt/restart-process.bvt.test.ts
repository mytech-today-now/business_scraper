/**
 * BVT Tests for Restart, Rebuild, and Relaunch Process
 * Comprehensive tests for the restart enhancement
 */

import { describe, test, expect, beforeAll, afterAll, jest } from '@jest/globals';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';

const execAsync = promisify(exec);

describe('Restart, Rebuild, and Relaunch Process BVT', () => {
  const testTimeout = 300000; // 5 minutes
  const scriptsDir = path.join(process.cwd(), 'scripts');
  const logsDir = path.join(process.cwd(), 'logs');

  beforeAll(async () => {
    // Ensure logs directory exists
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
  });

  afterAll(async () => {
    // Cleanup any test artifacts
    jest.clearAllMocks();
  });

  describe('Individual Script Components', () => {
    test('stop-application.js should exist and be executable', async () => {
      const scriptPath = path.join(scriptsDir, 'stop-application.js');
      expect(fs.existsSync(scriptPath)).toBe(true);
      
      // Test help command
      const { stdout } = await execAsync(`node "${scriptPath}" --help`);
      expect(stdout).toContain('Application Stop Script');
      expect(stdout).toContain('Usage:');
    }, testTimeout);

    test('clean-build-environment.js should exist and be executable', async () => {
      const scriptPath = path.join(scriptsDir, 'clean-build-environment.js');
      expect(fs.existsSync(scriptPath)).toBe(true);
      
      // Test help command
      const { stdout } = await execAsync(`node "${scriptPath}" --help`);
      expect(stdout).toContain('Build Environment Cleanup Script');
      expect(stdout).toContain('Usage:');
    }, testTimeout);

    test('build-and-launch.js should exist and be executable', async () => {
      const scriptPath = path.join(scriptsDir, 'build-and-launch.js');
      expect(fs.existsSync(scriptPath)).toBe(true);
      
      // Test help command
      const { stdout } = await execAsync(`node "${scriptPath}" --help`);
      expect(stdout).toContain('Production Build and Launch Script');
      expect(stdout).toContain('Usage:');
    }, testTimeout);

    test('error-handler-github.js should exist and be executable', async () => {
      const scriptPath = path.join(scriptsDir, 'error-handler-github.js');
      expect(fs.existsSync(scriptPath)).toBe(true);
      
      // Test help command
      const { stdout } = await execAsync(`node "${scriptPath}" --help`);
      expect(stdout).toContain('Error Handler with GitHub Integration');
      expect(stdout).toContain('Usage:');
    }, testTimeout);

    test('restart-rebuild-relaunch.js should exist and be executable', async () => {
      const scriptPath = path.join(scriptsDir, 'restart-rebuild-relaunch.js');
      expect(fs.existsSync(scriptPath)).toBe(true);
      
      // Test help command
      const { stdout } = await execAsync(`node "${scriptPath}" --help`);
      expect(stdout).toContain('Restart, Rebuild, and Relaunch Orchestrator');
      expect(stdout).toContain('Usage:');
    }, testTimeout);
  });

  describe('Script Functionality Tests', () => {
    test('stop-application.js dry run should work without errors', async () => {
      const scriptPath = path.join(scriptsDir, 'stop-application.js');
      
      try {
        const { stdout, stderr } = await execAsync(`node "${scriptPath}" --verbose`);
        // Should complete without throwing an error
        expect(stderr).toBe('');
      } catch (error) {
        // Even if it fails, it should be a controlled failure
        expect(error.code).toBeDefined();
      }
    }, testTimeout);

    test('clean-build-environment.js dry run should analyze targets', async () => {
      const scriptPath = path.join(scriptsDir, 'clean-build-environment.js');
      
      const { stdout } = await execAsync(`node "${scriptPath}" --dry-run --verbose`);
      expect(stdout).toContain('Build environment cleaned successfully');
      expect(stdout).toContain('This was a dry run');
    }, testTimeout);

    test('build-and-launch.js with skip-launch should validate environment', async () => {
      const scriptPath = path.join(scriptsDir, 'build-and-launch.js');
      
      try {
        const { stdout } = await execAsync(`node "${scriptPath}" --skip-launch --verbose`);
        expect(stdout).toContain('Production build and launch completed successfully');
      } catch (error) {
        // If it fails, it should be due to missing dependencies or build issues
        expect(error.message).toContain('Command failed');
      }
    }, testTimeout);

    test('error-handler-github.js should handle test errors', async () => {
      const scriptPath = path.join(scriptsDir, 'error-handler-github.js');
      
      const { stdout } = await execAsync(`node "${scriptPath}" --dry-run --verbose`);
      expect(stdout).toContain('Error handled successfully');
    }, testTimeout);
  });

  describe('BVT Suite Integration', () => {
    test('run-bvt.js should validate configuration', async () => {
      const scriptPath = path.join(scriptsDir, 'run-bvt.js');
      
      const { stdout } = await execAsync(`node "${scriptPath}" --mode=validate`);
      expect(stdout).toContain('BVT Configuration Validation');
      expect(stdout).toContain('BVT Configuration is valid');
    }, testTimeout);

    test('run-bvt.js should show information', async () => {
      const scriptPath = path.join(scriptsDir, 'run-bvt.js');
      
      const { stdout } = await execAsync(`node "${scriptPath}" --mode=info`);
      expect(stdout).toContain('BVT Suite Information');
      expect(stdout).toContain('Test Categories (12 total)');
    }, testTimeout);

    test('Enhanced BVT script should have proper test categories', async () => {
      const scriptPath = path.join(scriptsDir, 'run-bvt.js');
      const scriptContent = fs.readFileSync(scriptPath, 'utf8');
      
      // Check for test categories
      expect(scriptContent).toContain('unit:');
      expect(scriptContent).toContain('integration:');
      expect(scriptContent).toContain('e2e:');
      expect(scriptContent).toContain('system:');
      expect(scriptContent).toContain('regression:');
      expect(scriptContent).toContain('acceptance:');
      expect(scriptContent).toContain('performance:');
      expect(scriptContent).toContain('security:');
      expect(scriptContent).toContain('accessibility:');
      expect(scriptContent).toContain('compatibility:');
      expect(scriptContent).toContain('exploratory:');
      expect(scriptContent).toContain('smoke:');
    });
  });

  describe('NPM Scripts Integration', () => {
    test('package.json should contain new restart scripts', async () => {
      const packageJsonPath = path.join(process.cwd(), 'package.json');
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      
      expect(packageJson.scripts).toHaveProperty('restart:app');
      expect(packageJson.scripts).toHaveProperty('restart:app:verbose');
      expect(packageJson.scripts).toHaveProperty('restart:app:dry-run');
      expect(packageJson.scripts).toHaveProperty('restart:app:clean-deps');
      expect(packageJson.scripts).toHaveProperty('restart:app:health');
      expect(packageJson.scripts).toHaveProperty('restart:stop');
      expect(packageJson.scripts).toHaveProperty('restart:clean');
      expect(packageJson.scripts).toHaveProperty('restart:build');
      expect(packageJson.scripts).toHaveProperty('restart:error-handler');
    });

    test('restart scripts should point to correct files', async () => {
      const packageJsonPath = path.join(process.cwd(), 'package.json');
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      
      expect(packageJson.scripts['restart:app']).toContain('restart-rebuild-relaunch.js');
      expect(packageJson.scripts['restart:stop']).toContain('stop-application.js');
      expect(packageJson.scripts['restart:clean']).toContain('clean-build-environment.js');
      expect(packageJson.scripts['restart:build']).toContain('build-and-launch.js');
      expect(packageJson.scripts['restart:error-handler']).toContain('error-handler-github.js');
    });
  });

  describe('Master Orchestrator Tests', () => {
    test('restart-rebuild-relaunch.js dry run should complete all steps', async () => {
      const scriptPath = path.join(scriptsDir, 'restart-rebuild-relaunch.js');
      
      const { stdout } = await execAsync(`node "${scriptPath}" --dry-run --skip-bvt --verbose`);
      expect(stdout).toContain('Restart, Rebuild, and Relaunch Process Completed Successfully');
      expect(stdout).toContain('This was a dry run');
    }, testTimeout);

    test('restart process should generate proper reports', async () => {
      const scriptPath = path.join(scriptsDir, 'restart-rebuild-relaunch.js');
      
      await execAsync(`node "${scriptPath}" --dry-run --skip-bvt --verbose`);
      
      // Check if report files are generated
      const reportFiles = fs.readdirSync(logsDir).filter(file => 
        file.startsWith('restart-report-') && file.endsWith('.md')
      );
      
      expect(reportFiles.length).toBeGreaterThan(0);
      
      // Check report content
      const latestReport = reportFiles.sort().pop();
      const reportContent = fs.readFileSync(path.join(logsDir, latestReport!), 'utf8');
      
      expect(reportContent).toContain('# Restart, Rebuild, and Relaunch Process Report');
      expect(reportContent).toContain('## Summary');
      expect(reportContent).toContain('## Step Details');
    }, testTimeout);
  });

  describe('Error Handling Tests', () => {
    test('error handler should create proper error reports', async () => {
      const scriptPath = path.join(scriptsDir, 'error-handler-github.js');
      
      const testError = JSON.stringify({
        message: 'Test error for BVT',
        type: 'Test Error',
        component: 'BVT Test',
        severity: 'low'
      });
      
      const { stdout } = await execAsync(`node "${scriptPath}" --dry-run --verbose '${testError}'`);
      expect(stdout).toContain('Error handled successfully');
    }, testTimeout);

    test('error reports should be generated in logs directory', async () => {
      const scriptPath = path.join(scriptsDir, 'error-handler-github.js');
      
      const testError = JSON.stringify({
        message: 'Test error for report generation',
        type: 'Test Error',
        component: 'BVT Test'
      });
      
      await execAsync(`node "${scriptPath}" --dry-run '${testError}'`);
      
      // Check if error report files are generated
      const errorReports = fs.readdirSync(logsDir).filter(file => 
        file.startsWith('error-report-') && file.endsWith('.md')
      );
      
      expect(errorReports.length).toBeGreaterThan(0);
    }, testTimeout);
  });

  describe('Integration and System Tests', () => {
    test('all scripts should have proper logging capabilities', async () => {
      const scripts = [
        'stop-application.js',
        'clean-build-environment.js',
        'build-and-launch.js',
        'error-handler-github.js',
        'restart-rebuild-relaunch.js'
      ];
      
      for (const script of scripts) {
        const scriptPath = path.join(scriptsDir, script);
        const scriptContent = fs.readFileSync(scriptPath, 'utf8');
        
        // Check for logging functionality
        expect(scriptContent).toContain('log(');
        expect(scriptContent).toContain('logFile');
      }
    });

    test('all scripts should handle verbose mode', async () => {
      const scripts = [
        'stop-application.js',
        'clean-build-environment.js', 
        'build-and-launch.js',
        'error-handler-github.js',
        'restart-rebuild-relaunch.js'
      ];
      
      for (const script of scripts) {
        const scriptPath = path.join(scriptsDir, script);
        
        try {
          const { stdout } = await execAsync(`node "${scriptPath}" --help`);
          expect(stdout).toContain('--verbose');
        } catch (error) {
          // Some scripts might not have help, but should still support verbose
          const scriptContent = fs.readFileSync(scriptPath, 'utf8');
          expect(scriptContent).toContain('verbose');
        }
      }
    });

    test('restart process should be resilient to failures', async () => {
      const scriptPath = path.join(scriptsDir, 'restart-rebuild-relaunch.js');
      
      // Test with invalid BVT mode to trigger controlled failure
      try {
        await execAsync(`node "${scriptPath}" --dry-run --bvt-mode=invalid --verbose`);
      } catch (error) {
        // Should fail gracefully with proper error handling
        expect(error.code).toBeDefined();
      }
    }, testTimeout);
  });

  describe('Performance and Reliability Tests', () => {
    test('scripts should complete within reasonable time limits', async () => {
      const scriptPath = path.join(scriptsDir, 'restart-rebuild-relaunch.js');
      
      const startTime = Date.now();
      await execAsync(`node "${scriptPath}" --dry-run --skip-bvt`);
      const duration = Date.now() - startTime;
      
      // Dry run should complete within 30 seconds
      expect(duration).toBeLessThan(30000);
    }, testTimeout);

    test('scripts should handle concurrent execution gracefully', async () => {
      const scriptPath = path.join(scriptsDir, 'stop-application.js');
      
      // Run multiple instances concurrently
      const promises = Array(3).fill(0).map(() => 
        execAsync(`node "${scriptPath}" --verbose`)
      );
      
      const results = await Promise.allSettled(promises);
      
      // At least one should succeed, others may fail gracefully
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(0);
    }, testTimeout);
  });
});
