#!/usr/bin/env node
/**
 * Master Restart, Rebuild, and Relaunch Script
 * Orchestrates the complete application restart process with BVT testing
 * Part of the Restart, Rebuild, and Relaunch Enhancement
 */

const fs = require('fs');
const path = require('path');
const ApplicationStopper = require('./stop-application');
const BuildEnvironmentCleaner = require('./clean-build-environment');
const ProductionBuilder = require('./build-and-launch');
const BVTRunner = require('./run-bvt');
const GitHubErrorHandler = require('./error-handler-github');

class RestartRebuildRelaunchOrchestrator {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.dryRun = options.dryRun || false;
    this.skipCleanDeps = options.skipCleanDeps !== false; // Default true
    this.skipBVT = options.skipBVT || false;
    this.bvtMode = options.bvtMode || 'full';
    this.timeout = options.timeout || 1200000; // 20 minutes
    this.logFile = path.join(process.cwd(), 'logs', 'restart-rebuild-relaunch.log');
    this.reportFile = path.join(process.cwd(), 'logs', `restart-report-${Date.now()}.md`);
    this.ensureDirectories();
    
    // Initialize components
    this.stopper = new ApplicationStopper({ verbose: this.verbose });
    this.cleaner = new BuildEnvironmentCleaner({ 
      verbose: this.verbose, 
      dryRun: this.dryRun,
      preserveDependencies: this.skipCleanDeps 
    });
    this.builder = new ProductionBuilder({ verbose: this.verbose });
    this.bvtRunner = new BVTRunner({ mode: this.bvtMode, verbose: this.verbose });
    this.errorHandler = new GitHubErrorHandler({ verbose: this.verbose, dryRun: this.dryRun });
  }

  ensureDirectories() {
    const dirs = [
      path.dirname(this.logFile),
      path.dirname(this.reportFile)
    ];
    
    dirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level}] ${message}`;
    
    if (this.verbose || level === 'ERROR' || level === 'WARN') {
      console.log(logMessage);
    }
    
    try {
      fs.appendFileSync(this.logFile, logMessage + '\n');
    } catch (error) {
      console.error('Failed to write to log file:', error.message);
    }
  }

  async executeStep(stepName, stepFunction, errorContext = {}) {
    this.log(`=== Starting Step: ${stepName} ===`);
    const stepStartTime = Date.now();
    
    try {
      const result = await stepFunction();
      const stepDuration = Date.now() - stepStartTime;
      
      if (result && result.success === false) {
        throw new Error(result.message || `${stepName} failed`);
      }
      
      this.log(`=== Step Completed: ${stepName} (${stepDuration}ms) ===`, 'SUCCESS');
      return { success: true, duration: stepDuration, result };
      
    } catch (error) {
      const stepDuration = Date.now() - stepStartTime;
      this.log(`=== Step Failed: ${stepName} (${stepDuration}ms) ===`, 'ERROR');
      this.log(`Error: ${error.message}`, 'ERROR');
      
      // Handle error with GitHub integration
      const errorData = {
        message: error.message,
        type: `${stepName} Error`,
        component: stepName,
        severity: 'high',
        summary: `${stepName} failed during restart process`,
        description: `The ${stepName} step failed during the restart, rebuild, and relaunch process.`,
        reproductionSteps: [
          'Run the restart, rebuild, and relaunch process',
          `Observe failure during ${stepName} step`
        ],
        expectedBehavior: `${stepName} should complete successfully`,
        actualBehavior: `${stepName} failed with error: ${error.message}`,
        additionalContext: JSON.stringify(errorContext),
        stack: error.stack
      };
      
      if (!this.dryRun) {
        await this.errorHandler.handleError(errorData);
      }
      
      return { success: false, duration: stepDuration, error: error.message };
    }
  }

  async stopApplication() {
    return await this.executeStep(
      'Stop Application',
      () => this.stopper.stopApplication(),
      { component: 'Application Stopper', action: 'stop processes and containers' }
    );
  }

  async cleanBuildEnvironment() {
    return await this.executeStep(
      'Clean Build Environment',
      () => this.cleaner.cleanBuildEnvironment(),
      { component: 'Build Environment Cleaner', action: 'clean artifacts and cache' }
    );
  }

  async buildAndLaunchApplication() {
    return await this.executeStep(
      'Build and Launch Application',
      () => this.builder.buildAndLaunch(),
      { component: 'Production Builder', action: 'build and launch application' }
    );
  }

  async runBVTSuite() {
    if (this.skipBVT) {
      this.log('Skipping BVT suite execution (skip-bvt flag set)', 'INFO');
      return { success: true, duration: 0, result: { skipped: true } };
    }
    
    return await this.executeStep(
      'Run BVT Suite',
      () => this.bvtRunner.run(),
      { component: 'BVT Runner', action: 'execute build verification tests' }
    );
  }

  generateProcessReport(steps, totalDuration) {
    const timestamp = new Date().toISOString();
    const successfulSteps = steps.filter(step => step.success).length;
    const failedSteps = steps.length - successfulSteps;
    const overallSuccess = failedSteps === 0;
    
    let report = `# Restart, Rebuild, and Relaunch Process Report\n\n`;
    report += `**Generated:** ${timestamp}\n`;
    report += `**Total Duration:** ${(totalDuration / 1000).toFixed(2)} seconds\n`;
    report += `**Overall Result:** ${overallSuccess ? '✅ SUCCESS' : '❌ FAILURE'}\n\n`;
    
    report += `## Summary\n\n`;
    report += `- **Total Steps:** ${steps.length}\n`;
    report += `- **Successful Steps:** ${successfulSteps}\n`;
    report += `- **Failed Steps:** ${failedSteps}\n`;
    report += `- **Success Rate:** ${((successfulSteps / steps.length) * 100).toFixed(1)}%\n\n`;
    
    report += `## Step Details\n\n`;
    report += `| Step | Status | Duration | Notes |\n`;
    report += `|------|--------|----------|-------|\n`;
    
    steps.forEach(step => {
      const status = step.success ? '✅ SUCCESS' : '❌ FAILURE';
      const duration = `${(step.duration / 1000).toFixed(2)}s`;
      const notes = step.error || (step.result?.skipped ? 'Skipped' : 'Completed');
      
      report += `| ${step.name} | ${status} | ${duration} | ${notes} |\n`;
    });
    
    if (failedSteps > 0) {
      report += `\n## Failed Steps Details\n\n`;
      steps.filter(step => !step.success).forEach(step => {
        report += `### ${step.name}\n\n`;
        report += `**Error:** ${step.error}\n\n`;
      });
    }
    
    report += `\n## Process Configuration\n\n`;
    report += `- **Verbose Mode:** ${this.verbose ? 'Enabled' : 'Disabled'}\n`;
    report += `- **Dry Run:** ${this.dryRun ? 'Enabled' : 'Disabled'}\n`;
    report += `- **Clean Dependencies:** ${!this.skipCleanDeps ? 'Enabled' : 'Disabled'}\n`;
    report += `- **BVT Mode:** ${this.skipBVT ? 'Skipped' : this.bvtMode}\n`;
    report += `- **Timeout:** ${this.timeout / 1000} seconds\n\n`;
    
    report += `## Log Files\n\n`;
    report += `- **Process Log:** ${this.logFile}\n`;
    report += `- **BVT Log:** ${this.bvtRunner.logFile}\n`;
    report += `- **Error Handler Log:** ${this.errorHandler.logFile}\n\n`;
    
    return report;
  }

  async executeRestartProcess() {
    this.log('=== Restart, Rebuild, and Relaunch Process Started ===');
    const processStartTime = Date.now();
    
    const steps = [];
    
    try {
      // Step 1: Stop running applications
      const stopResult = await this.stopApplication();
      steps.push({ name: 'Stop Application', ...stopResult });
      
      if (!stopResult.success) {
        throw new Error('Failed to stop application - aborting process');
      }
      
      // Step 2: Clean build environment
      const cleanResult = await this.cleanBuildEnvironment();
      steps.push({ name: 'Clean Build Environment', ...cleanResult });
      
      if (!cleanResult.success) {
        this.log('Build environment cleanup failed, continuing with caution...', 'WARN');
      }
      
      // Step 3: Build and launch application
      const buildResult = await this.buildAndLaunchApplication();
      steps.push({ name: 'Build and Launch Application', ...buildResult });
      
      if (!buildResult.success) {
        throw new Error('Failed to build and launch application - aborting process');
      }
      
      // Step 4: Run BVT suite
      const bvtResult = await this.runBVTSuite();
      steps.push({ name: 'Run BVT Suite', ...bvtResult });
      
      if (!bvtResult.success && !bvtResult.result?.skipped) {
        this.log('BVT suite failed - process completed with warnings', 'WARN');
      }
      
      const totalDuration = Date.now() - processStartTime;
      
      // Generate process report
      const report = this.generateProcessReport(steps, totalDuration);
      fs.writeFileSync(this.reportFile, report);
      
      const overallSuccess = steps.every(step => step.success || step.result?.skipped);
      
      this.log(`=== Restart Process Completed in ${totalDuration}ms ===`, 'SUCCESS');
      this.log(`Report generated: ${this.reportFile}`, 'INFO');
      
      return {
        success: overallSuccess,
        duration: totalDuration,
        steps,
        reportFile: this.reportFile,
        message: overallSuccess ? 'Process completed successfully' : 'Process completed with errors'
      };
      
    } catch (error) {
      const totalDuration = Date.now() - processStartTime;
      this.log(`=== Restart Process Failed after ${totalDuration}ms ===`, 'ERROR');
      this.log(`Critical Error: ${error.message}`, 'ERROR');
      
      // Generate failure report
      const report = this.generateProcessReport(steps, totalDuration);
      fs.writeFileSync(this.reportFile, report);
      
      return {
        success: false,
        duration: totalDuration,
        steps,
        error: error.message,
        reportFile: this.reportFile,
        message: 'Process failed due to critical error'
      };
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose') || args.includes('-v');
  const dryRun = args.includes('--dry-run') || args.includes('-d');
  const cleanDeps = args.includes('--clean-deps') || args.includes('--dependencies');
  const skipBVT = args.includes('--skip-bvt');
  const bvtMode = args.find(arg => arg.startsWith('--bvt-mode='))?.split('=')[1] || 'full';
  const timeout = parseInt(args.find(arg => arg.startsWith('--timeout='))?.split('=')[1]) || 1200000;
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Restart, Rebuild, and Relaunch Orchestrator
Usage: node scripts/restart-rebuild-relaunch.js [options]

Options:
  --verbose, -v         Enable verbose logging
  --dry-run, -d         Show what would be done without making changes
  --clean-deps          Also clean node_modules and lock files
  --dependencies        Alias for --clean-deps
  --skip-bvt            Skip BVT suite execution
  --bvt-mode=<mode>     BVT mode: full, health, validate, info (default: full)
  --timeout=<ms>        Set timeout for entire process (default: 1200000ms)
  --help, -h            Show this help message

Examples:
  node scripts/restart-rebuild-relaunch.js
  node scripts/restart-rebuild-relaunch.js --verbose
  node scripts/restart-rebuild-relaunch.js --dry-run
  node scripts/restart-rebuild-relaunch.js --clean-deps --bvt-mode=health
`);
    process.exit(0);
  }
  
  const orchestrator = new RestartRebuildRelaunchOrchestrator({
    verbose,
    dryRun,
    skipCleanDeps: !cleanDeps,
    skipBVT,
    bvtMode,
    timeout
  });
  
  console.log('🔄 Starting Restart, Rebuild, and Relaunch Process...');
  console.log('====================================================');
  
  orchestrator.executeRestartProcess()
    .then(result => {
      console.log('');
      if (result.success) {
        console.log('✅ Restart, Rebuild, and Relaunch Process Completed Successfully!');
        console.log(`⏱️  Total Duration: ${(result.duration / 1000).toFixed(2)} seconds`);
        console.log(`📊 Steps Completed: ${result.steps.filter(s => s.success).length}/${result.steps.length}`);
        console.log(`📄 Report: ${result.reportFile}`);
        
        if (dryRun) {
          console.log('🔍 This was a dry run - no actual changes were made');
        }
        
        process.exit(0);
      } else {
        console.error('❌ Restart, Rebuild, and Relaunch Process Failed!');
        console.error(`⏱️  Total Duration: ${(result.duration / 1000).toFixed(2)} seconds`);
        console.error(`📊 Steps Completed: ${result.steps.filter(s => s.success).length}/${result.steps.length}`);
        console.error(`💥 Error: ${result.error || result.message}`);
        console.log(`📄 Report: ${result.reportFile}`);
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('');
      console.error('❌ Unexpected error in restart process!');
      console.error(`Error: ${error.message}`);
      process.exit(1);
    });
}

module.exports = RestartRebuildRelaunchOrchestrator;
