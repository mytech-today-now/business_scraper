#!/usr/bin/env node
/**
 * Build Environment Cleanup Script
 * Cleans build artifacts, coverage, test results, and temporary files
 * Part of the Restart, Rebuild, and Relaunch Enhancement
 */

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

class BuildEnvironmentCleaner {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.dryRun = options.dryRun || false;
    this.preserveDependencies = options.preserveDependencies !== false; // Default true
    this.logFile = path.join(process.cwd(), 'logs', 'clean-build-environment.log');
    this.ensureLogDirectory();
    
    // Define directories and files to clean
    this.cleanupTargets = {
      buildArtifacts: [
        '.next',
        'dist',
        'build',
        'out'
      ],
      testArtifacts: [
        'coverage',
        'test-results',
        'playwright-report',
        '.nyc_output'
      ],
      temporaryFiles: [
        'temp',
        'tmp',
        '.tmp'
      ],
      logFiles: [
        'logs/*.log',
        'logs/*.log.*',
        '*.log'
      ],
      cacheFiles: [
        '.cache',
        'node_modules/.cache',
        '.eslintcache',
        '.tsbuildinfo'
      ],
      dependencyFiles: [
        'node_modules',
        'package-lock.json',
        'yarn.lock'
      ]
    };
  }

  ensureLogDirectory() {
    const logDir = path.dirname(this.logFile);
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  log(message, level = 'INFO') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level}] ${message}`;
    
    if (this.verbose || level === 'ERROR' || level === 'WARN') {
      console.log(logMessage);
    }
    
    // Append to log file
    try {
      fs.appendFileSync(this.logFile, logMessage + '\n');
    } catch (error) {
      console.error('Failed to write to log file:', error.message);
    }
  }

  async removeDirectory(dirPath) {
    if (!fs.existsSync(dirPath)) {
      this.log(`Directory does not exist: ${dirPath}`, 'DEBUG');
      return false;
    }

    if (this.dryRun) {
      this.log(`[DRY RUN] Would remove directory: ${dirPath}`, 'INFO');
      return true;
    }

    try {
      await fs.promises.rm(dirPath, { recursive: true, force: true });
      this.log(`Removed directory: ${dirPath}`, 'SUCCESS');
      return true;
    } catch (error) {
      this.log(`Failed to remove directory ${dirPath}: ${error.message}`, 'ERROR');
      return false;
    }
  }

  async removeFile(filePath) {
    if (!fs.existsSync(filePath)) {
      this.log(`File does not exist: ${filePath}`, 'DEBUG');
      return false;
    }

    if (this.dryRun) {
      this.log(`[DRY RUN] Would remove file: ${filePath}`, 'INFO');
      return true;
    }

    try {
      await fs.promises.unlink(filePath);
      this.log(`Removed file: ${filePath}`, 'SUCCESS');
      return true;
    } catch (error) {
      this.log(`Failed to remove file ${filePath}: ${error.message}`, 'ERROR');
      return false;
    }
  }

  async removeGlobPattern(pattern) {
    const glob = require('glob');
    const files = glob.sync(pattern, { ignore: ['node_modules/**'] });
    
    let removedCount = 0;
    for (const file of files) {
      const stat = await fs.promises.stat(file).catch(() => null);
      if (stat) {
        if (stat.isDirectory()) {
          if (await this.removeDirectory(file)) removedCount++;
        } else {
          if (await this.removeFile(file)) removedCount++;
        }
      }
    }
    
    return removedCount;
  }

  async cleanBuildArtifacts() {
    this.log('Cleaning build artifacts...');
    let totalRemoved = 0;
    
    for (const target of this.cleanupTargets.buildArtifacts) {
      if (await this.removeDirectory(target)) {
        totalRemoved++;
      }
    }
    
    this.log(`Build artifacts cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async cleanTestArtifacts() {
    this.log('Cleaning test artifacts...');
    let totalRemoved = 0;
    
    for (const target of this.cleanupTargets.testArtifacts) {
      if (await this.removeDirectory(target)) {
        totalRemoved++;
      }
    }
    
    this.log(`Test artifacts cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async cleanTemporaryFiles() {
    this.log('Cleaning temporary files...');
    let totalRemoved = 0;
    
    for (const target of this.cleanupTargets.temporaryFiles) {
      if (await this.removeDirectory(target)) {
        totalRemoved++;
      }
    }
    
    this.log(`Temporary files cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async cleanLogFiles() {
    this.log('Cleaning log files...');
    let totalRemoved = 0;
    
    for (const pattern of this.cleanupTargets.logFiles) {
      const removed = await this.removeGlobPattern(pattern);
      totalRemoved += removed;
    }
    
    this.log(`Log files cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async cleanCacheFiles() {
    this.log('Cleaning cache files...');
    let totalRemoved = 0;
    
    for (const target of this.cleanupTargets.cacheFiles) {
      if (await this.removeDirectory(target)) {
        totalRemoved++;
      }
    }
    
    this.log(`Cache files cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async cleanDependencies() {
    if (this.preserveDependencies) {
      this.log('Skipping dependency cleanup (preserve dependencies enabled)', 'INFO');
      return 0;
    }
    
    this.log('Cleaning dependencies (WARNING: This will require npm install)...');
    let totalRemoved = 0;
    
    for (const target of this.cleanupTargets.dependencyFiles) {
      if (target === 'node_modules') {
        if (await this.removeDirectory(target)) {
          totalRemoved++;
        }
      } else {
        if (await this.removeFile(target)) {
          totalRemoved++;
        }
      }
    }
    
    this.log(`Dependencies cleanup completed. Removed ${totalRemoved} items.`, 'SUCCESS');
    return totalRemoved;
  }

  async getDirectorySize(dirPath) {
    if (!fs.existsSync(dirPath)) return 0;
    
    try {
      const stats = await fs.promises.stat(dirPath);
      if (stats.isFile()) {
        return stats.size;
      }
      
      let totalSize = 0;
      const files = await fs.promises.readdir(dirPath);
      
      for (const file of files) {
        const filePath = path.join(dirPath, file);
        totalSize += await this.getDirectorySize(filePath);
      }
      
      return totalSize;
    } catch (error) {
      return 0;
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async analyzeCleanupTargets() {
    this.log('Analyzing cleanup targets...');
    const analysis = {};
    
    const allTargets = [
      ...this.cleanupTargets.buildArtifacts,
      ...this.cleanupTargets.testArtifacts,
      ...this.cleanupTargets.temporaryFiles,
      ...this.cleanupTargets.cacheFiles
    ];
    
    if (!this.preserveDependencies) {
      allTargets.push(...this.cleanupTargets.dependencyFiles);
    }
    
    let totalSize = 0;
    for (const target of allTargets) {
      const size = await this.getDirectorySize(target);
      if (size > 0) {
        analysis[target] = size;
        totalSize += size;
      }
    }
    
    this.log(`Analysis complete. Total size to clean: ${this.formatBytes(totalSize)}`, 'INFO');
    return { analysis, totalSize };
  }

  async cleanBuildEnvironment() {
    this.log('=== Build Environment Cleanup Started ===');
    const startTime = Date.now();
    
    try {
      // Analyze what will be cleaned
      const { analysis, totalSize } = await this.analyzeCleanupTargets();
      
      if (this.verbose) {
        this.log('Cleanup targets analysis:', 'INFO');
        for (const [target, size] of Object.entries(analysis)) {
          this.log(`  ${target}: ${this.formatBytes(size)}`, 'INFO');
        }
      }
      
      let totalItemsRemoved = 0;
      
      // Clean build artifacts
      totalItemsRemoved += await this.cleanBuildArtifacts();
      
      // Clean test artifacts
      totalItemsRemoved += await this.cleanTestArtifacts();
      
      // Clean temporary files
      totalItemsRemoved += await this.cleanTemporaryFiles();
      
      // Clean cache files
      totalItemsRemoved += await this.cleanCacheFiles();
      
      // Clean log files (but preserve current log)
      totalItemsRemoved += await this.cleanLogFiles();
      
      // Clean dependencies if requested
      totalItemsRemoved += await this.cleanDependencies();
      
      const duration = Date.now() - startTime;
      this.log(`=== Build Environment Cleanup Completed in ${duration}ms ===`, 'SUCCESS');
      this.log(`Total items removed: ${totalItemsRemoved}`, 'SUCCESS');
      this.log(`Estimated space freed: ${this.formatBytes(totalSize)}`, 'SUCCESS');
      
      return {
        success: true,
        duration,
        itemsRemoved: totalItemsRemoved,
        spaceFreed: totalSize,
        message: 'Build environment cleaned successfully'
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.log(`=== Build Environment Cleanup Failed after ${duration}ms ===`, 'ERROR');
      this.log(`Error: ${error.message}`, 'ERROR');
      
      return {
        success: false,
        duration,
        error: error.message,
        message: 'Build environment cleanup failed'
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
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Build Environment Cleanup Script
Usage: node scripts/clean-build-environment.js [options]

Options:
  --verbose, -v         Enable verbose logging
  --dry-run, -d         Show what would be cleaned without actually removing files
  --clean-deps          Also clean node_modules and lock files (requires npm install)
  --dependencies        Alias for --clean-deps
  --help, -h            Show this help message

Examples:
  node scripts/clean-build-environment.js
  node scripts/clean-build-environment.js --verbose
  node scripts/clean-build-environment.js --dry-run
  node scripts/clean-build-environment.js --clean-deps --verbose
`);
    process.exit(0);
  }
  
  const cleaner = new BuildEnvironmentCleaner({ 
    verbose, 
    dryRun, 
    preserveDependencies: !cleanDeps 
  });
  
  cleaner.cleanBuildEnvironment()
    .then(result => {
      if (result.success) {
        console.log('✅ Build environment cleaned successfully');
        if (dryRun) {
          console.log('🔍 This was a dry run - no files were actually removed');
        }
        process.exit(0);
      } else {
        console.error('❌ Build environment cleanup failed:', result.message);
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('❌ Unexpected error:', error.message);
      process.exit(1);
    });
}

module.exports = BuildEnvironmentCleaner;
