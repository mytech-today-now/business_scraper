#!/usr/bin/env node
/**
 * Application Stop Script
 * Gracefully stops running Node.js processes and Docker containers
 * Part of the Restart, Rebuild, and Relaunch Enhancement
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

class ApplicationStopper {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.timeout = options.timeout || 30000; // 30 seconds
    this.forceKill = options.forceKill || false;
    this.logFile = path.join(process.cwd(), 'logs', 'stop-application.log');
    this.ensureLogDirectory();
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
    
    if (this.verbose || level === 'ERROR') {
      console.log(logMessage);
    }
    
    // Append to log file
    try {
      fs.appendFileSync(this.logFile, logMessage + '\n');
    } catch (error) {
      console.error('Failed to write to log file:', error.message);
    }
  }

  async executeCommand(command, description) {
    return new Promise((resolve, reject) => {
      this.log(`Executing: ${command}`, 'DEBUG');
      
      exec(command, { timeout: this.timeout }, (error, stdout, stderr) => {
        if (error) {
          this.log(`${description} failed: ${error.message}`, 'ERROR');
          if (stderr) this.log(`stderr: ${stderr}`, 'ERROR');
          reject(error);
        } else {
          this.log(`${description} completed successfully`, 'SUCCESS');
          if (stdout && this.verbose) this.log(`stdout: ${stdout}`, 'DEBUG');
          resolve(stdout);
        }
      });
    });
  }

  async checkProcessesOnPort(port = 3000) {
    this.log(`Checking for processes on port ${port}...`);
    
    try {
      // Windows command to check port usage
      const result = await this.executeCommand(
        `netstat -ano | findstr :${port}`,
        `Port ${port} check`
      );
      
      if (result.trim()) {
        this.log(`Found processes on port ${port}:`, 'WARN');
        this.log(result, 'INFO');
        return true;
      } else {
        this.log(`No processes found on port ${port}`, 'SUCCESS');
        return false;
      }
    } catch (error) {
      // If netstat fails, assume no processes (common on some systems)
      this.log(`Port check completed - no active processes on port ${port}`, 'SUCCESS');
      return false;
    }
  }

  async stopNodeProcesses() {
    this.log('Stopping Node.js processes...');
    
    try {
      // Check for Node.js processes
      const nodeProcesses = await this.executeCommand(
        'tasklist | findstr node',
        'Node.js process check'
      );
      
      if (nodeProcesses.trim()) {
        this.log('Found Node.js processes:', 'INFO');
        this.log(nodeProcesses, 'INFO');
        
        if (this.forceKill) {
          // Force kill all node processes
          await this.executeCommand(
            'taskkill /F /IM node.exe',
            'Force kill Node.js processes'
          );
        } else {
          // Graceful shutdown - try to find and kill specific processes
          const lines = nodeProcesses.split('\n').filter(line => line.includes('node.exe'));
          for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            const pid = parts[1];
            if (pid && !isNaN(pid)) {
              try {
                await this.executeCommand(
                  `taskkill /PID ${pid}`,
                  `Graceful stop Node.js process ${pid}`
                );
              } catch (error) {
                this.log(`Failed to stop process ${pid}, trying force kill...`, 'WARN');
                try {
                  await this.executeCommand(
                    `taskkill /F /PID ${pid}`,
                    `Force kill Node.js process ${pid}`
                  );
                } catch (forceError) {
                  this.log(`Failed to force kill process ${pid}: ${forceError.message}`, 'ERROR');
                }
              }
            }
          }
        }
      } else {
        this.log('No Node.js processes found', 'SUCCESS');
      }
    } catch (error) {
      this.log('No Node.js processes to stop', 'SUCCESS');
    }
  }

  async stopDockerContainers() {
    this.log('Stopping Docker containers...');
    
    try {
      // Check if Docker is available
      await this.executeCommand('docker --version', 'Docker availability check');
      
      // Stop and remove containers using docker-compose
      const composeFiles = [
        'docker-compose.yml',
        'docker-compose.prod.yml',
        'docker-compose.production.yml',
        'docker-compose.simple.yml',
        'docker-compose.simple-prod.yml'
      ];
      
      for (const composeFile of composeFiles) {
        if (fs.existsSync(composeFile)) {
          this.log(`Stopping containers from ${composeFile}...`);
          try {
            await this.executeCommand(
              `docker-compose -f ${composeFile} down`,
              `Stop containers from ${composeFile}`
            );
          } catch (error) {
            this.log(`Failed to stop containers from ${composeFile}: ${error.message}`, 'WARN');
          }
        }
      }
      
      // Remove orphaned containers
      try {
        await this.executeCommand(
          'docker container prune -f',
          'Remove orphaned containers'
        );
      } catch (error) {
        this.log(`Failed to remove orphaned containers: ${error.message}`, 'WARN');
      }
      
    } catch (error) {
      this.log('Docker not available or no containers to stop', 'INFO');
    }
  }

  async stopApplication() {
    this.log('=== Application Stop Process Started ===');
    const startTime = Date.now();
    
    try {
      // Step 1: Check current port usage
      await this.checkProcessesOnPort(3000);
      
      // Step 2: Stop Node.js processes
      await this.stopNodeProcesses();
      
      // Step 3: Stop Docker containers
      await this.stopDockerContainers();
      
      // Step 4: Final verification
      await this.checkProcessesOnPort(3000);
      
      const duration = Date.now() - startTime;
      this.log(`=== Application Stop Process Completed in ${duration}ms ===`, 'SUCCESS');
      
      return {
        success: true,
        duration,
        message: 'Application stopped successfully'
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.log(`=== Application Stop Process Failed after ${duration}ms ===`, 'ERROR');
      this.log(`Error: ${error.message}`, 'ERROR');
      
      return {
        success: false,
        duration,
        error: error.message,
        message: 'Application stop process failed'
      };
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose') || args.includes('-v');
  const forceKill = args.includes('--force') || args.includes('-f');
  const timeout = parseInt(args.find(arg => arg.startsWith('--timeout='))?.split('=')[1]) || 30000;
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Application Stop Script
Usage: node scripts/stop-application.js [options]

Options:
  --verbose, -v     Enable verbose logging
  --force, -f       Force kill processes instead of graceful shutdown
  --timeout=<ms>    Set timeout for operations (default: 30000ms)
  --help, -h        Show this help message

Examples:
  node scripts/stop-application.js
  node scripts/stop-application.js --verbose
  node scripts/stop-application.js --force --verbose
`);
    process.exit(0);
  }
  
  const stopper = new ApplicationStopper({ verbose, forceKill, timeout });
  
  stopper.stopApplication()
    .then(result => {
      if (result.success) {
        console.log('✅ Application stopped successfully');
        process.exit(0);
      } else {
        console.error('❌ Application stop failed:', result.message);
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('❌ Unexpected error:', error.message);
      process.exit(1);
    });
}

module.exports = ApplicationStopper;
