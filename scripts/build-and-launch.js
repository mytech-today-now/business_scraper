#!/usr/bin/env node
/**
 * Production Build and Launch Script
 * Handles production environment setup, build process, and application launch
 * Part of the Restart, Rebuild, and Relaunch Enhancement
 */

const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

class ProductionBuilder {
  constructor(options = {}) {
    this.verbose = options.verbose || false;
    this.timeout = options.timeout || 600000; // 10 minutes
    this.skipBuild = options.skipBuild || false;
    this.skipLaunch = options.skipLaunch || false;
    this.port = options.port || 3000;
    this.logFile = path.join(process.cwd(), 'logs', 'build-and-launch.log');
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

  async executeCommand(command, description, options = {}) {
    return new Promise((resolve, reject) => {
      this.log(`Executing: ${command}`, 'DEBUG');
      
      const childProcess = exec(command, { 
        timeout: options.timeout || this.timeout,
        maxBuffer: 1024 * 1024 * 10, // 10MB buffer
        ...options
      }, (error, stdout, stderr) => {
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

      // Log real-time output for long-running commands
      if (this.verbose && (description.includes('build') || description.includes('install'))) {
        childProcess.stdout?.on('data', (data) => {
          process.stdout.write(data);
        });
        childProcess.stderr?.on('data', (data) => {
          process.stderr.write(data);
        });
      }
    });
  }

  async validateEnvironment() {
    this.log('Validating environment...');
    
    // Check Node.js version
    try {
      const nodeVersion = await this.executeCommand('node --version', 'Node.js version check');
      this.log(`Node.js version: ${nodeVersion.trim()}`, 'INFO');
    } catch (error) {
      throw new Error('Node.js is not installed or not accessible');
    }

    // Check npm availability
    try {
      const npmVersion = await this.executeCommand('npm --version', 'npm version check');
      this.log(`npm version: ${npmVersion.trim()}`, 'INFO');
    } catch (error) {
      throw new Error('npm is not installed or not accessible');
    }

    // Check package.json exists
    if (!fs.existsSync('package.json')) {
      throw new Error('package.json not found in current directory');
    }

    this.log('Environment validation completed', 'SUCCESS');
  }

  async setupProductionEnvironment() {
    this.log('Setting up production environment...');
    
    // Set environment variables
    process.env.NODE_ENV = 'production';
    process.env.NEXT_TELEMETRY_DISABLED = '1';
    
    this.log('Environment variables set:', 'INFO');
    this.log(`  NODE_ENV=${process.env.NODE_ENV}`, 'INFO');
    this.log(`  NEXT_TELEMETRY_DISABLED=${process.env.NEXT_TELEMETRY_DISABLED}`, 'INFO');
    
    // Validate configuration if script exists
    try {
      if (fs.existsSync('scripts/load-config.js')) {
        await this.executeCommand('npm run config:validate', 'Configuration validation');
      } else {
        this.log('Configuration validation script not found, skipping', 'WARN');
      }
    } catch (error) {
      this.log(`Configuration validation failed: ${error.message}`, 'WARN');
    }
    
    this.log('Production environment setup completed', 'SUCCESS');
  }

  async installDependencies() {
    this.log('Installing dependencies...');
    
    // Check if node_modules exists
    if (!fs.existsSync('node_modules')) {
      this.log('node_modules not found, installing dependencies...', 'INFO');
      await this.executeCommand('npm install', 'Dependency installation', { timeout: 300000 }); // 5 minutes
    } else {
      this.log('node_modules exists, checking for updates...', 'INFO');
      try {
        await this.executeCommand('npm ci', 'Clean dependency installation', { timeout: 300000 });
      } catch (error) {
        this.log('npm ci failed, falling back to npm install', 'WARN');
        await this.executeCommand('npm install', 'Dependency installation fallback', { timeout: 300000 });
      }
    }
    
    this.log('Dependencies installation completed', 'SUCCESS');
  }

  async buildApplication() {
    if (this.skipBuild) {
      this.log('Skipping build process (skip-build flag set)', 'INFO');
      return;
    }
    
    this.log('Building application for production...');
    
    try {
      // Run production build
      await this.executeCommand('npm run build', 'Production build', { timeout: 600000 }); // 10 minutes
      
      // Verify build artifacts
      if (fs.existsSync('.next')) {
        this.log('Build artifacts verified (.next directory exists)', 'SUCCESS');
        
        // Check for specific build files
        const buildFiles = ['.next/BUILD_ID', '.next/package.json'];
        for (const file of buildFiles) {
          if (fs.existsSync(file)) {
            this.log(`Build file verified: ${file}`, 'DEBUG');
          }
        }
      } else {
        throw new Error('Build artifacts not found (.next directory missing)');
      }
      
    } catch (error) {
      this.log(`Build failed: ${error.message}`, 'ERROR');
      throw error;
    }
    
    this.log('Application build completed successfully', 'SUCCESS');
  }

  async launchApplication() {
    if (this.skipLaunch) {
      this.log('Skipping application launch (skip-launch flag set)', 'INFO');
      return null;
    }
    
    this.log('Launching production application...');
    
    return new Promise((resolve, reject) => {
      // Start the production server
      const serverProcess = spawn('npm', ['start'], {
        stdio: this.verbose ? 'inherit' : 'pipe',
        env: { ...process.env, NODE_ENV: 'production' }
      });
      
      let serverStarted = false;
      let startupTimeout;
      
      // Set startup timeout
      startupTimeout = setTimeout(() => {
        if (!serverStarted) {
          this.log('Server startup timeout reached', 'ERROR');
          serverProcess.kill();
          reject(new Error('Server startup timeout'));
        }
      }, 60000); // 1 minute timeout
      
      // Handle server output
      if (serverProcess.stdout) {
        serverProcess.stdout.on('data', (data) => {
          const output = data.toString();
          if (this.verbose) {
            process.stdout.write(output);
          }
          
          // Check for server ready indicators
          if (output.includes('ready') || output.includes('started') || output.includes(`localhost:${this.port}`)) {
            if (!serverStarted) {
              serverStarted = true;
              clearTimeout(startupTimeout);
              this.log('Production server started successfully', 'SUCCESS');
              resolve(serverProcess);
            }
          }
        });
      }
      
      if (serverProcess.stderr) {
        serverProcess.stderr.on('data', (data) => {
          const error = data.toString();
          this.log(`Server stderr: ${error}`, 'WARN');
          if (this.verbose) {
            process.stderr.write(error);
          }
        });
      }
      
      serverProcess.on('error', (error) => {
        clearTimeout(startupTimeout);
        this.log(`Server process error: ${error.message}`, 'ERROR');
        reject(error);
      });
      
      serverProcess.on('exit', (code) => {
        clearTimeout(startupTimeout);
        if (code !== 0 && !serverStarted) {
          this.log(`Server exited with code ${code}`, 'ERROR');
          reject(new Error(`Server process exited with code ${code}`));
        }
      });
      
      // Give the server a moment to start
      setTimeout(() => {
        if (!serverStarted) {
          this.verifyServerRunning()
            .then(() => {
              if (!serverStarted) {
                serverStarted = true;
                clearTimeout(startupTimeout);
                this.log('Server verified as running', 'SUCCESS');
                resolve(serverProcess);
              }
            })
            .catch(() => {
              // Continue waiting for server startup
            });
        }
      }, 5000);
    });
  }

  async verifyServerRunning() {
    this.log(`Verifying server is running on port ${this.port}...`);
    
    try {
      // Check if port is in use
      await this.executeCommand(
        `netstat -ano | findstr :${this.port}`,
        'Port verification'
      );
      
      // Try to make a basic HTTP request
      const http = require('http');
      return new Promise((resolve, reject) => {
        const req = http.get(`http://localhost:${this.port}`, (res) => {
          this.log(`Server responding with status: ${res.statusCode}`, 'SUCCESS');
          resolve(true);
        });
        
        req.on('error', (error) => {
          this.log(`Server verification failed: ${error.message}`, 'ERROR');
          reject(error);
        });
        
        req.setTimeout(5000, () => {
          req.destroy();
          reject(new Error('Server verification timeout'));
        });
      });
      
    } catch (error) {
      throw new Error(`Server verification failed: ${error.message}`);
    }
  }

  async buildAndLaunch() {
    this.log('=== Production Build and Launch Process Started ===');
    const startTime = Date.now();
    
    try {
      // Step 1: Validate environment
      await this.validateEnvironment();
      
      // Step 2: Setup production environment
      await this.setupProductionEnvironment();
      
      // Step 3: Install dependencies if needed
      await this.installDependencies();
      
      // Step 4: Build application
      await this.buildApplication();
      
      // Step 5: Launch application
      const serverProcess = await this.launchApplication();
      
      // Step 6: Verify server is running
      if (!this.skipLaunch) {
        await this.verifyServerRunning();
      }
      
      const duration = Date.now() - startTime;
      this.log(`=== Production Build and Launch Completed in ${duration}ms ===`, 'SUCCESS');
      
      return {
        success: true,
        duration,
        serverProcess,
        message: 'Application built and launched successfully'
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      this.log(`=== Production Build and Launch Failed after ${duration}ms ===`, 'ERROR');
      this.log(`Error: ${error.message}`, 'ERROR');
      
      return {
        success: false,
        duration,
        error: error.message,
        message: 'Production build and launch failed'
      };
    }
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const verbose = args.includes('--verbose') || args.includes('-v');
  const skipBuild = args.includes('--skip-build');
  const skipLaunch = args.includes('--skip-launch');
  const port = parseInt(args.find(arg => arg.startsWith('--port='))?.split('=')[1]) || 3000;
  const timeout = parseInt(args.find(arg => arg.startsWith('--timeout='))?.split('=')[1]) || 600000;
  
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
Production Build and Launch Script
Usage: node scripts/build-and-launch.js [options]

Options:
  --verbose, -v     Enable verbose logging
  --skip-build      Skip the build process (use existing build)
  --skip-launch     Skip launching the application
  --port=<number>   Set the port to verify (default: 3000)
  --timeout=<ms>    Set timeout for operations (default: 600000ms)
  --help, -h        Show this help message

Examples:
  node scripts/build-and-launch.js
  node scripts/build-and-launch.js --verbose
  node scripts/build-and-launch.js --skip-build
  node scripts/build-and-launch.js --port=8080
`);
    process.exit(0);
  }
  
  const builder = new ProductionBuilder({ verbose, skipBuild, skipLaunch, port, timeout });
  
  builder.buildAndLaunch()
    .then(result => {
      if (result.success) {
        console.log('✅ Production build and launch completed successfully');
        if (!skipLaunch) {
          console.log(`🚀 Server is running on http://localhost:${port}`);
          console.log('Press Ctrl+C to stop the server');
        }
        // Don't exit if server is running
        if (skipLaunch) {
          process.exit(0);
        }
      } else {
        console.error('❌ Production build and launch failed:', result.message);
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('❌ Unexpected error:', error.message);
      process.exit(1);
    });
}

module.exports = ProductionBuilder;
