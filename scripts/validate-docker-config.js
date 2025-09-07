#!/usr/bin/env node

/**
 * Docker Configuration Validation Script
 * Validates environment variables and Docker configuration for production deployment
 */

const fs = require('fs');
const path = require('path');

// Color codes for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

function log(message, color = 'white') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function validateDockerConfig() {
  log('🐳 Docker Configuration Validation', 'cyan');
  log('=====================================', 'cyan');

  const results = {
    passed: 0,
    failed: 0,
    warnings: 0,
    issues: []
  };

  // Check if required files exist
  const requiredFiles = [
    '.env',
    '.env.docker.production.template',
    'docker-compose.production.yml',
    'Dockerfile.production'
  ];

  log('\n📁 Checking required files...', 'blue');
  requiredFiles.forEach(file => {
    if (fs.existsSync(file)) {
      log(`  ✅ ${file}`, 'green');
      results.passed++;
    } else {
      log(`  ❌ ${file} - Missing`, 'red');
      results.failed++;
      results.issues.push(`Missing required file: ${file}`);
    }
  });

  // Load and validate .env file
  log('\n🔧 Validating .env configuration...', 'blue');
  if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf8');
    const envLines = envContent.split('\n').filter(line => line.trim() && !line.startsWith('#'));
    
    // Check for Docker-specific configurations
    const dockerChecks = [
      { key: 'NODE_ENV', expected: 'production', critical: true },
      { key: 'HOSTNAME', expected: '0.0.0.0', critical: true },
      { key: 'DB_HOST', expected: 'postgres', critical: true },
      { key: 'REDIS_HOST', expected: 'redis', critical: true },
      { key: 'DOCKER_DEPLOYMENT', expected: 'true', critical: false },
      { key: 'CONTAINER_NAME_PREFIX', expected: null, critical: false },
      { key: 'RESTART_POLICY', expected: 'unless-stopped', critical: false }
    ];

    const envVars = {};
    envLines.forEach(line => {
      const [key, ...valueParts] = line.split('=');
      if (key && valueParts.length > 0) {
        envVars[key] = valueParts.join('=');
      }
    });

    dockerChecks.forEach(check => {
      const value = envVars[check.key];
      if (!value) {
        if (check.critical) {
          log(`  ❌ ${check.key} - Missing (Critical)`, 'red');
          results.failed++;
          results.issues.push(`Missing critical environment variable: ${check.key}`);
        } else {
          log(`  ⚠️  ${check.key} - Missing (Optional)`, 'yellow');
          results.warnings++;
        }
      } else if (check.expected && value !== check.expected) {
        if (check.critical) {
          log(`  ❌ ${check.key}=${value} - Expected: ${check.expected}`, 'red');
          results.failed++;
          results.issues.push(`Incorrect value for ${check.key}: got ${value}, expected ${check.expected}`);
        } else {
          log(`  ⚠️  ${check.key}=${value} - Recommended: ${check.expected}`, 'yellow');
          results.warnings++;
        }
      } else {
        log(`  ✅ ${check.key}=${value}`, 'green');
        results.passed++;
      }
    });

    // Check for placeholder values that need to be replaced
    const placeholderChecks = [
      'YOUR_SECURE_POSTGRES_PASSWORD_HERE',
      'YOUR_SECURE_REDIS_PASSWORD_HERE',
      'YOUR_SECURE_ADMIN_PASSWORD_HERE',
      'YOUR_PRODUCTION_AZURE_AI_FOUNDRY_API_KEY',
      'pk_live_YOUR_PRODUCTION_STRIPE_PUBLISHABLE_KEY',
      'sk_live_YOUR_PRODUCTION_STRIPE_SECRET_KEY'
    ];

    log('\n🔐 Checking for placeholder values...', 'blue');
    let hasPlaceholders = false;
    placeholderChecks.forEach(placeholder => {
      if (envContent.includes(placeholder)) {
        log(`  ⚠️  Found placeholder: ${placeholder}`, 'yellow');
        results.warnings++;
        hasPlaceholders = true;
      }
    });

    if (!hasPlaceholders) {
      log('  ✅ No placeholder values found', 'green');
      results.passed++;
    }
  }

  // Validate Docker Compose configuration
  log('\n🐋 Validating Docker Compose configuration...', 'blue');
  if (fs.existsSync('docker-compose.production.yml')) {
    const composeContent = fs.readFileSync('docker-compose.production.yml', 'utf8');
    
    const composeChecks = [
      { pattern: /version:\s*['"]3\.\d+['"]/, name: 'Docker Compose version 3.x' },
      { pattern: /networks:/, name: 'Networks configuration' },
      { pattern: /volumes:/, name: 'Volumes configuration' },
      { pattern: /env_file:/, name: 'Environment file usage' },
      { pattern: /healthcheck:/, name: 'Health checks' },
      { pattern: /restart:\s*unless-stopped/, name: 'Restart policy' },
      { pattern: /deploy:/, name: 'Resource limits' }
    ];

    composeChecks.forEach(check => {
      if (check.pattern.test(composeContent)) {
        log(`  ✅ ${check.name}`, 'green');
        results.passed++;
      } else {
        log(`  ❌ ${check.name} - Missing`, 'red');
        results.failed++;
        results.issues.push(`Missing Docker Compose configuration: ${check.name}`);
      }
    });
  }

  // Check for security best practices
  log('\n🔒 Security validation...', 'blue');
  const securityChecks = [
    {
      name: 'No hardcoded secrets in .env',
      check: () => {
        if (!fs.existsSync('.env')) return false;
        const content = fs.readFileSync('.env', 'utf8');
        const suspiciousPatterns = [
          /password=.{1,20}$/mi,
          /secret=.{1,30}$/mi,
          /key=.{1,40}$/mi
        ];
        return !suspiciousPatterns.some(pattern => pattern.test(content));
      }
    },
    {
      name: 'Production environment set',
      check: () => {
        if (!fs.existsSync('.env')) return false;
        const content = fs.readFileSync('.env', 'utf8');
        return content.includes('NODE_ENV=production');
      }
    },
    {
      name: 'Debug disabled in production',
      check: () => {
        if (!fs.existsSync('.env')) return false;
        const content = fs.readFileSync('.env', 'utf8');
        return content.includes('NEXT_PUBLIC_DEBUG=false');
      }
    }
  ];

  securityChecks.forEach(check => {
    if (check.check()) {
      log(`  ✅ ${check.name}`, 'green');
      results.passed++;
    } else {
      log(`  ⚠️  ${check.name} - Review needed`, 'yellow');
      results.warnings++;
    }
  });

  // Summary
  log('\n📊 Validation Summary', 'magenta');
  log('===================', 'magenta');
  log(`✅ Passed: ${results.passed}`, 'green');
  log(`⚠️  Warnings: ${results.warnings}`, 'yellow');
  log(`❌ Failed: ${results.failed}`, 'red');

  if (results.issues.length > 0) {
    log('\n🚨 Critical Issues to Address:', 'red');
    results.issues.forEach((issue, index) => {
      log(`  ${index + 1}. ${issue}`, 'red');
    });
  }

  if (results.warnings > 0) {
    log('\n💡 Recommendations:', 'yellow');
    log('  - Replace all placeholder values with production secrets', 'yellow');
    log('  - Use Docker secrets for sensitive data in production', 'yellow');
    log('  - Verify all external service configurations', 'yellow');
    log('  - Test deployment in staging environment first', 'yellow');
  }

  if (results.failed === 0) {
    log('\n🎉 Docker configuration validation passed!', 'green');
    log('Ready for production deployment.', 'green');
    return true;
  } else {
    log('\n❌ Docker configuration validation failed!', 'red');
    log('Please address the critical issues before deployment.', 'red');
    return false;
  }
}

// Run validation
if (require.main === module) {
  const isValid = validateDockerConfig();
  process.exit(isValid ? 0 : 1);
}

module.exports = { validateDockerConfig };
