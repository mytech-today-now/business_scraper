#!/usr/bin/env node

/**
 * GitHub Setup Validation Script
 * 
 * This script validates your GitHub token configuration and security setup.
 * 
 * Usage:
 *   node scripts/validate-github-setup.js
 *   npm run validate:github
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

class GitHubSetupValidator {
  constructor() {
    this.envLocalPath = path.join(process.cwd(), '.env.local');
    this.gitignorePath = path.join(process.cwd(), '.gitignore');
    this.errors = [];
    this.warnings = [];
    this.passed = [];
  }

  async validate() {
    console.log('🔍 Validating GitHub Token Setup');
    console.log('=================================\n');

    try {
      this.checkEnvironmentFile();
      this.checkGitIgnoreProtection();
      await this.validateToken();
      this.checkFilePermissions();
      this.checkWorkflowScripts();
      
      this.displayResults();
      
      if (this.errors.length > 0) {
        process.exit(1);
      }
    } catch (error) {
      console.error('❌ Validation failed:', error.message);
      process.exit(1);
    }
  }

  checkEnvironmentFile() {
    console.log('📁 Checking environment file...');
    
    if (!fs.existsSync(this.envLocalPath)) {
      this.errors.push('.env.local file not found');
      this.errors.push('Run: npm run setup:github to create it');
      return;
    }

    const content = fs.readFileSync(this.envLocalPath, 'utf8');
    
    if (!content.includes('GITHUB_TOKEN=')) {
      this.errors.push('GITHUB_TOKEN not found in .env.local');
      return;
    }

    const tokenMatch = content.match(/GITHUB_TOKEN=(.+)/);
    if (!tokenMatch || tokenMatch[1].trim() === '' || tokenMatch[1].includes('your_github_token_here')) {
      this.errors.push('GITHUB_TOKEN is not set to a real value');
      return;
    }

    this.passed.push('✅ .env.local file exists with GITHUB_TOKEN');
  }

  checkGitIgnoreProtection() {
    console.log('🛡️  Checking .gitignore protection...');
    
    if (!fs.existsSync(this.gitignorePath)) {
      this.warnings.push('.gitignore file not found');
      return;
    }

    const gitignoreContent = fs.readFileSync(this.gitignorePath, 'utf8');
    
    const protectedPatterns = [
      '.env.local',
      '.env.*',
      '*github-token*',
      '*token*.txt',
      '*token*.env'
    ];

    const missingPatterns = protectedPatterns.filter(pattern => 
      !gitignoreContent.includes(pattern)
    );

    if (missingPatterns.length > 0) {
      this.warnings.push(`Missing .gitignore patterns: ${missingPatterns.join(', ')}`);
    } else {
      this.passed.push('✅ .gitignore properly protects sensitive files');
    }
  }

  async validateToken() {
    console.log('🔑 Validating GitHub token...');
    
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      // Try to load from .env.local
      if (fs.existsSync(this.envLocalPath)) {
        const content = fs.readFileSync(this.envLocalPath, 'utf8');
        const tokenMatch = content.match(/GITHUB_TOKEN=(.+)/);
        if (tokenMatch) {
          process.env.GITHUB_TOKEN = tokenMatch[1].trim();
        }
      }
    }

    if (!process.env.GITHUB_TOKEN) {
      this.errors.push('GITHUB_TOKEN not available in environment');
      return;
    }

    const finalToken = process.env.GITHUB_TOKEN;

    // Validate token format
    if (!finalToken.startsWith('ghp_') && !finalToken.startsWith('github_pat_')) {
      this.errors.push('Invalid token format (should start with ghp_ or github_pat_)');
      return;
    }

    if (finalToken.length < 40) {
      this.errors.push('Token appears to be too short');
      return;
    }

    // Test API connectivity
    try {
      const user = await this.testGitHubAPI(finalToken);
      this.passed.push(`✅ Token valid for user: ${user.login}`);
      
      // Check token scopes
      await this.checkTokenScopes(finalToken);
      
    } catch (error) {
      this.errors.push(`GitHub API test failed: ${error.message}`);
    }
  }

  async testGitHubAPI(token) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.github.com',
        path: '/user',
        method: 'GET',
        headers: {
          'Authorization': `token ${token}`,
          'User-Agent': 'Business-Scraper-Validator',
          'Accept': 'application/vnd.github.v3+json'
        }
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${data}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(10000, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.end();
    });
  }

  async checkTokenScopes(token) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.github.com',
        path: '/user',
        method: 'HEAD',
        headers: {
          'Authorization': `token ${token}`,
          'User-Agent': 'Business-Scraper-Validator'
        }
      };

      const req = https.request(options, (res) => {
        const scopes = res.headers['x-oauth-scopes'];
        if (scopes) {
          const scopeList = scopes.split(', ').map(s => s.trim());
          
          const requiredScopes = ['repo'];
          const missingScopes = requiredScopes.filter(scope => !scopeList.includes(scope));
          
          if (missingScopes.length > 0) {
            this.warnings.push(`Missing token scopes: ${missingScopes.join(', ')}`);
          } else {
            this.passed.push('✅ Token has required scopes');
          }
        }
        resolve();
      });

      req.on('error', () => resolve()); // Don't fail validation for scope check
      req.setTimeout(5000, () => {
        req.destroy();
        resolve();
      });

      req.end();
    });
  }

  checkFilePermissions() {
    console.log('🔒 Checking file permissions...');
    
    if (!fs.existsSync(this.envLocalPath)) {
      return;
    }

    try {
      const stats = fs.statSync(this.envLocalPath);
      const mode = stats.mode & parseInt('777', 8);
      
      // Check if file is readable by others (Unix-like systems)
      if (process.platform !== 'win32' && (mode & parseInt('044', 8)) !== 0) {
        this.warnings.push('.env.local is readable by others (run: chmod 600 .env.local)');
      } else {
        this.passed.push('✅ File permissions are secure');
      }
    } catch (error) {
      this.warnings.push('Could not check file permissions');
    }
  }

  checkWorkflowScripts() {
    console.log('⚙️  Checking workflow scripts...');
    
    const requiredScripts = [
      'scripts/console-log-enhancement-workflow.js',
      'scripts/setup-github-token.js'
    ];

    const missingScripts = requiredScripts.filter(script => 
      !fs.existsSync(path.join(process.cwd(), script))
    );

    if (missingScripts.length > 0) {
      this.errors.push(`Missing workflow scripts: ${missingScripts.join(', ')}`);
    } else {
      this.passed.push('✅ All workflow scripts are present');
    }
  }

  displayResults() {
    console.log('\n📊 Validation Results');
    console.log('=====================\n');

    if (this.passed.length > 0) {
      console.log('✅ PASSED:');
      this.passed.forEach(item => console.log(`   ${item}`));
      console.log();
    }

    if (this.warnings.length > 0) {
      console.log('⚠️  WARNINGS:');
      this.warnings.forEach(item => console.log(`   ⚠️  ${item}`));
      console.log();
    }

    if (this.errors.length > 0) {
      console.log('❌ ERRORS:');
      this.errors.forEach(item => console.log(`   ❌ ${item}`));
      console.log();
    }

    // Summary
    const total = this.passed.length + this.warnings.length + this.errors.length;
    const score = Math.round((this.passed.length / total) * 100);
    
    console.log(`📈 Overall Score: ${score}% (${this.passed.length}/${total} checks passed)`);
    
    if (this.errors.length === 0) {
      console.log('🎉 Setup is ready for production use!');
      console.log('\n🚀 You can now run:');
      console.log('   npm run workflow:enhancement');
    } else {
      console.log('🔧 Please fix the errors above before using the workflow.');
      console.log('\n💡 Quick fixes:');
      console.log('   npm run setup:github  # Interactive setup');
      console.log('   npm run workflow:enhancement:analyze  # Test without GitHub');
    }
  }
}

// Run validation if called directly
if (require.main === module) {
  const validator = new GitHubSetupValidator();
  validator.validate().catch(console.error);
}

module.exports = GitHubSetupValidator;
