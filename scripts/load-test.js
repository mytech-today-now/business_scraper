#!/usr/bin/env node

/**
 * Load Testing Script
 * Performs basic load testing for the application
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

// Configuration
const config = {
  baseUrl: process.env.TEST_URL || 'http://localhost:3000',
  concurrentUsers: parseInt(process.env.LOAD_TEST_USERS) || 10,
  duration: parseInt(process.env.LOAD_TEST_DURATION) || 30, // seconds
  endpoints: [
    '/',
    '/api/health',
    '/login',
    '/dashboard'
  ]
};

class LoadTester {
  constructor(config) {
    this.config = config;
    this.results = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      minResponseTime: Infinity,
      maxResponseTime: 0,
      responseTimes: []
    };
  }

  async makeRequest(endpoint) {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const url = new URL(endpoint, this.config.baseUrl);
      const client = url.protocol === 'https:' ? https : http;

      const req = client.get(url, (res) => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        this.results.totalRequests++;
        this.results.responseTimes.push(responseTime);

        if (res.statusCode >= 200 && res.statusCode < 400) {
          this.results.successfulRequests++;
        } else {
          this.results.failedRequests++;
        }

        this.updateResponseTimeStats(responseTime);
        resolve({ statusCode: res.statusCode, responseTime });
      });

      req.on('error', (error) => {
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        this.results.totalRequests++;
        this.results.failedRequests++;
        this.results.responseTimes.push(responseTime);
        this.updateResponseTimeStats(responseTime);

        resolve({ error: error.message, responseTime });
      });

      req.setTimeout(10000, () => {
        req.destroy();
        const endTime = Date.now();
        const responseTime = endTime - startTime;

        this.results.totalRequests++;
        this.results.failedRequests++;
        this.results.responseTimes.push(responseTime);
        this.updateResponseTimeStats(responseTime);

        resolve({ error: 'Timeout', responseTime });
      });
    });
  }

  updateResponseTimeStats(responseTime) {
    this.results.minResponseTime = Math.min(this.results.minResponseTime, responseTime);
    this.results.maxResponseTime = Math.max(this.results.maxResponseTime, responseTime);
    
    const sum = this.results.responseTimes.reduce((a, b) => a + b, 0);
    this.results.averageResponseTime = sum / this.results.responseTimes.length;
  }

  async runLoadTest() {
    console.log('🚀 Starting Load Test...');
    console.log(`📊 Configuration:`);
    console.log(`   Base URL: ${this.config.baseUrl}`);
    console.log(`   Concurrent Users: ${this.config.concurrentUsers}`);
    console.log(`   Duration: ${this.config.duration} seconds`);
    console.log(`   Endpoints: ${this.config.endpoints.join(', ')}`);
    console.log('');

    const startTime = Date.now();
    const endTime = startTime + (this.config.duration * 1000);
    const workers = [];

    // Start concurrent workers
    for (let i = 0; i < this.config.concurrentUsers; i++) {
      workers.push(this.runWorker(endTime));
    }

    // Wait for all workers to complete
    await Promise.all(workers);

    this.generateReport();
  }

  async runWorker(endTime) {
    while (Date.now() < endTime) {
      const endpoint = this.config.endpoints[Math.floor(Math.random() * this.config.endpoints.length)];
      await this.makeRequest(endpoint);
      
      // Small delay between requests
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  generateReport() {
    console.log('\n📈 Load Test Results:');
    console.log('='.repeat(50));
    console.log(`Total Requests: ${this.results.totalRequests}`);
    console.log(`Successful Requests: ${this.results.successfulRequests}`);
    console.log(`Failed Requests: ${this.results.failedRequests}`);
    console.log(`Success Rate: ${((this.results.successfulRequests / this.results.totalRequests) * 100).toFixed(2)}%`);
    console.log('');
    console.log('Response Time Statistics:');
    console.log(`  Average: ${this.results.averageResponseTime.toFixed(2)}ms`);
    console.log(`  Minimum: ${this.results.minResponseTime}ms`);
    console.log(`  Maximum: ${this.results.maxResponseTime}ms`);
    
    // Calculate percentiles
    const sortedTimes = this.results.responseTimes.sort((a, b) => a - b);
    const p50 = sortedTimes[Math.floor(sortedTimes.length * 0.5)];
    const p95 = sortedTimes[Math.floor(sortedTimes.length * 0.95)];
    const p99 = sortedTimes[Math.floor(sortedTimes.length * 0.99)];
    
    console.log(`  50th Percentile: ${p50}ms`);
    console.log(`  95th Percentile: ${p95}ms`);
    console.log(`  99th Percentile: ${p99}ms`);
    console.log('');

    // Performance assessment
    const successRate = (this.results.successfulRequests / this.results.totalRequests) * 100;
    const avgResponseTime = this.results.averageResponseTime;

    if (successRate >= 95 && avgResponseTime <= 1000) {
      console.log('✅ Load test PASSED - Good performance');
      process.exit(0);
    } else if (successRate >= 90 && avgResponseTime <= 2000) {
      console.log('⚠️  Load test WARNING - Acceptable performance');
      process.exit(0);
    } else {
      console.log('❌ Load test FAILED - Poor performance');
      process.exit(1);
    }
  }
}

// Run the load test
async function main() {
  try {
    const tester = new LoadTester(config);
    await tester.runLoadTest();
  } catch (error) {
    console.error('❌ Load test failed:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = LoadTester;
