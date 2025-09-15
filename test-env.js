#!/usr/bin/env node

// Load environment variables using dotenv
require('dotenv').config({ path: 'config/production.env' });

console.log('=== Environment Variables Test ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('DB_TYPE:', process.env.DB_TYPE);
console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'SET' : 'NOT SET');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD:', process.env.DB_PASSWORD ? 'SET' : 'NOT SET');

// Test the database configuration logic
console.log('\n=== Database Configuration Test ===');
console.log('typeof window:', typeof window);
console.log('typeof process:', typeof process);
console.log('process.env exists:', !!process.env);
console.log('Server environment check:', typeof window === 'undefined' && typeof process !== 'undefined' && process.env);
console.log('DB_TYPE check:', process.env.DB_TYPE === 'postgresql');
console.log('Combined check:', typeof window === 'undefined' && process.env.DB_TYPE === 'postgresql');
