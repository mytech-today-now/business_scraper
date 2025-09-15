#!/usr/bin/env node

// Load environment variables using dotenv
require('dotenv').config({ path: 'config/production.env' });

// Test the exact logic from the database.ts file
console.log('=== Debug Database Configuration Logic ===');

console.log('Environment checks:');
console.log('typeof window:', typeof window);
console.log('process.env.DB_TYPE:', process.env.DB_TYPE);
console.log('DB_TYPE === "postgresql":', process.env.DB_TYPE === 'postgresql');

const serverSideCheck = typeof window === 'undefined';
const dbTypeCheck = process.env.DB_TYPE === 'postgresql';
const combinedCheck = serverSideCheck && dbTypeCheck;

console.log('\nLogic checks:');
console.log('Server-side check (typeof window === "undefined"):', serverSideCheck);
console.log('DB type check (process.env.DB_TYPE === "postgresql"):', dbTypeCheck);
console.log('Combined check (server-side AND postgresql):', combinedCheck);

console.log('\nEnvironment variables:');
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD exists:', !!process.env.DB_PASSWORD);

// Test the exact condition from checkDatabaseConnection
if (typeof window === 'undefined' && process.env.DB_TYPE === 'postgresql') {
  console.log('\n✅ SHOULD USE POSTGRESQL');
} else {
  console.log('\n❌ WILL USE INDEXEDDB');
  console.log('Reason: Server-side =', serverSideCheck, ', DB_TYPE =', process.env.DB_TYPE);
}
