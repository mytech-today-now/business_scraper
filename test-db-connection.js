const postgres = require('postgres');

console.log('=== Database Connection Test ===');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('DATABASE_URL available:', !!process.env.DATABASE_URL);
console.log('DATABASE_URL length:', process.env.DATABASE_URL ? process.env.DATABASE_URL.length : 0);
console.log('DATABASE_URL preview:', process.env.DATABASE_URL ? process.env.DATABASE_URL.substring(0, 50) + '...' : 'undefined');

console.log('\nIndividual environment variables:');
console.log('DB_HOST:', process.env.DB_HOST);
console.log('DB_PORT:', process.env.DB_PORT);
console.log('DB_NAME:', process.env.DB_NAME);
console.log('DB_USER:', process.env.DB_USER);
console.log('DB_PASSWORD length:', process.env.DB_PASSWORD ? process.env.DB_PASSWORD.length : 0);

async function testConnection() {
  console.log('\n=== Testing Direct Connection with DATABASE_URL ===');
  
  if (!process.env.DATABASE_URL) {
    console.error('DATABASE_URL not available');
    return;
  }

  try {
    const sql = postgres(process.env.DATABASE_URL, {
      max: 1,
      idle_timeout: 10,
      connect_timeout: 10,
      ssl: false,
    });

    console.log('postgres.js connection created successfully');
    
    // Test a simple query
    const result = await sql`SELECT 1 as test`;
    console.log('Query result:', result);
    
    await sql.end();
    console.log('Connection closed successfully');
    
  } catch (error) {
    console.error('Connection test failed:', error.message);
    console.error('Error details:', error);
  }
}

async function testConnectionWithIndividualFields() {
  console.log('\n=== Testing Connection with Individual Fields ===');
  
  const host = process.env.DB_HOST || 'postgres';
  const port = process.env.DB_PORT || '5432';
  const database = process.env.DB_NAME || 'business_scraper';
  const username = process.env.DB_USER || 'postgres';
  const password = process.env.DB_PASSWORD || 'password';
  
  const connectionString = `postgresql://${username}:${encodeURIComponent(password)}@${host}:${port}/${database}`;
  console.log('Built connection string:', connectionString.replace(/:[^:@]*@/, ':***@'));
  
  try {
    const sql = postgres(connectionString, {
      max: 1,
      idle_timeout: 10,
      connect_timeout: 10,
      ssl: false,
    });

    console.log('postgres.js connection created successfully');
    
    // Test a simple query
    const result = await sql`SELECT 1 as test`;
    console.log('Query result:', result);
    
    await sql.end();
    console.log('Connection closed successfully');
    
  } catch (error) {
    console.error('Connection test failed:', error.message);
    console.error('Error details:', error);
  }
}

// Run tests
testConnection()
  .then(() => testConnectionWithIndividualFields())
  .then(() => {
    console.log('\n=== Test Complete ===');
    process.exit(0);
  })
  .catch((error) => {
    console.error('Test failed:', error);
    process.exit(1);
  });
