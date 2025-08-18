// netlify/functions/api/po-data.js
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');

// JWT secret - should match your auth function
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  // Check for authentication token
  const authHeader = event.headers.authorization || event.headers.Authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'No authentication token provided' })
    };
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Token is valid, proceed with fetching data
    const sql = neon(process.env.DATABASE_URL);
    
    // Fetch vendors and projects
    const [vendors, projects] = await Promise.all([
      sql`SELECT name FROM vendors WHERE active = true ORDER BY name`,
      sql`SELECT name FROM projects WHERE active = true ORDER BY name`
    ]);
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        vendors: vendors.map(v => v.name),
        projects: projects.map(p => p.name)
      })
    };
  } catch (error) {
    console.error('Error:', error);
    
    // Check if it's a JWT error
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid or expired token' })
      };
    }
    
    // Database or other error
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch data' })
    };
  }
};
