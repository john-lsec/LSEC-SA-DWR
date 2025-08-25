// netlify/functions/auth.js - Complete Authentication Handler
const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize database connection
const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';
const TOKEN_EXPIRY = '24h';

// Helper function to hash passwords
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Helper function to verify passwords
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Helper function to create JWT token
function createJWT(userId, role, email) {
  return jwt.sign(
    { userId, role, email, iat: Date.now() },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

// Helper function to verify JWT token
function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// Handle login
async function handleLogin(event, headers) {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Email and password are required' })
      };
    }

    // Find user by email
    const users = await sql`
      SELECT id, email, password_hash, role, name, is_active 
      FROM users 
      WHERE email = ${email.toLowerCase()} 
      AND is_active = true
    `;

    if (users.length === 0) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    const user = users[0];

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.password_hash);
    
    if (!isPasswordValid) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    // Create JWT token
    const token = createJWT(user.id, user.role, user.email);

    // Create session in database
    const sessionExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    await sql`
      INSERT INTO user_sessions (user_id, token_hash, expires_at, created_at)
      VALUES (${user.id}, ${token}, ${sessionExpiry}, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id) 
      DO UPDATE SET 
        token_hash = ${token},
        expires_at = ${sessionExpiry},
        updated_at = CURRENT_TIMESTAMP
    `;

    // Return successful login response
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        message: 'Login successful',
        token: token,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        }
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Login failed' })
    };
  }
}

// Handle token verification
async function handleVerify(event, headers) {
  if (event.httpMethod !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ valid: false, error: 'No token provided' })
      };
    }

    const token = authHeader.substring(7);
    const decoded = verifyJWT(token);

    if (!decoded) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ valid: false, error: 'Invalid token' })
      };
    }

    // Verify session is still valid in database
    const sessions = await sql`
      SELECT u.id, u.email, u.name, u.role, u.is_active
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.user_id = ${decoded.userId}
        AND s.expires_at > CURRENT_TIMESTAMP
        AND u.is_active = true
      LIMIT 1
    `;

    if (sessions.length === 0) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ valid: false, error: 'Session expired' })
      };
    }

    const user = sessions[0];

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        valid: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role
        }
      })
    };

  } catch (error) {
    console.error('Token verification error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ valid: false, error: 'Verification failed' })
    };
  }
}

// Handle logout
async function handleLogout(event, headers) {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = verifyJWT(token);

      if (decoded && decoded.userId) {
        // Delete session from database
        await sql`
          DELETE FROM user_sessions 
          WHERE user_id = ${decoded.userId}
        `;
      }
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Logout successful' })
    };

  } catch (error) {
    console.error('Logout error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Logout failed' })
    };
  }
}

// Main handler
exports.handler = async (event, context) => {
  console.log('Auth function called');
  console.log('Path:', event.path);
  console.log('Method:', event.httpMethod);
  
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight requests
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Parse the path to determine endpoint
  let endpoint = '';
  
  if (event.path.includes('/auth/')) {
    // Pattern: /.netlify/functions/auth/login
    endpoint = event.path.split('/auth/')[1];
  } else if (event.path.includes('/auth-')) {
    // Pattern: /.netlify/functions/auth-login  
    endpoint = event.path.split('/auth-')[1];
  } else {
    // Default to login if no specific endpoint
    endpoint = 'login';
  }
  
  // Remove any trailing slashes or query parameters
  endpoint = endpoint.split('?')[0].split('/')[0];
  
  console.log('Auth endpoint:', endpoint);

  // Route to appropriate auth handler
  try {
    switch (endpoint) {
      case 'login':
        return await handleLogin(event, headers);
      
      case 'verify':
        return await handleVerify(event, headers);
      
      case 'logout':
        return await handleLogout(event, headers);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Auth endpoint not found',
            endpoint: endpoint,
            availableEndpoints: ['login', 'verify', 'logout']
          })
        };
    }
  } catch (error) {
    console.error('Auth handler error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Authentication service error',
        details: error.message
      })
    };
  }
};
