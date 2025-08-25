// netlify/functions/auth.js - FIXED VERSION
const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';
const TOKEN_EXPIRY = '24h';
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15; // minutes

// Helper function to get database connection
function getDb() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL not configured');
  }
  return neon(process.env.DATABASE_URL);
}

// Helper function to hash passwords
async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

// Helper function to verify passwords
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Helper function to create JWT token
function createJWT(userId, role) {
  return jwt.sign(
    { userId, role, iat: Date.now() },
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

// Main handler - FIXED VERSION
exports.handler = async (event, context) => {
  console.log('Auth function called');
  console.log('Path:', event.path);
  console.log('Method:', event.httpMethod);
  console.log('Body:', event.body);
  
  // Enable CORS
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

  // FIXED: Simplified path parsing
  let endpoint = 'login'; // Default to login
  
  // Extract endpoint from path
  if (event.path.includes('/auth/')) {
    const parts = event.path.split('/auth/');
    if (parts.length > 1 && parts[1]) {
      endpoint = parts[1].replace(/\/$/, ''); // Remove trailing slash
    }
  }
  
  console.log('Parsed endpoint:', endpoint);
  console.log('Route will be:', `${event.httpMethod}:${endpoint}`);

  // Get database connection
  let sql;
  try {
    sql = getDb();
  } catch (error) {
    console.error('Database connection error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Database configuration error',
        message: error.message 
      })
    };
  }

  try {
    // Route based on endpoint and method
    const route = `${event.httpMethod}:${endpoint}`;
    console.log('Processing route:', route);
    
    switch (route) {
      case 'POST:login':
        return await handleLogin(event, headers, sql);
      
      case 'POST:logout':
        return await handleLogout(event, headers, sql);
      
      case 'GET:verify':
        return await handleVerify(event, headers, sql);
      
      case 'POST:register':
        return await handleRegister(event, headers, sql);
      
      case 'PUT:password':
        return await handlePasswordChange(event, headers, sql);
        
      default:
        console.log('Unknown route:', route);
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Auth endpoint not found',
            endpoint: endpoint,
            method: event.httpMethod,
            path: event.path,
            availableRoutes: ['POST:login', 'POST:logout', 'GET:verify', 'POST:register', 'PUT:password']
          })
        };
    }
  } catch (error) {
    console.error('Auth error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error',
        message: error.message 
      })
    };
  }
};

// FIXED: Handle login with better error handling
async function handleLogin(event, headers, sql) {
  console.log('handleLogin called');
  console.log('Raw event body:', event.body);
  
  // FIXED: Better body parsing with error handling
  let body;
  try {
    body = JSON.parse(event.body || '{}');
    console.log('Parsed body:', body);
  } catch (parseError) {
    console.error('Body parsing error:', parseError);
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        error: 'Invalid JSON in request body',
        details: parseError.message 
      })
    };
  }
  
  const { username, password } = body;
  console.log('Extracted fields:', { username: !!username, password: !!password });

  // FIXED: More specific error message
  if (!username || !password) {
    console.log('Missing credentials:', { username, password });
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ 
        error: 'Username/email and password are required',
        received: { username: !!username, password: !!password },
        body: body
      })
    };
  }

  try {
    console.log('Attempting login for:', username);
    
    // Find user by username or email
    const users = await sql`
      SELECT id, username, email, password_hash, first_name, last_name, 
             role, is_active, failed_login_attempts, locked_until
      FROM users 
      WHERE (username = ${username} OR email = ${username})
      LIMIT 1
    `;

    console.log('Users found:', users.length);

    if (users.length === 0) {
      console.log('No user found for:', username);
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    const user = users[0];
    console.log('Found user:', { id: user.id, username: user.username, email: user.email, is_active: user.is_active });

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      console.log('Account locked until:', user.locked_until);
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Account locked',
          minutesLeft 
        })
      };
    }

    // Check if account is active
    if (!user.is_active) {
      console.log('Account inactive for user:', username);
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Account inactive' })
      };
    }

    // Verify password
    console.log('Verifying password...');
    const validPassword = await verifyPassword(password, user.password_hash);
    console.log('Password valid:', validPassword);
    
    if (!validPassword) {
      // Increment failed attempts
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockedUntil = null;
      
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        // Lock account
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + LOCKOUT_DURATION);
        lockedUntil = lockTime.toISOString();
        console.log('Account will be locked until:', lockedUntil);
      }

      await sql`
        UPDATE users 
        SET failed_login_attempts = ${newAttempts},
            locked_until = ${lockedUntil}
        WHERE id = ${user.id}
      `;

      console.log('Invalid password, attempts:', newAttempts);
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Invalid credentials',
          attemptsLeft: Math.max(0, MAX_LOGIN_ATTEMPTS - newAttempts)
        })
      };
    }

    console.log('Password valid, creating session...');

    // Successful login - reset failed attempts and update last login
    await sql`
      UPDATE users 
      SET failed_login_attempts = 0,
          locked_until = NULL,
          last_login = CURRENT_TIMESTAMP
      WHERE id = ${user.id}
    `;

    // Create JWT token
    const token = createJWT(user.id, user.role);
    
    // FIXED: Create session in user_sessions table
    try {
      const sessionId = crypto.randomUUID();
      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 24); // 24 hours from now

      await sql`
        INSERT INTO user_sessions (id, user_id, session_token, expires_at, created_at)
        VALUES (${sessionId}, ${user.id}, ${token}, ${expiresAt.toISOString()}, CURRENT_TIMESTAMP)
        ON CONFLICT (session_token) DO UPDATE SET 
          expires_at = EXCLUDED.expires_at,
          created_at = EXCLUDED.created_at
      `;

      console.log('Session created:', sessionId);
    } catch (sessionError) {
      console.error('Session creation error:', sessionError);
      // Continue anyway, token will still work
    }

    // Return success response
    const response = {
      success: true,
      token: token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.first_name && user.last_name 
          ? `${user.first_name} ${user.last_name}`
          : user.first_name || user.last_name || user.username,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name
      }
    };

    console.log('Login successful for:', username);
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(response)
    };

  } catch (error) {
    console.error('Login error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error during login',
        message: error.message 
      })
    };
  }
}

// Handle logout
async function handleLogout(event, headers, sql) {
  console.log('handleLogout called');
  
  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      // Remove session from database
      await sql`
        DELETE FROM user_sessions 
        WHERE session_token = ${token}
      `;
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ success: true, message: 'Logged out successfully' })
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

// Handle session verification
async function handleVerify(event, headers, sql) {
  console.log('handleVerify called');
  
  try {
    const authHeader = event.headers.authorization || event.headers.Authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'No authorization header' })
      };
    }

    const token = authHeader.substring(7);
    const decoded = verifyJWT(token);

    if (!decoded) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid token' })
      };
    }

    // Check if session exists and user is active
    const sessions = await sql`
      SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.role, u.is_active
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.session_token = ${token}
        AND s.expires_at > CURRENT_TIMESTAMP
        AND u.is_active = true
      LIMIT 1
    `;

    if (sessions.length === 0) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Session expired' })
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
          username: user.username,
          email: user.email,
          name: user.first_name && user.last_name 
            ? `${user.first_name} ${user.last_name}`
            : user.first_name || user.last_name || user.username,
          role: user.role
        }
      })
    };

  } catch (error) {
    console.error('Verify error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Verification failed' })
    };
  }
}

// Handle user registration (stub)
async function handleRegister(event, headers, sql) {
  return {
    statusCode: 501,
    headers,
    body: JSON.stringify({ error: 'Registration not implemented yet' })
  };
}

// Handle password change (stub)
async function handlePasswordChange(event, headers, sql) {
  return {
    statusCode: 501,
    headers,
    body: JSON.stringify({ error: 'Password change not implemented yet' })
  };
}
