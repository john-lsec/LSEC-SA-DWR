// auth.js - Authentication API endpoints
// Place this in your netlify/functions/api folder

const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Environment variables needed:
// DATABASE_URL - Your Neon database connection string
// JWT_SECRET - Secret key for JWT tokens (generate a strong random string)
// Set these in your Netlify environment variables

const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const TOKEN_EXPIRY = '24h';
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15; // minutes

// Helper function to generate session token
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
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

// Main authentication handler
exports.handler = async (event, context) => {
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

  const path = event.path.replace('/api/auth/', '');
  const method = event.httpMethod;

  try {
    // Route to appropriate handler
    switch (`${method}:${path}`) {
      case 'POST:login':
        return await handleLogin(event, headers);
      
      case 'POST:logout':
        return await handleLogout(event, headers);
      
      case 'GET:verify':
        return await handleVerify(event, headers);
      
      case 'POST:register':
        return await handleRegister(event, headers);
      
      case 'PUT:password':
        return await handlePasswordChange(event, headers);
      
      case 'GET:users':
        return await handleGetUsers(event, headers);
      
      case 'PUT:users/:id':
        return await handleUpdateUser(event, headers);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'Not found' })
        };
    }
  } catch (error) {
    console.error('Auth error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};

// Handle login
async function handleLogin(event, headers) {
  const body = JSON.parse(event.body || '{}');
  const { username, password } = body;

  if (!username || !password) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Username and password required' })
    };
  }

  try {
    // Find user by username or email
    const users = await sql`
      SELECT id, username, email, password_hash, first_name, last_name, 
             role, is_active, failed_login_attempts, locked_until
      FROM users 
      WHERE (username = ${username} OR email = ${username})
      LIMIT 1
    `;

    if (users.length === 0) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    const user = users[0];

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
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
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Account inactive' })
      };
    }

    // Verify password
    const validPassword = await verifyPassword(password, user.password_hash);
    
    if (!validPassword) {
      // Increment failed attempts
      const newAttempts = (user.failed_login_attempts || 0) + 1;
      let lockedUntil = null;
      
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        // Lock account
        const lockTime = new Date();
        lockTime.setMinutes(lockTime.getMinutes() + LOCKOUT_DURATION);
        lockedUntil = lockTime.toISOString();
      }

      await sql`
        UPDATE users 
        SET failed_login_attempts = ${newAttempts},
            locked_until = ${lockedUntil}
        WHERE id = ${user.id}
      `;

      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Invalid credentials',
          attemptsLeft: Math.max(0, MAX_LOGIN_ATTEMPTS - newAttempts)
        })
      };
    }

    // Successful login - reset failed attempts and update last login
    await sql`
      UPDATE users 
      SET failed_login_attempts = 0,
          locked_until = NULL,
          last_login = CURRENT_TIMESTAMP
      WHERE id = ${user.id}
    `;

    // Create session
    const sessionToken = generateSessionToken();
    const jwtToken = createJWT(user.id, user.role);
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    // Store session in database
    await sql`
      INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
      VALUES (${user.id}, ${sessionToken}, ${event.headers['client-ip'] || 'unknown'}, 
              ${event.headers['user-agent'] || 'unknown'}, ${expiresAt.toISOString()})
    `;

    // Log the login
    await sql`
      INSERT INTO audit_log (user_id, action, ip_address)
      VALUES (${user.id}, 'login', ${event.headers['client-ip'] || 'unknown'})
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        token: jwtToken,
        sessionToken,
        userId: user.id,
        name: `${user.first_name} ${user.last_name}`.trim() || user.username,
        role: user.role,
        email: user.email
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

// Handle logout
async function handleLogout(event, headers) {
  const authHeader = event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'No token provided' })
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

  try {
    // Delete session from database
    await sql`
      DELETE FROM user_sessions 
      WHERE user_id = ${decoded.userId}
    `;

    // Log the logout
    await sql`
      INSERT INTO audit_log (user_id, action, ip_address)
      VALUES (${decoded.userId}, 'logout', ${event.headers['client-ip'] || 'unknown'})
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Logged out successfully' })
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
async function handleVerify(event, headers) {
  const authHeader = event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'No token provided' })
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

  try {
    // Check if session exists and is valid
    const sessions = await sql`
      SELECT s.*, u.username, u.email, u.first_name, u.last_name, u.role, u.is_active
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
        body: JSON.stringify({ error: 'Session expired or invalid' })
      };
    }

    const session = sessions[0];

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        valid: true,
        userId: decoded.userId,
        name: `${session.first_name} ${session.last_name}`.trim() || session.username,
        role: session.role,
        email: session.email
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

// Handle user registration (admin only)
async function handleRegister(event, headers) {
  // Verify admin token
  const authHeader = event.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'Unauthorized' })
    };
  }

  const token = authHeader.substring(7);
  const decoded = verifyJWT(token);

  if (!decoded || decoded.role !== 'admin') {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Admin access required' })
    };
  }

  const body = JSON.parse(event.body || '{}');
  const { username, email, password, firstName, lastName, role } = body;

  if (!username || !email || !password || !role) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Missing required fields' })
    };
  }

  try {
    // Check if user exists
    const existing = await sql`
      SELECT id FROM users 
      WHERE username = ${username} OR email = ${email}
      LIMIT 1
    `;

    if (existing.length > 0) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Username or email already exists' })
      };
    }

    // Hash password and create user
    const passwordHash = await hashPassword(password);
    
    const newUser = await sql`
      INSERT INTO users (username, email, password_hash, first_name, last_name, role, created_by)
      VALUES (${username}, ${email}, ${passwordHash}, ${firstName}, ${lastName}, ${role}, ${decoded.userId})
      RETURNING id, username, email, first_name, last_name, role
    `;

    // Log the action
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, record_id, new_values, ip_address)
      VALUES (${decoded.userId}, 'create_user', 'users', ${newUser[0].id}, 
              ${JSON.stringify(newUser[0])}, ${event.headers['client-ip'] || 'unknown'})
    `;

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({
        message: 'User created successfully',
        user: newUser[0]
      })
    };

  } catch (error) {
    console.error('Register error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Registration failed' })
    };
  }
}

// Middleware to check authentication for protected routes
async function requireAuth(event) {
  const authHeader = event.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return { authorized: false, error: 'No token provided' };
  }

  const token = authHeader.substring(7);
  const decoded = verifyJWT(token);

  if (!decoded) {
    return { authorized: false, error: 'Invalid token' };
  }

  try {
    // Verify session is still valid
    const sessions = await sql`
      SELECT u.id, u.role, u.is_active
      FROM user_sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.user_id = ${decoded.userId}
        AND s.expires_at > CURRENT_TIMESTAMP
        AND u.is_active = true
      LIMIT 1
    `;

    if (sessions.length === 0) {
      return { authorized: false, error: 'Session expired' };
    }

    return { 
      authorized: true, 
      userId: decoded.userId, 
      role: sessions[0].role 
    };

  } catch (error) {
    console.error('Auth check error:', error);
    return { authorized: false, error: 'Authorization failed' };
  }
}

// Middleware to check specific role permissions
function requireRole(userRole, requiredRoles) {
  return requiredRoles.includes(userRole);
}

// Export middleware functions for use in other API endpoints
module.exports = {
  requireAuth,
  requireRole,
  verifyJWT
};
