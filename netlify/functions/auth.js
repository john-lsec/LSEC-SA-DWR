// netlify/functions/auth.js - COMPLETE FIXED VERSION
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

// FIXED: Enhanced UUID validation for auth system
function validateAndConvertId(id, fieldName) {
  if (!id || id === null || id === undefined || id === '') return null;
  
  const idStr = String(id).trim();
  
  // Check if it's already a valid UUID
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (uuidRegex.test(idStr)) {
    return idStr;
  }
  
  // Check if it's a valid integer (for transition period)
  const integerRegex = /^\d+$/;
  if (integerRegex.test(idStr)) {
    const intValue = parseInt(idStr);
    if (intValue > 0 && intValue <= Number.MAX_SAFE_INTEGER) {
      console.warn(`Warning: ${fieldName} using integer ID ${intValue}. Should be migrated to UUID.`);
      return idStr;
    }
  }
  
  throw new Error(`Invalid ${fieldName}: "${id}". Must be a valid UUID or integer ID.`);
}

// Main handler - MUST be named 'handler' and exported
exports.handler = async (event, context) => {
  console.log('Auth function called');
  console.log('Path:', event.path);
  console.log('Method:', event.httpMethod);
  
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

  // Get database connection
  const sql = getDb();

  // Parse the path - handle different URL patterns
  let endpoint = '';
  
  // Check different path patterns
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
  
  console.log('Parsed endpoint:', endpoint);

  try {
    switch (endpoint) {
      case 'login':
        return await handleLogin(event, headers, sql);
      
      case 'logout':
        return await handleLogout(event, headers, sql);
      
      case 'verify':
        return await handleVerify(event, headers, sql);
      
      case 'register':
        return await handleRegister(event, headers, sql);
      
      case 'change-password':
        return await handleChangePassword(event, headers, sql);
      
      case 'forgot-password':
        return await handleForgotPassword(event, headers, sql);
      
      case 'reset-password':
        return await handleResetPassword(event, headers, sql);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Authentication endpoint not found',
            endpoint: endpoint,
            availableEndpoints: ['login', 'logout', 'verify', 'register', 'change-password', 'forgot-password', 'reset-password']
          })
        };
    }
  } catch (error) {
    console.error('Auth handler error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      })
    };
  }
};

// FIXED: Enhanced login handler with proper error handling
async function handleLogin(event, headers, sql) {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { username, email, password } = JSON.parse(event.body || '{}');
    const loginIdentifier = username || email;
    
    if (!loginIdentifier || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Username/email and password are required' })
      };
    }

    console.log('Login attempt for:', loginIdentifier);

    // Find user by username or email
    const users = await sql`
      SELECT id, username, email, password_hash, first_name, last_name, role, 
             is_active, failed_login_attempts, locked_until
      FROM users 
      WHERE (username = ${loginIdentifier} OR email = ${loginIdentifier})
        AND is_active = true
      LIMIT 1
    `;

    if (users.length === 0) {
      console.log('User not found:', loginIdentifier);
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid credentials' })
      };
    }

    const user = users[0];
    const userId = user.id;

    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const lockoutEnd = new Date(user.locked_until);
      return {
        statusCode: 423,
        headers,
        body: JSON.stringify({ 
          error: 'Account is temporarily locked due to multiple failed login attempts',
          lockout_until: lockoutEnd.toISOString()
        })
      };
    }

    // Verify password
    const isValidPassword = await verifyPassword(password, user.password_hash);
    
    if (!isValidPassword) {
      console.log('Invalid password for user:', loginIdentifier);
      
      // Increment failed login attempts
      const newFailedAttempts = (user.failed_login_attempts || 0) + 1;
      let lockoutUntil = null;
      
      if (newFailedAttempts >= MAX_LOGIN_ATTEMPTS) {
        lockoutUntil = new Date(Date.now() + LOCKOUT_DURATION * 60 * 1000);
        console.log(`Locking account ${loginIdentifier} until ${lockoutUntil}`);
      }
      
      await sql`
        UPDATE users 
        SET failed_login_attempts = ${newFailedAttempts},
            locked_until = ${lockoutUntil}
        WHERE id = ${userId}
      `;
      
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          error: 'Invalid credentials',
          attempts_remaining: newFailedAttempts >= MAX_LOGIN_ATTEMPTS ? 0 : MAX_LOGIN_ATTEMPTS - newFailedAttempts
        })
      };
    }

    console.log('Successful login for user:', loginIdentifier);

    // Reset failed login attempts and update last login
    await sql`
      UPDATE users 
      SET failed_login_attempts = 0, 
          locked_until = NULL,
          last_login = CURRENT_TIMESTAMP
      WHERE id = ${userId}
    `;

    // Create JWT token
    const token = createJWT(userId, user.role);
    
    // Create user session
    const sessionToken = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await sql`
      INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
      VALUES (
        ${userId}, 
        ${sessionToken}, 
        ${event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown'},
        ${event.headers['user-agent'] || 'unknown'},
        ${expiresAt}
      )
    `;

    // Log successful login
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, new_values, ip_address, created_at)
      VALUES (
        ${userId}, 
        'LOGIN', 
        'users', 
        ${JSON.stringify({ login_method: username ? 'username' : 'email' })},
        ${event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown'},
        CURRENT_TIMESTAMP
      )
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        token: token,
        user: {
          id: userId,
          username: user.username,
          email: user.email,
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.username
        }
      })
    };

  } catch (error) {
    console.error('Login error:', error);
    
    if (error.message.includes('JSON')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid JSON in request body' })
      };
    }
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Login failed due to server error' })
    };
  }
}

// FIXED: Enhanced logout handler
async function handleLogout(event, headers, sql) {
  if (event.httpMethod !== 'POST') {
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

    const userId = decoded.userId;

    // Invalidate all user sessions
    await sql`
      DELETE FROM user_sessions 
      WHERE user_id = ${userId}
    `;

    // Log logout
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, ip_address, created_at)
      VALUES (
        ${userId}, 
        'LOGOUT', 
        'users', 
        ${event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown'},
        CURRENT_TIMESTAMP
      )
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        success: true,
        message: 'Logged out successfully' 
      })
    };

  } catch (error) {
    console.error('Logout error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Logout failed due to server error' })
    };
  }
}

// FIXED: Enhanced verify handler
async function handleVerify(event, headers, sql) {
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
        body: JSON.stringify({ 
          valid: false,
          error: 'No token provided' 
        })
      };
    }

    const token = authHeader.substring(7);
    const decoded = verifyJWT(token);

    if (!decoded) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ 
          valid: false,
          error: 'Invalid token' 
        })
      };
    }

    // Check if session is still valid
    const sessions = await sql`
      SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.role, u.is_active
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
        body: JSON.stringify({ 
          valid: false,
          error: 'Session expired or user inactive' 
        })
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
          firstName: user.first_name,
          lastName: user.last_name,
          role: user.role,
          name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.username
        }
      })
    };

  } catch (error) {
    console.error('Verify error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        valid: false,
        error: 'Token verification failed due to server error' 
      })
    };
  }
}

// FIXED: Enhanced register handler
async function handleRegister(event, headers, sql) {
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const { username, email, password, firstName, lastName, role = 'viewer' } = JSON.parse(event.body || '{}');
    
    // Validate required fields
    if (!username || !email || !password) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Username, email, and password are required' })
      };
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid email format' })
      };
    }

    // Validate password strength
    if (password.length < 8) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Password must be at least 8 characters long' })
      };
    }

    // Check if username or email already exists
    const existingUsers = await sql`
      SELECT id, username, email 
      FROM users 
      WHERE username = ${username} OR email = ${email}
      LIMIT 1
    `;

    if (existingUsers.length > 0) {
      const existing = existingUsers[0];
      const field = existing.username === username ? 'username' : 'email';
      return {
        statusCode: 409,
        headers,
        body: JSON.stringify({ error: `User with this ${field} already exists` })
      };
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create user
    const newUsers = await sql`
      INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active, created_at, updated_at)
      VALUES (${username}, ${email}, ${passwordHash}, ${firstName || null}, ${lastName || null}, ${role}, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
      RETURNING id, username, email, first_name, last_name, role
    `;

    const newUser = newUsers[0];

    // Log user creation
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, new_values, ip_address, created_at)
      VALUES (
        ${newUser.id}, 
        'USER_CREATED', 
        'users', 
        ${JSON.stringify({ username, email, role })},
        ${event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown'},
        CURRENT_TIMESTAMP
      )
    `;

    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'User created successfully',
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
          firstName: newUser.first_name,
          lastName: newUser.last_name,
          role: newUser.role,
          name: `${newUser.first_name || ''} ${newUser.last_name || ''}`.trim() || newUser.username
        }
      })
    };

  } catch (error) {
    console.error('Registration error:', error);
    
    if (error.message.includes('JSON')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid JSON in request body' })
      };
    }
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Registration failed due to server error' })
    };
  }
}

// FIXED: Change password handler
async function handleChangePassword(event, headers, sql) {
  if (event.httpMethod !== 'POST') {
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

    const { currentPassword, newPassword } = JSON.parse(event.body || '{}');
    
    if (!currentPassword || !newPassword) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Current password and new password are required' })
      };
    }

    if (newPassword.length < 8) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'New password must be at least 8 characters long' })
      };
    }

    const userId = decoded.userId;

    // Get current user
    const users = await sql`
      SELECT id, username, password_hash 
      FROM users 
      WHERE id = ${userId} AND is_active = true
      LIMIT 1
    `;

    if (users.length === 0) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({ error: 'User not found' })
      };
    }

    const user = users[0];

    // Verify current password
    const isValidPassword = await verifyPassword(currentPassword, user.password_hash);
    
    if (!isValidPassword) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Current password is incorrect' })
      };
    }

    // Hash new password
    const newPasswordHash = await hashPassword(newPassword);

    // Update password
    await sql`
      UPDATE users 
      SET password_hash = ${newPasswordHash}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ${userId}
    `;

    // Log password change
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, ip_address, created_at)
      VALUES (
        ${userId}, 
        'PASSWORD_CHANGED', 
        'users', 
        ${event.headers['x-forwarded-for'] || event.headers['x-real-ip'] || 'unknown'},
        CURRENT_TIMESTAMP
      )
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        message: 'Password changed successfully'
      })
    };

  } catch (error) {
    console.error('Change password error:', error);
    
    if (error.message.includes('JSON')) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Invalid JSON in request body' })
      };
    }
    
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Password change failed due to server error' })
    };
  }
}

// Placeholder handlers for forgot/reset password
async function handleForgotPassword(event, headers, sql) {
  return {
    statusCode: 501,
    headers,
    body: JSON.stringify({ error: 'Forgot password functionality not yet implemented' })
  };
}

async function handleResetPassword(event, headers, sql) {
  return {
    statusCode: 501,
    headers,
    body: JSON.stringify({ error: 'Reset password functionality not yet implemented' })
  };
}
