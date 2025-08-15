// netlify/functions/auth.js - Complete Authentication System
const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Environment variables
const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this';
const TOKEN_EXPIRY = '24h';
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15; // minutes

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

  // Parse the path - handle both /auth/ and /api/auth/ paths
  const path = event.path
    .replace('/.netlify/functions/', '')
    .replace('/auth/', '')
    .replace('/api/auth/', '');
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
      
      case 'POST:reset-password':
        return await handlePasswordReset(event, headers);
        
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'Auth endpoint not found' })
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
    const sessionToken = crypto.randomBytes(32).toString('hex');
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
        name: `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.username,
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

  try {
    // Delete all sessions for this user
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
        name: `${session.first_name || ''} ${session.last_name || ''}`.trim() || session.username,
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
  const authHeader = event.headers.authorization || event.headers.Authorization;
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

  // Validate role
  const validRoles = ['admin', 'manager', 'editor', 'viewer'];
  if (!validRoles.includes(role)) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid role' })
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
      VALUES (${username}, ${email}, ${passwordHash}, ${firstName || null}, ${lastName || null}, ${role}, ${decoded.userId})
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

// Handle password change
async function handlePasswordChange(event, headers) {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'Unauthorized' })
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

  const body = JSON.parse(event.body || '{}');
  const { currentPassword, newPassword } = body;

  if (!currentPassword || !newPassword) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Current and new passwords required' })
    };
  }

  try {
    // Get user's current password hash
    const users = await sql`
      SELECT password_hash FROM users WHERE id = ${decoded.userId}
    `;

    if (users.length === 0) {
      return {
        statusCode: 404,
        headers,
        body: JSON.stringify({ error: 'User not found' })
      };
    }

    // Verify current password
    const validPassword = await verifyPassword(currentPassword, users[0].password_hash);
    
    if (!validPassword) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Current password is incorrect' })
      };
    }

    // Hash new password and update
    const newPasswordHash = await hashPassword(newPassword);
    
    await sql`
      UPDATE users 
      SET password_hash = ${newPasswordHash},
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ${decoded.userId}
    `;

    // Log the action
    await sql`
      INSERT INTO audit_log (user_id, action, ip_address)
      VALUES (${decoded.userId}, 'password_change', ${event.headers['client-ip'] || 'unknown'})
    `;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Password changed successfully' })
    };

  } catch (error) {
    console.error('Password change error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to change password' })
    };
  }
}

// Handle password reset request (simplified - in production, send email)
async function handlePasswordReset(event, headers) {
  const body = JSON.parse(event.body || '{}');
  const { email } = body;

  if (!email) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Email required' })
    };
  }

  try {
    // Check if user exists
    const users = await sql`
      SELECT id, email FROM users WHERE email = ${email}
    `;

    // Always return success to prevent email enumeration
    // In production, send reset email here if user exists
    
    if (users.length > 0) {
      // Generate reset token (in production, save this and send via email)
      const resetToken = crypto.randomBytes(32).toString('hex');
      
      // Log the request
      await sql`
        INSERT INTO audit_log (user_id, action, ip_address)
        VALUES (${users[0].id}, 'password_reset_request', ${event.headers['client-ip'] || 'unknown'})
      `;
      
      // In production: Send email with reset link
      console.log(`Password reset token for ${email}: ${resetToken}`);
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        message: 'If an account exists with this email, password reset instructions have been sent.' 
      })
    };

  } catch (error) {
    console.error('Password reset error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to process password reset' })
    };
  }
}

// Middleware to check authentication for protected routes
async function requireAuth(event) {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  
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
  verifyJWT,
  hashPassword
};
