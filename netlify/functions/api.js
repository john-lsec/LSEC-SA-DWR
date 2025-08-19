// netlify/functions/api.js - Complete version with DWR and User Management functionality
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Add this for password hashing

const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';

// Helper function to verify JWT token
function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
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
      SELECT u.id, u.role, u.email, u.is_active
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
      role: sessions[0].role,
      email: sessions[0].email
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

exports.handler = async (event, context) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Better path parsing
  let resource = '';
  let id = null;
  let action = null;
  
  // Parse the path - handle different patterns
  const pathParts = event.path.split('/');
  const apiIndex = pathParts.indexOf('api');
  
  if (apiIndex !== -1 && pathParts.length > apiIndex + 1) {
    resource = pathParts[apiIndex + 1];
    if (pathParts.length > apiIndex + 2) {
      id = pathParts[apiIndex + 2];
    }
    if (pathParts.length > apiIndex + 3) {
      action = pathParts[apiIndex + 3];
    }
  }
  
  const method = event.httpMethod;
  
  console.log('API Request:', { path: event.path, resource, id, action, method });

  // Special handling for test endpoint
  if (resource === 'test') {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        message: 'API is working!',
        timestamp: new Date().toISOString(),
        method: method,
        path: event.path,
        resource: resource
      })
    };
  }

  // Check authentication for protected endpoints
  const publicEndpoints = ['test'];
  const isPublicEndpoint = publicEndpoints.includes(resource);
  
  if (!isPublicEndpoint) {
    const auth = await requireAuth(event);
    
    if (!auth.authorized) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: auth.error })
      };
    }

    // Store auth info for use in handlers
    event.auth = {
      userId: auth.userId,
      role: auth.role,
      email: auth.email
    };
  }

  try {
    // Route to appropriate handler based on resource
    switch (resource) {
      case 'foremen':
        return await handleForemen(event, headers, method);
      
      case 'laborers':
        return await handleLaborers(event, headers, method);
      
      case 'projects':
        return await handleProjects(event, headers, method, id);
      
      case 'equipment':
        return await handleEquipment(event, headers, method);
      
      // Support both naming conventions
      case 'bid-items':
      case 'master-bid-items':
        return await handleBidItems(event, headers, method, id);
      
      // Consolidated project bid items endpoint - handles all CRUD operations
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      case 'submit-dwr':
        return await handleDWRSubmission(event, headers, method);
      
      // PO-related endpoints
      case 'po-data':
        return await handlePOData(event, headers, method);
      
      case 'po-submit':
        return await handlePOSubmit(event, headers, method);
      
      case 'po-requests':
        return await handlePORequests(event, headers, method, id);
      
      case 'vendors':
        return await handleVendors(event, headers, method, id);
      
      case 'authorized-users':
        return await handleAuthorizedUsers(event, headers, method, id);
      
      case 'users':
        return await handleUsers(event, headers, method, id, action);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Resource not found',
            resource: resource,
            availableEndpoints: [
              'foremen', 'laborers', 'projects', 'equipment',
              'bid-items', 'project-bid-items', 'submit-dwr',
              'po-data', 'po-submit', 'po-requests', 'vendors', 
              'authorized-users', 'users'
            ]
          })
        };
    }
  } catch (error) {
    console.error('API Error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Internal server error', 
        details: error.message 
      })
    };
  }
};

// [Keep all your existing handlers exactly as they are - foremen, laborers, projects, equipment, etc.]
// I'm only showing the updated Users handler here to save space

// Enhanced Users handler with full CRUD operations
async function handleUsers(event, headers, method, id, action) {
  const { role, userId } = event.auth || {};

  // Handle user status toggle action
  if (action === 'toggle-status' && method === 'POST') {
    if (!requireRole(role, ['Admin', 'Manager'])) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Insufficient permissions' })
      };
    }

    if (!id) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'User ID required' })
      };
    }

    try {
      // Get current user status
      const currentUser = await sql`
        SELECT is_active FROM users WHERE id = ${id}
      `;

      if (currentUser.length === 0) {
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'User not found' })
        };
      }

      // Toggle the status
      const newStatus = !currentUser[0].is_active;
      
      await sql`
        UPDATE users 
        SET is_active = ${newStatus}, updated_at = CURRENT_TIMESTAMP
        WHERE id = ${id}
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `User ${newStatus ? 'enabled' : 'disabled'} successfully`
        })
      };

    } catch (error) {
      console.error('Error toggling user status:', error);
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: 'Failed to update user status' })
      };
    }
  }

  // Regular CRUD operations
  switch (method) {
    case 'GET':
      if (!requireRole(role, ['Admin', 'Manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        if (id) {
          const users = await sql`
            SELECT id::text as id, username, email, first_name, last_name, role, 
                   is_active, last_login, failed_login_attempts, created_at, updated_at
            FROM users 
            WHERE id = ${id}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users[0] || null)
          };
        } else {
          const users = await sql`
            SELECT id::text as id, username, email, first_name, last_name, role, 
                   is_active, last_login, failed_login_attempts, created_at, updated_at
            FROM users 
            ORDER BY created_at DESC
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users)
          };
        }
      } catch (error) {
        console.error('Error fetching users:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch users' })
        };
      }

    case 'POST':
      if (!requireRole(role, ['Admin', 'Manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        const userData = JSON.parse(event.body);
        
        // Validate required fields
        const requiredFields = ['username', 'email', 'password', 'first_name', 'last_name', 'role'];
        for (const field of requiredFields) {
          if (!userData[field]) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ 
                success: false,
                error: `Missing required field: ${field}` 
              })
            };
          }
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(userData.email)) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ 
              success: false,
              error: 'Invalid email format' 
            })
          };
        }

        // Validate password strength
        const password = userData.password;
        if (password.length < 8 || 
            !/[A-Z]/.test(password) || 
            !/[a-z]/.test(password) || 
            !/\d/.test(password) || 
            !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ 
              success: false,
              error: 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character' 
            })
          };
        }

        // Check if username or email already exists
        const existingUser = await sql`
          SELECT id FROM users 
          WHERE username = ${userData.username} OR email = ${userData.email}
        `;

        if (existingUser.length > 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ 
              success: false,
              error: 'Username or email already exists' 
            })
          };
        }

        // Hash the password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert new user
        const newUser = await sql`
          INSERT INTO users (
            username, email, password_hash, first_name, last_name, role, 
            is_active, failed_login_attempts, created_at, updated_at, created_by
          ) VALUES (
            ${userData.username},
            ${userData.email},
            ${passwordHash},
            ${userData.first_name},
            ${userData.last_name},
            ${userData.role},
            ${userData.is_active !== false},
            0,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            ${userId}
          )
          RETURNING id::text as id, username, email, first_name, last_name, role, is_active, created_at
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify({
            success: true,
            user: newUser[0],
            message: 'User created successfully'
          })
        };

      } catch (error) {
        console.error('Error creating user:', error);
        
        let errorMessage = 'Failed to create user';
        if (error.message.includes('unique')) {
          errorMessage = 'Username or email already exists';
        }
        
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ 
            success: false,
            error: errorMessage,
            details: error.message 
          })
        };
      }

    case 'PUT':
      if (!requireRole(role, ['Admin', 'Manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'User ID required for update' })
        };
      }

      try {
        const updateData = JSON.parse(event.body);
        
        // Check if user exists
        const existingUser = await sql`
          SELECT * FROM users WHERE id = ${id}
        `;

        if (existingUser.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'User not found' })
          };
        }

        const user = existingUser[0];

        // If updating username or email, check for conflicts
        if (updateData.username && updateData.username !== user.username) {
          const usernameExists = await sql`
            SELECT id FROM users WHERE username = ${updateData.username} AND id != ${id}
          `;
          if (usernameExists.length > 0) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ error: 'Username already exists' })
            };
          }
        }

        if (updateData.email && updateData.email !== user.email) {
          const emailExists = await sql`
            SELECT id FROM users WHERE email = ${updateData.email} AND id != ${id}
          `;
          if (emailExists.length > 0) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ error: 'Email already exists' })
            };
          }
        }

        // Prepare update fields
        let updateFields = {
          username: updateData.username || user.username,
          email: updateData.email || user.email,
          first_name: updateData.first_name || user.first_name,
          last_name: updateData.last_name || user.last_name,
          role: updateData.role || user.role,
          is_active: updateData.is_active !== undefined ? updateData.is_active : user.is_active
        };

        // Handle password update separately if provided
        if (updateData.password) {
          const saltRounds = 12;
          updateFields.password_hash = await bcrypt.hash(updateData.password, saltRounds);
        }

        // Update user
        const updated = await sql`
          UPDATE users
          SET 
            username = ${updateFields.username},
            email = ${updateFields.email},
            first_name = ${updateFields.first_name},
            last_name = ${updateFields.last_name},
            role = ${updateFields.role},
            is_active = ${updateFields.is_active},
            ${updateFields.password_hash ? sql`password_hash = ${updateFields.password_hash},` : sql``}
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
          RETURNING id::text as id, username, email, first_name, last_name, role, is_active, updated_at
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: true,
            user: updated[0],
            message: 'User updated successfully'
          })
        };

      } catch (error) {
        console.error('Error updating user:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ 
            success: false,
            error: 'Failed to update user',
            details: error.message 
          })
        };
      }

    case 'DELETE':
      if (!requireRole(role, ['Admin'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Admin access required for deletion' })
        };
      }

      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'User ID required for deletion' })
        };
      }

      try {
        // Check if user exists
        const existingUser = await sql`
          SELECT id FROM users WHERE id = ${id}
        `;

        if (existingUser.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'User not found' })
          };
        }

        // Soft delete by deactivating instead of hard delete
        await sql`
          UPDATE users 
          SET is_active = false, updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({
            success: true,
            message: 'User deactivated successfully'
          })
        };

      } catch (error) {
        console.error('Error deleting user:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ 
            success: false,
            error: 'Failed to delete user',
            details: error.message 
          })
        };
      }

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// [Keep all your other existing handler functions exactly as they are]
// This includes: handleForemen, handleLaborers, handleProjects, handleEquipment, 
// handleBidItems, handleProjectBidItems, handleDWRSubmission, handlePOSubmit, 
// handlePORequests, handleVendors, handleAuthorizedUsers
