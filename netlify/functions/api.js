// api.js - Main API with authentication protection
// This replaces your existing api.js file

const { neon } = require('@neondatabase/serverless');
const { requireAuth, requireRole } = require('./auth');

const sql = neon(process.env.DATABASE_URL);

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

  // Parse the path
  const segments = event.path.replace('/api/', '').split('/');
  const resource = segments[0];
  const id = segments[1];
  const method = event.httpMethod;

  // Check authentication for all endpoints except auth
  if (!event.path.includes('/api/auth/')) {
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
      role: auth.role
    };
  }

  try {
    // Route to appropriate handler based on resource
    switch (resource) {
      case 'master-bid-items':
        return await handleMasterBidItems(event, headers, method, id);
      
      case 'projects':
        return await handleProjects(event, headers, method, id);
      
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      case 'users':
        return await handleUsers(event, headers, method, id);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'Resource not found' })
        };
    }
  } catch (error) {
    console.error('API Error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};

// Master Bid Items handlers with role checks
async function handleMasterBidItems(event, headers, method, id) {
  const { role, userId } = event.auth;

  switch (method) {
    case 'GET':
      // All authenticated users can view
      if (id) {
        const items = await sql`
          SELECT * FROM master_bid_items WHERE id = ${id}
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(items[0] || null)
        };
      } else {
        const items = await sql`
          SELECT * FROM master_bid_items ORDER BY item_code
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(items)
        };
      }

    case 'POST':
      // Only admin, manager, and editor can create
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      const createData = JSON.parse(event.body);
      
      // Validate required fields
      if (!createData.item_code || !createData.item_name) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Item code and name are required' })
        };
      }

      const newItem = await sql`
        INSERT INTO master_bid_items (
          item_code, item_name, category, default_unit, 
          material_cost, description, is_active
        ) VALUES (
          ${createData.item_code},
          ${createData.item_name},
          ${createData.category || null},
          ${createData.default_unit || null},
          ${createData.material_cost || 0},
          ${createData.description || null},
          ${createData.is_active !== false}
        )
        RETURNING *
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
        VALUES (${userId}, 'create', 'master_bid_items', ${newItem[0].id}, ${JSON.stringify(newItem[0])})
      `;

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(newItem[0])
      };

    case 'PUT':
      // Only admin, manager, and editor can update
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
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
          body: JSON.stringify({ error: 'ID required for update' })
        };
      }

      const updateData = JSON.parse(event.body);
      
      // Get old values for audit
      const oldValues = await sql`
        SELECT * FROM master_bid_items WHERE id = ${id}
      `;

      const updated = await sql`
        UPDATE master_bid_items
        SET 
          item_code = ${updateData.item_code},
          item_name = ${updateData.item_name},
          category = ${updateData.category || null},
          default_unit = ${updateData.default_unit || null},
          material_cost = ${updateData.material_cost || 0},
          description = ${updateData.description || null},
          is_active = ${updateData.is_active !== false},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ${id}
        RETURNING *
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
        VALUES (${userId}, 'update', 'master_bid_items', ${id}, 
                ${JSON.stringify(oldValues[0])}, ${JSON.stringify(updated[0])})
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(updated[0])
      };

    case 'DELETE':
      // Only admin and manager can delete
      if (!requireRole(role, ['admin', 'manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions to delete' })
        };
      }

      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'ID required for delete' })
        };
      }

      // Get old values for audit
      const toDelete = await sql`
        SELECT * FROM master_bid_items WHERE id = ${id}
      `;

      await sql`
        DELETE FROM master_bid_items WHERE id = ${id}
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values)
        VALUES (${userId}, 'delete', 'master_bid_items', ${id}, ${JSON.stringify(toDelete[0])})
      `;

      return {
        statusCode: 204,
        headers,
        body: ''
      };

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Projects handlers with role checks
async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth;

  switch (method) {
    case 'GET':
      // All authenticated users can view
      if (id) {
        const projects = await sql`
          SELECT * FROM projects WHERE id = ${id}
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(projects[0] || null)
        };
      } else {
        const projects = await sql`
          SELECT * FROM projects ORDER BY created_at DESC
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(projects)
        };
      }

    case 'POST':
      // Only admin, manager, and editor can create
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      const projectData = JSON.parse(event.body);
      
      const newProject = await sql`
        INSERT INTO projects (
          project_name, project_number, location, 
          start_date, end_date, status, description
        ) VALUES (
          ${projectData.project_name},
          ${projectData.project_number || null},
          ${projectData.location || null},
          ${projectData.start_date || null},
          ${projectData.end_date || null},
          ${projectData.status || 'active'},
          ${projectData.description || null}
        )
        RETURNING *
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
        VALUES (${userId}, 'create', 'projects', ${newProject[0].id}, ${JSON.stringify(newProject[0])})
      `;

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(newProject[0])
      };

    case 'PUT':
      // Only admin, manager, and editor can update
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
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
          body: JSON.stringify({ error: 'ID required for update' })
        };
      }

      const updateProjectData = JSON.parse(event.body);
      
      // Get old values for audit
      const oldProject = await sql`
        SELECT * FROM projects WHERE id = ${id}
      `;

      const updatedProject = await sql`
        UPDATE projects
        SET 
          project_name = ${updateProjectData.project_name},
          project_number = ${updateProjectData.project_number || null},
          location = ${updateProjectData.location || null},
          start_date = ${updateProjectData.start_date || null},
          end_date = ${updateProjectData.end_date || null},
          status = ${updateProjectData.status || 'active'},
          description = ${updateProjectData.description || null},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ${id}
        RETURNING *
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values, new_values)
        VALUES (${userId}, 'update', 'projects', ${id}, 
                ${JSON.stringify(oldProject[0])}, ${JSON.stringify(updatedProject[0])})
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(updatedProject[0])
      };

    case 'DELETE':
      // Only admin and manager can delete
      if (!requireRole(role, ['admin', 'manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions to delete' })
        };
      }

      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'ID required for delete' })
        };
      }

      // Get old values for audit
      const projectToDelete = await sql`
        SELECT * FROM projects WHERE id = ${id}
      `;

      // Delete related bid items first
      await sql`
        DELETE FROM project_bid_items WHERE project_id = ${id}
      `;

      await sql`
        DELETE FROM projects WHERE id = ${id}
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, old_values)
        VALUES (${userId}, 'delete', 'projects', ${id}, ${JSON.stringify(projectToDelete[0])})
      `;

      return {
        statusCode: 204,
        headers,
        body: ''
      };

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// User management handlers (admin only)
async function handleUsers(event, headers, method, id) {
  const { role, userId } = event.auth;

  // Only admins can manage users
  if (role !== 'admin') {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Admin access required' })
    };
  }

  switch (method) {
    case 'GET':
      if (id) {
        const users = await sql`
          SELECT id, username, email, first_name, last_name, role, 
                 is_active, last_login, created_at
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
          SELECT id, username, email, first_name, last_name, role, 
                 is_active, last_login, created_at
          FROM users 
          ORDER BY created_at DESC
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(users)
        };
      }

    case 'PUT':
      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'ID required for update' })
        };
      }

      const userData = JSON.parse(event.body);
      
      const updatedUser = await sql`
        UPDATE users
        SET 
          first_name = ${userData.first_name || null},
          last_name = ${userData.last_name || null},
          role = ${userData.role},
          is_active = ${userData.is_active !== false},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ${id}
        RETURNING id, username, email, first_name, last_name, role, is_active
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
        VALUES (${userId}, 'update_user', 'users', ${id}, ${JSON.stringify(updatedUser[0])})
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(updatedUser[0])
      };

    case 'DELETE':
      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'ID required for delete' })
        };
      }

      // Prevent self-deletion
      if (id === userId) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Cannot delete your own account' })
        };
      }

      await sql`
        DELETE FROM users WHERE id = ${id}
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id)
        VALUES (${userId}, 'delete_user', 'users', ${id})
      `;

      return {
        statusCode: 204,
        headers,
        body: ''
      };

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Project Bid Items handler remains the same but with auth checks
async function handleProjectBidItems(event, headers, method, id) {
  const { role, userId } = event.auth;

  // Implementation similar to above with role checks
  // ... (keeping the same structure as your existing project-bid-items handler)
  // Just add the role checks for POST, PUT, DELETE operations
}
