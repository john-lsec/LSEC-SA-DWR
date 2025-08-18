// netlify/functions/api.js - Complete version with DWR functionality
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');

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
  
  // Parse the path - handle different patterns
  const pathParts = event.path.split('/');
  const apiIndex = pathParts.indexOf('api');
  
  if (apiIndex !== -1 && pathParts.length > apiIndex + 1) {
    resource = pathParts[apiIndex + 1];
    if (pathParts.length > apiIndex + 2) {
      id = pathParts[apiIndex + 2];
    }
  }
  
  const method = event.httpMethod;
  
  console.log('API Request:', { path: event.path, resource, id, method });

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
        return await handleUsers(event, headers, method, id);
      
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

// Foremen handler
async function handleForemen(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const foremen = await sql`
      SELECT id, name, email, phone 
      FROM foremen 
      WHERE is_active = true 
      ORDER BY name
    `;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(foremen)
    };
  } catch (error) {
    console.error('Error fetching foremen:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch foremen' })
    };
  }
}

// Laborers handler
async function handleLaborers(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const laborers = await sql`
      SELECT id, name, employee_id, email, phone 
      FROM laborers 
      WHERE is_active = true 
      ORDER BY name
    `;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(laborers)
    };
  } catch (error) {
    console.error('Error fetching laborers:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch laborers' })
    };
  }
}

// Corrected Projects handler for fixed schema
async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          // Get specific project by UUID
          const projects = await sql`
            SELECT * FROM projects WHERE id = ${id}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects[0] || null)
          };
        } else {
          // Get all active projects
          const projects = await sql`
            SELECT * FROM projects 
            WHERE active = true
            ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects)
          };
        }
      } catch (error) {
        console.error('Error fetching projects:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch projects' })
        };
      }

    case 'POST':
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        const projectData = JSON.parse(event.body);
        
        // Validate required fields
        if (!projectData.name) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Project name is required' })
          };
        }
        
        const newProject = await sql`
          INSERT INTO projects (name, project_code, active, created_at, updated_at)
          VALUES (
            ${projectData.name}, 
            ${projectData.project_code || null}, 
            ${projectData.active !== false},
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
          )
          RETURNING *
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(newProject[0])
        };
      } catch (error) {
        console.error('Error creating project:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to create project: ' + error.message })
        };
      }

    case 'PUT':
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

      try {
        const updateData = JSON.parse(event.body);
        
        // Check if project exists
        const existing = await sql`
          SELECT * FROM projects WHERE id = ${id}
        `;
        
        if (existing.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'Project not found' })
          };
        }
        
        const updated = await sql`
          UPDATE projects
          SET 
            name = ${updateData.name || existing[0].name},
            project_code = ${updateData.project_code !== undefined ? updateData.project_code : existing[0].project_code},
            active = ${updateData.active !== undefined ? updateData.active : existing[0].active},
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
          RETURNING *
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(updated[0])
        };
      } catch (error) {
        console.error('Error updating project:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update project: ' + error.message })
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

// Equipment handler
async function handleEquipment(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const params = event.queryStringParameters || {};
    const type = params.type;
    
    let equipment;
    
    // Check if type column exists and use it for filtering
    const hasTypeColumn = await sql`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'equipment' 
      AND column_name = 'type'
    `;
    
    if (hasTypeColumn.length > 0 && type) {
      // Use type column for exact matching
      equipment = await sql`
        SELECT id, name, type FROM equipment 
        WHERE type = ${type} AND active = true 
        ORDER BY name
      `;
    } else if (type) {
      // Fallback: filter by name pattern if type was requested but column doesn't exist
      equipment = await sql`
        SELECT id, name FROM equipment 
        WHERE active = true 
        ORDER BY name
      `;
      
      // Filter by name pattern
      equipment = equipment.filter(e => 
        e.name.toUpperCase().includes(type.toUpperCase())
      );
    } else {
      // No type filter requested
      equipment = await sql`
        SELECT id, name FROM equipment 
        WHERE active = true 
        ORDER BY name
      `;
    }
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(equipment)
    };
  } catch (error) {
    console.error('Error fetching equipment:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch equipment' })
    };
  }
}

// Bid Items handler (Master)
async function handleBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const items = await sql`
            SELECT * FROM bid_items WHERE id = ${id}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(items[0] || null)
          };
        } else {
          const items = await sql`
            SELECT * FROM bid_items 
            WHERE is_active = true
            ORDER BY item_code
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(items)
          };
        }
      } catch (error) {
        console.error('Error fetching bid items:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch bid items' })
        };
      }

    case 'POST':
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        const createData = JSON.parse(event.body);
        
        const newItem = await sql`
          INSERT INTO bid_items (
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

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(newItem[0])
        };
      } catch (error) {
        console.error('Error creating bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to create bid item' })
        };
      }

    case 'PUT':
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

      try {
        const updateData = JSON.parse(event.body);
        
        const updated = await sql`
          UPDATE bid_items
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

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(updated[0])
        };
      } catch (error) {
        console.error('Error updating bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update bid item' })
        };
      }

    case 'DELETE':
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

      try {
        await sql`DELETE FROM bid_items WHERE id = ${id}`;
        
        return {
          statusCode: 204,
          headers,
          body: ''
        };
      } catch (error) {
        console.error('Error deleting bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to delete bid item' })
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

// Corrected Project Bid Items handler for fixed schema
async function handleProjectBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        const params = event.queryStringParameters || {};
        const projectId = params.project_id;
        
        if (id) {
          // Get specific project bid item by ID
          const bidItems = await sql`
            SELECT 
              pbi.id as project_bid_item_id,
              pbi.project_id,
              pbi.bid_item_id,
              bi.item_code,
              bi.item_name,
              bi.category,
              bi.description,
              pbi.unit,
              pbi.rate,
              pbi.material_cost,
              pbi.material_cost as current_cost,
              pbi.notes,
              CASE 
                WHEN pbi.material_cost > 0 
                THEN ((pbi.rate - pbi.material_cost) / pbi.material_cost * 100)
                ELSE 0 
              END as markup_percentage,
              pbi.is_active,
              pbi.created_at,
              pbi.updated_at
            FROM project_bid_items pbi
            JOIN bid_items bi ON pbi.bid_item_id = bi.id
            WHERE pbi.id = ${id} AND pbi.is_active = true
          `;
          
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(bidItems[0] || null)
          };
        }
        
        if (!projectId) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'project_id parameter required' })
          };
        }
        
        // Verify project exists
        const projectCheck = await sql`
          SELECT id, name FROM projects WHERE id = ${projectId} AND active = true
        `;
        
        if (projectCheck.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'Project not found or inactive' })
          };
        }
        
        // Get all project bid items for the project
        const bidItems = await sql`
          SELECT 
            pbi.id as project_bid_item_id,
            pbi.project_id,
            pbi.bid_item_id,
            bi.item_code,
            bi.item_name,
            bi.category,
            bi.description,
            pbi.unit,
            pbi.rate,
            pbi.material_cost,
            pbi.material_cost as current_cost,
            pbi.notes,
            CASE 
              WHEN pbi.material_cost > 0 
              THEN ((pbi.rate - pbi.material_cost) / pbi.material_cost * 100)
              ELSE 0 
            END as markup_percentage,
            pbi.is_active,
            pbi.created_at,
            pbi.updated_at
          FROM project_bid_items pbi
          JOIN bid_items bi ON pbi.bid_item_id = bi.id
          WHERE pbi.project_id = ${projectId} 
            AND pbi.is_active = true
          ORDER BY bi.item_code
        `;
        
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(bidItems)
        };
        
      } catch (error) {
        console.error('Error fetching project bid items:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ 
            error: 'Failed to fetch project bid items',
            details: error.message
          })
        };
      }

    case 'POST':
      // Add new project bid item
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        const data = JSON.parse(event.body);
        
        // Validate required fields
        if (!data.project_id || !data.bid_item_id) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'project_id and bid_item_id are required' })
          };
        }
        
        // Verify project exists
        const projectExists = await sql`
          SELECT id FROM projects WHERE id = ${data.project_id} AND active = true
        `;
        
        if (projectExists.length === 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid or inactive project_id' })
          };
        }
        
        // Check if item already exists for this project
        const existing = await sql`
          SELECT id FROM project_bid_items 
          WHERE project_id = ${data.project_id} 
            AND bid_item_id = ${data.bid_item_id}
            AND is_active = true
        `;
        
        if (existing.length > 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'This bid item already exists for this project' })
          };
        }
        
        // Get bid item details for defaults
        const bidItem = await sql`
          SELECT material_cost, default_unit FROM bid_items 
          WHERE id = ${data.bid_item_id} AND is_active = true
        `;
        
        if (bidItem.length === 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Invalid or inactive bid_item_id' })
          };
        }
        
        const defaultMaterialCost = bidItem[0].material_cost || 0;
        const defaultUnit = bidItem[0].default_unit || 'EA';
        
        // Insert new project bid item
        const newItem = await sql`
          INSERT INTO project_bid_items (
            project_id, bid_item_id, rate, material_cost, unit, notes, is_active, created_at, updated_at
          ) VALUES (
            ${data.project_id},
            ${data.bid_item_id},
            ${data.rate || 0},
            ${data.material_cost !== undefined ? data.material_cost : defaultMaterialCost},
            ${data.unit || defaultUnit},
            ${data.notes || null},
            ${data.is_active !== false},
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
          )
          RETURNING *
        `;

        // Return the created item with joined bid item details
        const createdItem = await sql`
          SELECT 
            pbi.id as project_bid_item_id,
            pbi.project_id,
            pbi.bid_item_id,
            bi.item_code,
            bi.item_name,
            bi.category,
            pbi.unit,
            pbi.rate,
            pbi.material_cost,
            pbi.notes,
            CASE 
              WHEN pbi.material_cost > 0 
              THEN ((pbi.rate - pbi.material_cost) / pbi.material_cost * 100)
              ELSE 0 
            END as markup_percentage,
            pbi.is_active,
            pbi.created_at,
            pbi.updated_at
          FROM project_bid_items pbi
          JOIN bid_items bi ON pbi.bid_item_id = bi.id
          WHERE pbi.id = ${newItem[0].id}
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(createdItem[0])
        };
        
      } catch (error) {
        console.error('Error adding project bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to add project bid item: ' + error.message })
        };
      }

    case 'PUT':
      // Update project bid item
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

      try {
        const data = JSON.parse(event.body);
        
        // Check if the item exists
        const existing = await sql`
          SELECT * FROM project_bid_items WHERE id = ${id} AND is_active = true
        `;
        
        if (existing.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'Project bid item not found' })
          };
        }
        
        // Update the item
        const updated = await sql`
          UPDATE project_bid_items
          SET 
            rate = ${data.rate !== undefined ? data.rate : existing[0].rate},
            material_cost = ${data.material_cost !== undefined ? data.material_cost : existing[0].material_cost},
            unit = ${data.unit !== undefined ? data.unit : existing[0].unit},
            notes = ${data.notes !== undefined ? data.notes : existing[0].notes},
            is_active = ${data.is_active !== undefined ? data.is_active : existing[0].is_active},
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
          RETURNING *
        `;

        // Return the updated item with joined bid item details
        const updatedItem = await sql`
          SELECT 
            pbi.id as project_bid_item_id,
            pbi.project_id,
            pbi.bid_item_id,
            bi.item_code,
            bi.item_name,
            bi.category,
            pbi.unit,
            pbi.rate,
            pbi.material_cost,
            pbi.notes,
            CASE 
              WHEN pbi.material_cost > 0 
              THEN ((pbi.rate - pbi.material_cost) / pbi.material_cost * 100)
              ELSE 0 
            END as markup_percentage,
            pbi.is_active,
            pbi.created_at,
            pbi.updated_at
          FROM project_bid_items pbi
          JOIN bid_items bi ON pbi.bid_item_id = bi.id
          WHERE pbi.id = ${id}
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(updatedItem[0])
        };
        
      } catch (error) {
        console.error('Error updating project bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update project bid item: ' + error.message })
        };
      }

    case 'DELETE':
      // Delete (soft delete) project bid item
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

      try {
        // Check if the item exists
        const existing = await sql`
          SELECT id FROM project_bid_items WHERE id = ${id} AND is_active = true
        `;
        
        if (existing.length === 0) {
          return {
            statusCode: 404,
            headers,
            body: JSON.stringify({ error: 'Project bid item not found' })
          };
        }
        
        // Soft delete by setting is_active to false
        await sql`
          UPDATE project_bid_items 
          SET is_active = false, updated_at = CURRENT_TIMESTAMP 
          WHERE id = ${id}
        `;
        
        return {
          statusCode: 204,
          headers,
          body: ''
        };
        
      } catch (error) {
        console.error('Error deleting project bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to delete project bid item: ' + error.message })
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
// DWR Submission handler - Enhanced for better error handling
async function handleDWRSubmission(event, headers, method) {
  if (method !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  const { userId } = event.auth || {};

  try {
    const data = JSON.parse(event.body);
    
    // Validate required fields
    const requiredFields = ['work_date', 'foreman_id', 'project_id', 'arrival_time', 'departure_time', 'billable_work'];
    for (const field of requiredFields) {
      if (!data[field]) {
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

    // Convert string IDs to appropriate types
    const projectId = parseInt(data.project_id);
    const foremanId = data.foreman_id; // UUID
    const truckId = data.truck_id ? parseInt(data.truck_id) : null;
    const trailerId = data.trailer_id ? parseInt(data.trailer_id) : null;

    // Insert main DWR record
    const [dwr] = await sql`
      INSERT INTO daily_work_reports (
        work_date, foreman_id, project_id, arrival_time, departure_time,
        truck_id, trailer_id, billable_work, maybe_explanation, per_diem,
        submission_timestamp
      ) VALUES (
        ${data.work_date}, 
        ${foremanId}, 
        ${projectId},
        ${data.arrival_time}, 
        ${data.departure_time}, 
        ${truckId},
        ${trailerId}, 
        ${data.billable_work}, 
        ${data.maybe_explanation || null},
        ${data.per_diem || false}, 
        CURRENT_TIMESTAMP
      ) RETURNING id
    `;
    
    // Insert crew members if provided
    if (data.laborers && Array.isArray(data.laborers) && data.laborers.length > 0) {
      for (const laborerId of data.laborers) {
        await sql`
          INSERT INTO dwr_crew_members (dwr_id, laborer_id)
          VALUES (${dwr.id}, ${laborerId})
        `;
      }
    }
    
    // Insert machines if provided
    if (data.machines && Array.isArray(data.machines) && data.machines.length > 0) {
      for (const machineId of data.machines) {
        const machineIdInt = parseInt(machineId);
        await sql`
          INSERT INTO dwr_machines (dwr_id, machine_id)
          VALUES (${dwr.id}, ${machineIdInt})
        `;
      }
    }
    
    // Insert items if provided
    if (data.items && Array.isArray(data.items) && data.items.length > 0) {
      let itemIndex = 0;
      for (const item of data.items) {
        await sql`
          INSERT INTO dwr_items (
            dwr_id, item_name, quantity, unit, location_description,
            latitude, longitude, duration_hours, notes, item_index,
            bid_item_id, project_bid_item_id
          ) VALUES (
            ${dwr.id}, 
            ${item.item_name}, 
            ${item.quantity}, 
            ${item.unit || 'EA'},
            ${item.location_description}, 
            ${item.latitude || null}, 
            ${item.longitude || null},
            ${item.duration_hours}, 
            ${item.notes || null}, 
            ${itemIndex++},
            ${item.bid_item_id || null}, 
            ${item.project_bid_item_id || null}
          )
        `;
      }
    }
    
    return {
      statusCode: 201,
      headers,
      body: JSON.stringify({ 
        success: true, 
        id: dwr.id,
        message: 'Daily work report submitted successfully' 
      })
    };
  } catch (error) {
    console.error('Error submitting DWR:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: 'Failed to submit daily work report',
        details: error.message 
      })
    };
  }
}

// PO Data handler - returns vendors and projects for the PO form
async function handlePOData(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
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
    console.error('Error fetching PO data:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch data' })
    };
  }
}

// PO Submit handler - handles PO request submission
async function handlePOSubmit(event, headers, method) {
  if (method !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const data = JSON.parse(event.body);
    const { userId, email } = event.auth || {};
    
    // Validate required fields
    if (!data.name || !data.phone || !data.vendor || !data.project || !data.quotedPrice || !data.taxable) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          success: false,
          error: 'Missing required fields' 
        })
      };
    }
    
    // Generate PO number - just use a random number since it's an integer in your DB
    const poNumber = Math.floor(Math.random() * 900000) + 100000; // 6-digit number
    
    // Insert PO request with correct column names
    const result = await sql`
      INSERT INTO po_requests (
        po_number, 
        request_date,
        requested_by_name, 
        requested_by_email,
        phone, 
        vendor_name,
        project_name, 
        quoted_price, 
        taxable, 
        material_requested,
        approved,
        sms_sent,
        created_at
      ) VALUES (
        ${poNumber}, 
        CURRENT_TIMESTAMP,
        ${data.name}, 
        ${email || null},
        ${data.phone}, 
        ${data.vendor},
        ${data.project}, 
        ${data.quotedPrice}, 
        ${data.taxable},
        ${data.materialRequested || null}, 
        'PENDING',
        false,
        CURRENT_TIMESTAMP
      ) RETURNING *
    `;
    
    // Check if auto-approval should happen
    // Auto-approve if amount is less than $500
    let authorized = false;
    const amount = parseFloat(data.quotedPrice.replace(/[^0-9.-]/g, ''));
    if (!isNaN(amount) && amount < 500) {
      authorized = true;
      
      // Update status to approved
      await sql`
        UPDATE po_requests 
        SET approved = 'APPROVED', 
            approved_at = CURRENT_TIMESTAMP,
            approved_by = 'AUTO'
        WHERE po_number = ${poNumber}
      `;
    }
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        poNumber: `PO-${poNumber}`,
        authorized: authorized,
        message: authorized 
          ? 'PO request automatically approved' 
          : 'PO request submitted for approval'
      })
    };
  } catch (error) {
    console.error('Error submitting PO:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: 'Failed to submit PO request',
        details: error.message 
      })
    };
  }
}

// PO Requests handler - view PO requests
async function handlePORequests(event, headers, method, id) {
  const { role, userId, email } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const requests = await sql`
            SELECT * FROM po_requests WHERE id = ${parseInt(id)}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(requests[0] || null)
          };
        } else {
          // Get all PO requests - admins see all, others see their own
          let requests;
          if (role === 'admin' || role === 'manager') {
            requests = await sql`
              SELECT * FROM po_requests 
              ORDER BY request_date DESC
              LIMIT 100
            `;
          } else {
            requests = await sql`
              SELECT * FROM po_requests 
              WHERE requested_by_email = ${email}
              ORDER BY request_date DESC
              LIMIT 50
            `;
          }
          
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(requests)
          };
        }
      } catch (error) {
        console.error('Error fetching PO requests:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch PO requests' })
        };
      }

    case 'PUT':
      if (!requireRole(role, ['admin', 'manager'])) {
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

      try {
        const data = JSON.parse(event.body);
        
        const updated = await sql`
          UPDATE po_requests
          SET 
            approved = ${data.approved || 'PENDING'},
            approved_by = ${data.approved_by || null},
            approved_at = ${data.approved === 'APPROVED' ? sql`CURRENT_TIMESTAMP` : null},
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
          RETURNING *
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(updated[0])
        };
      } catch (error) {
        console.error('Error updating PO request:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update PO request' })
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

// Vendors handler
async function handleVendors(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const vendors = await sql`
            SELECT * FROM vendors WHERE id = ${parseInt(id)}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(vendors[0] || null)
          };
        } else {
          const vendors = await sql`
            SELECT * FROM vendors 
            WHERE active = true 
            ORDER BY name
          `;
          
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(vendors)
          };
        }
      } catch (error) {
        console.error('Error fetching vendors:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch vendors' })
        };
      }

    case 'POST':
      if (!requireRole(role, ['admin', 'manager'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      try {
        const data = JSON.parse(event.body);
        
        const newVendor = await sql`
          INSERT INTO vendors (name, active)
          VALUES (${data.name}, ${data.active !== false})
          RETURNING *
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(newVendor[0])
        };
      } catch (error) {
        console.error('Error creating vendor:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to create vendor' })
        };
      }

    case 'PUT':
      if (!requireRole(role, ['admin', 'manager'])) {
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

      try {
        const data = JSON.parse(event.body);
        
        const updated = await sql`
          UPDATE vendors
          SET 
            name = ${data.name},
            active = ${data.active !== false},
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ${id}
          RETURNING *
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(updated[0])
        };
      } catch (error) {
        console.error('Error updating vendor:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update vendor' })
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

// Authorized Users handler
async function handleAuthorizedUsers(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  if (!requireRole(role, ['admin'])) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Admin access required' })
    };
  }

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const users = await sql`
            SELECT * FROM authorized_users WHERE id = ${parseInt(id)}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users[0] || null)
          };
        } else {
          const users = await sql`
            SELECT * FROM authorized_users 
            ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users)
          };
        }
      } catch (error) {
        console.error('Error fetching authorized users:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch authorized users' })
        };
      }

    case 'POST':
      try {
        const data = JSON.parse(event.body);
        
        const newUser = await sql`
          INSERT INTO authorized_users (email, name, phone, active)
          VALUES (${data.email}, ${data.name || null}, ${data.phone || null}, ${data.active !== false})
          RETURNING *
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(newUser[0])
        };
      } catch (error) {
        console.error('Error creating authorized user:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to create authorized user' })
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

// Users handler
async function handleUsers(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  if (!requireRole(role, ['admin', 'manager'])) {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Insufficient permissions' })
    };
  }

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const users = await sql`
            SELECT id, username, email, first_name, last_name, role, is_active, last_login, created_at 
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
            SELECT id, username, email, first_name, last_name, role, is_active, last_login, created_at 
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}
