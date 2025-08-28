// netlify/functions/api.js - Fixed version with proper installed quantities endpoint
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';

// Google Maps API configuration
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;

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

// User activity logging
async function logUserActivity(userId, action, details = null) {
  try {
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, new_values, created_at)
      VALUES (${userId}, ${action}, 'users', ${details ? JSON.stringify(details) : null}, CURRENT_TIMESTAMP)
    `;
  } catch (error) {
    console.error('Failed to log user activity:', error);
    // Don't throw - activity logging shouldn't break the main operation
  }
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

  // Enhanced path parsing to handle nested actions
  let resource = '';
  let id = null;
  let action = null;

  // Parse the path - handle different patterns including nested actions
  const pathParts = event.path.split('/');
  const apiIndex = pathParts.indexOf('api');

  if (apiIndex !== -1 && pathParts.length > apiIndex + 1) {
    resource = pathParts[apiIndex + 1];
    if (pathParts.length > apiIndex + 2) {
      // Could be an ID or an action
      const secondPart = pathParts[apiIndex + 2];
      if (pathParts.length > apiIndex + 3) {
        // Pattern: /api/resource/id/action
        id = secondPart;
        action = pathParts[apiIndex + 3];
      } else {
        // Pattern: /api/resource/id_or_action
        // Try to determine if it's an ID (UUID) or action (string)
        if (secondPart.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i) || 
            !isNaN(parseInt(secondPart))) {
          id = secondPart;
        } else {
          action = secondPart;
        }
      }
    }
  }
  
  const method = event.httpMethod;
  
  console.log('API Request:', { path: event.path, resource, id, method, action });

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
        resource: resource,
        googleMapsEnabled: !!GOOGLE_MAPS_API_KEY
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
      
      case 'projects-with-contractors':
        return await handleProjectsWithContractors(event, headers, method);
      
      case 'general-contractors':
        return await handleGeneralContractors(event, headers, method, id);
      
      case 'equipment':
        return await handleEquipment(event, headers, method);
      
      // Support both naming conventions
      case 'bid-items':
      case 'master-bid-items':
        return await handleBidItems(event, headers, method, id);
      
      // Consolidated project bid items endpoint - handles all CRUD operations
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      // NEW: Installed quantities endpoint
      case 'installed-quantities':
        return await handleInstalledQuantities(event, headers, method);
      
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
      
      // Enhanced users endpoint with action support
      case 'users':
        return await handleUsers(event, headers, method, id, action);
      
      case 'billing-data':
        return await handleBillingData(event, headers, method);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Resource not found',
            resource: resource,
            availableEndpoints: [
              'foremen', 'laborers', 'projects', 'projects-with-contractors', 'general-contractors', 'equipment',
              'bid-items', 'project-bid-items', 'installed-quantities', 'submit-dwr',
              'po-data', 'po-submit', 'po-requests', 'vendors', 
              'authorized-users', 'users', 'billing-data'
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

// NEW: Installed Quantities handler - gets actual installed quantities from dwr_items
async function handleInstalledQuantities(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const params = event.queryStringParameters || {};
    const projectId = params.project_id;
    
    if (!projectId) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'project_id parameter is required' })
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

    // Get installed quantities by finding dwr_items that reference project_bid_items for this project
    const installedQuantities = await sql`
      SELECT 
        dwr.work_date,
        di.item_name,
        bi.item_code,
        di.quantity,
        di.unit,
        pbi.rate,
        (di.quantity * pbi.rate) as extension,
        di.location_description,
        di.duration_hours,
        di.notes,
        di.latitude,
        di.longitude,
        di.project_bid_item_id,
        pbi.id as project_bid_item_uuid
      FROM dwr_items di
      JOIN daily_work_reports dwr ON di.dwr_id = dwr.id
      JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
      JOIN bid_items bi ON pbi.bid_item_id = bi.id
      WHERE pbi.project_id = ${projectId}
        AND pbi.is_active = true
        AND bi.is_active = true
      ORDER BY dwr.work_date DESC, bi.item_code
    `;

    // Format the response to match what the frontend expects
    const formattedQuantities = installedQuantities.map(item => ({
      work_date: item.work_date ? new Date(item.work_date).toISOString().split('T')[0] : '',
      item_code: item.item_code || '',
      item_name: item.item_name || '',
      quantity: parseFloat(item.quantity) || 0,
      unit: item.unit || 'EA',
      rate: parseFloat(item.rate) || 0,
      extension: parseFloat(item.extension) || 0,
      location_description: item.location_description || 'N/A',
      duration_hours: parseFloat(item.duration_hours) || 0,
      notes: item.notes || '',
      latitude: item.latitude ? parseFloat(item.latitude) : null,
      longitude: item.longitude ? parseFloat(item.longitude) : null,
      project_bid_item_id: item.project_bid_item_id,
      project_bid_item_uuid: item.project_bid_item_uuid
    }));

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(formattedQuantities)
    };

  } catch (error) {
    console.error('Error fetching installed quantities:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Failed to fetch installed quantities',
        details: error.message
      })
    };
  }
}

// General Contractors handler - uses correct column names
async function handleGeneralContractors(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          // Get specific contractor by ID
          const contractors = await sql`
            SELECT id::text as id, name, contact_person, email, phone, address, 
                   city, state, zip, is_active, created_at, updated_at 
            FROM general_contractors WHERE id = ${id}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(contractors[0] || null)
          };
        } else {
          // Get all contractors
          const contractors = await sql`
            SELECT id::text as id, name, contact_person, email, phone, address, 
                   city, state, zip, is_active, created_at, updated_at 
            FROM general_contractors 
            ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(contractors)
          };
        }
      } catch (error) {
        console.error('Error fetching general contractors:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch general contractors' })
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
        const contractorData = JSON.parse(event.body);
        
        // Validate required fields
        if (!contractorData.name) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Contractor name is required' })
          };
        }
        
        const newContractor = await sql`
          INSERT INTO general_contractors (
            name, contact_person, email, phone, address, city, state, zip, is_active, created_at, updated_at
          ) VALUES (
            ${contractorData.name}, 
            ${contractorData.contact_person || null}, 
            ${contractorData.email || null},
            ${contractorData.phone || null},
            ${contractorData.address || null},
            ${contractorData.city || null},
            ${contractorData.state || null},
            ${contractorData.zip || null},
            ${contractorData.is_active !== false},
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
          )
          RETURNING id::text as id, name, contact_person, email, phone, address, 
                   city, state, zip, is_active, created_at, updated_at
        `;

        return {
          statusCode: 201,
          headers,
          body: JSON.stringify(newContractor[0])
        };
      } catch (error) {
        console.error('Error creating general contractor:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to create general contractor: ' + error.message })
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

// Projects with Contractors handler - includes site_location and county
async function handleProjectsWithContractors(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const projects = await sql`
      SELECT 
        p.id::text as id, 
        p.name, 
        p.project_code, 
        p.general_contractor_id::text as general_contractor_id,
        p.site_location,
        p.county,
        p.active, 
        p.created_at, 
        p.updated_at,
        gc.name as contractor_name
      FROM projects p
      LEFT JOIN general_contractors gc ON p.general_contractor_id = gc.id
      ORDER BY p.name
    `;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(projects)
    };
  } catch (error) {
    console.error('Error fetching projects with contractors:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Failed to fetch projects with contractors' })
    };
  }
}

// Projects handler - includes site_location and county
async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          // Get specific project by UUID
          const projects = await sql`
            SELECT 
              p.id::text as id, 
              p.name, 
              p.project_code, 
              p.general_contractor_id::text as general_contractor_id,
              p.site_location,
              p.county,
              p.active, 
              p.created_at, 
              p.updated_at,
              gc.name as contractor_name
            FROM projects p
            LEFT JOIN general_contractors gc ON p.general_contractor_id = gc.id
            WHERE p.id = ${id}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects[0] || null)
          };
        } else {
          // Get all active projects
          const projects = await sql`
            SELECT 
              p.id::text as id, 
              p.name, 
              p.project_code, 
              p.general_contractor_id::text as general_contractor_id,
              p.site_location,
              p.county,
              p.active, 
              p.created_at, 
              p.updated_at,
              gc.name as contractor_name
            FROM projects p
            LEFT JOIN general_contractors gc ON p.general_contractor_id = gc.id
            WHERE p.active = true
            ORDER BY p.name
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Laborers handler - includes employee_id
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
      SELECT id::text as id, name, employee_id, email, phone, hourly_rate
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

// Foremen handler - includes hourly_rate
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
      SELECT id::text as id, name, email, phone, hourly_rate
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

// Equipment handler - includes hourly_rate
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
    
    if (type) {
      // Use type column for exact matching
      equipment = await sql`
        SELECT id::text as id, name, type, hourly_rate
        FROM equipment 
        WHERE type = ${type} AND active = true 
        ORDER BY name
      `;
    } else {
      // No type filter requested
      equipment = await sql`
        SELECT id::text as id, name, type, hourly_rate
        FROM equipment 
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

// FINAL WORKING VERSION - Fixes response size issue
async function handleBidItems(event, headers, method, id) {
  console.log('handleBidItems called:', { method, id });
  
  const { role, userId } = event.auth || {};

  try {
    switch (method) {
      case 'GET':
        try {
          if (id) {
            console.log('Fetching single item with id:', id);
            const items = await sql`
              SELECT 
                id::text as id,
                item_code, 
                item_name, 
                category, 
                default_unit, 
                COALESCE(material_cost, 0)::numeric as material_cost, 
                description, 
                COALESCE(is_active, true) as is_active, 
                created_at, 
                updated_at
              FROM bid_items 
              WHERE id = ${id}::uuid
            `;
            
            return {
              statusCode: 200,
              headers,
              body: JSON.stringify(items[0] || null)
            };
            
          } else {
            console.log('Fetching all active bid items...');
            
            // Clean query with only essential fields to avoid response size issues
            const items = await sql`
              SELECT 
                id::text as id,
                item_code, 
                item_name, 
                category, 
                default_unit, 
                COALESCE(material_cost, 0)::numeric as material_cost, 
                description, 
                COALESCE(is_active, true) as is_active
              FROM bid_items 
              WHERE COALESCE(is_active, true) = true
              ORDER BY item_code
            `;
            
            console.log(`Found ${items.length} bid items`);
            
            // Clean the data to ensure JSON serialization works
            const cleanItems = items.map(item => ({
              id: String(item.id),
              item_code: String(item.item_code || ''),
              item_name: String(item.item_name || ''),
              category: item.category ? String(item.category) : null,
              default_unit: String(item.default_unit || 'EA'),
              material_cost: parseFloat(item.material_cost) || 0,
              description: item.description ? String(item.description) : null,
              is_active: Boolean(item.is_active)
            }));
            
            return {
              statusCode: 200,
              headers,
              body: JSON.stringify(cleanItems)
            };
          }
          
        } catch (dbError) {
          console.error('Database error:', dbError);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
              error: 'Failed to fetch bid items',
              details: dbError.message
            })
          };
        }

      case 'POST':
        // Create new bid item
        if (!requireRole(role, ['admin', 'manager', 'editor'])) {
          return {
            statusCode: 403,
            headers,
            body: JSON.stringify({ error: 'Insufficient permissions' })
          };
        }

        try {
          const data = JSON.parse(event.body);
          console.log('Creating new bid item:', data.item_code);
          
          // Validate required fields
          if (!data.item_code || !data.item_name) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ 
                error: 'Missing required fields: item_code, item_name' 
              })
            };
          }

          // Check if item_code already exists
          const existing = await sql`
            SELECT id FROM bid_items 
            WHERE item_code = ${data.item_code.trim()}
          `;

          if (existing.length > 0) {
            return {
              statusCode: 400,
              headers,
              body: JSON.stringify({ error: 'Item code already exists' })
            };
          }

          const newItem = await sql`
            INSERT INTO bid_items (
              item_code, item_name, category, default_unit, material_cost, 
              description, is_active
            ) VALUES (
              ${data.item_code.trim()},
              ${data.item_name.trim()},
              ${data.category || null},
              ${data.default_unit || 'EA'},
              ${parseFloat(data.material_cost) || 0},
              ${data.description || null},
              ${data.is_active !== false}
            )
            RETURNING 
              id::text as id,
              item_code, item_name, category, default_unit, 
              material_cost, description, is_active
          `;

          // Clean response
          const cleanItem = {
            id: String(newItem[0].id),
            item_code: String(newItem[0].item_code),
            item_name: String(newItem[0].item_name),
            category: newItem[0].category ? String(newItem[0].category) : null,
            default_unit: String(newItem[0].default_unit),
            material_cost: parseFloat(newItem[0].material_cost) || 0,
            description: newItem[0].description ? String(newItem[0].description) : null,
            is_active: Boolean(newItem[0].is_active)
          };

          if (typeof logUserActivity === 'function') {
            await logUserActivity(userId, 'BID_ITEM_CREATED', {
              item_code: data.item_code,
              item_name: data.item_name
            });
          }

          return {
            statusCode: 201,
            headers,
            body: JSON.stringify(cleanItem)
          };
          
        } catch (error) {
          console.error('Error creating bid item:', error);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
              error: 'Failed to create bid item: ' + error.message 
            })
          };
        }

      case 'PUT':
        // Update bid item
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
          console.log('Updating bid item:', id);
          
          // Check if item exists
          const existing = await sql`
            SELECT * FROM bid_items WHERE id = ${id}::uuid
          `;

          if (existing.length === 0) {
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Bid item not found' })
            };
          }

          const currentItem = existing[0];
          const updatedItem = await sql`
            UPDATE bid_items
            SET 
              item_code = ${data.item_code !== undefined ? data.item_code.trim() : currentItem.item_code},
              item_name = ${data.item_name !== undefined ? data.item_name.trim() : currentItem.item_name},
              category = ${data.category !== undefined ? data.category : currentItem.category},
              default_unit = ${data.default_unit !== undefined ? data.default_unit : currentItem.default_unit},
              material_cost = ${data.material_cost !== undefined ? parseFloat(data.material_cost) : currentItem.material_cost},
              description = ${data.description !== undefined ? data.description : currentItem.description},
              is_active = ${data.is_active !== undefined ? data.is_active : currentItem.is_active},
              updated_at = CURRENT_TIMESTAMP
            WHERE id = ${id}::uuid
            RETURNING 
              id::text as id,
              item_code, item_name, category, default_unit, 
              material_cost, description, is_active
          `;

          // Clean response
          const cleanItem = {
            id: String(updatedItem[0].id),
            item_code: String(updatedItem[0].item_code),
            item_name: String(updatedItem[0].item_name),
            category: updatedItem[0].category ? String(updatedItem[0].category) : null,
            default_unit: String(updatedItem[0].default_unit),
            material_cost: parseFloat(updatedItem[0].material_cost) || 0,
            description: updatedItem[0].description ? String(updatedItem[0].description) : null,
            is_active: Boolean(updatedItem[0].is_active)
          };

          if (typeof logUserActivity === 'function') {
            await logUserActivity(userId, 'BID_ITEM_UPDATED', {
              item_id: id,
              item_code: updatedItem[0].item_code
            });
          }

          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(cleanItem)
          };
          
        } catch (error) {
          console.error('Error updating bid item:', error);
          return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
              error: 'Failed to update bid item: ' + error.message 
            })
          };
        }

      case 'DELETE':
        // Delete (soft delete) bid item
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
          console.log('Deleting bid item:', id);
          
          // Check if item exists
          const existing = await sql`
            SELECT item_code, item_name FROM bid_items WHERE id = ${id}::uuid
          `;

          if (existing.length === 0) {
            return {
              statusCode: 404,
              headers,
              body: JSON.stringify({ error: 'Bid item not found' })
            };
          }

          // Soft delete by setting is_active to false
          await sql`
            UPDATE bid_items 
            SET is_active = false, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ${id}::uuid
          `;

          if (typeof logUserActivity === 'function') {
            await logUserActivity(userId, 'BID_ITEM_DELETED', {
              item_id: id,
              item_code: existing[0].item_code,
              item_name: existing[0].item_name
            });
          }

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
            body: JSON.stringify({ 
              error: 'Failed to delete bid item: ' + error.message 
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
    
  } catch (error) {
    console.error('Function error:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Function execution error',
        details: error.message
      })
    };
  }
}

// DWR Submission handler for all-UUID database schema
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
    console.log('Received DWR data:', JSON.stringify(data, null, 2));
    
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

    // Helper function to validate and format UUID
    function validateUuid(id, fieldName) {
      if (!id) return null;
      
      // If it's already a valid UUID, return it
      if (typeof id === 'string' && id.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)) {
        return id;
      }
      
      // If it's an integer, this is wrong - we need to look up the actual UUID
      if (parseInt(id).toString() === id.toString()) {
        throw new Error(`${fieldName} should be a UUID but received integer: ${id}. Check your API endpoints.`);
      }
      
      throw new Error(`Invalid UUID format for ${fieldName}: ${id}`);
    }

    try {
      // Validate all UUIDs before attempting insertion
      const foremanId = validateUuid(data.foreman_id, 'foreman_id');
      const projectId = validateUuid(data.project_id, 'project_id');
      const truckId = validateUuid(data.truck_id, 'truck_id');
      const trailerId = validateUuid(data.trailer_id, 'trailer_id');
      
      console.log('Validated UUIDs:', { foremanId, projectId, truckId, trailerId });
      
      // Insert main DWR record
      const dwrResult = await sql`
        INSERT INTO daily_work_reports (
          work_date, 
          foreman_id, 
          project_id, 
          arrival_time, 
          departure_time,
          truck_id, 
          trailer_id, 
          billable_work, 
          maybe_explanation, 
          per_diem,
          submission_timestamp,
          created_at,
          updated_at
        ) VALUES (
          ${data.work_date}, 
          ${foremanId}::uuid, 
          ${projectId}::uuid,
          ${data.arrival_time}, 
          ${data.departure_time}, 
          ${truckId}::uuid,
          ${trailerId}::uuid, 
          ${data.billable_work}, 
          ${data.maybe_explanation || null},
          ${data.per_diem || false}, 
          CURRENT_TIMESTAMP,
          CURRENT_TIMESTAMP,
          CURRENT_TIMESTAMP
        ) RETURNING id
      `;
      
      const dwrId = dwrResult[0].id;
      console.log(`DWR record created with ID: ${dwrId}`);
      
      // Insert crew members if provided
      if (data.laborers && Array.isArray(data.laborers) && data.laborers.length > 0) {
        console.log(`Processing ${data.laborers.length} crew members...`);
        for (const laborerId of data.laborers) {
          if (laborerId) {
            try {
              const validLaborerId = validateUuid(laborerId, 'laborer_id');
              await sql`
                INSERT INTO dwr_crew_members (
                  dwr_id, 
                  laborer_id,
                  created_at
                ) VALUES (
                  ${dwrId}, 
                  ${validLaborerId}::uuid,
                  CURRENT_TIMESTAMP
                )
              `;
              console.log(`Inserted crew member: ${validLaborerId}`);
            } catch (error) {
              console.error(`Failed to insert laborer ${laborerId}:`, error.message);
              // Don't fail entire submission for one bad ID
            }
          }
        }
      }
      
      // Insert machines if provided
      if (data.machines && Array.isArray(data.machines) && data.machines.length > 0) {
        console.log(`Processing ${data.machines.length} machines...`);
        for (const machineId of data.machines) {
          if (machineId) {
            try {
              const validMachineId = validateUuid(machineId, 'machine_id');
              await sql`
                INSERT INTO dwr_machines (
                  dwr_id, 
                  machine_id,
                  created_at
                ) VALUES (
                  ${dwrId}, 
                  ${validMachineId}::uuid,
                  CURRENT_TIMESTAMP
                )
              `;
              console.log(`Inserted machine: ${validMachineId}`);
            } catch (error) {
              console.error(`Failed to insert machine ${machineId}:`, error.message);
              // Don't fail entire submission for one bad ID
            }
          }
        }
      }
      
      // Insert items if provided
      if (data.items && Array.isArray(data.items) && data.items.length > 0) {
        console.log(`Processing ${data.items.length} items...`);
        for (let i = 0; i < data.items.length; i++) {
          const item = data.items[i];
          try {
            const validBidItemId = validateUuid(item.bid_item_id, 'bid_item_id');
            const validProjectBidItemId = validateUuid(item.project_bid_item_id, 'project_bid_item_id');
            
            await sql`
              INSERT INTO dwr_items (
                dwr_id, 
                item_name, 
                quantity, 
                unit, 
                location_description,
                latitude, 
                longitude, 
                duration_hours, 
                notes, 
                item_index,
                bid_item_id, 
                project_bid_item_id,
                created_at,
                updated_at
              ) VALUES (
                ${dwrId}, 
                ${item.item_name}, 
                ${parseFloat(item.quantity)}, 
                ${item.unit || 'EA'},
                ${item.location_description}, 
                ${item.latitude ? parseFloat(item.latitude) : null}, 
                ${item.longitude ? parseFloat(item.longitude) : null},
                ${parseFloat(item.duration_hours)}, 
                ${item.notes || null}, 
                ${i},
                ${validBidItemId}::uuid, 
                ${validProjectBidItemId}::uuid,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
              )
            `;
            console.log(`Inserted item ${i + 1}: ${item.item_name}`);
          } catch (error) {
            console.error(`Failed to insert item ${i}:`, error.message);
            console.error('Item data:', item);
            // Don't fail entire submission for one bad item
          }
        }
      }
      
      return {
        statusCode: 201,
        headers,
        body: JSON.stringify({ 
          success: true, 
          id: dwrId,
          message: 'Daily work report submitted successfully' 
        })
      };
      
    } catch (dbError) {
      console.error('Database error in DWR submission:', dbError);
      throw dbError;
    }
    
  } catch (error) {
    console.error('Error submitting DWR:', error);
    
    let errorMessage = 'Failed to submit daily work report';
    let statusCode = 500;
    
    if (error.message.includes('JSON')) {
      errorMessage = 'Invalid JSON data provided';
      statusCode = 400;
    } else if (error.message.includes('should be a UUID but received integer')) {
      errorMessage = error.message + ' Your API endpoints need to return UUIDs, not integers.';
      statusCode = 400;
    } else if (error.message.includes('Invalid UUID format')) {
      errorMessage = error.message;
      statusCode = 400;
    } else if (error.message.includes('foreign key')) {
      errorMessage = 'Invalid reference data - one or more UUIDs don\'t exist in the database';
      statusCode = 400;
    } else if (error.message.includes('not null')) {
      errorMessage = 'Missing required field in database';
      statusCode = 400;
    }
    
    return {
      statusCode: statusCode,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: errorMessage,
        details: error.message,
        helpText: 'Make sure all your API endpoints (foremen, projects, equipment, laborers) return UUID format IDs, not integers.'
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Enhanced Users handler with action support and full CRUD operations
async function handleUsers(event, headers, method, id, action) {
  const { role, userId } = event.auth || {};

  // Handle specific actions
  if (action === 'toggle-status' && method === 'POST') {
    if (!requireRole(role, ['admin', 'project_manager', 'superintendent'])) {
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
        SELECT is_active, username FROM users WHERE id = ${id}
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

      // Log the activity
      await logUserActivity(userId, `USER_${newStatus ? 'ENABLED' : 'DISABLED'}`, {
        target_user_id: id,
        target_username: currentUser[0].username,
        new_status: newStatus
      });

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({ 
          success: true,
          message: `User ${newStatus ? 'enabled' : 'disabled'} successfully`,
          new_status: newStatus
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
      if (!requireRole(role, ['admin', 'project_manager', 'superintendent'])) {
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Billing Data handler for quantities report
async function handleBillingData(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  const { role, userId } = event.auth || {};

  try {
    const params = event.queryStringParameters || {};
    const startDate = params.start_date;
    const endDate = params.end_date;

    if (!startDate || !endDate) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          error: 'start_date and end_date parameters are required (YYYY-MM-DD format)' 
        })
      };
    }

    // Validate date format
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(startDate) || !dateRegex.test(endDate)) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ 
          error: 'Invalid date format. Use YYYY-MM-DD format.' 
        })
      };
    }

    // Configuration for financial calculations
    const MOH_RATE_PERCENTAGE = 0.10; // 10% MOH rate (configurable)
    const RETAINAGE_PERCENTAGE = 0.05; // 5% retainage (configurable)

    // Main query to get all billing data for the date range
    const billingData = await sql`
      SELECT 
        p.name as project_name,
        p.id as project_id,
        bi.item_code,
        bi.item_name,
        bi.category,
        dwr.work_date,
        di.quantity,
        di.unit,
        pbi.rate,
        pbi.material_cost,
        (di.quantity * pbi.rate) as extension
      FROM daily_work_reports dwr
      JOIN dwr_items di ON dwr.id = di.dwr_id
      JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
      JOIN projects p ON pbi.project_id = p.id
      JOIN bid_items bi ON pbi.bid_item_id = bi.id
      WHERE dwr.work_date >= ${startDate}::date 
        AND dwr.work_date <= ${endDate}::date
        AND p.active = true
        AND pbi.is_active = true
        AND bi.is_active = true
      ORDER BY p.name, bi.item_name, dwr.work_date
    `;

    if (billingData.length === 0) {
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify({
          projects: [],
          grandTotals: {
            extension: 0,
            mohAmount: 0,
            lessMoh: 0,
            retainage: 0,
            billableAmount: 0
          }
        })
      };
    }

    // Process and group the data
    const projectsMap = new Map();
    const grandTotals = {
      extension: 0,
      mohAmount: 0,
      lessMoh: 0,
      retainage: 0,
      billableAmount: 0
    };

    billingData.forEach(row => {
      const projectName = row.project_name;
      const itemKey = `${row.item_code}-${row.item_name}`;
      
      // Initialize project if not exists
      if (!projectsMap.has(projectName)) {
        projectsMap.set(projectName, {
          name: projectName,
          items: new Map(),
          totals: {
            extension: 0,
            mohAmount: 0,
            lessMoh: 0,
            retainage: 0,
            billableAmount: 0,
            retainagePercent: RETAINAGE_PERCENTAGE * 100
          }
        });
      }

      const project = projectsMap.get(projectName);

      // Initialize item if not exists
      if (!project.items.has(itemKey)) {
        project.items.set(itemKey, {
          name: `${row.item_code} - ${row.item_name}`,
          totalQty: 0,
          entries: [],
          totals: {
            extension: 0,
            mohAmount: 0,
            lessMoh: 0,
            retainage: 0,
            billableAmount: 0,
            retainagePercent: RETAINAGE_PERCENTAGE * 100
          }
        });
      }

      const item = project.items.get(itemKey);

      // Convert numeric values and calculate financial metrics
      const qty = parseFloat(row.quantity) || 0;
      const rate = parseFloat(row.rate) || 0;
      const materialCost = parseFloat(row.material_cost) || 0;
      const extension = parseFloat(row.extension) || 0;
      
      // Calculate financial metrics in JavaScript
      const mohAmount = extension * MOH_RATE_PERCENTAGE;
      const lessMoh = extension - mohAmount;
      const retainageAmount = extension * RETAINAGE_PERCENTAGE;
      const billableAmount = lessMoh - retainageAmount;

      // Add entry
      item.entries.push({
        workDate: row.work_date ? new Date(row.work_date).toISOString().split('T')[0] : '',
        qty: qty,
        unit: row.unit || 'EA',
        rate: rate,
        mohRate: rate * MOH_RATE_PERCENTAGE, // MOH rate per unit
        extension: extension,
        mohAmount: mohAmount,
        lessMoh: lessMoh,
        retainage: retainageAmount,
        billableAmount: billableAmount
      });

      // Update item totals
      item.totalQty += qty;
      item.totals.extension += extension;
      item.totals.mohAmount += mohAmount;
      item.totals.lessMoh += lessMoh;
      item.totals.retainage += retainageAmount;
      item.totals.billableAmount += billableAmount;

      // Update project totals
      project.totals.extension += extension;
      project.totals.mohAmount += mohAmount;
      project.totals.lessMoh += lessMoh;
      project.totals.retainage += retainageAmount;
      project.totals.billableAmount += billableAmount;

      // Update grand totals
      grandTotals.extension += extension;
      grandTotals.mohAmount += mohAmount;
      grandTotals.lessMoh += lessMoh;
      grandTotals.retainage += retainageAmount;
      grandTotals.billableAmount += billableAmount;
    });

    // Convert Maps to Arrays for JSON response
    const projects = Array.from(projectsMap.values()).map(project => ({
      ...project,
      items: Array.from(project.items.values())
    }));

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        projects: projects,
        grandTotals: grandTotals,
        dateRange: `${startDate} - ${endDate}`,
        configuration: {
          mohRatePercentage: MOH_RATE_PERCENTAGE * 100,
          retainagePercentage: RETAINAGE_PERCENTAGE * 100
        }
      })
    };

  } catch (error) {
    console.error('Error fetching billing data:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: 'Failed to fetch billing data',
        details: error.message 
      })
    };
  }
}
