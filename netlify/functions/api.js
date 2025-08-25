// netlify/functions/api.js - Complete API Handler with all endpoints
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');

// Initialize database connection
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

// Projects handler
async function handleProjects(event, headers, method, id) {
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

// Project Bid Items handler
async function handleProjectBidItems(event, headers, method, id) {
  switch (method) {
    case 'GET':
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

        const projectBidItems = await sql`
          SELECT 
            pbi.id::text as project_bid_item_id,
            bi.item_code,
            bi.item_name,
            bi.category,
            bi.unit,
            pbi.rate,
            pbi.material_cost,
            pbi.contract_quantity,
            pbi.is_active,
            pbi.project_id::text as project_id,
            bi.id::text as bid_item_id
          FROM project_bid_items pbi
          JOIN bid_items bi ON pbi.bid_item_id = bi.id
          WHERE pbi.project_id = ${projectId}
            AND pbi.is_active = true
            AND bi.is_active = true
          ORDER BY bi.item_code
        `;

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(projectBidItems)
        };
      } catch (error) {
        console.error('Error fetching project bid items:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch project bid items' })
        };
      }

    case 'PUT':
      try {
        const data = JSON.parse(event.body);
        
        if (!id) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'Project bid item ID is required' })
          };
        }

        // Update contract quantity
        if (data.contract_quantity !== undefined) {
          await sql`
            UPDATE project_bid_items 
            SET contract_quantity = ${data.contract_quantity},
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ${id}
          `;
        }

        return {
          statusCode: 200,
          headers,
          body: JSON.stringify({ message: 'Project bid item updated successfully' })
        };
      } catch (error) {
        console.error('Error updating project bid item:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to update project bid item' })
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

// Installed Quantities handler
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

    // Get installed quantities from DWR items
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
        di.notes,
        di.project_bid_item_id::text,
        pbi.id::text as project_bid_item_uuid
      FROM dwr_items di
      JOIN daily_work_reports dwr ON di.dwr_id = dwr.id
      JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
      JOIN bid_items bi ON pbi.bid_item_id = bi.id
      WHERE pbi.project_id = ${projectId}
        AND pbi.is_active = true
        AND bi.is_active = true
      ORDER BY dwr.work_date DESC, bi.item_code
    `;

    // Format the response
    const formattedQuantities = installedQuantities.map(item => ({
      work_date: item.work_date ? new Date(item.work_date).toISOString().split('T')[0] : '',
      item_code: item.item_code || '',
      item_name: item.item_name || '',
      quantity: parseFloat(item.quantity) || 0,
      unit: item.unit || 'EA',
      rate: parseFloat(item.rate) || 0,
      extension: parseFloat(item.extension) || 0,
      location_description: item.location_description || 'N/A',
      notes: item.notes || '',
      project_bid_item_id: item.project_bid_item_id
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
      body: JSON.stringify({ error: 'Failed to fetch installed quantities' })
    };
  }
}

// Foremen handler
async function handleForemen(event, headers, method) {
  switch (method) {
    case 'GET':
      try {
        const foremen = await sql`
          SELECT 
            id::text as id, 
            name, 
            employee_id, 
            email,
            active, 
            created_at, 
            updated_at
          FROM foremen 
          WHERE active = true 
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
  switch (method) {
    case 'GET':
      try {
        const params = event.queryStringParameters || {};
        const equipmentType = params.type;
        
        let query;
        if (equipmentType) {
          query = sql`
            SELECT 
              id::text as id, 
              name, 
              equipment_type, 
              active,
              created_at, 
              updated_at
            FROM equipment 
            WHERE active = true 
              AND equipment_type = ${equipmentType}
            ORDER BY name
          `;
        } else {
          query = sql`
            SELECT 
              id::text as id, 
              name, 
              equipment_type, 
              active,
              created_at, 
              updated_at
            FROM equipment 
            WHERE active = true 
            ORDER BY equipment_type, name
          `;
        }
        
        const equipment = await query;
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Main handler
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
  let resource = '';
  let id = null;
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
      case 'projects':
        return await handleProjects(event, headers, method, id);
      
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      case 'installed-quantities':
        return await handleInstalledQuantities(event, headers, method);
      
      case 'foremen':
        return await handleForemen(event, headers, method);
      
      case 'equipment':
        return await handleEquipment(event, headers, method);
      
      default:
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ 
            error: 'Resource not found',
            resource: resource,
            availableEndpoints: [
              'projects', 'project-bid-items', 'installed-quantities', 
              'foremen', 'equipment'
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
