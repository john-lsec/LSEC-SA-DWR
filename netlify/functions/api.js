// netlify/functions/api.js - Debug version with better path parsing
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

  // Debug: Log the incoming path
  console.log('Incoming path:', event.path);
  console.log('HTTP Method:', event.httpMethod);

  // Better path parsing
  let resource = '';
  let id = null;
  
  // The path will be something like /.netlify/functions/api/foremen
  // We need to extract 'foremen' from this
  const pathParts = event.path.split('/');
  console.log('Path parts:', pathParts);
  
  // Find the index of 'api' and get the next part as the resource
  const apiIndex = pathParts.indexOf('api');
  if (apiIndex !== -1 && pathParts.length > apiIndex + 1) {
    resource = pathParts[apiIndex + 1];
    if (pathParts.length > apiIndex + 2) {
      id = pathParts[apiIndex + 2];
    }
  }
  
  console.log('Extracted resource:', resource);
  console.log('Extracted ID:', id);
  
  const method = event.httpMethod;

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
        debug: {
          pathParts: pathParts,
          apiIndex: apiIndex
        }
      })
    };
  }

  // Check authentication for protected endpoints
  const publicEndpoints = ['test', 'auth', 'po-data', 'po-submit', 'po-approve'];
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
      role: auth.role
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
      
      case 'master-bid-items':
        return await handleMasterBidItems(event, headers, method, id);
      
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      case 'submit-dwr':
        return await handleDWRSubmission(event, headers, method);
      
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
            path: event.path,
            debug: {
              pathParts: pathParts,
              apiIndex: apiIndex,
              availableResources: [
                'test', 'foremen', 'laborers', 'projects', 'equipment',
                'master-bid-items', 'project-bid-items', 'submit-dwr',
                'po-requests', 'vendors', 'authorized-users', 'users'
              ]
            }
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
        details: error.message,
        stack: error.stack 
      })
    };
  }
};

// Foremen handler - FIXED column names
async function handleForemen(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    console.log('Fetching foremen from database...');
    const foremen = await sql`
      SELECT id, name FROM foremen 
      WHERE is_active = true 
      ORDER BY name
    `;
    
    console.log(`Found ${foremen.length} foremen`);
    
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
      body: JSON.stringify({ 
        error: 'Failed to fetch foremen',
        details: error.message 
      })
    };
  }
}

// Laborers handler - FIXED column names
async function handleLaborers(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    console.log('Fetching laborers from database...');
    const laborers = await sql`
      SELECT id, name FROM laborers 
      WHERE is_active = true 
      ORDER BY name
    `;
    
    console.log(`Found ${laborers.length} laborers`);
    
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
      body: JSON.stringify({ 
        error: 'Failed to fetch laborers',
        details: error.message 
      })
    };
  }
}

// Projects handler - FIXED column names and data types
async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const projects = await sql`
            SELECT * FROM projects WHERE id = ${parseInt(id)}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects[0] || null)
          };
        } else {
          console.log('Fetching all active projects...');
          const projects = await sql`
            SELECT * FROM projects 
            WHERE active = true
            ORDER BY name
          `;
          console.log(`Found ${projects.length} projects`);
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects)
          };
        }
      } catch (error) {
        console.error('Error in projects handler:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ 
            error: 'Failed to fetch projects',
            details: error.message 
          })
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

      const projectData = JSON.parse(event.body);
      
      const newProject = await sql`
        INSERT INTO projects (
          name, project_code, active
        ) VALUES (
          ${projectData.name},
          ${projectData.project_code || null},
          ${projectData.active !== false}
        )
        RETURNING *
      `;

      // Log the action
      await sql`
        INSERT INTO audit_log (user_id, action, table_name, record_id, new_values)
        VALUES (${userId}, 'create', 'projects', ${newProject[0].id}::uuid, ${JSON.stringify(newProject[0])})
      `;

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(newProject[0])
      };

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

      const updateData = JSON.parse(event.body);
      
      const updated = await sql`
        UPDATE projects
        SET 
          name = ${updateData.name},
          project_code = ${updateData.project_code || null},
          active = ${updateData.active !== false},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ${parseInt(id)}
        RETURNING *
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(updated[0])
      };

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

      await sql`
        DELETE FROM projects WHERE id = ${parseInt(id)}
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
    
    console.log('Fetching equipment, type filter:', type);
    
    // First, check if we have a type column
    let equipment;
    try {
      if (type) {
        equipment = await sql`
          SELECT id, name, type FROM equipment 
          WHERE type = ${type} AND active = true 
          ORDER BY name
        `;
      } else {
        equipment = await sql`
          SELECT id, name, type FROM equipment 
          WHERE active = true 
          ORDER BY name
        `;
      }
    } catch (error) {
      // If type column doesn't exist, fall back to just id and name
      console.log('Type column might not exist, falling back...');
      equipment = await sql`
        SELECT id, name FROM equipment 
        WHERE active = true 
        ORDER BY name
      `;
      
      // Filter by name pattern if type was requested
      if (type) {
        equipment = equipment.filter(e => 
          e.name.toUpperCase().includes(type.toUpperCase())
        );
      }
    }
    
    console.log(`Found ${equipment.length} equipment items`);
    
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
      body: JSON.stringify({ 
        error: 'Failed to fetch equipment',
        details: error.message 
      })
    };
  }
}

// Master Bid Items - FIXED to use 'bid_items' table
async function handleMasterBidItems(event, headers, method, id) {
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
          console.log('Fetching all bid items...');
          const items = await sql`
            SELECT * FROM bid_items 
            WHERE is_active = true
            ORDER BY item_code
          `;
          console.log(`Found ${items.length} bid items`);
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
          body: JSON.stringify({ 
            error: 'Failed to fetch bid items',
            details: error.message 
          })
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

      const createData = JSON.parse(event.body);
      
      if (!createData.item_code || !createData.item_name) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'Item code and name are required' })
        };
      }

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

      await sql`
        DELETE FROM bid_items WHERE id = ${id}
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

// Other handlers remain the same...
// (Include all the other handlers from the previous version)

// Vendors handler
async function handleVendors(event, headers, method, id) {
  const { role } = event.auth || {};

  switch (method) {
    case 'GET':
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

    case 'POST':
      if (!requireRole(role, ['admin', 'manager', 'editor'])) {
        return {
          statusCode: 403,
          headers,
          body: JSON.stringify({ error: 'Insufficient permissions' })
        };
      }

      const vendorData = JSON.parse(event.body);
      const newVendor = await sql`
        INSERT INTO vendors (name, active)
        VALUES (${vendorData.name}, ${vendorData.active !== false})
        RETURNING *
      `;

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(newVendor[0])
      };

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

// Add the rest of the handlers here...
// (handleProjectBidItems, handleDWRSubmission, handlePORequests, 
//  handleAuthorizedUsers, handleUsers)
