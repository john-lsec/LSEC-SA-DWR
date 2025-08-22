// netlify/functions/api.js - COMPLETE FIXED VERSION
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET || '416cf56a29ba481816ab028346c8dcdc169b2241187b10e9b274192da564523234ad0aec4f6dd567e1896c6e52c10f7e8494d6d15938afab7ef11db09630fd8fa8005';

// Google Maps API configuration
const GOOGLE_MAPS_API_KEY = process.env.GOOGLE_MAPS_API_KEY;

// FIXED: Enhanced UUID validation that handles transition period
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

// Helper function to verify JWT token
function verifyJWT(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// FIXED: Enhanced authentication middleware
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

// FIXED: User activity logging with proper error handling
async function logUserActivity(userId, action, details = null) {
  try {
    await sql`
      INSERT INTO audit_log (user_id, action, table_name, new_values, created_at)
      VALUES (${userId}, ${action}, 'user_activity', ${details ? JSON.stringify(details) : null}, CURRENT_TIMESTAMP)
    `;
  } catch (error) {
    console.error('Failed to log user activity:', error);
  }
}

// MAIN HANDLER
exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Parse path and extract resource/ID
  const pathParts = event.path.split('/').filter(part => part !== '');
  const resource = pathParts[pathParts.length - 1] || pathParts[pathParts.length - 2];
  const method = event.httpMethod;
  
  // Extract ID and action from query parameters or path
  const queryParams = event.queryStringParameters || {};
  let id = queryParams.id || pathParts[pathParts.length - 1];
  let action = queryParams.action;

  // Special handling for numeric IDs in path
  if (/^\d+$/.test(id)) {
    id = pathParts[pathParts.length - 1];
    action = queryParams.action;
  } else if (pathParts.length > 2) {
    id = pathParts[pathParts.length - 1];
    action = queryParams.action;
  }

  // Test endpoint for connectivity
  if (resource === 'test') {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        message: 'API is working correctly',
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
        return await handleForemen(event, headers, method, id);
      
      case 'laborers':
        return await handleLaborers(event, headers, method, id);
      
      case 'projects':
        return await handleProjects(event, headers, method, id);
      
      case 'projects-with-contractors':
        return await handleProjectsWithContractors(event, headers, method);
      
      case 'general-contractors':
        return await handleGeneralContractors(event, headers, method, id);
      
      case 'equipment':
        return await handleEquipment(event, headers, method, id);
      
      case 'bid-items':
      case 'master-bid-items':
        return await handleBidItems(event, headers, method, id);
      
      case 'project-bid-items':
        return await handleProjectBidItems(event, headers, method, id);
      
      case 'installed-quantities':
        return await handleInstalledQuantities(event, headers, method);
      
      case 'submit-dwr':
        return await handleDWRSubmission(event, headers, method);
      
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

// FIXED: Complete DWR Submission handler
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

    try {
      // Validate and convert IDs
      const foremanId = validateAndConvertId(data.foreman_id, 'foreman_id');
      const projectId = validateAndConvertId(data.project_id, 'project_id');
      const truckId = validateAndConvertId(data.truck_id, 'truck_id');
      const trailerId = validateAndConvertId(data.trailer_id, 'trailer_id');
      
      console.log('Validated IDs:', { foremanId, projectId, truckId, trailerId });
      
      // Verify that referenced records exist
      if (foremanId) {
        const foremanExists = await sql`SELECT id FROM foremen WHERE id = ${foremanId} AND is_active = true LIMIT 1`;
        if (foremanExists.length === 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ 
              success: false,
              error: `Foreman with ID ${foremanId} not found or inactive` 
            })
          };
        }
      }
      
      if (projectId) {
        const projectExists = await sql`SELECT id FROM projects WHERE id = ${projectId} AND active = true LIMIT 1`;
        if (projectExists.length === 0) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ 
              success: false,
              error: `Project with ID ${projectId} not found or inactive` 
            })
          };
        }
      }
      
      // Insert main DWR record
      const dwrResult = await sql`
        INSERT INTO daily_work_reports (
          work_date, foreman_id, project_id, arrival_time, departure_time,
          truck_id, trailer_id, billable_work, maybe_explanation, per_diem,
          submission_timestamp, created_at, updated_at
        ) VALUES (
          ${data.work_date}, ${foremanId}, ${projectId},
          ${data.arrival_time}, ${data.departure_time}, 
          ${truckId}, ${trailerId}, ${data.billable_work}, 
          ${data.maybe_explanation || null}, ${data.per_diem || false}, 
          CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        ) RETURNING id
      `;
      
      const dwrId = dwrResult[0].id;
      console.log(`DWR record created with ID: ${dwrId}`);
      
      // Insert crew members
      if (data.laborers && Array.isArray(data.laborers) && data.laborers.length > 0) {
        console.log(`Processing ${data.laborers.length} crew members...`);
        for (const laborerId of data.laborers) {
          if (laborerId) {
            try {
              const validLaborerId = validateAndConvertId(laborerId, 'laborer_id');
              const laborerExists = await sql`SELECT id FROM laborers WHERE id = ${validLaborerId} AND is_active = true LIMIT 1`;
              if (laborerExists.length > 0) {
                await sql`
                  INSERT INTO dwr_crew_members (dwr_id, laborer_id, created_at) 
                  VALUES (${dwrId}, ${validLaborerId}, CURRENT_TIMESTAMP)
                `;
                console.log(`Inserted crew member: ${validLaborerId}`);
              }
            } catch (error) {
              console.error(`Failed to insert laborer ${laborerId}:`, error.message);
            }
          }
        }
      }
      
      // Insert machines
      if (data.machines && Array.isArray(data.machines) && data.machines.length > 0) {
        console.log(`Processing ${data.machines.length} machines...`);
        for (const machineId of data.machines) {
          if (machineId) {
            try {
              const validMachineId = validateAndConvertId(machineId, 'machine_id');
              const machineExists = await sql`SELECT id FROM equipment WHERE id = ${validMachineId} AND active = true LIMIT 1`;
              if (machineExists.length > 0) {
                await sql`
                  INSERT INTO dwr_machines (dwr_id, machine_id, created_at) 
                  VALUES (${dwrId}, ${validMachineId}, CURRENT_TIMESTAMP)
                `;
                console.log(`Inserted machine: ${validMachineId}`);
              }
            } catch (error) {
              console.error(`Failed to insert machine ${machineId}:`, error.message);
            }
          }
        }
      }
      
      // Insert items
      if (data.items && Array.isArray(data.items) && data.items.length > 0) {
        console.log(`Processing ${data.items.length} items...`);
        for (let i = 0; i < data.items.length; i++) {
          const item = data.items[i];
          try {
            const validBidItemId = validateAndConvertId(item.bid_item_id, 'bid_item_id');
            const validProjectBidItemId = validateAndConvertId(item.project_bid_item_id, 'project_bid_item_id');
            
            const quantity = parseFloat(item.quantity);
            if (isNaN(quantity) || quantity <= 0) continue;
            
            await sql`
              INSERT INTO dwr_items (
                dwr_id, item_name, quantity, unit, location_description,
                latitude, longitude, duration_hours, notes, item_index,
                bid_item_id, project_bid_item_id, created_at, updated_at
              ) VALUES (
                ${dwrId}, ${item.item_name || 'Unknown Item'}, ${quantity}, 
                ${item.unit || 'EA'}, ${item.location_description || 'Location not specified'}, 
                ${item.latitude ? parseFloat(item.latitude) : null}, 
                ${item.longitude ? parseFloat(item.longitude) : null},
                ${item.duration_hours ? parseFloat(item.duration_hours) : null}, 
                ${item.notes || null}, ${i}, ${validBidItemId}, ${validProjectBidItemId},
                CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
              )
            `;
            console.log(`Inserted item ${i + 1}: ${item.item_name}`);
          } catch (error) {
            console.error(`Failed to insert item ${i}:`, error.message);
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
    } else if (error.message.includes('Invalid')) {
      errorMessage = error.message;
      statusCode = 400;
    } else if (error.message.includes('not found')) {
      errorMessage = error.message;
      statusCode = 400;
    }
    
    return {
      statusCode: statusCode,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: errorMessage,
        details: error.message
      })
    };
  }
}

// FIXED: Installed quantities handler
async function handleInstalledQuantities(event, headers, method) {
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
    const projectId = params.project_id;
    const startDate = params.start_date;
    const endDate = params.end_date;

    let query = sql`
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
        di.id::text as id,
        pbi.id::text as project_bid_item_id,
        pbi.id::text as project_bid_item_uuid
      FROM dwr_items di
      JOIN daily_work_reports dwr ON di.dwr_id = dwr.id
      LEFT JOIN bid_items bi ON di.bid_item_id = bi.id
      LEFT JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
      WHERE 1=1
    `;

    // Add filters
    const conditions = [];
    if (projectId) {
      conditions.push(sql`dwr.project_id = ${projectId}`);
    }
    if (startDate) {
      conditions.push(sql`dwr.work_date >= ${startDate}`);
    }
    if (endDate) {
      conditions.push(sql`dwr.work_date <= ${endDate}`);
    }

    // Combine conditions
    for (const condition of conditions) {
      query = sql`${query} AND ${condition}`;
    }

    query = sql`${query} ORDER BY dwr.work_date DESC, di.item_name`;

    const results = await query;

    // Format results
    const formattedQuantities = results.map(item => ({
      id: item.id,
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

// FIXED: Handle other endpoints with consistent UUID handling
async function handleForemen(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'foreman_id');
          const foremen = await sql`
            SELECT id::text as id, name, email, phone, is_active, hourly_rate, created_at, updated_at
            FROM foremen WHERE id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(foremen[0] || null)
          };
        } else {
          const foremen = await sql`
            SELECT id::text as id, name, email, phone, is_active, hourly_rate, created_at, updated_at
            FROM foremen WHERE is_active = true ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(foremen)
          };
        }
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

async function handleLaborers(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'laborer_id');
          const laborers = await sql`
            SELECT id::text as id, name, email, phone, is_active, hourly_rate, employee_id, created_at, updated_at
            FROM laborers WHERE id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(laborers[0] || null)
          };
        } else {
          const laborers = await sql`
            SELECT id::text as id, name, email, phone, is_active, hourly_rate, employee_id, created_at, updated_at
            FROM laborers WHERE is_active = true ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(laborers)
          };
        }
      } catch (error) {
        console.error('Error fetching laborers:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch laborers' })
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

async function handleEquipment(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'equipment_id');
          const equipment = await sql`
            SELECT id::text as id, name, type, active, hourly_rate, created_at, updated_at
            FROM equipment WHERE id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(equipment[0] || null)
          };
        } else {
          const equipment = await sql`
            SELECT id::text as id, name, type, active, hourly_rate, created_at, updated_at
            FROM equipment WHERE active = true ORDER BY name
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(equipment)
          };
        }
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

async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'project_id');
          const projects = await sql`
            SELECT p.id::text as id, p.name, p.project_code, p.active, p.retainage, 
                   p.site_location, p.county, p.created_at, p.updated_at,
                   p.general_contractor_id::text as general_contractor_id,
                   gc.name as contractor_name
            FROM projects p
            LEFT JOIN general_contractors gc ON p.general_contractor_id = gc.id
            WHERE p.id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projects[0] || null)
          };
        } else {
          const projects = await sql`
            SELECT p.id::text as id, p.name, p.project_code, p.active, p.retainage, 
                   p.site_location, p.county, p.created_at, p.updated_at,
                   p.general_contractor_id::text as general_contractor_id,
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
      SELECT p.id::text as id, p.name, p.project_code, p.active, p.retainage, 
             p.site_location, p.county, p.created_at, p.updated_at,
             p.general_contractor_id::text as general_contractor_id,
             gc.name as contractor_name, gc.contact_person, gc.email as contractor_email, gc.phone as contractor_phone
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

async function handleGeneralContractors(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'contractor_id');
          const contractors = await sql`
            SELECT id::text as id, name, contact_person, email, phone, address, 
                   city, state, zip, is_active, created_at, updated_at 
            FROM general_contractors WHERE id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(contractors[0] || null)
          };
        } else {
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

async function handleBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'bid_item_id');
          const bidItems = await sql`
            SELECT id::text as id, item_code, item_name, description, default_unit, 
                   category, is_active, material_cost, created_at, updated_at
            FROM bid_items WHERE id = ${validId}
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(bidItems[0] || null)
          };
        } else {
          const bidItems = await sql`
            SELECT id::text as id, item_code, item_name, description, default_unit, 
                   category, is_active, material_cost, created_at, updated_at
            FROM bid_items WHERE is_active = true ORDER BY item_code
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(bidItems)
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

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

async function handleProjectBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        const params = event.queryStringParameters || {};
        const projectId = params.project_id;

        if (id) {
          const validId = validateAndConvertId(id, 'project_bid_item_id');
          const projectBidItems = await sql`
            SELECT pbi.id::text as id, pbi.project_id::text as project_id, pbi.bid_item_id::text as bid_item_id,
                   pbi.rate, pbi.material_cost, pbi.unit, pbi.notes, pbi.is_active, 
                   pbi.contract_quantity, pbi.created_at, pbi.updated_at,
                   bi.item_code, bi.item_name, bi.category, bi.description
            FROM project_bid_items pbi
            LEFT JOIN bid_items bi ON pbi.bid_item_id = bi.id
            WHERE pbi.id = ${validId} AND pbi.is_active = true
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projectBidItems[0] || null)
          };
        } else if (projectId) {
          const validProjectId = validateAndConvertId(projectId, 'project_id');
          const projectBidItems = await sql`
            SELECT pbi.id::text as id, pbi.project_id::text as project_id, pbi.bid_item_id::text as bid_item_id,
                   pbi.rate, pbi.material_cost, pbi.unit, pbi.notes, pbi.is_active, 
                   pbi.contract_quantity, pbi.created_at, pbi.updated_at,
                   bi.item_code, bi.item_name, bi.category, bi.description
            FROM project_bid_items pbi
            LEFT JOIN bid_items bi ON pbi.bid_item_id = bi.id
            WHERE pbi.project_id = ${validProjectId} AND pbi.is_active = true
            ORDER BY bi.item_code
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projectBidItems)
          };
        } else {
          const projectBidItems = await sql`
            SELECT pbi.id::text as id, pbi.project_id::text as project_id, pbi.bid_item_id::text as bid_item_id,
                   pbi.rate, pbi.material_cost, pbi.unit, pbi.notes, pbi.is_active, 
                   pbi.contract_quantity, pbi.created_at, pbi.updated_at,
                   bi.item_code, bi.item_name, bi.category, bi.description,
                   p.name as project_name
            FROM project_bid_items pbi
            LEFT JOIN bid_items bi ON pbi.bid_item_id = bi.id
            LEFT JOIN projects p ON pbi.project_id = p.id
            WHERE pbi.is_active = true
            ORDER BY p.name, bi.item_code
          `;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(projectBidItems)
          };
        }
      } catch (error) {
        console.error('Error fetching project bid items:', error);
        return {
          statusCode: 500,
          headers,
          body: JSON.stringify({ error: 'Failed to fetch project bid items' })
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

// Stub implementations for remaining handlers
async function handlePOData(event, headers, method) {
  return { statusCode: 501, headers, body: JSON.stringify({ error: 'Not implemented' }) };
}

async function handlePOSubmit(event, headers, method) {
  return { statusCode: 501, headers, body: JSON.stringify({ error: 'Not implemented' }) };
}

async function handlePORequests(event, headers, method, id) {
  return { statusCode: 501, headers, body: JSON.stringify({ error: 'Not implemented' }) };
}

async function handleVendors(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        if (id) {
          const validId = validateAndConvertId(id, 'vendor_id');
          const vendors = await sql`SELECT * FROM vendors WHERE id = ${validId}`;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(vendors[0] || null)
          };
        } else {
          const vendors = await sql`SELECT * FROM vendors WHERE active = true ORDER BY name`;
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
          const validId = validateAndConvertId(id, 'authorized_user_id');
          const users = await sql`SELECT * FROM authorized_users WHERE id = ${validId}`;
          return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users[0] || null)
          };
        } else {
          const users = await sql`SELECT * FROM authorized_users WHERE active = true ORDER BY name`;
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

async function handleUsers(event, headers, method, id, action) {
  const { role, userId } = event.auth || {};

  // Handle toggle action
  if (action === 'toggle' && id) {
    if (!requireRole(role, ['admin'])) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: 'Admin access required' })
      };
    }

    try {
      const validId = validateAndConvertId(id, 'user_id');
      
      const currentUser = await sql`SELECT is_active, username FROM users WHERE id = ${validId}`;
      if (currentUser.length === 0) {
        return {
          statusCode: 404,
          headers,
          body: JSON.stringify({ error: 'User not found' })
        };
      }

      const newStatus = !currentUser[0].is_active;
      
      await sql`UPDATE users SET is_active = ${newStatus}, updated_at = CURRENT_TIMESTAMP WHERE id = ${validId}`;

      await logUserActivity(userId, `USER_${newStatus ? 'ENABLED' : 'DISABLED'}`, {
        target_user_id: validId,
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
          const validId = validateAndConvertId(id, 'user_id');
          const users = await sql`
            SELECT id::text as id, username, email, first_name, last_name, role, 
                   is_active, last_login, failed_login_attempts, created_at, updated_at
            FROM users WHERE id = ${validId}
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
            FROM users ORDER BY created_at DESC
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

async function handleBillingData(event, headers, method) {
  if (method !== 'GET') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

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

    // Get billing data
    const RETAINAGE_PERCENTAGE = 0.10;
    const MOH_RATE_PERCENTAGE = 0.15;

    const billingData = await sql`
      SELECT 
        p.name as project_name,
        dwr.work_date,
        bi.item_code,
        bi.item_name,
        di.quantity,
        pbi.rate,
        pbi.material_cost,
        (di.quantity * pbi.rate) as extension
      FROM dwr_items di
      JOIN daily_work_reports dwr ON di.dwr_id = dwr.id
      JOIN projects p ON dwr.project_id = p.id
      LEFT JOIN bid_items bi ON di.bid_item_id = bi.id
      LEFT JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
      WHERE dwr.work_date >= ${startDate} 
        AND dwr.work_date <= ${endDate}
        AND p.active = true
      ORDER BY p.name, dwr.work_date, bi.item_code
    `;

    // Process data by projects
    const projects = new Map();
    let grandTotals = {
      extension: 0,
      mohAmount: 0,
      lessMoh: 0,
      retainage: 0,
      billableAmount: 0
    };

    billingData.forEach(row => {
      const projectName = row.project_name;
      
      if (!projects.has(projectName)) {
        projects.set(projectName, {
          name: projectName,
          items: new Map(),
          totals: {
            extension: 0,
            mohAmount: 0,
            lessMoh: 0,
            retainage: 0,
            billableAmount: 0
          }
        });
      }

      const project = projects.get(projectName);
      const itemKey = `${row.item_code}-${row.item_name}`;
      
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
      const qty = parseFloat(row.quantity) || 0;
      const rate = parseFloat(row.rate) || 0;
      const extension = qty * rate;
      
      const mohAmount = extension * MOH_RATE_PERCENTAGE;
      const lessMoh = extension - mohAmount;
      const retainageAmount = extension * RETAINAGE_PERCENTAGE;
      const billableAmount = lessMoh - retainageAmount;

      item.entries.push({
        workDate: row.work_date ? new Date(row.work_date).toISOString().split('T')[0] : '',
        quantity: qty,
        rate: rate,
        extension: extension,
        mohAmount: mohAmount,
        lessMoh: lessMoh,
        retainage: retainageAmount,
        billableAmount: billableAmount
      });

      item.totalQty += qty;
      item.totals.extension += extension;
      item.totals.mohAmount += mohAmount;
      item.totals.lessMoh += lessMoh;
      item.totals.retainage += retainageAmount;
      item.totals.billableAmount += billableAmount;

      project.totals.extension += extension;
      project.totals.mohAmount += mohAmount;
      project.totals.lessMoh += lessMoh;
      project.totals.retainage += retainageAmount;
      project.totals.billableAmount += billableAmount;

      grandTotals.extension += extension;
      grandTotals.mohAmount += mohAmount;
      grandTotals.lessMoh += lessMoh;
      grandTotals.retainage += retainageAmount;
      grandTotals.billableAmount += billableAmount;
    });

    // Convert maps to arrays for JSON response
    const projectsArray = Array.from(projects.values()).map(project => ({
      ...project,
      items: Array.from(project.items.values())
    }));

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        projects: projectsArray,
        grandTotals: grandTotals,
        dateRange: { startDate, endDate },
        summary: {
          totalProjects: projectsArray.length,
          totalItems: billingData.length,
          retainagePercentage: RETAINAGE_PERCENTAGE * 100,
          mohPercentage: MOH_RATE_PERCENTAGE * 100
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
