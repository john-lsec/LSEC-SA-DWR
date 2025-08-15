// netlify/functions/api.js - Main API with authentication protection
// Updated to include PO system endpoints and complete authentication

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
  const segments = event.path.replace('/.netlify/functions/', '').replace('/api/', '').split('/');
  const resource = segments[0];
  const id = segments[1];
  const method = event.httpMethod;

  // Check authentication for protected endpoints
  const publicEndpoints = ['auth', 'po-data', 'po-submit', 'po-approve'];
  const isPublicEndpoint = publicEndpoints.some(endpoint => event.path.includes(endpoint));
  
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
      // Existing DWR endpoints
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
      
      // PO System endpoints
      case 'po-requests':
        return await handlePORequests(event, headers, method, id);
      
      case 'vendors':
        return await handleVendors(event, headers, method, id);
      
      case 'authorized-users':
        return await handleAuthorizedUsers(event, headers, method, id);
      
      // User management
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
      body: JSON.stringify({ error: 'Internal server error', details: error.message })
    };
  }
};

// Master Bid Items handlers with role checks
async function handleMasterBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

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

// Existing DWR handlers
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
      SELECT id, name FROM foremen 
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
}

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
      SELECT id, name FROM laborers 
      WHERE active = true 
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
      equipment = await sql`
        SELECT id, name, type FROM equipment 
        WHERE type = ${type} AND active = true 
        ORDER BY name
      `;
    } else {
      equipment = await sql`
        SELECT id, name, type FROM equipment 
        WHERE active = true 
        ORDER BY type, name
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

async function handleProjectBidItems(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      try {
        const params = event.queryStringParameters || {};
        const projectId = params.project_id;
        
        if (!projectId) {
          return {
            statusCode: 400,
            headers,
            body: JSON.stringify({ error: 'project_id parameter required' })
          };
        }
        
        const bidItems = await sql`
          SELECT 
            pbi.id as project_bid_item_id,
            pbi.project_id,
            pbi.bid_item_id,
            mbi.item_code,
            mbi.item_name,
            mbi.default_unit as unit,
            pbi.rate,
            pbi.current_cost,
            pbi.markup_percentage
          FROM project_bid_items pbi
          JOIN master_bid_items mbi ON pbi.bid_item_id = mbi.id
          WHERE pbi.project_id = ${projectId}
          ORDER BY mbi.item_code
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
          body: JSON.stringify({ error: 'Failed to fetch project bid items' })
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
      
      const newItem = await sql`
        INSERT INTO project_bid_items (
          project_id, bid_item_id, rate, current_cost, markup_percentage
        ) VALUES (
          ${createData.project_id},
          ${createData.bid_item_id},
          ${createData.rate || 0},
          ${createData.current_cost || 0},
          ${createData.markup_percentage || 0}
        )
        RETURNING *
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
      
      const updated = await sql`
        UPDATE project_bid_items
        SET 
          rate = ${updateData.rate || 0},
          current_cost = ${updateData.current_cost || 0},
          markup_percentage = ${updateData.markup_percentage || 0},
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

      await sql`
        DELETE FROM project_bid_items WHERE id = ${id}
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

async function handleDWRSubmission(event, headers, method) {
  if (method !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const data = JSON.parse(event.body);
    
    // Insert main DWR record
    const [dwr] = await sql`
      INSERT INTO daily_work_reports (
        work_date, foreman_id, project_id, arrival_time, departure_time,
        truck_id, trailer_id, billable_work, maybe_explanation, per_diem
      ) VALUES (
        ${data.work_date}, ${data.foreman_id}, ${data.project_id},
        ${data.arrival_time}, ${data.departure_time}, ${data.truck_id},
        ${data.trailer_id}, ${data.billable_work}, ${data.maybe_explanation},
        ${data.per_diem}
      ) RETURNING id
    `;
    
    // Insert laborers
    if (data.laborers && data.laborers.length > 0) {
      for (const laborerId of data.laborers) {
        await sql`
          INSERT INTO dwr_laborers (dwr_id, laborer_id)
          VALUES (${dwr.id}, ${laborerId})
        `;
      }
    }
    
    // Insert machines
    if (data.machines && data.machines.length > 0) {
      for (const machineId of data.machines) {
        await sql`
          INSERT INTO dwr_machines (dwr_id, machine_id)
          VALUES (${dwr.id}, ${machineId})
        `;
      }
    }
    
    // Insert items
    if (data.items && data.items.length > 0) {
      for (const item of data.items) {
        await sql`
          INSERT INTO dwr_items (
            dwr_id, item_name, quantity, unit, location_description,
            latitude, longitude, duration_hours, notes,
            bid_item_id, project_bid_item_id
          ) VALUES (
            ${dwr.id}, ${item.item_name}, ${item.quantity}, ${item.unit},
            ${item.location_description}, ${item.latitude}, ${item.longitude},
            ${item.duration_hours}, ${item.notes}, ${item.bid_item_id},
            ${item.project_bid_item_id}
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
        message: error.message 
      })
    };
  }
}

// PO System handlers
async function handlePORequests(event, headers, method, id) {
  const { role, userId } = event.auth || {};

  switch (method) {
    case 'GET':
      if (id) {
        const poRequest = await sql`
          SELECT * FROM po_requests WHERE id = ${id}
        `;
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(poRequest[0] || null)
        };
      } else {
        // Get query parameters for filtering
        const params = event.queryStringParameters || {};
        
        let whereConditions = [];
        let queryParams = {};
        
        if (params.status) {
          whereConditions.push('approved = ${status}');
          queryParams.status = params.status;
        }
        
        if (params.from_date) {
          whereConditions.push('request_date >= ${from_date}');
          queryParams.from_date = params.from_date;
        }
        
        if (params.to_date) {
          whereConditions.push('request_date <= ${to_date}');
          queryParams.to_date = params.to_date;
        }
        
        const whereClause = whereConditions.length > 0 
          ? 'WHERE ' + whereConditions.join(' AND ')
          : '';
        
        const poRequests = await sql`
          SELECT * FROM po_requests 
          ${whereClause}
          ORDER BY request_date DESC
        `;
        
        return {
          statusCode: 200,
          headers,
          body: JSON.stringify(poRequests)
        };
      }

    case 'PUT':
      // Only admin and manager can update PO requests
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

      const updateData = JSON.parse(event.body);
      
      const updated = await sql`
        UPDATE po_requests
        SET 
          approved = ${updateData.approved},
          approved_by = ${userId},
          approved_at = ${updateData.approved === 'YES' || updateData.approved === 'DENIED' ? new Date().toISOString() : null},
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ${id}
        RETURNING *
      `;

      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(updated[0])
      };

    default:
      return {
        statusCode: 405,
        headers,
        body: JSON.stringify({ error: 'Method not allowed' })
      };
  }
}

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

async function handleAuthorizedUsers(event, headers, method, id) {
  const { role } = event.auth || {};

  // Only admin can manage authorized users
  if (role !== 'admin') {
    return {
      statusCode: 403,
      headers,
      body: JSON.stringify({ error: 'Admin access required' })
    };
  }

  switch (method) {
    case 'GET':
      const users = await sql`
        SELECT * FROM authorized_users 
        ORDER BY email
      `;
      return {
        statusCode: 200,
        headers,
        body: JSON.stringify(users)
      };

    case 'POST':
      const userData = JSON.parse(event.body);
      const newUser = await sql`
        INSERT INTO authorized_users (email, name, phone, active)
        VALUES (${userData.email}, ${userData.name}, ${userData.phone}, ${userData.active !== false})
        RETURNING *
      `;

      return {
        statusCode: 201,
        headers,
        body: JSON.stringify(newUser[0])
      };

    case 'DELETE':
      if (!id) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ error: 'ID required for delete' })
        };
      }

      await sql`
        DELETE FROM authorized_users WHERE id = ${id}
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

// Projects handler (handles both DWR projects and PO projects)
async function handleProjects(event, headers, method, id) {
  const { role, userId } = event.auth || {};

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
          name = ${updateProjectData.name},
          project_code = ${updateProjectData.project_code || null},
          active = ${updateProjectData.active !== false},
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
