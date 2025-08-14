// netlify/functions/api.js - Debug Version
const { neon } = require('@neondatabase/serverless');

exports.handler = async (event, context) => {
  // Add comprehensive logging
  console.log('Function invoked with path:', event.path);
  console.log('HTTP Method:', event.httpMethod);
  console.log('Environment variables check:', {
    hasDbUrl: !!process.env.NETLIFY_DATABASE_URL,
    dbUrlLength: process.env.NETLIFY_DATABASE_URL?.length || 0
  });

  const path = event.path.replace('/.netlify/functions/api/', '').replace('/.netlify/functions/api', '');
  console.log('Parsed path:', path);
  
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS, DELETE',
    'Content-Type': 'application/json'
  };
  
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    console.log('Handling CORS preflight');
    return { statusCode: 200, headers, body: '' };
  }
  
  try {
    // Test database connection first
    if (!process.env.NETLIFY_DATABASE_URL) {
      console.error('NETLIFY_DATABASE_URL environment variable is not set');
      return { 
        statusCode: 500, 
        headers, 
        body: JSON.stringify({ error: 'Database configuration missing' })
      };
    }

    console.log('Attempting to connect to database...');
    const sql = neon(process.env.NETLIFY_DATABASE_URL);
    
    // Test connection with a simple query
    console.log('Testing database connection...');
    const testResult = await sql`SELECT 1 as test`;
    console.log('Database connection successful:', testResult);
    
    // Parse query parameters
    const params = event.queryStringParameters || {};
    console.log('Query parameters:', params);
    
    // Add a test endpoint
    if (path === 'test') {
      return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify({ 
          message: 'API is working!', 
          timestamp: new Date().toISOString(),
          path: path,
          method: event.httpMethod
        })
      };
    }
    
    // Route handling based on path
    switch (path) {
      case '':
      case 'foremen': {
        console.log('Loading foremen...');
        const foremen = await sql`SELECT id, name FROM foremen WHERE is_active = true ORDER BY name`;
        console.log('Foremen loaded:', foremen.length);
        return { statusCode: 200, headers, body: JSON.stringify(foremen) };
      }
        
      case 'laborers': {
        console.log('Loading laborers...');
        const laborers = await sql`SELECT id, name FROM laborers WHERE is_active = true ORDER BY name`;
        console.log('Laborers loaded:', laborers.length);
        return { statusCode: 200, headers, body: JSON.stringify(laborers) };
      }
        
      case 'projects': {
        console.log('Loading projects...');
        const projects = await sql`SELECT id, name FROM projects WHERE is_active = true ORDER BY name`;
        console.log('Projects loaded:', projects.length);
        return { statusCode: 200, headers, body: JSON.stringify(projects) };
      }
        
      case 'equipment': {
        const type = params.type;
        console.log('Loading equipment, type:', type);
        if (!type) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Type required' }) };
        }
        const equipment = await sql`SELECT id, name FROM equipment WHERE equipment_type = ${type} AND is_active = true ORDER BY name`;
        console.log('Equipment loaded:', equipment.length);
        return { statusCode: 200, headers, body: JSON.stringify(equipment) };
      }

      case 'project-bid-items': {
        const bidProjectId = params.project_id;
        console.log('Loading project bid items for project:', bidProjectId);
        if (!bidProjectId) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Project ID required' }) };
        }
        const bidItems = await sql`
          SELECT 
            pbi.id as project_bid_item_id,
            bi.id as bid_item_id,
            bi.item_code,
            bi.item_name,
            bi.category,
            pbi.rate,
            pbi.current_cost,
            pbi.unit,
            CASE 
              WHEN pbi.current_cost > 0 
              THEN ROUND(((pbi.rate - pbi.current_cost) / pbi.current_cost * 100), 2)
              ELSE NULL 
            END as markup_percentage
          FROM project_bid_items pbi
          JOIN bid_items bi ON pbi.bid_item_id = bi.id
          WHERE pbi.project_id = ${bidProjectId} 
            AND pbi.is_active = true
          ORDER BY bi.item_code
        `;
        console.log('Project bid items loaded:', bidItems.length);
        return { statusCode: 200, headers, body: JSON.stringify(bidItems) };
      }

      case 'bid-items': {
        console.log('Loading all bid items...');
        const bidItems = await sql`
          SELECT id, item_code, item_name, category, description 
          FROM bid_items 
          WHERE is_active = true 
          ORDER BY item_code
        `;
        console.log('Bid items loaded:', bidItems.length);
        return { statusCode: 200, headers, body: JSON.stringify(bidItems) };
      }
      
      case 'add-project-bid-item': {
        if (event.httpMethod !== 'POST') {
          return { statusCode: 405, headers, body: JSON.stringify({ error: 'POST required' }) };
        }
        
        console.log('Adding project bid item...');
        const data = JSON.parse(event.body);
        const { project_id, bid_item_id, rate, current_cost, unit } = data;
        
        // Validate required fields
        if (!project_id || !bid_item_id || rate === undefined || current_cost === undefined || !unit) {
          return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ error: 'Missing required fields' }) 
          };
        }
        
        // Insert project bid item
        const [projectBidItem] = await sql`
          INSERT INTO project_bid_items (
            project_id, bid_item_id, rate, current_cost, unit, is_active
          ) VALUES (
            ${project_id}, ${bid_item_id}, ${rate}, ${current_cost}, ${unit}, true
          ) RETURNING id
        `;
        
        console.log('Project bid item added with ID:', projectBidItem.id);
        return { 
          statusCode: 200, 
          headers, 
          body: JSON.stringify({ 
            success: true, 
            id: projectBidItem.id,
            message: 'Project bid item added successfully' 
          }) 
        };
      }

      case 'submit-dwr': {
        if (event.httpMethod !== 'POST') {
          return { statusCode: 405, headers, body: JSON.stringify({ error: 'POST required' }) };
        }
        
        console.log('Submitting DWR...');
        const data = JSON.parse(event.body);
        const {
          work_date, foreman_id, project_id, arrival_time, departure_time,
          truck_id, trailer_id, billable_work, maybe_explanation, per_diem,
          laborers, machines, items
        } = data;
        
        console.log('DWR data:', { work_date, foreman_id, project_id, billable_work });
        
        // Insert main DWR
        const [dwr] = await sql`
          INSERT INTO daily_work_reports (
            work_date, foreman_id, project_id, arrival_time, departure_time,
            truck_id, trailer_id, billable_work, maybe_explanation, per_diem
          ) VALUES (
            ${work_date}, ${foreman_id}, ${project_id}, ${arrival_time}, ${departure_time},
            ${truck_id || null}, ${trailer_id || null}, ${billable_work}, 
            ${maybe_explanation || null}, ${per_diem}
          ) RETURNING id
        `;
        
        const dwrId = dwr.id;
        console.log('DWR created with ID:', dwrId);
        
        // Insert crew members
        if (laborers?.length) {
          console.log('Inserting crew members:', laborers.length);
          for (const laborerId of laborers) {
            await sql`INSERT INTO dwr_crew_members (dwr_id, laborer_id) VALUES (${dwrId}, ${laborerId})`;
          }
        }
        
        // Insert machines  
        if (machines?.length) {
          console.log('Inserting machines:', machines.length);
          for (const machineId of machines) {
            await sql`INSERT INTO dwr_machines (dwr_id, machine_id) VALUES (${dwrId}, ${machineId})`;
          }
        }
        
        // Insert items (with bid item support)
        if (items?.length) {
          console.log('Inserting items:', items.length);
          for (let i = 0; i < items.length; i++) {
            const item = items[i];
            await sql`
              INSERT INTO dwr_items (
                dwr_id, item_name, quantity, unit, location_description,
                latitude, longitude, duration_hours, notes, item_index,
                bid_item_id, project_bid_item_id
              ) VALUES (
                ${dwrId}, ${item.item_name}, ${item.quantity}, ${item.unit},
                ${item.location_description}, ${item.latitude || null}, 
                ${item.longitude || null}, ${item.duration_hours}, 
                ${item.notes || null}, ${i + 1},
                ${item.bid_item_id || null}, ${item.project_bid_item_id || null}
              )
            `;
          }
        }
        
        console.log('DWR submission complete');
        return { 
          statusCode: 200, 
          headers, 
          body: JSON.stringify({ 
            success: true, 
            id: dwrId, 
            message: 'DWR submitted successfully' 
          })
        };
      }
        
      default: {
        // Check if the path starts with "update-project-bid-item/"
        if (path.startsWith('update-project-bid-item/')) {
          const projectBidItemId = path.replace('update-project-bid-item/', '');
          
          if (!projectBidItemId) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'Item ID required' }) };
          }
          
          if (event.httpMethod !== 'PUT') {
            return { statusCode: 405, headers, body: JSON.stringify({ error: 'PUT required' }) };
          }
          
          console.log('Updating project bid item:', projectBidItemId);
          const data = JSON.parse(event.body);
          const { rate, current_cost, unit } = data;
          
          // Validate required fields
          if (rate === undefined || current_cost === undefined || !unit) {
            return { 
              statusCode: 400, 
              headers, 
              body: JSON.stringify({ error: 'Missing required fields' }) 
            };
          }
          
          // Update project bid item
          await sql`
            UPDATE project_bid_items 
            SET rate = ${rate}, current_cost = ${current_cost}, unit = ${unit}
            WHERE id = ${projectBidItemId}
          `;
          
          console.log('Project bid item updated successfully');
          return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
              success: true, 
              message: 'Project bid item updated successfully' 
            }) 
          };
        }
        
        // Check if the path starts with "delete-project-bid-item/"
        if (path.startsWith('delete-project-bid-item/')) {
          const projectBidItemId = path.replace('delete-project-bid-item/', '');
          
          if (!projectBidItemId) {
            return { statusCode: 400, headers, body: JSON.stringify({ error: 'Item ID required' }) };
          }
          
          if (event.httpMethod !== 'DELETE') {
            return { statusCode: 405, headers, body: JSON.stringify({ error: 'DELETE required' }) };
          }
          
          console.log('Deleting project bid item:', projectBidItemId);
          
          // Soft delete project bid item
          await sql`
            UPDATE project_bid_items 
            SET is_active = false
            WHERE id = ${projectBidItemId}
          `;
          
          console.log('Project bid item deleted successfully');
          return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
              success: true, 
              message: 'Project bid item deleted successfully' 
            }) 
          };
        }
        
        console.log('Unknown path:', path);
        return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found' }) };
      }
    }
    
  } catch (error) {
    console.error('API Error:', error);
    console.error('Error stack:', error.stack);
    return { 
      statusCode: 500, 
      headers, 
      body: JSON.stringify({ 
        error: error.message,
        details: error.stack?.split('\n')[0] // First line of stack for debugging
      })
    };
  }
};
