const { neon } = require('@netlify/neon');

exports.handler = async (event, context) => {
  const path = event.path.replace('/.netlify/functions/api/', '').replace('/.netlify/functions/api', '');
  
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Content-Type': 'application/json'
  };
  
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }
  
  try {
    const sql = neon(process.env.NETLIFY_DATABASE_URL);
    
    // Parse query parameters
    const params = event.queryStringParameters || {};
    
    // Route handling
    switch (path) {
      case '':
      case 'foremen':
        const foremen = await sql`SELECT id, name FROM foremen WHERE is_active = true ORDER BY name`;
        return { statusCode: 200, headers, body: JSON.stringify(foremen) };
        
      case 'laborers':
        const laborers = await sql`SELECT id, name FROM laborers WHERE is_active = true ORDER BY name`;
        return { statusCode: 200, headers, body: JSON.stringify(laborers) };
        
      case 'projects':
        const projects = await sql`SELECT id, name FROM projects WHERE is_active = true ORDER BY name`;
        return { statusCode: 200, headers, body: JSON.stringify(projects) };
        
      case 'equipment':
        const type = params.type;
        if (!type) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Type required' }) };
        }
        const equipment = await sql`SELECT id, name FROM equipment WHERE equipment_type = ${type} AND is_active = true ORDER BY name`;
        return { statusCode: 200, headers, body: JSON.stringify(equipment) };
        
      case 'project-items':
        const projectId = params.project_id;
        if (!projectId) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Project ID required' }) };
        }
        const items = await sql`SELECT item_name, unit FROM project_items WHERE project_id = ${projectId} AND is_active = true ORDER BY item_name`;
        return { statusCode: 200, headers, body: JSON.stringify(items) };
        
      case 'submit-dwr':
        if (event.httpMethod !== 'POST') {
          return { statusCode: 405, headers, body: JSON.stringify({ error: 'POST required' }) };
        }
        
        const data = JSON.parse(event.body);
        const {
          work_date, foreman_id, project_id, arrival_time, departure_time,
          truck_id, trailer_id, billable_work, maybe_explanation, per_diem,
          laborers, machines, items
        } = data;
        
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
        
        // Insert crew members
        if (laborers?.length) {
          for (const laborerId of laborers) {
            await sql`INSERT INTO dwr_crew_members (dwr_id, laborer_id) VALUES (${dwrId}, ${laborerId})`;
          }
        }
        
        // Insert machines  
        if (machines?.length) {
          for (const machineId of machines) {
            await sql`INSERT INTO dwr_machines (dwr_id, machine_id) VALUES (${dwrId}, ${machineId})`;
          }
        }
        
        // Insert items
        if (items?.length) {
          for (let i = 0; i < items.length; i++) {
            const item = items[i];
            await sql`
              INSERT INTO dwr_items (
                dwr_id, item_name, quantity, unit, location_description,
                latitude, longitude, duration_hours, notes, item_index
              ) VALUES (
                ${dwrId}, ${item.item_name}, ${item.quantity}, ${item.unit},
                ${item.location_description}, ${item.latitude || null}, 
                ${item.longitude || null}, ${item.duration_hours}, 
                ${item.notes || null}, ${i + 1}
              )
            `;
          }
        }
        
        return { 
          statusCode: 200, 
          headers, 
          body: JSON.stringify({ 
            success: true, 
            id: dwrId, 
            message: 'DWR submitted successfully' 
          })
        };
        
      default:
        return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found' }) };
    }
    
  } catch (error) {
    console.error('API Error:', error);
    return { 
      statusCode: 500, 
      headers, 
      body: JSON.stringify({ error: error.message })
    };
  }
};
