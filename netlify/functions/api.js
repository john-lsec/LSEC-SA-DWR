// netlify/functions/api.js
const { neon } = require('@neondatabase/serverless');

exports.handler = async (event, context) => {
  const path = event.path.replace('/.netlify/functions/api/', '').replace('/.netlify/functions/api', '');
  
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
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
    
    // Route handling based on path
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

      case 'project-bid-items':
        const bidProjectId = params.project_id;
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
        return { statusCode: 200, headers, body: JSON.stringify(bidItems) };

      case 'bid-items':
        // Get all available bid items
        const allBidItems = await sql`
          SELECT id, item_code, item_name, description, default_unit, category
          FROM bid_items 
          WHERE is_active = true 
          ORDER BY category, item_code
        `;
        return { statusCode: 200, headers, body: JSON.stringify(allBidItems) };

      case 'project-profitability':
        const profitProjectId = params.project_id;
        const startDate = params.start_date;
        const endDate = params.end_date;
        
        if (!profitProjectId) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Project ID required' }) };
        }

        const profitability = await sql`
          SELECT * FROM get_project_profitability(
            ${profitProjectId}::UUID,
            ${startDate || null}::DATE,
            ${endDate || null}::DATE
          )
        `;
        return { statusCode: 200, headers, body: JSON.stringify(profitability[0] || {}) };

      case 'update-bid-item-cost':
        if (event.httpMethod !== 'PUT') {
          return { statusCode: 405, headers, body: JSON.stringify({ error: 'PUT required' }) };
        }
        
        const costData = JSON.parse(event.body);
        const { project_bid_item_id, new_cost, change_reason, notes, changed_by } = costData;
        
        if (!project_bid_item_id || new_cost === undefined) {
          return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing required fields' }) };
        }

        const updateResult = await sql`
          SELECT update_bid_item_cost(
            ${project_bid_item_id}::UUID,
            ${new_cost}::DECIMAL,
            ${change_reason || null},
            ${notes || null},
            ${changed_by || null}
          ) as success
        `;
        
        return { 
          statusCode: 200, 
          headers, 
          body: JSON.stringify({ 
            success: updateResult[0].success,
            message: updateResult[0].success ? 'Cost updated successfully' : 'No changes made'
          })
        };
        
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
        
        // Insert items (with bid item support)
        if (items?.length) {
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
        
        return { 
          statusCode: 200, 
          headers, 
          body: JSON.stringify({ 
            success: true, 
            id: dwrId, 
            message: 'DWR submitted successfully' 
          })
        };

      case 'dwr-summary':
        // Get DWR summaries with profit calculations
        const limit = params.limit ? parseInt(params.limit) : 50;
        const offset = params.offset ? parseInt(params.offset) : 0;
        
        const dwrSummaries = await sql`
          SELECT 
            dwr.id,
            dwr.work_date,
            f.name as foreman_name,
            p.name as project_name,
            dwr.billable_work,
            COUNT(di.id) as item_count,
            COALESCE(SUM(di.quantity * pbi.rate), 0) as total_revenue,
            COALESCE(SUM(di.quantity * pbi.current_cost), 0) as total_cost,
            COALESCE(SUM(di.quantity * (pbi.rate - pbi.current_cost)), 0) as total_profit
          FROM daily_work_reports dwr
          JOIN foremen f ON dwr.foreman_id = f.id
          JOIN projects p ON dwr.project_id = p.id
          LEFT JOIN dwr_items di ON dwr.id = di.dwr_id
          LEFT JOIN project_bid_items pbi ON di.project_bid_item_id = pbi.id
          GROUP BY dwr.id, f.name, p.name
          ORDER BY dwr.work_date DESC, dwr.submission_timestamp DESC
          LIMIT ${limit} OFFSET ${offset}
        `;
        return { statusCode: 200, headers, body: JSON.stringify(dwrSummaries) };
        
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
