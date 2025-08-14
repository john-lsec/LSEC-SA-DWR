// netlify/functions/api.js - Updated for Material Cost
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
            pbi.material_cost,
            pbi.unit,
            CASE 
              WHEN pbi.material_cost > 0 
              THEN ROUND(((pbi.rate - pbi.material_cost) / pbi.material_cost * 100), 2)
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
          SELECT id, item_code, item_name, category, description, material_cost 
          FROM bid_items 
          WHERE is_active = true 
          ORDER BY item_code
        `;
        console.log('Bid items loaded:', bidItems.length);
        return { statusCode: 200, headers, body: JSON.stringify(bidItems) };
      }
