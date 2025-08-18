const { neon } = require('@neondatabase/serverless');

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  try {
    const sql = neon(process.env.DATABASE_URL);
    const data = JSON.parse(event.body);
    
    // Generate PO number (you can customize this logic)
    const poNumber = 'PO-' + Date.now().toString().slice(-6);
    
    // Insert PO request
    const result = await sql`
      INSERT INTO po_requests (
        po_number, requester_name, requester_phone, vendor,
        project, quoted_price, taxable, material_requested,
        approved, request_date
      ) VALUES (
        ${poNumber}, ${data.name}, ${data.phone}, ${data.vendor},
        ${data.project}, ${data.quotedPrice}, ${data.taxable},
        ${data.materialRequested || null}, 'PENDING', CURRENT_TIMESTAMP
      ) RETURNING *
    `;
    
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        success: true,
        poNumber: poNumber,
        authorized: false,
        message: 'PO request submitted successfully'
      })
    };
  } catch (error) {
    console.error('Error submitting PO:', error);
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        success: false,
        error: 'Failed to submit PO request' 
      })
    };
  }
};
