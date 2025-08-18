// netlify/functions/api/po-submit.js
const { neon } = require('@neondatabase/serverless');
const jwt = require('jsonwebtoken');

// JWT secret - should match your auth function
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

exports.handler = async (event, context) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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

  // Check for authentication token
  const authHeader = event.headers.authorization || event.headers.Authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'No authentication token provided' })
    };
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  try {
    // Verify JWT token
    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Token is valid, proceed with processing the PO
    const sql = neon(process.env.DATABASE_URL);
    const data = JSON.parse(event.body);
    
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
    
    // Generate PO number with timestamp and random component
    const timestamp = Date.now().toString().slice(-6);
    const random = Math.floor(Math.random() * 100).toString().padStart(2, '0');
    const poNumber = `PO-${timestamp}${random}`;
    
    // Insert PO request with user information from token
    const result = await sql`
      INSERT INTO po_requests (
        po_number, 
        requester_name, 
        requester_phone, 
        vendor,
        project, 
        quoted_price, 
        taxable, 
        material_requested,
        status, 
        created_by,
        created_at
      ) VALUES (
        ${poNumber}, 
        ${data.name}, 
        ${data.phone}, 
        ${data.vendor},
        ${data.project}, 
        ${data.quotedPrice}, 
        ${data.taxable},
        ${data.materialRequested || null}, 
        'PENDING',
        ${decoded.userId || decoded.username},
        CURRENT_TIMESTAMP
      ) RETURNING *
    `;
    
    // Check if auto-approval should happen (you can customize this logic)
    // For example, auto-approve if amount is less than $500
    let authorized = false;
    const amount = parseFloat(data.quotedPrice.replace(/[^0-9.-]/g, ''));
    if (!isNaN(amount) && amount < 500) {
      authorized = true;
      
      // Update status to approved
      await sql`
        UPDATE po_requests 
        SET status = 'APPROVED', 
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
        poNumber: poNumber,
        authorized: authorized,
        message: authorized 
          ? 'PO request automatically approved' 
          : 'PO request submitted for approval'
      })
    };
  } catch (error) {
    console.error('Error:', error);
    
    // Check if it's a JWT error
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid or expired token' })
      };
    }
    
    // Database or other error
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
