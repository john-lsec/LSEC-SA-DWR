const { neon } = require('@neondatabase/serverless');

exports.handler = async (event, context) => {
    const headers = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Content-Type': 'application/json'
    };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    if (event.httpMethod !== 'GET') {
        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    const diagnostics = {
        timestamp: new Date().toISOString(),
        environment: {
            DATABASE_URL: process.env.DATABASE_URL ? 'SET' : 'NOT SET',
            JWT_SECRET: process.env.JWT_SECRET ? 'SET' : 'NOT SET',
            NODE_ENV: process.env.NODE_ENV || 'not set'
        },
        database: {
            connection: 'unknown',
            users_table: 'unknown',
            user_count: 0,
            sample_users: []
        }
    };

    try {
        // Test database connection
        if (!process.env.DATABASE_URL) {
            diagnostics.database.connection = 'NO DATABASE_URL';
            diagnostics.database.error = 'DATABASE_URL environment variable is not set';
        } else {
            const sql = neon(process.env.DATABASE_URL);
            
            // Test basic connection
            await sql`SELECT 1 as test`;
            diagnostics.database.connection = 'SUCCESS';
            
            // Test users table
            try {
                const userCount = await sql`SELECT COUNT(*) as count FROM users`;
                diagnostics.database.user_count = parseInt(userCount[0].count);
                
                // Get sample users (without passwords)
                const sampleUsers = await sql`
                    SELECT username, email, role, is_active, last_login, failed_login_attempts
                    FROM users 
                    ORDER BY created_at DESC 
                    LIMIT 3
                `;
                diagnostics.database.sample_users = sampleUsers;
                
                diagnostics.database.users_table = 'EXISTS';
                
            } catch (tableError) {
                diagnostics.database.users_table = 'ERROR';
                diagnostics.database.table_error = tableError.message;
            }
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(diagnostics, null, 2)
        };

    } catch (error) {
        diagnostics.database.connection = 'FAILED';
        diagnostics.database.error = error.message;
        
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify(diagnostics, null, 2)
        };
    }
};
