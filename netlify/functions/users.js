const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('crypto');

const sql = neon(process.env.DATABASE_URL);

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

    // Parse path to get action
    const pathParts = event.path.split('/');
    const action = pathParts[pathParts.length - 1];
    
    console.log('Users function called:', {
        method: event.httpMethod,
        path: event.path,
        action: action
    });

    try {
        // Route based on action
        switch (action) {
            case 'users':
                if (event.httpMethod === 'GET') {
                    return await getAllUsers(headers);
                }
                break;
                
            case 'unlock-all':
                if (event.httpMethod === 'POST') {
                    return await unlockAllUsers(headers);
                }
                break;
                
            case 'reset-attempts':
                if (event.httpMethod === 'POST') {
                    return await resetAllFailedAttempts(headers);
                }
                break;
                
            case 'create-admin':
                if (event.httpMethod === 'POST') {
                    return await createOrUpdateAdmin(event, headers);
                }
                break;
                
            default:
                // Handle user-specific actions like /users/{id}/unlock
                const userId = pathParts[pathParts.length - 2];
                const userAction = pathParts[pathParts.length - 1];
                
                if (userAction === 'unlock' && event.httpMethod === 'POST') {
                    return await unlockUser(userId, headers);
                }
                
                if (userAction === 'reset-password' && event.httpMethod === 'POST') {
                    return await resetUserPassword(userId, event, headers);
                }
                
                return {
                    statusCode: 404,
                    headers,
                    body: JSON.stringify({ error: 'Endpoint not found' })
                };
        }

        return {
            statusCode: 405,
            headers,
            body: JSON.stringify({ error: 'Method not allowed' })
        };

    } catch (error) {
        console.error('Users function error:', error);
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

// Get all users
async function getAllUsers(headers) {
    try {
        const users = await sql`
            SELECT 
                id::text as id,
                username,
                email,
                first_name,
                last_name,
                role,
                is_active,
                last_login,
                failed_login_attempts,
                locked_until,
                created_at,
                updated_at
            FROM users 
            ORDER BY created_at DESC
        `;

        console.log(`Found ${users.length} users`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(users)
        };

    } catch (error) {
        console.error('Error getting users:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to get users',
                details: error.message 
            })
        };
    }
}

// Unlock all users
async function unlockAllUsers(headers) {
    try {
        const result = await sql`
            UPDATE users 
            SET 
                locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE locked_until IS NOT NULL
        `;

        console.log(`Unlocked ${result.count} users`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true,
                message: `Unlocked ${result.count} users`,
                unlocked_count: result.count
            })
        };

    } catch (error) {
        console.error('Error unlocking users:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to unlock users',
                details: error.message 
            })
        };
    }
}

// Reset all failed login attempts
async function resetAllFailedAttempts(headers) {
    try {
        const result = await sql`
            UPDATE users 
            SET 
                failed_login_attempts = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE failed_login_attempts > 0
        `;

        console.log(`Reset failed attempts for ${result.count} users`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true,
                message: `Reset failed attempts for ${result.count} users`,
                reset_count: result.count
            })
        };

    } catch (error) {
        console.error('Error resetting failed attempts:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to reset failed attempts',
                details: error.message 
            })
        };
    }
}

// Create or update admin user
async function createOrUpdateAdmin(event, headers) {
    try {
        const data = JSON.parse(event.body || '{}');
        const { 
            username = 'admin', 
            email, 
            password, 
            first_name, 
            last_name,
            role = 'admin' 
        } = data;

        if (!password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Password is required' })
            };
        }

        // Hash the password
        const passwordHash = await bcrypt.hash(password, 12);

        // Check if user already exists
        const existingUsers = await sql`
            SELECT id FROM users 
            WHERE username = ${username} OR email = ${email}
            LIMIT 1
        `;

        let result;
        
        if (existingUsers.length > 0) {
            // Update existing user
            result = await sql`
                UPDATE users 
                SET 
                    password_hash = ${passwordHash},
                    first_name = ${first_name},
                    last_name = ${last_name},
                    role = ${role},
                    is_active = true,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ${existingUsers[0].id}
                RETURNING id::text as id, username, email, first_name, last_name, role
            `;
            
            console.log(`Updated existing admin user: ${username}`);
        } else {
            // Create new user
            const userId = uuidv4();
            result = await sql`
                INSERT INTO users (
                    id, username, email, password_hash, first_name, last_name, 
                    role, is_active, failed_login_attempts, created_at, updated_at
                ) VALUES (
                    ${userId}, ${username}, ${email}, ${passwordHash}, 
                    ${first_name}, ${last_name}, ${role}, true, 0, 
                    CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                ) RETURNING id::text as id, username, email, first_name, last_name, role
            `;
            
            console.log(`Created new admin user: ${username}`);
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                message: `Admin user ${existingUsers.length > 0 ? 'updated' : 'created'} successfully`,
                user: result[0],
                credentials: {
                    username: username,
                    password: password
                }
            })
        };

    } catch (error) {
        console.error('Error creating/updating admin:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to create/update admin user',
                details: error.message 
            })
        };
    }
}

// Unlock specific user
async function unlockUser(userId, headers) {
    try {
        const result = await sql`
            UPDATE users 
            SET 
                locked_until = NULL,
                failed_login_attempts = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ${userId}
            RETURNING username
        `;

        if (result.length === 0) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        console.log(`Unlocked user: ${result[0].username}`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true,
                message: `User ${result[0].username} unlocked successfully`
            })
        };

    } catch (error) {
        console.error('Error unlocking user:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to unlock user',
                details: error.message 
            })
        };
    }
}

// Reset user password
async function resetUserPassword(userId, event, headers) {
    try {
        const data = JSON.parse(event.body || '{}');
        const { password } = data;

        if (!password) {
            return {
                statusCode: 400,
                headers,
                body: JSON.stringify({ error: 'Password is required' })
            };
        }

        // Hash the new password
        const passwordHash = await bcrypt.hash(password, 12);

        const result = await sql`
            UPDATE users 
            SET 
                password_hash = ${passwordHash},
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ${userId}
            RETURNING username
        `;

        if (result.length === 0) {
            return {
                statusCode: 404,
                headers,
                body: JSON.stringify({ error: 'User not found' })
            };
        }

        console.log(`Reset password for user: ${result[0].username}`);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true,
                message: `Password reset for ${result[0].username} successfully`
            })
        };

    } catch (error) {
        console.error('Error resetting password:', error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                error: 'Failed to reset password',
                details: error.message 
            })
        };
    }
}
