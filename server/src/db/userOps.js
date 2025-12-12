// User DB operations for LDAP login
import pool from './index.js';
import { v4 as uuidv4 } from 'uuid';

/**
 * Get a user by their username with all related data
 * @param {string} username - The username to look up
 * @returns {Promise<object|null>} The user object with roles or null if not found
 * @throws {Error} If there's a database error or invalid input
 */
async function getUserByUsername(username, dbClient = null) {
  if (!username || typeof username !== 'string') {
    throw new Error('Username must be a non-empty string');
  }

  const client = dbClient || await pool.connect();
  const releaseNeeded = !dbClient;
  try {
    // Get user with all basic info
    const { rows } = await client.query(
      `SELECT 
        u.id, u.username, u.email, u.is_active as "isActive", 
        u.display_name as "displayName",
        u.created_at as "createdAt", u.updated_at as "updatedAt"
      FROM users u
      WHERE u.username = $1`,
      [username]
    );
    
    if (!rows[0]) {
      console.warn(`User not found with username: ${username}`);
      return null;
    }
    
    // Get user's roles
    const { rows: roleRows } = await client.query(
      `SELECT r.name 
       FROM roles r 
       JOIN user_roles ur ON r.id = ur.role_id 
       WHERE ur.user_id = $1`,
      [rows[0].id]
    );
    
    // Format the user object with all data
    const user = {
      ...rows[0],
      id: rows[0].id.toString(),
      user_id: rows[0].id.toString(),
      roles: roleRows.map(r => r.name)
    };
    
    // Add isAdmin flag for convenience
    user.isAdmin = user.roles.includes('admin');
    
    return user;
  } catch (error) {
    console.error('Database error in getUserByUsername:', {
      error: error.message,
      username,
      stack: error.stack
    });
    throw new Error('Failed to retrieve user from database');
  } finally {
    // IMPORTANT: release client only if we created it here
    if (releaseNeeded) client.release();
  }
}

/**
 * Create or update a user with the specified role
 * @param {Object} userData - User data
 * @param {string} userData.username - The username (required)
 * @param {string} userData.email - The user's email (required)
 * @param {string} [userData.roleName='user'] - The role to assign (defaults to 'user')
 * @param {string} [userData.displayName] - The user's display name
 * @returns {Promise<string>} The created/updated user's ID
 * @throws {Error} If there's a database error or role not found
 */
async function createUserWithRole({ 
  username, 
  email, 
  roleName = 'user',
  displayName = null
}, dbClient = null) {
  if (!username || !email) {
    throw new Error('Username and email are required');
  }

  const client = dbClient || await pool.connect();
  const ownClient = !dbClient;
  try {
    if (ownClient) await client.query('BEGIN');
    
    // Check if user already exists
    const existingUser = await getUserByUsername(username, client);
    let userId;
    
    if (existingUser) {
      // Update existing user
      userId = existingUser.id;
      
      const updateFields = [];
      const updateValues = [];
      let paramCount = 1;
      
      // Only update fields that are provided and exist in the schema
      if (email) {
        updateFields.push(`email = $${paramCount++}`);
        updateValues.push(email);
      }
      
      // Handle optional fields
      if (typeof displayName !== 'undefined') {
        updateFields.push(`display_name = $${paramCount++}`);
        updateValues.push(displayName);
      }
      
      // Always update the timestamp
      updateFields.push(`updated_at = NOW()`);
      
      if (updateFields.length > 0) {
        const query = `
          UPDATE users 
          SET ${updateFields.join(', ')}
          WHERE id = $${paramCount}
          RETURNING id`;
          
        await client.query(query, [...updateValues, userId]);
      }
    } else {
      // Create new user with only the fields that exist in the schema
      userId = uuidv4();
      // Insert new user
      const insertQuery = `
        INSERT INTO users (
          username, email, 
          display_name,
          created_at, updated_at
        )
        VALUES ($1, $2, $3, NOW(), NOW())
        RETURNING id`;
      
      const insertResult = await client.query(insertQuery, [
        username, 
        email,
        displayName
      ]);
      userId = insertResult.rows[0].id;
    }
    
    // Get the role ID
    const { rows: roleRows } = await client.query(
      'SELECT id FROM roles WHERE name = $1', 
      [roleName]
    );
    
    if (!roleRows[0]) {
      throw new Error(`Role "${roleName}" not found`);
    }
    
    const roleId = roleRows[0].id;
    
    // Assign role to user with ON CONFLICT UPDATE to handle role changes
    await client.query(
      `INSERT INTO user_roles (user_id, role_id)
       VALUES ($1, $2)
       ON CONFLICT (user_id) 
       DO UPDATE SET role_id = EXCLUDED.role_id
       RETURNING user_id`,
      [userId, roleId]
    );
    
    if (ownClient) await client.query('COMMIT');
    return userId.toString();
    
  } catch (error) {
    if (ownClient) await client.query('ROLLBACK');
    console.error('Error in createUserWithRole:', {
      error: error.message,
      username,
      roleName,
      stack: error.stack
    });
    throw error;
  } finally {
    if (ownClient) client.release();
  }
}

/**
 * Get all roles for a specific user
 * @param {string} userId - The user's UUID
 * @returns {Promise<string[]>} Array of role names
 * @throws {Error} If there's a database error or invalid UUID format
 */
async function getUserRoles(userId) {
  // Validate UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userId)) {
    throw new Error(`Invalid UUID format: ${userId}`);
  }

  try {
    const { rows } = await pool.query(
      `SELECT r.name 
       FROM user_roles ur 
       JOIN roles r ON ur.role_id = r.id 
       WHERE ur.user_id = $1::uuid`,
      [userId]
    );
    
    return rows.map(row => row.name);
  } catch (error) {
    console.error('Database error in getUserRoles:', {
      error: error.message,
      userId,
      stack: error.stack
    });
    throw new Error('Failed to retrieve user roles');
  }
}

/**
 * Get a user by their ID
 * @param {string} userId - The user's UUID
 * @returns {Promise<object|null>} The user object or null if not found
 * @throws {Error} If there's a database error or invalid UUID format
 */
async function getUserById(userId) {
  // Validate UUID format
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(userId)) {
    throw new Error(`Invalid UUID format: ${userId}`);
  }

  try {
    // Get user with all their roles in a single query
    const { rows } = await pool.query(
      `WITH user_roles AS (
        SELECT 
          u.id, 
          u.username, 
          u.email,
          u.display_name as "displayName",
          u.created_at as "createdAt",
          u.updated_at as "updatedAt",
          COALESCE(
            json_agg(
              json_build_object(
                'id', r.id,
                'name', r.name
              )
            ) FILTER (WHERE r.id IS NOT NULL),
            '[]'::json
          ) as roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        WHERE u.id = $1::uuid
        GROUP BY u.id
      )
      SELECT 
        id,
        username,
        email,
        "displayName",
        "createdAt",
        "updatedAt",
        roles
      FROM user_roles`,
      [userId]
    );
    
    if (!rows[0]) {
      console.warn(`User not found with ID: ${userId}`);
      return null;
    }
    
    // Process the roles array
    const roles = rows[0].roles || [];
    const roleNames = roles.map(role => role.name);
    
    // Ensure consistent ID format and include roles
    const user = {
      ...rows[0],
      id: rows[0].id.toString(),
      user_id: rows[0].id.toString(),
      roles: roleNames,
      isAdmin: roleNames.includes('admin')
    };
    
    return user;
  } catch (error) {
    console.error('Database error in getUserById:', {
      error: error.message,
      userId,
      stack: error.stack
    });
    throw new Error('Failed to retrieve user from database');
  }
}

export {
  getUserByUsername,
  createUserWithRole,
  getUserRoles,
  getUserById
};
