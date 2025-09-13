require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'stghfs4q56h346nn57u4werhertu475eu4w5bwtr';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Postgres (Supabase) setup
const db = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: process.env.SUPABASE_DB_SSL === 'true' ? { rejectUnauthorized: false } : false
});

// Initialize database tables (run once in Supabase, not here)
// You should create tables in Supabase dashboard or with SQL migrations.

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Helper functions
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 10);
};

const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
};

// Routes

// Global variable to cache database schema state
let hasExpirationFeatures = null;

// Check if expiration features are available in database
const checkExpirationFeatures = async () => {
  if (hasExpirationFeatures !== null) return hasExpirationFeatures;
  
  try {
    const columnsCheck = await db.query(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'session_shares' 
      AND column_name IN ('expires_at', 'expiration_minutes', 'is_revoked', 'revoked_at')
    `);
    
    hasExpirationFeatures = columnsCheck.rows.length >= 4;
    console.log(`Expiration features ${hasExpirationFeatures ? 'ENABLED' : 'DISABLED'} - Database migration ${hasExpirationFeatures ? 'complete' : 'required'}`);
    return hasExpirationFeatures;
  } catch (error) {
    console.error('Error checking database schema:', error);
    hasExpirationFeatures = false;
    return false;
  }
};

// Health check
app.get('/api/health', async (req, res) => {
  const expirationEnabled = await checkExpirationFeatures();
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    features: {
      expiration: expirationEnabled,
      migration_required: !expirationEnabled
    }
  });
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }
    // Check if user already exists
    const userExists = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    // Create new user
    const passwordHash = await hashPassword(password);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, passwordHash]
    );
    const user = result.rows[0];
    const token = generateToken(user);
    res.status(201).json({
      user,
      token,
      message: 'User created successfully'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const isValidPassword = await comparePassword(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = generateToken(user);
    const userResponse = { id: user.id, email: user.email };
    res.json({
      user: userResponse,
      token,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user sessions
app.get('/api/sessions', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const result = await db.query(
      'SELECT id, domain, url, created_at, updated_at FROM sessions WHERE user_id = $1 ORDER BY updated_at DESC',
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Create session
app.post('/api/sessions', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { domain, url, cookies, userAgent } = req.body;
  if (!domain || !cookies || !Array.isArray(cookies)) {
    return res.status(400).json({ error: 'Domain and cookies are required' });
  }
  const cookiesJson = JSON.stringify(cookies);
  try {
    // Check if session for this domain already exists
    const existing = await db.query('SELECT id FROM sessions WHERE user_id = $1 AND domain = $2', [userId, domain]);
    if (existing.rows.length > 0) {
      // Update existing session
      await db.query(
        'UPDATE sessions SET url = $1, cookies = $2, user_agent = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
        [url, cookiesJson, userAgent, existing.rows[0].id]
      );
      res.json({
        id: existing.rows[0].id,
        message: 'Session updated successfully',
        cookieCount: cookies.length
      });
    } else {
      // Create new session
      const result = await db.query(
        'INSERT INTO sessions (user_id, domain, url, cookies, user_agent) VALUES ($1, $2, $3, $4, $5) RETURNING id',
        [userId, domain, url, cookiesJson, userAgent]
      );
      res.status(201).json({
        id: result.rows[0].id,
        message: 'Session saved successfully',
        cookieCount: cookies.length
      });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get sessions shared with the current user
app.get('/api/sessions/shared', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const hasExpiration = await checkExpirationFeatures();
    
    if (hasExpiration) {
      // With expiration support - filter out expired and revoked sessions
      const query = `
        SELECT 
          s.id, s.domain, s.url, s.created_at, s.updated_at,
          owner.email as ownerEmail,
          ss.shared_at,
          ss.expires_at,
          ss.expiration_minutes
        FROM sessions s
        JOIN session_shares ss ON s.id = ss.session_id
        JOIN users owner ON s.user_id = owner.id
        WHERE ss.shared_with_user_id = $1
          AND (ss.expires_at IS NULL OR ss.expires_at > NOW())
          AND (ss.is_revoked IS NULL OR ss.is_revoked = FALSE)
        ORDER BY ss.shared_at DESC
      `;
      const result = await db.query(query, [userId]);
      res.json(result.rows);
    } else {
      // Legacy mode without expiration filtering
      const query = `
        SELECT 
          s.id, s.domain, s.url, s.created_at, s.updated_at,
          owner.email as ownerEmail,
          ss.shared_at
        FROM sessions s
        JOIN session_shares ss ON s.id = ss.session_id
        JOIN users owner ON s.user_id = owner.id
        WHERE ss.shared_with_user_id = $1
        ORDER BY ss.shared_at DESC
      `;
      const result = await db.query(query, [userId]);
      res.json(result.rows);
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch shared sessions' });
  }
});

// Get specific shared session data
app.get('/api/sessions/shared/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  
  try {
    const hasExpiration = await checkExpirationFeatures();
    
    let query;
    if (hasExpiration) {
      query = `
        SELECT s.*, owner.email as ownerEmail, ss.expires_at, ss.expiration_minutes
        FROM sessions s
        JOIN session_shares ss ON s.id = ss.session_id
        JOIN users owner ON s.user_id = owner.id
        WHERE s.id = $1 AND ss.shared_with_user_id = $2
          AND (ss.expires_at IS NULL OR ss.expires_at > NOW())
          AND (ss.is_revoked IS NULL OR ss.is_revoked = FALSE)
      `;
    } else {
      query = `
        SELECT s.*, owner.email as ownerEmail
        FROM sessions s
        JOIN session_shares ss ON s.id = ss.session_id
        JOIN users owner ON s.user_id = owner.id
        WHERE s.id = $1 AND ss.shared_with_user_id = $2
      `;
    }
    
    const result = await db.query(query, [sessionId, userId]);
    const row = result.rows[0];
    if (!row) {
      return res.status(404).json({ error: 'Shared session not found, not accessible, or expired' });
    }
    try {
      const cookies = JSON.parse(row.cookies);
      const response = {
        id: row.id,
        domain: row.domain,
        url: row.url,
        cookies: cookies,
        userAgent: row.user_agent,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        ownerEmail: row.ownerEmail
      };
      
      if (hasExpiration && row.expires_at) {
        response.expiresAt = row.expires_at;
        response.expirationMinutes = row.expiration_minutes;
      }
      
      res.json(response);
    } catch (parseError) {
      console.error('JSON parse error:', parseError);
      res.status(500).json({ error: 'Corrupted session data' });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Get specific session
app.get('/api/sessions/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  console.log('sessions/:id called with sessionId:', sessionId, 'and userId:', userId);
  try {
    const result = await db.query('SELECT * FROM sessions WHERE id = $1 AND user_id = $2', [sessionId, userId]);
    const row = result.rows[0];
    if (!row) {
      return res.status(404).json({ error: 'Session Lookup: Session not found'});
    }
    try {
      const cookies = JSON.parse(row.cookies);
      res.json({
        id: row.id,
        domain: row.domain,
        url: row.url,
        cookies: cookies,
        userAgent: row.user_agent,
        createdAt: row.created_at,
        updatedAt: row.updated_at
      });
    } catch (parseError) {
      console.error('JSON parse error:', parseError);
      res.status(500).json({ error: 'Corrupted session data' });
    }
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// Share session with another user (with expiration support)
app.post('/api/sessions/:id/share', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const { email, expirationMinutes = 60 } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required' });
  }

  if (expirationMinutes < 1 || expirationMinutes > 10080) { // 1 minute to 7 days
    return res.status(400).json({ error: 'Expiration must be between 1 minute and 7 days' });
  }

  try {
    // Verify the session belongs to the current user
    const sessionResult = await db.query(
      'SELECT id FROM sessions WHERE id = $1 AND user_id = $2',
      [sessionId, userId]
    );
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found or not owned by you' });
    }

    // Find the user to share with
    const userResult = await db.query(
      'SELECT id, email FROM users WHERE email = $1',
      [email]
    );
    const targetUser = userResult.rows[0];
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found with that email address' });
    }

    if (targetUser.id === userId) {
      return res.status(400).json({ error: 'Cannot share session with yourself' });
    }

    // Check if expiration features are available
    const hasExpiration = await checkExpirationFeatures();
    
    if (hasExpiration) {
      // Calculate expiration time
      const expiresAt = new Date(Date.now() + (expirationMinutes * 60 * 1000));
      console.log(`DEBUG: Setting expires_at to: ${expiresAt}`);
      console.log(`DEBUG: Attempting to insert - sessionId: ${sessionId}, userId: ${userId}, targetUser: ${targetUser.id}`);

      try {
        // Share the session (upsert) with expiration
        const insertResult = await db.query(
          `INSERT INTO session_shares (session_id, owner_user_id, shared_with_user_id, expires_at, expiration_minutes)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (session_id, shared_with_user_id)
           DO UPDATE SET shared_at = CURRENT_TIMESTAMP, expires_at = $4, expiration_minutes = $5, is_revoked = FALSE, revoked_at = NULL
           RETURNING *`,
          [sessionId, userId, targetUser.id, expiresAt, expirationMinutes]
        );
        console.log(`DEBUG: Insert successful. Returned data:`, insertResult.rows);
        console.log(`DEBUG: Row count affected:`, insertResult.rowCount);
        
        // Double-check what's actually in the table now
        const verifyResult = await db.query(
          'SELECT * FROM session_shares WHERE session_id = $1 AND shared_with_user_id = $2 ORDER BY shared_at DESC LIMIT 1',
          [sessionId, targetUser.id]
        );
        console.log(`DEBUG: Verification - found row:`, verifyResult.rows);
        
      } catch (insertError) {
        console.error('DEBUG: Database insertion error:', insertError);
        return res.status(500).json({ error: 'Database insertion failed', details: insertError.message });
      }

      res.json({
        message: `Session shared successfully with ${email} (expires in ${expirationMinutes} minutes)`,
        sharedWith: targetUser.email,
        expiresAt: expiresAt,
        expirationMinutes: expirationMinutes,
        features: { expiration: true }
      });
    } else {
      // Use old format for compatibility
      console.log(`DEBUG: Using legacy mode for sharing`);
      const insertResult = await db.query(
        `INSERT INTO session_shares (session_id, owner_user_id, shared_with_user_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (session_id, shared_with_user_id)
         DO UPDATE SET shared_at = CURRENT_TIMESTAMP`,
        [sessionId, userId, targetUser.id]
      );
      console.log(`DEBUG: Legacy insert result:`, insertResult.rowCount, 'rows affected');

      res.json({
        message: `Session shared successfully with ${email} (permanent - no expiration)`,
        sharedWith: targetUser.email,
        features: { expiration: false },
        note: 'Run database migration to enable auto-expiration features'
      });
    }

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to share session' });
  }
});

// Unshare session (remove share)
app.delete('/api/sessions/:id/share', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required' });
  }

  try {
    const sessionResult = await db.query(
      'SELECT id FROM sessions WHERE id = $1 AND user_id = $2',
      [sessionId, userId]
    );
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found or not owned by you' });
    }

    const userResult = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    const targetUser = userResult.rows[0];
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found with that email address' });
    }

    const deleteResult = await db.query(
      `DELETE FROM session_shares
       WHERE session_id = $1 AND owner_user_id = $2 AND shared_with_user_id = $3`,
      [sessionId, userId, targetUser.id]
    );

    if (deleteResult.rowCount === 0) {
      return res.status(404).json({ error: 'Share not found' });
    }

    res.json({ message: `Session unshared from ${email}` });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to unshare session' });
  }
});

// Revoke access to all sessions for a domain (new functionality)
app.post('/api/sessions/revoke-domain-access', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { domain, email } = req.body;

  if (!domain || !email) {
    return res.status(400).json({ error: 'Domain and email are required' });
  }

  try {
    // Find the user to revoke access from
    const userResult = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    const targetUser = userResult.rows[0];
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found with that email address' });
    }

    // Revoke access to all sessions for this domain
    const revokeResult = await db.query(
      `UPDATE session_shares 
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
       WHERE owner_user_id = $1 AND shared_with_user_id = $2 
       AND session_id IN (
         SELECT id FROM sessions WHERE user_id = $1 AND domain = $3
       )
       AND is_revoked = FALSE`,
      [userId, targetUser.id, domain]
    );

    res.json({ 
      message: `Access revoked for ${email} to ${domain}`,
      sessionsRevoked: revokeResult.rowCount 
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to revoke domain access' });
  }
});

// Get list of users who have access to a specific session
app.get('/api/sessions/:id/shares', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;

  try {
    const sessionResult = await db.query(
      'SELECT id FROM sessions WHERE id = $1 AND user_id = $2',
      [sessionId, userId]
    );
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found or not owned by you' });
    }

    const hasExpiration = await checkExpirationFeatures();
    
    let sharesResult;
    if (hasExpiration) {
      sharesResult = await db.query(
        `SELECT 
           u.email,
           ss.shared_at,
           ss.expires_at,
           ss.expiration_minutes,
           ss.is_revoked,
           ss.revoked_at
         FROM session_shares ss
         JOIN users u ON ss.shared_with_user_id = u.id
         WHERE ss.session_id = $1 AND ss.owner_user_id = $2
         ORDER BY ss.shared_at DESC`,
        [sessionId, userId]
      );
    } else {
      sharesResult = await db.query(
        `SELECT 
           u.email,
           ss.shared_at
         FROM session_shares ss
         JOIN users u ON ss.shared_with_user_id = u.id
         WHERE ss.session_id = $1 AND ss.owner_user_id = $2
         ORDER BY ss.shared_at DESC`,
        [sessionId, userId]
      );
    }

    res.json(sharesResult.rows);

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch share list' });
  }
});

// Revoke a shared session
app.delete('/api/sessions/:id/share/:email', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const email = req.params.email;

  try {
    // Verify the session belongs to the current user
    const sessionResult = await db.query(
      'SELECT id FROM sessions WHERE id = $1 AND user_id = $2',
      [sessionId, userId]
    );
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ error: 'Session not found or not owned by you' });
    }

    // Find the user to revoke access from
    const userResult = await db.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    const targetUser = userResult.rows[0];
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found with that email address' });
    }

    const hasExpiration = await checkExpirationFeatures();
    
    if (hasExpiration) {
      // Mark as revoked instead of deleting
      const result = await db.query(
        `UPDATE session_shares 
         SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
         WHERE session_id = $1 AND owner_user_id = $2 AND shared_with_user_id = $3`,
        [sessionId, userId, targetUser.id]
      );
      
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Session was not shared with this user' });
      }
    } else {
      // Legacy mode - delete the share
      const result = await db.query(
        'DELETE FROM session_shares WHERE session_id = $1 AND owner_user_id = $2 AND shared_with_user_id = $3',
        [sessionId, userId, targetUser.id]
      );
      
      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Session was not shared with this user' });
      }
    }

    res.json({ message: `Session access revoked from ${email}` });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to revoke session access' });
  }
});

// Delete session
app.delete('/api/sessions/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;

  try {
    const result = await db.query(
      'DELETE FROM sessions WHERE id = $1 AND user_id = $2',
      [sessionId, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json({ message: 'Session deleted successfully' });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to delete session' });
  }
});

// ACCESS REQUEST ROUTES

// Request access to a specific URL/domain (friends-only)
app.post('/api/access-requests', authenticateToken, async (req, res) => {
  const requesterId = req.user.id;
  const { url, domain, message, friendId } = req.body;

  if (!url && !domain) {
    return res.status(400).json({ error: 'Either URL or domain is required' });
  }

  try {
    // Extract domain from URL if not provided
    const targetDomain = domain || new URL(url).hostname;
    const targetUrl = url || `https://${targetDomain}`;

    if (friendId) {
      // Request access from a specific friend
      const friendIdNum = parseInt(friendId);
      if (isNaN(friendIdNum)) {
        return res.status(400).json({ error: 'Invalid friend ID' });
      }

      // Verify friendship exists
      const user1Id = Math.min(requesterId, friendIdNum);
      const user2Id = Math.max(requesterId, friendIdNum);
      
      const friendshipResult = await db.query(
        'SELECT id FROM friendships WHERE user1_id = $1 AND user2_id = $2',
        [user1Id, user2Id]
      );
      
      if (friendshipResult.rows.length === 0) {
        return res.status(403).json({ error: 'You can only request access from friends' });
      }

      // Check if friend has sessions for this domain
      const sessionResult = await db.query(
        'SELECT id FROM sessions WHERE user_id = $1 AND domain = $2',
        [friendIdNum, targetDomain]
      );

      if (sessionResult.rows.length === 0) {
        return res.status(404).json({ error: 'Friend has no sessions for this domain' });
      }

      // Check if request already exists
      const existingRequest = await db.query(
        'SELECT id FROM access_requests WHERE requester_id = $1 AND owner_id = $2 AND domain = $3 AND status = $4',
        [requesterId, friendIdNum, targetDomain, 'pending']
      );

      if (existingRequest.rows.length > 0) {
        return res.status(400).json({ error: 'Access request already exists for this friend and domain' });
      }

      // Create access request
      await db.query(
        'INSERT INTO access_requests (requester_id, owner_id, url, domain, message, status) VALUES ($1, $2, $3, $4, $5, $6)',
        [requesterId, friendIdNum, targetUrl, targetDomain, message || `Access request for ${targetDomain}`, 'pending']
      );

      res.status(201).json({
        message: `Access request sent to friend for ${targetDomain}`,
        domain: targetDomain
      });

    } else {
      // Request access from all friends who have sessions for this domain
      const friendsWithSessionsResult = await db.query(`
        SELECT DISTINCT s.user_id, u.email 
        FROM sessions s 
        JOIN users u ON s.user_id = u.id
        JOIN friendships f ON (
          (f.user1_id = $1 AND f.user2_id = s.user_id) OR 
          (f.user2_id = $1 AND f.user1_id = s.user_id)
        )
        WHERE s.domain = $2 AND s.user_id != $1
      `, [requesterId, targetDomain]);

      if (friendsWithSessionsResult.rows.length === 0) {
        return res.status(404).json({ error: 'No friends found with sessions for this domain' });
      }

      // Create access requests for each friend with sessions
      let requestsCreated = 0;
      for (const friend of friendsWithSessionsResult.rows) {
        try {
          // Check if request already exists
          const existingRequest = await db.query(
            'SELECT id FROM access_requests WHERE requester_id = $1 AND owner_id = $2 AND domain = $3 AND status = $4',
            [requesterId, friend.user_id, targetDomain, 'pending']
          );

          if (existingRequest.rows.length === 0) {
            await db.query(
              'INSERT INTO access_requests (requester_id, owner_id, url, domain, message, status) VALUES ($1, $2, $3, $4, $5, $6)',
              [requesterId, friend.user_id, targetUrl, targetDomain, message || `Access request for ${targetDomain}`, 'pending']
            );
            requestsCreated++;
          }
        } catch (err) {
          console.error('Error creating access request:', err);
        }
      }

      if (requestsCreated > 0) {
        res.status(201).json({
          message: `Access requests sent to ${requestsCreated} friend(s) for ${targetDomain}`,
          requestsCreated,
          domain: targetDomain
        });
      } else {
        res.status(400).json({ error: 'Access requests already exist for this domain with all applicable friends' });
      }
    }

  } catch (error) {
    console.error('Access request error:', error);
    res.status(500).json({ error: 'Failed to create access request' });
  }
});

// Get incoming access requests (for session owners)
app.get('/api/access-requests/incoming', authenticateToken, async (req, res) => {
  const ownerId = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        ar.id, ar.url, ar.domain, ar.message, ar.status, ar.created_at,
        u.email as requesterEmail,
        COUNT(s.id) as sessionCount
      FROM access_requests ar
      JOIN users u ON ar.requester_id = u.id
      LEFT JOIN sessions s ON s.user_id = ar.owner_id AND s.domain = ar.domain
      WHERE ar.owner_id = $1
      GROUP BY ar.id, ar.url, ar.domain, ar.message, ar.status, ar.created_at, u.email
      ORDER BY ar.created_at DESC
    `, [ownerId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch incoming requests' });
  }
});

// Get outgoing access requests (for requesters)
app.get('/api/access-requests/outgoing', authenticateToken, async (req, res) => {
  const requesterId = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        ar.id, ar.url, ar.domain, ar.message, ar.status, ar.created_at, ar.responded_at,
        u.email as ownerEmail
      FROM access_requests ar
      JOIN users u ON ar.owner_id = u.id
      WHERE ar.requester_id = $1
      ORDER BY ar.created_at DESC
    `, [requesterId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch outgoing requests' });
  }
});

// Approve access request (with expiration support)
app.post('/api/access-requests/:id/approve', authenticateToken, async (req, res) => {
  const ownerId = req.user.id;
  const requestId = req.params.id;
  const { expirationMinutes } = req.body; // Owner can override the requested expiration

  try {
    // Get the access request
    const requestResult = await db.query(
      'SELECT * FROM access_requests WHERE id = $1 AND owner_id = $2 AND status = $3',
      [requestId, ownerId, 'pending']
    );

    const request = requestResult.rows[0];
    if (!request) {
      return res.status(404).json({ error: 'Access request not found or already processed' });
    }

    // Use provided expiration or fall back to requested expiration, with bounds checking
    const finalExpirationMinutes = expirationMinutes || request.requested_expiration_minutes || 60;
    if (finalExpirationMinutes < 5 || finalExpirationMinutes > 10080) {
      return res.status(400).json({ error: 'Expiration must be between 5 minutes and 7 days' });
    }

    const expiresAt = new Date(Date.now() + (finalExpirationMinutes * 60 * 1000));

    // Find sessions for this domain
    const sessionsResult = await db.query(
      'SELECT id FROM sessions WHERE user_id = $1 AND domain = $2',
      [ownerId, request.domain]
    );

    if (sessionsResult.rows.length === 0) {
      return res.status(404).json({ error: 'No sessions found for this domain' });
    }

    // Share all sessions for this domain with the requester (with expiration)
    for (const session of sessionsResult.rows) {
      await db.query(
        `INSERT INTO session_shares (session_id, owner_user_id, shared_with_user_id, expires_at, expiration_minutes)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (session_id, shared_with_user_id)
         DO UPDATE SET shared_at = CURRENT_TIMESTAMP, expires_at = $4, expiration_minutes = $5, is_revoked = FALSE, revoked_at = NULL`,
        [session.id, ownerId, request.requester_id, expiresAt, finalExpirationMinutes]
      );
    }

    // Update request status with approved expiration
    await db.query(
      'UPDATE access_requests SET status = $1, responded_at = CURRENT_TIMESTAMP, approved_expiration_minutes = $2, expires_at = $3 WHERE id = $4',
      ['approved', requestId, finalExpirationMinutes, expiresAt]
    );

    res.json({
      message: `Access request approved. ${sessionsResult.rows.length} session(s) shared for ${request.domain}`,
      sessionsShared: sessionsResult.rows.length,
      domain: request.domain,
      expiresAt: expiresAt,
      expirationMinutes: finalExpirationMinutes
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to approve access request' });
  }
});

// Deny access request
app.post('/api/access-requests/:id/deny', authenticateToken, async (req, res) => {
  const ownerId = req.user.id;
  const requestId = req.params.id;

  try {
    const result = await db.query(
      'UPDATE access_requests SET status = $1, responded_at = CURRENT_TIMESTAMP WHERE id = $2 AND owner_id = $3 AND status = $4',
      ['denied', requestId, ownerId, 'pending']
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Access request not found or already processed' });
    }

    res.json({ message: 'Access request denied' });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to deny access request' });
  }
});

// FRIENDS SYSTEM ROUTES

// Send friend request
app.post('/api/friends/request', authenticateToken, async (req, res) => {
  const senderId = req.user.id;
  const { email, message } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required' });
  }

  try {
    // Find the user to send request to
    const userResult = await db.query(
      'SELECT id, email FROM users WHERE email = $1',
      [email]
    );
    const targetUser = userResult.rows[0];
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found with that email address' });
    }

    if (targetUser.id === senderId) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    // Check if they are already friends
    const friendshipResult = await db.query(
      'SELECT id FROM friendships WHERE (user1_id = $1 AND user2_id = $2) OR (user1_id = $2 AND user2_id = $1)',
      [Math.min(senderId, targetUser.id), Math.max(senderId, targetUser.id)]
    );
    if (friendshipResult.rows.length > 0) {
      return res.status(400).json({ error: 'You are already friends with this user' });
    }

    // Check if request already exists
    const existingRequest = await db.query(
      'SELECT id, status FROM friend_requests WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)',
      [senderId, targetUser.id]
    );
    if (existingRequest.rows.length > 0) {
      const request = existingRequest.rows[0];
      if (request.status === 'pending') {
        return res.status(400).json({ error: 'Friend request already pending' });
      }
    }

    // Create friend request
    await db.query(
      'INSERT INTO friend_requests (sender_id, receiver_id, message) VALUES ($1, $2, $3)',
      [senderId, targetUser.id, message || `Friend request from ${req.user.email}`]
    );

    res.status(201).json({
      message: `Friend request sent to ${email}`,
      targetEmail: targetUser.email
    });

  } catch (error) {
    console.error('Friend request error:', error);
    res.status(500).json({ error: 'Failed to send friend request' });
  }
});

// Get incoming friend requests
app.get('/api/friends/requests/incoming', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        fr.id, fr.message, fr.created_at,
        u.email as senderEmail
      FROM friend_requests fr
      JOIN users u ON fr.sender_id = u.id
      WHERE fr.receiver_id = $1 AND fr.status = 'pending'
      ORDER BY fr.created_at DESC
    `, [userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch friend requests' });
  }
});

// Get outgoing friend requests
app.get('/api/friends/requests/outgoing', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        fr.id, fr.message, fr.status, fr.created_at, fr.responded_at,
        u.email as receiverEmail
      FROM friend_requests fr
      JOIN users u ON fr.receiver_id = u.id
      WHERE fr.sender_id = $1
      ORDER BY fr.created_at DESC
    `, [userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch friend requests' });
  }
});

// Accept friend request
app.post('/api/friends/requests/:id/accept', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const requestId = req.params.id;

  try {
    // Get the friend request
    const requestResult = await db.query(
      'SELECT * FROM friend_requests WHERE id = $1 AND receiver_id = $2 AND status = $3',
      [requestId, userId, 'pending']
    );

    const request = requestResult.rows[0];
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found or already processed' });
    }

    // Create friendship (ensure consistent ordering)
    const user1Id = Math.min(request.sender_id, request.receiver_id);
    const user2Id = Math.max(request.sender_id, request.receiver_id);
    
    await db.query(
      'INSERT INTO friendships (user1_id, user2_id) VALUES ($1, $2)',
      [user1Id, user2Id]
    );

    // Update request status
    await db.query(
      'UPDATE friend_requests SET status = $1, responded_at = CURRENT_TIMESTAMP WHERE id = $2',
      ['accepted', requestId]
    );

    res.json({ message: 'Friend request accepted' });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to accept friend request' });
  }
});

// Decline friend request
app.post('/api/friends/requests/:id/decline', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const requestId = req.params.id;

  try {
    const result = await db.query(
      'UPDATE friend_requests SET status = $1, responded_at = CURRENT_TIMESTAMP WHERE id = $2 AND receiver_id = $3 AND status = $4',
      ['declined', requestId, userId, 'pending']
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Friend request not found or already processed' });
    }

    res.json({ message: 'Friend request declined' });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to decline friend request' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(`
      SELECT 
        f.created_at as friendsSince,
        CASE 
          WHEN f.user1_id = $1 THEN u2.email
          ELSE u1.email
        END as friendEmail,
        CASE 
          WHEN f.user1_id = $1 THEN u2.id
          ELSE u1.id
        END as friendId
      FROM friendships f
      JOIN users u1 ON f.user1_id = u1.id
      JOIN users u2 ON f.user2_id = u2.id
      WHERE f.user1_id = $1 OR f.user2_id = $1
      ORDER BY f.created_at DESC
    `, [userId]);

    res.json(result.rows);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch friends list' });
  }
});

// Remove friend
app.delete('/api/friends/:friendId', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const friendId = parseInt(req.params.friendId);

  if (isNaN(friendId)) {
    return res.status(400).json({ error: 'Invalid friend ID' });
  }

  try {
    const user1Id = Math.min(userId, friendId);
    const user2Id = Math.max(userId, friendId);
    
    const result = await db.query(
      'DELETE FROM friendships WHERE user1_id = $1 AND user2_id = $2',
      [user1Id, user2Id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Friendship not found' });
    }

    res.json({ message: 'Friend removed successfully' });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to remove friend' });
  }
});

// EXPIRATION AND CLEANUP ROUTES

// Clean up expired sessions (can be called by background job or manually)
app.post('/api/sessions/cleanup-expired', authenticateToken, async (req, res) => {
  try {
    const now = new Date();
    
    // Find expired session shares
    const expiredResult = await db.query(
      `SELECT ss.session_id, ss.shared_with_user_id, s.domain, u.email
       FROM session_shares ss
       JOIN sessions s ON ss.session_id = s.id
       JOIN users u ON ss.shared_with_user_id = u.id
       WHERE ss.expires_at IS NOT NULL AND ss.expires_at <= $1 AND ss.is_revoked = FALSE`,
      [now]
    );

    // Mark expired sessions as revoked
    await db.query(
      `UPDATE session_shares 
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
       WHERE expires_at IS NOT NULL AND expires_at <= $1 AND is_revoked = FALSE`,
      [now]
    );

    res.json({
      message: 'Expired sessions cleaned up',
      expiredSessions: expiredResult.rows.length,
      expiredSessionDetails: expiredResult.rows
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to cleanup expired sessions' });
  }
});

// Get session expiration info for a user
app.get('/api/sessions/expiration-info', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    // Get sessions shared by this user with expiration info
    const sharedByUserResult = await db.query(
      `SELECT 
         s.domain, 
         u.email as shared_with_email,
         ss.expires_at,
         ss.expiration_minutes,
         ss.shared_at,
         ss.is_revoked,
         CASE 
           WHEN ss.expires_at IS NULL THEN 'permanent'
           WHEN ss.is_revoked = TRUE THEN 'revoked'
           WHEN ss.expires_at <= CURRENT_TIMESTAMP THEN 'expired'
           ELSE 'active'
         END as status
       FROM session_shares ss
       JOIN sessions s ON ss.session_id = s.id
       JOIN users u ON ss.shared_with_user_id = u.id
       WHERE ss.owner_user_id = $1
       ORDER BY ss.shared_at DESC`,
      [userId]
    );

    // Get sessions shared with this user with expiration info
    const sharedWithUserResult = await db.query(
      `SELECT 
         s.domain,
         u.email as owner_email,
         ss.expires_at,
         ss.expiration_minutes,
         ss.shared_at,
         ss.is_revoked,
         CASE 
           WHEN ss.expires_at IS NULL THEN 'permanent'
           WHEN ss.is_revoked = TRUE THEN 'revoked'
           WHEN ss.expires_at <= CURRENT_TIMESTAMP THEN 'expired'
           ELSE 'active'
         END as status
       FROM session_shares ss
       JOIN sessions s ON ss.session_id = s.id
       JOIN users u ON ss.owner_user_id = u.id
       WHERE ss.shared_with_user_id = $1
       ORDER BY ss.shared_at DESC`,
      [userId]
    );

    res.json({
      sharedByYou: sharedByUserResult.rows,
      sharedWithYou: sharedWithUserResult.rows
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch expiration info' });
  }
});

// Cleanup expired session shares
app.post('/api/sessions/cleanup-expired', authenticateToken, async (req, res) => {
  try {
    const hasExpiration = await checkExpirationFeatures();
    
    if (!hasExpiration) {
      return res.status(400).json({ 
        error: 'Expiration features not available', 
        note: 'Run database migration to enable cleanup' 
      });
    }

    // Count expired shares
    const countResult = await db.query(
      `SELECT COUNT(*) as expired_count 
       FROM session_shares 
       WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND is_revoked != TRUE`
    );

    // Mark expired shares as revoked (soft delete)
    const cleanupResult = await db.query(
      `UPDATE session_shares 
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP
       WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP AND is_revoked != TRUE`
    );

    res.json({
      message: 'Expired session shares cleaned up successfully',
      expiredCount: parseInt(countResult.rows[0].expired_count),
      cleanedUp: cleanupResult.rowCount
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to cleanup expired sessions' });
  }
});


// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const userResult = await db.query(
      'SELECT id, email, created_at FROM users WHERE id = $1',
      [userId]
    );
    const user = userResult.rows[0];
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const countResult = await db.query(
      'SELECT COUNT(*) FROM sessions WHERE user_id = $1',
      [userId]
    );

    res.json({
      id: user.id,
      email: user.email,
      createdAt: user.created_at,
      sessionCount: parseInt(countResult.rows[0].count, 10)
    });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});


// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\nShutting down server...');
  try {
    await db.end(); // ✅ correct for pg.Pool
    console.log('Database connection closed.');
  } catch (err) {
    console.error('Error closing database:', err);
  }
  process.exit(0);
});


// Start server
app.listen(PORT, () => {
  console.log(`Session Manager API server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});