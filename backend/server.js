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

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
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
  try {
    const result = await db.query(query, [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch shared sessions' });
  }
});

// Get specific shared session data
app.get('/api/sessions/shared/:id', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const query = `
    SELECT s.*, owner.email as ownerEmail
    FROM sessions s
    JOIN session_shares ss ON s.id = ss.session_id
    JOIN users owner ON s.user_id = owner.id
    WHERE s.id = $1 AND ss.shared_with_user_id = $2
  `;
  try {
    const result = await db.query(query, [sessionId, userId]);
    const row = result.rows[0];
    if (!row) {
      return res.status(404).json({ error: 'Shared session not found or not accessible' });
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
        updatedAt: row.updated_at,
        ownerEmail: row.ownerEmail
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

// Share session with another user
app.post('/api/sessions/:id/share', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const { email, expiration } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email address is required' });
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

    // Share the session (upsert)
    await db.query(
      `INSERT INTO session_shares (session_id, owner_user_id, shared_with_user_id, expiration)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (session_id, shared_with_user_id)
       DO UPDATE SET shared_at = CURRENT_TIMESTAMP, expiration = $4`,
      [sessionId, userId, targetUser.id, expiration || null]
    );

    res.json({
      message: `Session shared successfully with ${email}`,
      sharedWith: targetUser.email
    });

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

    const sharesResult = await db.query(
      `SELECT 
         u.email,
         ss.shared_at,
         ss.expiration
       FROM session_shares ss
       JOIN users u ON ss.shared_with_user_id = u.id
       WHERE ss.session_id = $1 AND ss.owner_user_id = $2
       ORDER BY ss.shared_at DESC`,
      [sessionId, userId]
    );

    res.json(sharesResult.rows);

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch share list' });
  }
});

// Update expiration for a shared user
app.put('/api/sessions/:id/share', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;
  const { email, expiration } = req.body;

  if (!email || !expiration) {
    return res.status(400).json({ error: 'Email and expiration are required' });
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

    const updateResult = await db.query(
      `UPDATE session_shares SET expiration = $1 WHERE session_id = $2 AND owner_user_id = $3 AND shared_with_user_id = $4`,
      [expiration, sessionId, userId, targetUser.id]
    );

    if (updateResult.rowCount === 0) {
      return res.status(404).json({ error: 'Share not found' });
    }

    res.json({ message: `Expiration updated for ${email}` });

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to update expiration' });
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