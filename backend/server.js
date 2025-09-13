require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'stghfs4q56h346nn57u4werhertu475eu4w5bwtr';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Database setup
const dbPath = path.join(__dirname, 'sessions.db');
const db = new sqlite3.Database(dbPath);

// Initialize database tables
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain TEXT NOT NULL,
      url TEXT NOT NULL,
      cookies TEXT NOT NULL,
      user_agent TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);
});

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
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      // Create new user
      const passwordHash = await hashPassword(password);
      
      db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
        [email, passwordHash], 
        function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }

          const user = { id: this.lastID, email };
          const token = generateToken(user);

          res.status(201).json({
            user,
            token,
            message: 'User created successfully'
          });
        }
      );
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

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

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
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user sessions
app.get('/api/sessions', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(
    'SELECT id, domain, url, created_at, updated_at FROM sessions WHERE user_id = ? ORDER BY updated_at DESC',
    [userId],
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to fetch sessions' });
      }

      res.json(rows);
    }
  );
});

// Create session
app.post('/api/sessions', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { domain, url, cookies, userAgent } = req.body;

  if (!domain || !cookies || !Array.isArray(cookies)) {
    return res.status(400).json({ error: 'Domain and cookies are required' });
  }

  const cookiesJson = JSON.stringify(cookies);

  // Check if session for this domain already exists
  db.get('SELECT id FROM sessions WHERE user_id = ? AND domain = ?', [userId, domain], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (row) {
      // Update existing session
      db.run(
        'UPDATE sessions SET url = ?, cookies = ?, user_agent = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [url, cookiesJson, userAgent, row.id],
        function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to update session' });
          }

          res.json({
            id: row.id,
            message: 'Session updated successfully',
            cookieCount: cookies.length
          });
        }
      );
    } else {
      // Create new session
      db.run(
        'INSERT INTO sessions (user_id, domain, url, cookies, user_agent) VALUES (?, ?, ?, ?, ?)',
        [userId, domain, url, cookiesJson, userAgent],
        function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to save session' });
          }

          res.status(201).json({
            id: this.lastID,
            message: 'Session saved successfully',
            cookieCount: cookies.length
          });
        }
      );
    }
  });
});

// Get specific session
app.get('/api/sessions/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;

  db.get(
    'SELECT * FROM sessions WHERE id = ? AND user_id = ?',
    [sessionId, userId],
    (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!row) {
        return res.status(404).json({ error: 'Session not found' });
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
    }
  );
});

// Delete session
app.delete('/api/sessions/:id', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const sessionId = req.params.id;

  db.run(
    'DELETE FROM sessions WHERE id = ? AND user_id = ?',
    [sessionId, userId],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to delete session' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Session not found' });
      }

      res.json({ message: 'Session deleted successfully' });
    }
  );
});

// Get user profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT id, email, created_at FROM users WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get session count
    db.get('SELECT COUNT(*) as count FROM sessions WHERE user_id = ?', [userId], (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      res.json({
        id: user.id,
        email: user.email,
        createdAt: user.created_at,
        sessionCount: result.count
      });
    });
  });
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
process.on('SIGINT', () => {
  console.log('\nShutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Session Manager API server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});
      