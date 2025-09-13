-- Database schema for BlackBox Session Manager
-- Run these SQL commands in your Supabase dashboard or PostgreSQL database

-- Users table (should already exist)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table (should already exist)
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  domain VARCHAR(255) NOT NULL,
  url TEXT,
  cookies JSONB NOT NULL,
  user_agent TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session shares table (should already exist)
CREATE TABLE IF NOT EXISTS session_shares (
  session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  shared_with_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id, shared_with_user_id)
);

-- NEW: Friend requests table
CREATE TABLE IF NOT EXISTS friend_requests (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  message TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  responded_at TIMESTAMP,
  UNIQUE(sender_id, receiver_id) -- Prevent duplicate requests between same users
);

-- NEW: Friendships table
CREATE TABLE IF NOT EXISTS friendships (
  id SERIAL PRIMARY KEY,
  user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user1_id, user2_id),
  CHECK (user1_id < user2_id) -- Ensure consistent ordering to prevent duplicates
);

-- NEW: Access requests table (modified to work with friends)
CREATE TABLE IF NOT EXISTS access_requests (
  id SERIAL PRIMARY KEY,
  requester_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  url TEXT,
  domain VARCHAR(255) NOT NULL,
  message TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  responded_at TIMESTAMP,
  UNIQUE(requester_id, owner_id, domain, status) -- Prevent duplicate pending requests
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_sessions_domain ON sessions(domain);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_session_shares_shared_with ON session_shares(shared_with_user_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_sender ON friend_requests(sender_id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_receiver ON friend_requests(receiver_id);
CREATE INDEX IF NOT EXISTS idx_friendships_user1 ON friendships(user1_id);
CREATE INDEX IF NOT EXISTS idx_friendships_user2 ON friendships(user2_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_owner ON access_requests(owner_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_requester ON access_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON access_requests(status);
