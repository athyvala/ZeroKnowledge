-- Migration to add expiration features to existing BlackBox database
-- Run this in your Supabase SQL Editor

-- Step 1: Add new columns to session_shares table
ALTER TABLE session_shares 
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS expiration_minutes INTEGER DEFAULT 60,
ADD COLUMN IF NOT EXISTS is_revoked BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP;

-- Step 2: Update access_requests table for expiration support
ALTER TABLE access_requests 
ADD COLUMN IF NOT EXISTS requested_expiration_minutes INTEGER DEFAULT 60,
ADD COLUMN IF NOT EXISTS approved_expiration_minutes INTEGER,
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;

-- Step 3: Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_session_shares_expires_at ON session_shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_session_shares_is_revoked ON session_shares(is_revoked);
CREATE INDEX IF NOT EXISTS idx_access_requests_expires_at ON access_requests(expires_at);

-- Step 4: Verify the migration worked
SELECT 
  column_name, 
  data_type, 
  is_nullable 
FROM information_schema.columns 
WHERE table_name = 'session_shares' 
  AND column_name IN ('expires_at', 'expiration_minutes', 'is_revoked', 'revoked_at');