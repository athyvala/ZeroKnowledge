# BlackBox Auto-Expiration Setup Guide

## Overview
Your BlackBox extension now includes auto-expiration functionality! Session shares can now automatically expire after a specified time period, and users will be logged out when their imported sessions expire.

## 🚀 Quick Setup (3 Steps)

### Step 1: Database Migration (Required)
To enable auto-expiration features, you need to update your Supabase database:

1. **Open Supabase SQL Editor:**
   - Go to your Supabase dashboard
   - Click on "SQL Editor" in the left sidebar

2. **Run the Migration Script:**
   - Copy the contents of `backend/migration_add_expiration.sql`
   - Paste and execute in the SQL Editor
   - You should see: "Migration completed successfully"

### Step 2: Restart Your Backend Server
```bash
cd backend
node server.js
```

### Step 3: Reload the Extension
- Open Chrome Extensions (`chrome://extensions/`)
- Click the reload button on your BlackBox extension
- Verify the popup shows "Auto-expiration: ✓"

## ✨ New Features

### Auto-Expiration
- **Share with Timer**: Set expiration time when sharing sessions (5 minutes to 7 days)
- **Auto-Logout**: Users are automatically logged out when imported sessions expire
- **Real-time Countdown**: See remaining time for active imported sessions
- **Background Cleanup**: Chrome alarms automatically handle session cleanup

### Enhanced UI
- **Expiration Controls**: Dropdown to select expiration time
- **Active Session Display**: Shows current imported session with countdown timer
- **Server Status**: Health indicator showing feature availability
- **One-Click Logout**: Clear imported sessions manually

### Backend Improvements
- **Backward Compatibility**: Works with old database schema in legacy mode
- **Feature Detection**: Automatically detects available features
- **Soft Deletion**: Revoked sessions are marked, not deleted
- **Cleanup Endpoint**: Manual cleanup of expired sessions

## 🔧 Technical Details

### Database Schema Updates
The migration adds these columns:
- `session_shares.expires_at` - When the share expires
- `session_shares.expiration_minutes` - Duration in minutes
- `session_shares.is_revoked` - Soft deletion flag
- `session_shares.revoked_at` - When it was revoked
- `access_requests.expires_at` - Request expiration
- `access_requests.expiration_minutes` - Request duration

### Chrome Extension Updates
- **Manifest V3**: Added `alarms` and `notifications` permissions
- **Background Script**: Auto-logout alarms and cleanup
- **Storage**: Tracks active imported sessions
- **UI**: Expiration controls and countdown timers

### API Enhancements
- `POST /api/sessions/:id/share` - Now accepts `expirationMinutes`
- `GET /api/health` - Feature detection endpoint
- `POST /api/sessions/cleanup-expired` - Manual cleanup
- `DELETE /api/sessions/:id/share/:email` - Revoke access

## 🛠 Troubleshooting

### "Auto-expiration: ⚠️ (migration needed)"
- The database migration hasn't been run yet
- Follow Step 1 above to run the migration script

### "Server: Disconnected"
- Backend server is not running
- Start with: `cd backend && node server.js`

### Sessions Not Expiring
- Check Chrome's alarm permissions
- Reload the extension
- Verify countdown timer appears in popup

### Migration Errors
- Ensure you're connected to the correct Supabase database
- Check that the tables exist in your schema
- Contact support if tables are missing

## 📋 Verification Checklist

After setup, verify these work:

- [ ] Popup shows "Auto-expiration: ✓"
- [ ] Can share session with expiration time
- [ ] Imported session shows countdown timer
- [ ] Auto-logout works when timer reaches zero
- [ ] Manual logout clears imported session
- [ ] Backend health endpoint returns expiration: true

## 🔄 Upgrade Path

If you had BlackBox installed before auto-expiration:

1. **Existing Shares**: Old session shares continue working (permanent)
2. **New Shares**: Will use auto-expiration by default
3. **Mixed Mode**: System works with both old and new shares
4. **Migration**: No data loss - all existing functionality preserved

## 🚀 Usage Examples

### Share with 2-hour expiration:
1. Save a session on any website
2. Click "Share Session"
3. Enter friend's email
4. Select "2 hours" from expiration dropdown
5. Click "Share"

### Import expiring session:
1. Friend shares session with you
2. Go to the shared website
3. Click "Load Session" → "Shared Sessions"
4. Import the session
5. See countdown timer in popup
6. Automatic logout when timer reaches zero

## 📞 Support

If you encounter issues:
1. Check the browser console for errors
2. Verify backend server logs
3. Ensure database migration completed
4. Try reloading the extension

Your BlackBox extension is now equipped with powerful auto-expiration features! 🎉