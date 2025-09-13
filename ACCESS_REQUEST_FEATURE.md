# Friends-Based Access Request System

## Overview
The Friends-Based Access Request feature allows users to build a network of trusted friends and request access to specific URLs/domains from them. This creates a secure, social approach to session sharing that's perfect for scenarios like:

- Requesting access to a friend's Netflix cookies
- Getting access to premium site sessions from trusted contacts
- Sharing work-related authenticated sessions within your team

## How It Works

### Building Your Friend Network
1. **Add Friends**: Click "Add Friend" and enter their email address
2. **Send Friend Requests**: Include an optional message with your request
3. **Accept/Decline Requests**: Manage incoming friend requests from others
4. **View Friends**: See all your current friends and manage your network

### For Requesters
1. **Navigate to the desired site** (e.g., netflix.com)
2. **Open the extension popup**
3. **Click "Request Access to Current Site"**
4. **Select which friends** to send the request to (or send to all friends with sessions)
5. **Add an optional message** explaining why you need access
6. **Send the requests** - they will only be sent to your selected friends

### For Session Owners
1. **Open the extension popup**
2. **Click "Manage Requests"** to see incoming access requests from friends
3. **Review requests** with details like:
   - Which friend is requesting access
   - What domain they want access to
   - How many sessions you have for that domain
   - Their message explaining why they need access
4. **Approve or Deny** the request
5. **If approved**, all your sessions for that domain are automatically shared with your friend

## Database Schema

The friends system adds three new tables:

```sql
-- Friend requests table
CREATE TABLE friend_requests (
  id SERIAL PRIMARY KEY,
  sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  message TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined')),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  responded_at TIMESTAMP,
  UNIQUE(sender_id, receiver_id) -- Prevent duplicate requests between same users
);

-- Friendships table
CREATE TABLE friendships (
  id SERIAL PRIMARY KEY,
  user1_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  user2_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user1_id, user2_id),
  CHECK (user1_id < user2_id) -- Ensure consistent ordering to prevent duplicates
);

-- Access requests table (modified to work with friends)
CREATE TABLE access_requests (
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
```

## API Endpoints

### Friends Management

#### POST /api/friends/request
Send a friend request to another user.

**Body:**
```json
{
  "email": "friend@example.com",
  "message": "Hi! I'd like to add you as a friend."
}
```

#### GET /api/friends/requests/incoming
Get all incoming friend requests.

#### GET /api/friends/requests/outgoing  
Get all outgoing friend requests.

#### POST /api/friends/requests/:id/accept
Accept a friend request.

#### POST /api/friends/requests/:id/decline
Decline a friend request.

#### GET /api/friends
Get list of all friends.

#### DELETE /api/friends/:friendId
Remove a friend.

### Access Requests (Friends-Only)

#### POST /api/access-requests
Create a new access request for a domain/URL (friends-only).

**Body (request from specific friend):**
```json
{
  "domain": "netflix.com",
  "url": "https://netflix.com",
  "message": "I'd like access to Netflix for movie night!",
  "friendId": 123
}
```

**Body (request from all friends with sessions):**
```json
{
  "domain": "netflix.com",
  "url": "https://netflix.com",
  "message": "I'd like access to Netflix for movie night!"
}
```

**Response:**
```json
{
  "message": "Access requests sent to 2 friend(s) for netflix.com",
  "requestsCreated": 2,
  "domain": "netflix.com"
}
```

### GET /api/access-requests/incoming
Get all incoming access requests for the current user.

**Response:**
```json
[
  {
    "id": 1,
    "domain": "netflix.com",
    "url": "https://netflix.com",
    "message": "I'd like access to Netflix for movie night!",
    "status": "pending",
    "created_at": "2024-01-01T12:00:00Z",
    "requesterEmail": "friend@example.com",
    "sessionCount": 3
  }
]
```

### GET /api/access-requests/outgoing
Get all outgoing access requests from the current user.

**Response:**
```json
[
  {
    "id": 1,
    "domain": "netflix.com",
    "url": "https://netflix.com", 
    "message": "I'd like access to Netflix for movie night!",
    "status": "approved",
    "created_at": "2024-01-01T12:00:00Z",
    "responded_at": "2024-01-01T13:00:00Z",
    "ownerEmail": "owner@example.com"
  }
]
```

### POST /api/access-requests/:id/approve
Approve an access request and share all sessions for that domain.

**Response:**
```json
{
  "message": "Access request approved. 3 session(s) shared for netflix.com",
  "sessionsShared": 3,
  "domain": "netflix.com"
}
```

### POST /api/access-requests/:id/deny
Deny an access request.

**Response:**
```json
{
  "message": "Access request denied"
}
```

## UI Components

### New Buttons
- **"Friends"** - View and manage your friends list
- **"Add Friend"** - Send friend request to another user
- **"Friend Requests"** - Manage incoming and outgoing friend requests
- **"Request Access to Current Site"** - Initiates access request for current domain (friends-only)
- **"My Requests"** - View status of outgoing access requests  
- **"Manage Requests"** - View and respond to incoming access requests

### New Modals
- **Friends Modal** - List of all friends with remove option
- **Add Friend Modal** - Form to send friend request with email and message
- **Friend Requests Modal** - Tabbed view of incoming/outgoing friend requests
- **Request Access from Friends Modal** - Select friends and send access request with message
- **View Requests Modal** - List of user's outgoing requests with status
- **Manage Requests Modal** - List of incoming requests with approve/deny actions

## Status Indicators
- **Pending** (Yellow) - Request waiting for response
- **Approved** (Green) - Request approved, access granted
- **Denied** (Red) - Request denied by owner

## Security Features
- **Friends-Only Access**: Users can only request access from people they've added as friends
- **Mutual Friend Requests**: Both users must agree to be friends before any session sharing
- **Duplicate Prevention**: Duplicate pending requests are prevented for both friend requests and access requests
- **Session Owner Control**: Only session owners can approve/deny requests for their domains
- **Audit Trail**: All requests are logged with timestamps for audit purposes
- **Friendship Management**: Users can remove friends at any time, which revokes all shared sessions

## Installation & Setup

1. **Run the database migration:**
   ```sql
   -- Execute the SQL in backend/database_schema.sql
   ```

2. **Restart your backend server:**
   ```bash
   cd backend
   npm start
   ```

3. **Reload the extension** in Chrome to get the new UI

## Usage Examples

### Example 1: Adding Friends and Netflix Access
1. **User A adds User B as friend**: Clicks "Add Friend", enters User B's email
2. **User B accepts**: Sees friend request in "Friend Requests" and accepts it
3. **User A requests Netflix access**: Visits netflix.com, clicks "Request Access to Current Site"
4. **User A selects User B**: Chooses User B from the friends list and adds message "Can I borrow your Netflix for the weekend?"
5. **User B approves**: Sees the request in "Manage Requests" and approves it
6. **User A gets access**: Can now load User B's Netflix session and access their account

### Example 2: Work Team Access
1. **Manager and Employee are friends**: They've already added each other as friends
2. **Employee requests work site access**: Visits company-internal-tool.com
3. **Employee sends request**: Clicks "Request Access to Current Site", selects manager, adds message "Need access to review the quarterly reports"
4. **Manager approves**: Sees request from friend and approves it
5. **Employee gets access**: Can now access the internal tool with manager's session

## Future Enhancements
- **Email notifications** for new friend requests and access requests
- **Request expiration dates** for time-limited access
- **Temporary access grants** (time-limited sessions)
- **Friend groups/categories** (work, personal, family, etc.)
- **Bulk approve/deny functionality** for multiple requests
- **Friend recommendations** based on mutual friends
- **Session usage analytics** to see who's using your shared sessions
- **Auto-approval settings** for trusted friends
