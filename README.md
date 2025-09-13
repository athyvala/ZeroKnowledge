# BlackBox — Borrow Nana’s Login Without Borrowing Nana’s Password

BlackBox lets a trusted helper temporarily “step into” someone’s website session (cookies only) to get important stuff done — like booking appointments or checking lab results — without swapping passwords or screen‑sharing chaos. Access times out automatically, and the owner can revoke at any moment. Think of it as a secure “hall pass” for the internet.

## Elevator Pitch
- Help elders safely with portals and billing: no credentials, no zoom screen‑share bingo.
- Time‑boxed access: “Help me for 30 minutes, then poof.”
- One‑click revoke: Nana presses Revoke, cookies go night‑night.
- Cleaner than sticky notes with “MyP@ssword123” on the fridge.

## How It Works
1) Request: Helper clicks “Request Access” for a domain (e.g., portal.examplehealth.com).
2) Approve: Owner approves with a duration (e.g., 30–60 minutes).
3) Load: Helper imports the session; the extension sets cookies and opens the site.
4) Auto‑Logout: Background alarm clears cookies at the timer, or immediately if the owner revokes.

## What We Actually Share
- Domain‑scoped session cookies only. No passwords, no saved forms, no spooky remote control.
- Cookies get imported, tracked locally with a timer, and auto‑deleted on expiry or revoke.

## Why It’s Safer (HIPAA‑friendly habits)
- Consent‑first: Owner explicitly approves the request and the timer.
- Least‑privilege: Only the target domain session; nothing else.
- Short‑lived: Auto‑logout cleans everything.
- Reversible: Revoke button sledgehammers the helper’s cookies instantly.
- PHI‑safe habits: Keep logs lean (timestamps, emails, domains only).

## Hackathon Demo Script
- “I’m the caregiver.” Click “Request Access” on the Sessions tab.
- “I’m Nana.” Click “Manage Requests” → Approve → choose 30 minutes.
- “I’m the caregiver again.” Click “Shared” → “Load” → Fix the portal thing.
- Ten minutes later: “Nana presses Revoke.” Helper’s session ends, cookies cleared. Everyone wins.

## Features
- Save/Load Sessions: Capture and re‑apply cookies for one domain.
- Share With Expiration: Owner chooses duration (minutes to a day).
- Access Requests: Request from specific friends or all friends with that domain.
- Revoke Any Time: Force an immediate logout on the helper’s device.
- Shared Tab Hygiene: Auto‑hides expired shares; you can hide manually too.
- Friendly Messaging: No scary warnings — just helpful nudges and clear timers.

## Architecture
- Chrome Extension (MV3): `extension/popup.html`, `extension/popup.js`, `extension/background.js`, `extension/manifest.json`.
- Node/Express API: `backend/server.js` (auth, sessions, shares, requests, revoke).
- PostgreSQL (Supabase friendly): schema in `backend/database_schema.sql`.

## Setup (Quick)
### Backend
1. `cd backend && npm install`
2. Create `.env`:
   - `PORT=3000`
   - `JWT_SECRET=some_long_random_string`
   - `SUPABASE_DB_URL=postgres://...`
   - `SUPABASE_DB_SSL=true` (if using Supabase)
3. Apply SQL from `backend/database_schema.sql` to your DB.
4. `npm run dev` (or `npm start`).

### Extension
1. Visit `chrome://extensions`, enable Developer mode.
2. Load unpacked → select the `extension` folder.
3. By default, popup points to `http://localhost:3000/api` (see `extension/popup.js`).

## Ethical Defaults
- Clear consent language (“You’re granting temporary access to this site only”).
- Short timers by default (e.g., 30 minutes).
- No PHI in logs; store only metadata.
- Optional “health portals only” mode (domain allowlist) for deployments.

## Roadmap
- SameSite/partitioned cookie fidelity for stricter portals.
- “Consent receipt” PDF for support tickets.
- Admin policies (max durations, allowed domains).
- Gentle onboarding for elders (“Press the big green button to help your helper help you”).

