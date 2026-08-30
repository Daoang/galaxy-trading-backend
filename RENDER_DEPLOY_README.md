# Deploying this backend to Render.com

## 1. Push this folder to a GitHub repo
Render deploys from GitHub. Create a new repo (can be private) and push
everything in this folder to it.

## 2. Create the Web Service on Render
- Go to https://dashboard.render.com -> New -> Web Service
- Connect the GitHub repo
- Runtime: Node
- Build Command: npm install
- Start Command: node app.js
- Instance Type: Free

## 3. Set Environment Variables
In the Render service -> Environment tab, add every variable listed in
`.env.production.template` (DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME,
ALLOWED_ORIGINS, SECRET_KEY, TOKEN_TTL_HOURS, PORT). Render sets its own
PORT automatically at runtime for some setups — if the app fails to bind,
check Render's logs; you may need to let Render's own PORT env var take
priority (it usually does, since config.js reads process.env.PORT either way).

## 4. Enable Remote MySQL access on Hostinger
In hPanel: Databases -> Remote MySQL -> add a new entry.
- If Render doesn't give a fixed IP on the free tier, use % (any host) as a
  fallback, but ONLY if your DB user has a strong password — this opens the
  database port to the internet. Prefer a specific IP if Render provides one
  for your plan/region.

## 5. Get your Render URL
After deploy, Render gives you a URL like:
  https://galaxy-trading-backend.onrender.com

Copy that URL. You need to paste it into TWO places in the frontend code
before uploading the frontend to Hostinger:
  - app.js -> const API_BASE = "..."
  - staff/staff.js -> API_BASE = '...'

(Already marked with REPLACE-WITH-YOUR-RENDER-URL placeholders.)

## Note on Render free tier
Free web services on Render spin down after ~15 minutes of no traffic and
take ~30-50 seconds to wake back up on the next request. For a thesis
defense, hit the URL a minute or two beforehand to "wake it up" so it's
already warm when you demo.
