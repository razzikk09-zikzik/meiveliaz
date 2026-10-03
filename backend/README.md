# MEYVIZHI Backend (FastAPI)

Scam detection and cyber-intelligence API. The React frontend on Vercel talks
to this backend through `VITE_API_URL`.

## Run locally

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env           # fill in values when you have them (optional)
uvicorn app.main:app --reload --port 8000
```

Interactive API docs: http://localhost:8000/docs

The backend **runs with zero credentials configured** — the heuristic engine
works and every external provider degrades gracefully.

## API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET  | `/health` | none | deployment health check |
| GET  | `/api/config-status` | none | which providers are configured (YES/NO) |
| POST | `/api/analyze` | none | risk engine: heuristics + Gemini + VirusTotal + graph |
| POST | `/api/analyze/image` | none | screenshot → OCR → same pipeline |
| POST | `/api/reports` | none | anonymous scam report |
| GET  | `/api/reports` | analyst JWT | analyst report list |
| GET  | `/api/threats` | none | live threats + alerts (real data or marked seed data) |
| POST | `/api/auth/login` | none | analyst login (Supabase Auth) |

## Environment variables

See `.env.example`. Everything is optional; missing keys disable that signal:

| Variable | Required | Missing → |
|----------|----------|-----------|
| `GEMINI_API_KEY` | optional | Gemini signal disabled |
| `VIRUSTOTAL_API_KEY` | optional | URL reputation signal disabled |
| `NEO4J_URI` / `NEO4J_USERNAME` / `NEO4J_PASSWORD` | optional | graph signal disabled |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` | optional | persistence + analyst auth disabled |
| `CORS_ORIGINS` | recommended | defaults to `http://localhost:5173` |
| `RATE_LIMIT_PER_MINUTE` | optional | defaults to 30 per IP |

Never put any of these in the frontend. Only `VITE_API_URL` belongs on Vercel.

## Supabase setup

1. Create a project at https://supabase.com/dashboard
2. SQL Editor → paste `supabase_schema.sql` → Run
3. Project Settings → API → copy URL, anon key, service_role key into `backend/.env`
4. Authentication → Users → Add user → create the analyst account

## Neo4j setup

1. Create a free AuraDB instance at https://neo4j.com/cloud/aura/
2. Copy the connection URI (`neo4j+s://....databases.neo4j.io`) and password into `backend/.env`
3. The backend uses Neo4j's HTTP Query API (works with Aura and Neo4j 5.19+)

## Deployment (Render example)

`render.yaml` in the repository root defines the service. Or manually:

- Runtime: Python, root directory `backend`
- Build: `pip install -r requirements.txt`
- Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check: `/health`
- Add the environment variables from `.env.example` in the Render dashboard
- Set `CORS_ORIGINS` to include your Vercel domain

Then in Vercel: **Project → Settings → Environment Variables** add
`VITE_API_URL=https://your-render-url.onrender.com` and redeploy.
