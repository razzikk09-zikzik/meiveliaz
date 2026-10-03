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

## What each service actually does

When someone clicks **Check for Scam**, the backend runs 4 independent
checkers in parallel and the Risk Engine fuses their answers:

```
                        ┌──────────────────────────────┐
  message ──────────────┤ 1. HEURISTIC ENGINE + BLOCKLISTS  (always on, free, instant)
                        │    your own code, no internet needed
                        ├──────────────────────────────┤
                        │ 2. GEMINI AI                 (needs GEMINI_API_KEY)
                        ├──────────────────────────────┤
                        │ 3. VIRUSTOTAL                (needs VIRUSTOTAL_API_KEY)
                        ├──────────────────────────────┤
                        │ 4. NEO4J GRAPH               (needs NEO4J_*)
                        └──────────────┬───────────────┘
                                       ↓
                          RISK ENGINE (weighted fusion)
             Gemini 30% · Heuristics 35% · VirusTotal 20% · Graph 15%
                                       ↓
                      SAFE (0-30) / SUSPICIOUS (31-60) / SCAM (61-100)
```

| Service | What it does | When it helps |
|---|---|---|
| **1. Heuristic engine + blocklists** (`heuristic_engine.py`, `blocklist_service.py`) | Deterministic pattern matching: urgency words, OTP/PIN/CVV requests, payment bait, bank/government impersonation, brand-in-domain mismatch, URL shorteners, raw IPs, risky TLDs. Plus **hardcoded blocklists** in `app/data/`: 10,089 known scam domains (`links.txt`), 80 phishing phrases (`malicious-terms.txt`), 39 phishing URL paths (`trailing-slashes.txt`). A domain on the blocklist is near-certain SCAM. | Always. Catches known scams instantly with zero cost, even offline. |
| **2. Gemini** (`gemini_service.py`) | Sends the message (or the whole screenshot, via vision) to Google's AI. Understands Tamil/Tanglish, novel scam stories, QR-code and payment-screen context — things pattern matching misses. Returns a score, signals and a human-readable explanation. | New/unknown scam wording. The AI explanation shown on the result page comes from here. |
| **3. VirusTotal** (`virustotal_service.py`) | Looks the URL up against 70+ security vendors' databases. "4 malicious" means vendors already flagged it. | Links only. Confirms known phishing URLs with real-world reputation. Rate-limited to 4 lookups/min on the free key — results are cached 1h. |
| **4. Neo4j graph** (`neo4j_service.py`) | When a report is submitted, its phone numbers, domains and UPI IDs become graph nodes linked to the report. On analysis, the message's entities are matched against the graph: "this phone number was already reported 3 times in Adyar". | Community memory — connects isolated reports into campaigns. Only useful once real reports accumulate. |
| **5. Supabase** (`supabase_service.py`) | Plain database storage (PostgreSQL) + analyst login. Reports, alerts and analysis results are stored here. **Nothing is stored without it.** | Reports persisting, the analyst report list, and the threats page aggregating real report counts per area. |

Every provider that fails or is missing returns `available: false` and the
analysis continues with the rest — the app never crashes because of a provider.

## Blocklists (hardcoded intelligence)

Curated data lives in `backend/app/data/` and is loaded once at startup:

- `links.txt` — known scam domains; a message linking to one is classified
  **SCAM** by the heuristics alone (score 65), no AI needed.
- `malicious-terms.txt` — phishing phrases (e.g. "airdrop nitro", "before the
  promotion ends"); each hit adds risk.
- `trailing-slashes.txt` — URL path patterns like `/claim`, `/airdrop`,
  `/billing` used by phishing landing pages.

To update the lists, replace the files and restart the backend.

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
