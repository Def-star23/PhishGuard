# PhishGuard

PhishGuard is a phishing detection tool that analyzes URLs, emails, and text messages. It gives each scan a risk score (0–100), classifies it as Safe, Suspicious, or Dangerous, and explains why the content was flagged.

---

## How it works

The heuristic engine looks for things like:

- Suspicious URL structure
- Typosquatting and brand impersonation
- URLs that use IP addresses instead of domain names
- Urgent or manipulative language
- Requests for passwords or personal information
- Suspicious attachment-related wording

---


## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | Next.js (App Router), Tailwind CSS |
| Backend | FastAPI |
| Database | PostgreSQL (Neon) |
| AI | OpenRouter (OpenAI-compatible API) |
| Deployment | Vercel (Frontend), Railway (Backend) |

---



---

## How to run locally.

### Backend

```bash
cd backend

python -m venv venv

# Windows
venv\Scripts\activate

pip install -r requirements.txt
```

Create a `.env` file:

```env
DATABASE_URL=your_database_url
OPENAI_API_KEY=your_openrouter_api_key
```

Start the backend:

```bash
uvicorn main:app --reload
```

---

### Frontend

```bash
cd frontend

npm install
```

Create a `.env.local`(in the frontend folder) file:

```env
NEXT_PUBLIC_API_URL=http://127.0.0.1:8000
```

Start the development server:

```bash
npm run dev
```

---

