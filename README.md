# 🛡️ LLM-Powered Semantic Web Application Firewall (WAF)

A next-generation, high-performance Web Application Firewall that replaces brittle regex pattern matching with **semantic vector embeddings**, **Pinecone vector similarity search**, **Redis cache-aside acceleration**, and **LangChain LLM fallback analysis** for zero-day exploit and malicious intent detection.

---

## 📐 Architecture & Detection Pipeline

```
  Incoming Request (Headers, Query, Body)
                     │
                     ▼
        ┌─────────────────────────┐
        │  Request Normalization  │ (Recursive URL decode, header strip, canonicalize)
        └────────────┬────────────┘
                     │
                     ▼
          ┌─────────────────────┐
          │  Redis Cache-Aside  │ ── [Cache Hit: < 5ms] ──> Return Verdict (BLOCK / ALLOW)
          └──────────┬──────────┘
                     │ (Cache Miss)
                     ▼
       ┌───────────────────────────┐
       │   Vector Embeddings       │ (Google Gemini models/text-embedding-004)
       └─────────────┬─────────────┘
                     │
                     ▼
       ┌───────────────────────────┐
       │  Pinecone Vector Search   │ (Cosine similarity against known attack signatures)
       └─────────────┬─────────────┘
                     │
       ┌─────────────┴────────────────────────┐
       │ Similarity Threshold Decision Logic  │
       └──────────────────────────────────────┘
            │                    │                     │
   Score > 0.85          0.70 <= Score <= 0.85        Score < 0.70
   (High Hazard)            (Boundary Range)           (Benign)
        │                        │                         │
        ▼                        ▼                         ▼
   ┌─────────┐       ┌───────────────────────┐       ┌─────────┐
   │  BLOCK  │       │ LangChain LLM Fallback│       │  ALLOW  │
   │ (403)   │       │ (Cognitive Reasoning) │       │ (Proxy) │
   └────┬────┘       └───────────┬───────────┘       └────┬────┘
        │                        │                        │
        └──────────────────┬─────┴────────────────────────┘
                           │
                           ▼
              ┌─────────────────────────┐
              │  Store Verdict in Redis │ (TTL: 3600s)
              └─────────────────────────┘
```

---

## 📂 Project Directory Structure

```text
.
├── config.py                 # Pydantic Settings & environment variables
├── requirements.txt          # Production dependencies
├── .env.example              # Template environment configuration
├── README.md                 # Complete system guide
├── core/
│   ├── __init__.py
│   ├── inspector.py          # Request extraction, normalization & SHA-256 fingerprinting
│   ├── cache.py              # Asynchronous Redis Cache-Aside client (< 5ms latency)
│   ├── embeddings.py         # Asynchronous OpenAI vector embedding service
│   ├── pinecone_client.py    # Pinecone vector search & similarity threshold evaluator
│   ├── llm_fallback.py       # LangChain cognitive zero-day analyzer for boundary cases
│   └── engine.py             # Central WAF decision pipeline orchestrator
├── middleware/
│   ├── __init__.py
│   └── waf_middleware.py     # Asynchronous reverse proxy & Starlette HTTP middleware
├── scripts/
│   ├── __init__.py
│   └── init_vector_db.py     # Pinecone index creation & attack payload seeding
└── tests/
    ├── mock_upstream.py      # Sample protected backend API service (Port 9000)
    └── test_waf_suite.py     # Automated test suite (SQLi, XSS, RCE, Cache-Hit, LLM)
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- Python 3.10+
- Running Redis instance (`redis-server` or cloud Redis)
- Pinecone API Key
- Google Gemini API Key (`GEMINI_API_KEY` or `GOOGLE_API_KEY`)

### 2. Environment Setup
```bash
# Clone the repository
cd CSec

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

Edit `.env` with your credentials:
```env
PINECONE_API_KEY=your_pinecone_api_key
GEMINI_API_KEY=your_gemini_api_key
UPSTREAM_URL=http://localhost:9000
```

### 3. Initialize & Seed Pinecone Vector Database
Prime the vector index with SQLi, XSS, Command Injection, SSRF, LFI, and SSTI vectors:
```bash
python scripts/init_vector_db.py
```

### 4. Run the Protected Backend & WAF Proxy

**Terminal 1: Start Protected Upstream Backend**
```bash
python tests/mock_upstream.py
# Runs on http://0.0.0.0:9000
```

**Terminal 2: Start Semantic WAF Reverse Proxy**
```bash
python main.py
# Runs on http://0.0.0.0:8000
```

### 5. Execute Test Suite
Run penetration testing simulations and latency verification:
```bash
python tests/test_waf_suite.py
```

---

## 🔍 REST Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `*` | `/{path:path}` | Reverse proxy interceptor (evaluates, blocks or forwards upstream) |
| `POST` | `/waf/inspect` | Direct evaluation endpoint for SOC analysts & security testing |
| `GET` | `/waf/health` | Health and connectivity probe (Redis, Pinecone, Upstream) |

---

## 🔒 Security Principles & Mitigations

1. **Evasion Resistance**: Recursive URL decoding counters multi-layer encoding tricks (`%2527` -> `'`). Monitored headers (`User-Agent`, `Referer`, `Cookie`) are normalized and combined with query and body data.
2. **Sub-5ms Cache-Aside**: SHA-256 fingerprints of canonical payloads ensure repeated identical queries (e.g. volumetric scanner probes) are rejected within 1-3ms without wasting embedding or LLM API tokens.
3. **Fail-Secure Architecture**: If the LLM fallback engine or external services timeout, requests falling within ambiguous boundary zones fail securely to `BLOCK`.
