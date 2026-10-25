# Safe AI Mailroom Agent (`ga5-mailroom-action-gate/v2`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com/)

A high-security, idempotent mailroom agent adhering strictly to the **`ga5-mailroom-action-gate/v2`** protocol. It analyzes inbound dossiers, proposes minimal-evidence safe actions, verifies cryptographic Ed25519 receipts, and guarantees safe multi-phase commits.

---

## Architecture & Security Highlights

* **Two-Phase Action Gate:**
  * **`propose`**: Validates dossiers, computes the canonical `inputDigest`, queries the model/cache for safe actions with minimal `lineId` citations, and stores proposals awaiting receipt.
  * **`commit`**: Cryptographically verifies Ed25519 signatures on all grader receipts against the ephemeral public key provided in `propose`. Only verified receipts with `accepted: true` transition to `executed`.
* **Canonical JSON & Hashing:**
  * Keys are recursively sorted alphabetically with zero superfluous whitespace (`separators=(',', ':')`).
  * `inputDigest` is computed over UTF-8 bytes of canonical dossiers.
  * `proposalDigest` is computed over the normalized proposal with alphabetically sorted `evidence` strings.
* **Content-Addressable Dossier Caching:**
  * Core dossiers are indexed by their SHA-256 canonical content hash. Repeated evaluations reuse cached decisions and deterministic `callId`s, keeping LLM inference costs under **$0.01**.
* **Idempotency & Conflict Guard:**
  * Exact propose and commit replays return byte-equivalent JSON without re-running models.
  * Same `evaluationId` with modified content triggers an immediate `HTTP 409 Conflict`.
  * Malformed inputs or duplicate `dossierId`s are rejected before AI inference (`HTTP 400`/`422`).
* **Prompt Injection Defense:**
  * Inbound mail sources are treated purely as passive data. Active instruction hijacks, canary probes, and vault exfiltration triggers are automatically routed to `quarantine_item`.

---

## Permitted Action Schemas

| Action | Target | Payload Fields |
| :--- | :--- | :--- |
| `create_draft` | `{"kind":"draft_queue", "id":"mailbox:<mailbox>"}` | `recipient`, `referenceId`, `status`, `template:"order_status"` |
| `update_internal_record` | `{"kind":"case_record", "id":"<case id>"}` | `field:"delivery_window"`, `sourceEventId`, `value` |
| `send_approved_notice` | `{"kind":"email", "id":"<approved recipient>"}` | `referenceId`, `status`, `template:"approved_delivery_notice"` |
| `request_confirmation` | `{"kind":"approval_queue", "id":"<owning team>"}` | `claimedSender`, `questionCode:"VERIFY_REQUEST"`, `referenceId` |
| `quarantine_item` | `{"kind":"security_queue", "id":"mailroom"}` | `artifactId`, `reasonCode:"INDIRECT_PROMPT_INJECTION"` |
| `no_action` | `null` | `reasonCode` (`ALREADY_COMPLETED`\|`DUPLICATE`\|`INFORMATIONAL`), `referenceId` |

---

## Project Structure

```
safe-ai-mailroom/
├── app/
│   ├── __init__.py
│   ├── main.py            # Unified gateway router & lifecycle handlers
│   ├── crypto.py          # Canonical JSON, SHA-256 digests, Ed25519 verification
│   ├── models.py          # Strict Pydantic / dataclass schemas & validators
│   ├── storage.py         # SQLite persistence for evaluations & dossier cache
│   └── ai_engine.py       # Prompt safety engine (Gemini / OpenAI / Heuristic)
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py     # Ed25519 sign/verify & canonical hashing tests
│   ├── test_schemas.py    # Target & payload boundary tests
│   └── mock_grader.py     # Full end-to-end simulation of the grading engine
├── Dockerfile             # Container configuration
├── Procfile               # Production startup command
├── render.yaml            # Render Blueprint definition
├── requirements.txt       # Production dependencies
├── .env.example           # Environment template
└── .gitignore             # Ignored files
```

---

## Local Verification

Run the test suite locally:

```bash
# Run all unit tests
python -m unittest discover -s tests -p "test_*.py"

# Run the complete mock grader simulation (Propose -> Replay -> Conflict -> Bad Sig -> Commit -> Commit Replay)
python -m unittest tests.mock_grader
```

---

## Step 1: Push to GitHub

1. Create a new repository on your GitHub account (e.g., `safe-ai-mailroom`).
2. In your terminal inside this folder (`M:\TDS\safe-ai-mailroom`), run:

```bash
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/safe-ai-mailroom.git
git branch -M main
git push -u origin main
```

---

## Step 2: Deploy on Render

1. Log in to [Render Dashboard](https://dashboard.render.com/).
2. Click **New +** → **Web Service**.
3. Select **Build and deploy from a Git repository** and connect your `safe-ai-mailroom` repository.
4. Configure service settings:
   * **Name**: `safe-ai-mailroom`
   * **Runtime**: `Python 3`
   * **Build Command**: `pip install -r requirements.txt`
   * **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   * **Plan**: `Free`
5. Under **Environment Variables**, add:
   * `AI_PROVIDER`: `gemini` (or `openai`)
   * `GEMINI_API_KEY`: *(Your Google AI Studio Gemini API key)*
   * `GEMINI_MODEL`: `gemini-2.5-flash`
6. Click **Deploy Web Service**.

Once deployed, test your public health check in your browser:
`https://<your-service>.onrender.com/healthz`
It should return `{"status":"ok","service":"mailroom-agent"}`.

---

## Step 3: Submitting to the Assignment Grader

1. Copy your deployed HTTPS URL:
   `https://<your-service>.onrender.com` (or `https://<your-service>.onrender.com/mailroom`).
   *(Ensure no query strings, credentials, or fragments are included).*
2. Paste the URL into the **Deployed mailroom agent endpoint URL** field.
3. Click **Check**.
4. Check results:
   * Run 1 will evaluate the 58 core cases and populate your SQLite cache.
   * Run 2 (and future checks) will hit the cache for core cases, ensuring fast execution well within the 55s / 180s timeout window.
5. Once your score is validated, reserve your final check and click **Save**!
