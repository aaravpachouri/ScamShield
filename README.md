# 🛡️ ScamShield

**Before you click, know what you're looking at.**

ScamShield is an AI-assisted digital-safety prototype that helps people inspect suspicious messages and URLs, understand potential warning signs, and choose safer next steps.

<p align="center">
  <a href="https://scam-shield-lyart-pi.vercel.app/"><strong>🚀 Try the live demo</strong></a>
  &nbsp;·&nbsp;
  <a href="https://scamshield-api-8ns3.onrender.com/api/health">API health</a>
</p>

> **Important:** ScamShield is an experimental decision-support tool, not a guarantee of safety. Its risk score is a heuristic assessment—not a probability that a message is fraudulent. Always verify important requests through official channels.

## ✨ What it can do

- **Message analysis** — inspect text for urgency, threats, suspicious requests, and other scam indicators.
- **URL inspection** — surface structural warning signs in links.
- **Evidence-based explanations** — show why an input was flagged instead of returning only a label.
- **Suggested next steps** — provide practical safety guidance based on the findings.
- **Screenshot text extraction** — supported when OCR dependencies are installed and available in the runtime.
- **Scam awareness** — explore educational material about common scam patterns.

Actual results and feature availability depend on the configured AI provider, hosting environment, and input. ScamShield can produce both false positives and false negatives.

## 🧪 Try the demo

1. Open the [ScamShield live website](https://scam-shield-lyart-pi.vercel.app/).
2. Open the Playground.
3. Submit a sample message or URL and run the analysis.
4. Review the risk assessment, evidence, and recommended next steps.

Try both suspicious and ordinary messages. A useful test checks whether the explanation matches the content—not just whether the score is high or low.

**Privacy tip:** Use fictional examples for public testing. Do not submit passwords, OTPs, bank details, private conversations, or other sensitive information. Submitted content may be processed by the configured AI provider.

## 🧠 How it works

1. **Input:** A user submits text, a URL, or a supported screenshot.
2. **Extraction:** OCR extracts screenshot text when the feature and dependencies are available.
3. **Analysis:** Heuristic checks and the configured AI provider evaluate available signals.
4. **Fusion:** The analysis components combine their findings into a structured assessment.
5. **Guidance:** The frontend presents a score, explanations, and suggested next steps.

## 🏗️ Technology

| Layer | Technology |
| --- | --- |
| Frontend | React, TypeScript, Vite |
| UI and motion | Custom CSS, Framer Motion, Lucide React |
| API | Python, FastAPI |
| AI | Google Gemini API or local Ollama, depending on configuration |
| Screenshot OCR | Pillow, pytesseract, Tesseract OCR |

## 📂 Project structure

```text
ScamShield/
├── api.py
├── core/
│   ├── analyzer.py
│   ├── fusion_engine.py
│   ├── risk_engine.py
│   └── url_analyzer.py
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── tests/
├── requirements.txt
├── .env.example
└── README.md
```

## 💻 Run locally (Windows PowerShell)

### Requirements

- Python 3.12 or newer
- Node.js and npm
- A Gemini API key **or** a working local Ollama setup
- Tesseract OCR installed and configured if you want to test screenshot OCR

### 1. Install backend dependencies

Run from the repository root:

```powershell
python -m pip install -r requirements.txt
```

### 2. Configure the AI provider

For a local Gemini-backed run, set your key in the current PowerShell session:

```powershell
$env:GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
```

Replace the placeholder locally. **Never put a real API key in source code, README files, screenshots, or Git commits.** For local Ollama use, install/start Ollama and pull the model expected by your configuration instead.

Optional settings are documented in `.env.example`. Environment variables set in PowerShell apply only to that terminal session unless you configure them separately.

### 3. Start the API

From the repository root:

```powershell
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

Check the API at [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health).

### 4. Start the frontend

Open a second PowerShell terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL printed by Vite. If you configure `VITE_SCAMSHIELD_API_URL`, point it to the backend base URL (for example, `http://127.0.0.1:8000`) and restart Vite after changing the variable.

## ☁️ Deployment overview

The current public demo uses:

- **Frontend:** Vercel — [open the website](https://scam-shield-lyart-pi.vercel.app/)
- **Backend:** Render — [check API health](https://scamshield-api-8ns3.onrender.com/api/health)

For a similar deployment, configure the frontend's `VITE_SCAMSHIELD_API_URL` to the backend's public base URL. Configure `GEMINI_API_KEY` privately in the backend host's environment settings, and set `SCAMSHIELD_CORS_ORIGINS` to the exact frontend origin(s). Do not expose the Gemini key through a `VITE_` variable. Free hosting tiers and AI quotas can change; a sleeping free backend may take time to wake up.

Screenshot OCR on a hosted backend requires Tesseract to be installed in that runtime as well as the Python packages. Do not assume it is available just because text and URL analysis work.

## 🧪 Testing and evaluation

The repository includes a `tests/` directory with test/evaluation material. Before running any evaluation script, inspect its code and dependencies. Results depend on the test data, model, and scoring rules; they are not proof of real-world detection accuracy.

When testing changes, include both:
- suspicious examples, such as urgent requests for payment or credentials;
- benign examples, such as routine meeting confirmations or appointment reminders.

## 🔒 Privacy and security

- Never commit API keys, credentials, or private environment files.
- Use fictional examples for public testing; avoid submitting sensitive or confidential content.
- AI providers may process submitted content according to their own service terms and privacy policies.
- A public deployment should use HTTPS, narrowly configured CORS, request limits, and abuse protections.
- Do not rely on a single score to decide whether a payment or disclosure is safe.

## ⚠️ Known limitations

- False positives and false negatives are possible.
- URL structure checks are not the same as a full reputation or threat-intelligence service.
- AI-generated findings may be incomplete or incorrect.
- Scores are not calibrated probabilities unless separately validated.
- A successful health check confirms API responsiveness, not necessarily that every analysis provider or optional feature is available.
- Model quotas, free-host availability, and OCR support depend on deployment configuration.

**If a message claims to be from a bank, government agency, delivery service, or another organisation, verify it using the official app, website, or phone number you find independently—not the contact details in the suspicious message.**

## 🗺️ Roadmap

- [ ] Publish reproducible evaluation metrics
- [ ] Document API endpoints and response schemas
- [ ] Expand benign and scam test coverage
- [ ] Improve URL reputation checks
- [ ] Add privacy-conscious usage and abuse protections

## 📄 License

A license has not yet been specified. Until a `LICENSE` file is added, do not assume this repository grants permission to reuse or redistribute the code.

---

Built as an ongoing project to make digital safety tools more accessible.
