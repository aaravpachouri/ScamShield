# 🛡️ ScamShield

**An AI-powered scam detection and digital safety platform.**

ScamShield helps users examine suspicious messages, links, and screenshots to identify potential scam indicators, understand warning signs, and make more informed decisions online.

> **Project status:** Active prototype. ScamShield provides risk assessments, not definitive proof that something is or isn't a scam.

## ✨ Features

- **Message analysis** — examine suspicious texts for potential fraud indicators.
- **URL inspection** — analyze links using heuristic signals.
- **Screenshot analysis** — extract text from supported screenshots using OCR.
- **AI-assisted detection** — use Gemini or a local Ollama model for contextual analysis.
- **Risk assessment** — combine available signals into a structured assessment.
- **Evidence-based explanations** — surface warning signs instead of returning only a label.
- **Scam awareness** — explore educational examples to learn common scam patterns.

Feature availability depends on the configured model, API connection, and runtime environment.

## 🧠 How It Works

1. **Input:** The user submits a message, link, or supported screenshot.
2. **Extraction:** Screenshot text is extracted using OCR when applicable.
3. **Analysis:** The system evaluates available heuristic signals and AI-generated findings.
4. **Fusion:** The analysis components combine their findings into a risk assessment.
5. **Output:** The frontend presents the result and relevant warning signs.

## 🏗️ Technology Stack

- **Frontend:** React, TypeScript, Vite
- **UI:** Custom CSS, Framer Motion, Lucide React
- **Backend:** Python, FastAPI
- **AI:** Google Gemini API or local Ollama
- **Screenshot processing:** Pillow, pytesseract, Tesseract OCR

## 📂 Project Structure

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

## 🚀 Run Locally

### Prerequisites

- Python 3.12+
- Node.js and npm
- A Gemini API key or a configured local Ollama installation
- Tesseract OCR for screenshot analysis

### 1. Install backend dependencies

From the project root:

```powershell
python -m pip install -r requirements.txt
```

### 2. Configure AI access

Set your Gemini API key as an environment variable. Never commit real API keys to GitHub.

```powershell
$env:GEMINI_API_KEY = "YOUR_API_KEY"
```

Alternatively, configure Ollama and the model specified by your project settings.

### 3. Start the backend

```powershell
python -m uvicorn api:app --reload --host 127.0.0.1 --port 8000
```

Check the health endpoint:

```text
http://127.0.0.1:8000/api/health
```

### 4. Start the frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the local URL displayed by Vite.

The frontend API URL can be configured with `VITE_SCAMSHIELD_API_URL` when required. Restart the frontend development server after changing environment variables.

## 🧪 Testing

The `tests/` directory contains scam-analysis test cases and evaluation artifacts.

Run the evaluation script from the project root:

```powershell
python tests/evaluate_scamshield.py
```

Review the script and its dependencies before running it. Evaluation results depend on the dataset, model, and scoring criteria; they should not be interpreted as proof of real-world detection accuracy.

## 🔒 Privacy and Security

- Never commit API keys, credentials, or private environment files.
- Avoid submitting real financial credentials, passwords, OTPs, or sensitive personal information.
- Do not assume that submitted data is private merely because the frontend does not store it locally. External AI providers may process submitted content.
- Public deployments should use HTTPS, restrict CORS appropriately, and apply suitable request limits and abuse protections.

## ⚠️ Limitations

- A risk assessment can produce false positives and false negatives.
- URL heuristics are not equivalent to a comprehensive threat-intelligence service.
- AI-generated explanations can be incorrect.
- Risk scores are not calibrated probabilities of fraud unless separately validated.
- A successful health check does not necessarily mean every analysis provider is available.
- Model quotas, hosting availability, and OCR support depend on the deployment configuration.

**Never rely on ScamShield alone to authorize payments, disclose sensitive information, or decide whether a message is safe. Verify important claims through trusted official channels.**

## 🗺️ Roadmap

- [ ] Public deployment and health monitoring
- [ ] Documented API endpoints and response schemas
- [ ] Reproducible evaluation metrics
- [ ] Expanded scam datasets and adversarial testing
- [ ] Improved URL reputation checks
- [ ] Privacy-focused usage analytics and abuse prevention

## 📄 License

A license has not yet been specified. Add a `LICENSE` file before describing the project as open source.

---

Built as an ongoing project to make digital safety tools more accessible.

- React + TypeScript + Vite
- Framer Motion
- Lucide React
- Custom responsive CSS / SVG animation
- FastAPI adapter for the existing ScamShield analyzer
