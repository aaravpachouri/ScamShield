# ScamShield NextGen — React frontend + local API adapter

A cinematic, responsive ScamShield product website with an animated neural-signal visual, capability explorer, interactive pipeline, message/link/screenshot playground, evidence results, evaluation notes, technical profile, developer quick start, and roadmap.

## Important architecture note

This uploaded snapshot includes the React/Vite frontend and a FastAPI adapter. It does **not** include the existing `core/` analysis modules. To run real analysis, place `api.py` and `requirements-api.txt` in the same project root as your existing `core/` directory, or copy the `core/` directory into this root. Do not overwrite your existing `core/` files.

The frontend never invents a response. If the API is offline, it displays an error and labels the service as unavailable.

## Start the frontend

From `frontend/`:

```powershell
npm install
npm run dev
```

Open the URL printed by Vite (normally `http://127.0.0.1:5173`).

## Start the API

From the project root, where `api.py`, `requirements-api.txt`, and the real `core/` directory are available:

```powershell
python -m pip install -r requirements-api.txt
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

The frontend defaults to `http://127.0.0.1:8000`. To override this, create `frontend/.env.local` with:

```dotenv
VITE_SCAMSHIELD_API_URL=http://127.0.0.1:8000
```

Restart Vite after changing environment variables.

## Screenshot OCR

Screenshot mode requires Pillow, `pytesseract`, and the Tesseract OCR desktop program installed on the machine running the API. Supported uploads are PNG, JPEG, and WEBP, up to 8 MB.

## Current limitations

- The API is local-first and does not persist submitted messages in this adapter.
- Ollama availability is checked by the real analysis request, not guaranteed by the health endpoint.
- URL inspection is heuristic and is not a full threat-intelligence/reputation lookup.
- Risk scores are prototype heuristic scores, not calibrated fraud probabilities.
- Public benchmark results are not yet published.
- The model details depend on the local Ollama installation; this is not a newly trained foundation model.

## Technology

- React + TypeScript + Vite
- Framer Motion
- Lucide React
- Custom responsive CSS / SVG animation
- FastAPI adapter for the existing ScamShield analyzer
