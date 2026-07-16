# Finspark Prototype — README

AI-Driven Correlation of Cybersecurity Telemetry & Transactional Behaviour.
A hackathon prototype demonstrating fraud detection, cyber threat correlation,
quantum risk monitoring, and explainable AI — built on synthetic data only.

## Project Structure (expected)

```
Finspark prototype/
├── api.py / main.py         # FastAPI backend — ML model, correlation, scoring endpoints
├── data_generator.py        # Synthetic data generation
├── fraud_model.py           # Isolation Forest + raw/correlated scoring
├── explainability.py        # SHAP or fallback explainability
├── dashboard.py             # (optional) Streamlit dashboard version
├── web/
│   └── index.html           # Frontend UI, served via Live Server
└── requirements.txt
```

## Running the backend (FastAPI)

```powershell
pip install -r requirements.txt
python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

Once running, confirm it's alive at:
```
http://127.0.0.1:8000/health
http://127.0.0.1:8000/docs      # interactive API explorer
```

**If you get a "port already in use" error (`WinError 10048`):**
Something is already bound to port 8000 — likely a previous uvicorn process still running.

```powershell
netstat -ano | findstr :8000
taskkill /PID <the_pid_shown> /F
```

Or just run on a different port and update the frontend's fetch URLs to match:
```powershell
python -m uvicorn api:app --host 0.0.0.0 --port 8001
```

## Running the frontend

The frontend at `web/index.html` is a static HTML/JS/CSS app — no build step needed.

**Using VS Code Live Server (recommended for this prototype):**
1. Open the project folder in VS Code.
2. Right-click `web/index.html` → **"Open with Live Server"**.
3. It will open at `http://127.0.0.1:5500/web/index.html`.

The frontend calls the backend at `http://127.0.0.1:8000` — make sure the backend is running first, or the dashboard will show empty/failed data fetches.

**CORS note:** the backend already has CORS enabled for all origins (`allow_origins=["*"]`), so a Live Server origin like `127.0.0.1:5500` calling a backend on `127.0.0.1:8000` will work without extra configuration.

## Running order (every time you demo)

1. Start the backend first: `python -m uvicorn api:app --host 0.0.0.0 --port 8000`
2. Wait for `Application startup complete.` in the terminal.
3. Then open `web/index.html` via Live Server.
4. If the frontend loads before the backend is ready, just refresh the page once the backend log shows it's up.

## Demo scenarios

Use the scenario controls in the UI to trigger repeatable outcomes rather than relying on random data:
- **Safe Transaction** — no security signals, should release normally.
- **SIM-Swap Fraud** — SIM swap + new device, should escalate to high risk and hold.
- **Large-But-Legitimate Transaction** — large amount, no security signals — should show a **lower correlated score than raw score**, demonstrating false-positive avoidance live.

## Optional: Streamlit dashboard alternative

If using `dashboard.py` instead of/alongside the web frontend:
```powershell
streamlit run dashboard.py
```
You may see deprecation warnings like:
```
`use_container_width` will be removed after 2025-12-31. Use `width='stretch'` instead.
```
This is harmless and doesn't affect functionality — Streamlit is just flagging an old parameter name. Safe to ignore for the hackathon demo; can be cleaned up later with a find-and-replace across the file.

## Outcome checklist (what to point to during judging)

| Outcome | Where to show it |
|---|---|
| Correlates cyber telemetry + transactions | Correlation graph panel |
| Detects cyber threats proactively | Sequence detection flag on the SIM-swap scenario |
| Identifies fraud patterns | Fraud Detection panel, Isolation Forest scores |
| Detects quantum-related attack indicators | Quantum Risk Monitoring panel |
| Reduces false positives | Raw vs. correlated score shown together, "Large-But-Legitimate" scenario |
| Explainable AI-driven threat intelligence | Explainable AI panel, factor breakdown + narrative |

## Notes

- All data is synthetic (Faker-generated) — no real banking or telecom data is used anywhere.
- This is a demo-scoped prototype: the ML model is trained on synthetic data at startup, not historical production data.
- If the backend isn't running, the frontend should ideally fail gracefully — worth confirming this behavior before a live demo so a dropped connection doesn't stall the presentation.
