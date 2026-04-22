# 🛡️ Cyber-Sentinel — Threat Intelligence Platform

> Multi-layer URL threat analysis with a professional deep-dark glassmorphism UI.

---

## ✨ Features

| Layer | What it does |
|---|---|
| **Heuristic Engine** | 10+ regex patterns, IP-hostname detection, subdomain depth, URL length analysis |
| **Reachability Probe** | HTTP/HTTPS status, SSL/TLS cert validation, redirect chain tracking |
| **VirusTotal API** | Real-time cross-reference against 70+ AV engines (optional) |
| **Live Log Terminal** | Animated console output with professional scan sequence |
| **Risk Meter** | Animated 0–100 composite threat score with color-coded gauge |

---

## 🚀 Run Locally

```bash
pip install -r requirements.txt
python app.py
# → http://localhost:5000
```

## 🔑 VirusTotal API (optional)

Get a free key at https://www.virustotal.com/gui/join-us  
Then set the environment variable:

```bash
export VIRUSTOTAL_API_KEY=your_key_here
```

Without it, the app still works using heuristics + reachability.

---

## ☁️ Deploy to Render

1. Push this folder to a GitHub repo
2. Create a new **Web Service** on [render.com](https://render.com)
3. Connect repo → Render auto-detects `render.yaml`
4. Add `VIRUSTOTAL_API_KEY` in the Environment dashboard
5. Deploy 🚀

---

## 📁 Structure

```
cyber-sentinel/
├── app.py           ← Flask backend (single file)
├── index.html       ← Full frontend (single file, Tailwind CDN)
├── requirements.txt
├── render.yaml      ← Render deployment config
└── README.md
```

---

## 🏆 Hackathon Notes

- **Zero external dependencies** in frontend (CDN only)
- **Never crashes** — all exceptions caught and returned as JSON errors  
- **Works without VT API key** — degrades gracefully
- **Sub-100ms UI response** — terminal logs appear instantly, backend runs async
