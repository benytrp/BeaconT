# ψ∞ Root Beacon → BridgeFile + ICL (Offline)

This repository is generated from a single HTML file and split into conventional project files.

## Structure
- `index.html` — main entry (rewired to external CSS/JS)
- `css/` — extracted styles (1 files)
- `js/` — extracted scripts (1 files)
- `assets/` — placeholder for images/fonts/media
- `data/bridgefile.json` — missing at package time
- `docs/foundation.md` — missing at package time
- `manifest.json` — integrity (sha256 + size)

## Dev
```bash
python -m http.server 5173
# open http://localhost:5173
```
