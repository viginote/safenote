[README_MAP_LAYERS.md](https://github.com/user-attachments/files/28513895/README_MAP_LAYERS.md)
# SafeNote Map Layers Upgrade

Upload to Render:
- safenote_api.py
- safenote_sa.html
- nhw_portal.html

What this adds:
- Public app suburb searches always draw a red area outline.
- If a true polygon boundary is unavailable, SafeNote draws an approximate red operational circle instead of only a blue pin.
- Public app shows a short boundary/approximation notice.
- NHW portal gets suburb/patrol-area search controls.
- NHW portal gets a risk layer using colour-coded circular cells:
  - green = low
  - yellow = medium
  - orange = high
  - red = critical
- API adds `/api/nhw/area-risk` for risk-layer shading.

This is groundwork for future patrol planning, colour-coded operational areas and suburb-level intelligence.
