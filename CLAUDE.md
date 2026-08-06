# Concord

Self-hosted E2E-encrypted chat: Rust relay server (`server/`, sees ciphertext only) + Tauri desktop client (`client/`, static UI in `client/ui/`).

## UI rules

- **No emojis in the UI.** Icons are inline stroke SVGs (feather-style: `viewBox="0 0 24 24"`, `stroke="currentColor"`, `stroke-width="2"`, class `ic`). Static markup in `index.html`, or the `ICONS` map + `svgIcon()` helper in `app.js` for dynamic nodes.
- Never build icon-plus-text content with `innerHTML` — message text and banners can contain peer-supplied names. Append `svgIcon(...)` and `document.createTextNode(text)` separately.
- Fonts are bundled locally in `client/ui/fonts/` — never load fonts or any asset from a CDN; the client must not phone home.
- Design tokens live as CSS variables in `client/ui/style.css` (moss/paper/amber system). Use them; don't hardcode new colors.
