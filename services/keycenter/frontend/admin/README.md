# KeyCenter Admin UI

This directory is the first cut of the dedicated Vue 3 frontend workspace for the KeyCenter admin UI.

Current intent:

- keep the existing visual output unchanged
- move UI source out of the embedded single HTML file
- build static assets into `internal/api/ui_dist/`
- let Go serve the built assets first, then fall back to the legacy embedded HTML
- use a real Vue SFC entry instead of a single inline HTML script block

Commands:

```bash
npm install
npm run build
```

Repository helper:

```bash
../../scripts/build-admin-ui.sh
```

Development:

- `VEILKEY_UI_DEV_DIR` can point only to a built UI directory that contains `index.html` and `assets/`
- KeyCenter no longer falls back to the legacy `admin_vue_preview.html`

Current structure:

- `src/App.vue`
  - SFC entry for the admin shell
- `src/useAdminApp.js`
  - migrated admin state and lifecycle logic
- `src/admin.css`
  - migrated admin styles
- `index.html`
  - minimal Vite shell only

Scope of this cut:

- dedicated frontend workspace introduced
- Vite build introduced
- built output is copied into `internal/api/ui_dist/`
- no visual redesign
- no large logic rewrite yet

Remaining migration work:

- remove legacy imperative render paths from the admin app
- split `useAdminApp.js` into page-level modules
- replace remaining `v-html`/imperative render paths with Vue-owned templates
- remove dependency on the legacy `admin_vue_preview.html` fallback
