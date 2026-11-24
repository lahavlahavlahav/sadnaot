# sadnaot.liloubooks.com

Lilou Books workshop board: workshops, prep checklists, inventory and linked
correspondence, behind one shared password. Hosted on Vercel.

- `public/index.html`: the board (static page).
- `api/[action].js`, `api/_lib.js`: login, data, Google Calendar (iCal) sync.
- Data lives in a private Vercel Blob store connected to the project, not in this repo.
- Env: `SADNAOT_PASSWORD` (set in Vercel), `BLOB_READ_WRITE_TOKEN` (injected by the Blob store).
