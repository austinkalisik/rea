# AusKal REA deployment

The unified dashboard is documented in [unified/README.md](unified/README.md).

- Live: https://dev.auskal.tech
- Account: existing GodsEye credentials; no password change required.
- Web entrypoint: `server.mjs` imports `unified/server.mjs`.
- Heavy engines: `unified/Dockerfile.engines`, separate queued/sandboxed workers.
- HTTPS, persistent sessions, and 24-hour input/report expiry are preserved.

See the detailed README for supported inputs, engine coverage, setup, optional AI, validation, limits, maintenance, and rollback.
