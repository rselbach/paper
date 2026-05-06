# Paper

Paper is a tiny one-time secret sharing site built with Go and pure-Go SQLite.

## Run

```sh
go run .
```

Then open <http://localhost:8080>.

Optional settings:

```sh
PAPER_ADDR=:8080 \
PAPER_DB=paper.db \
PAPER_PUBLIC_ORIGIN=https://paper.example.com \
PAPER_SECRET_TTL_HOURS=168 \
PAPER_CLEANUP_INTERVAL_MINUTES=60 \
PAPER_MAX_SECRET_BYTES=65536 \
go run .
```

## Security model

- Secrets are encrypted in the browser with Web Crypto AES-GCM.
- The decryption key is stored in the URL fragment after `#`, which browsers do
  not send to the server.
- The browser derives a consume proof from the fragment key, so path-only leaks
  cannot burn a note.
- SQLite stores only the random note id, ciphertext, nonce, consume proof, and
  expiry time.
- Revealing a note uses a `POST` action and deletes the encrypted payload before
  returning it to the browser.
- Expired notes are deleted at startup, opportunistically on reveal, and by a
  periodic cleanup ticker.
- In production, set `PAPER_PUBLIC_ORIGIN` so generated share links use a
  trusted configured origin instead of request headers.
- Security headers set `no-store`, CSP, `no-referrer`, and related browser
  hardening defaults.

Use HTTPS in production; Web Crypto works on HTTPS and localhost.
