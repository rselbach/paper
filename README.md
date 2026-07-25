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
PAPER_MAX_STORED_BYTES=1073741824 \
PAPER_MAX_STORED_SECRETS=10000 \
PAPER_CREATE_RATE_PER_MINUTE=60 \
go run .
```

## Security model

- Secrets are encrypted in the browser with Web Crypto AES-GCM.
- The decryption key is stored in the URL fragment after `#`, which browsers do
  not send to the server.
- The browser derives a consume proof from the fragment key, so path-only leaks
  cannot burn a note. Failed consume attempts return a uniform "unavailable"
  response, and creating a note with an id already in use answers exactly as a
  fresh create unless the caller proves it holds the key, so path-only
  observers cannot tell live notes from missing ones on either endpoint.
  Upgrades drop any pre-proof rows that lacked a consume verifier.
- SQLite stores only the random note id, ciphertext, nonce, consume proof, and
  expiry time.
- Revealing a note uses a `POST` action and deletes the encrypted payload before
  returning it to the browser. This provides at-most-once access: a network or
  decryption failure after deletion burns the note without revealing it.
- Expired notes are deleted at startup, opportunistically on reveal, and by a
  periodic cleanup ticker.
- Creation is rate limited, and stored ciphertext is bounded by byte and item
  budgets so anonymous traffic cannot exhaust the host filesystem.
- Absolute share URLs come only from `PAPER_PUBLIC_ORIGIN`. Without it the
  API returns a path and the browser builds the link from its own origin,
  so request `Host` headers cannot mint attacker-controlled URLs.
- Security headers set `no-store`, CSP, `no-referrer`, and related browser
  hardening defaults.

Use HTTPS in production; Web Crypto works on HTTPS and localhost.

## Deploy

Check the existing server without changing it:

```sh
./deploy/deploy-server.sh check
```

Pushes to `main` deploy to `paper.exe.xyz` with GitHub Actions. The workflow
requires the `PAPER_SSH_PRIVATE_KEY` and `PAPER_SSH_KNOWN_HOSTS` repository
secrets.

Deploy the current worktree manually to the same host:

```sh
./deploy/deploy-server.sh deploy
```

The script identifies clean builds by their commit SHA and dirty builds as
`dev`. It runs the checks, cross-compiles for Linux/amd64, verifies the upload
checksum, backs up the current binary and database, installs the new binary,
and verifies both the local service and public endpoint. It rolls back the
binary automatically if the restarted local service is unhealthy, or if the
public health check or version marker fails after install.
