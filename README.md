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
- The browser derives separate create and consume proofs from the fragment key.
  The note id commits to the create proof, so a path-only observer cannot submit
  a valid creation request for that id. The consume proof prevents the same
  observer from burning the note, and failed consume attempts return a uniform
  "unavailable" response. Upgrades drop any pre-proof rows that lacked a
  consume verifier.
- SQLite stores only the note id commitment, ciphertext, nonce, consume proof, and
  expiry time.
- Creation IDs commit to a server-referenced timestamp. Creation retries are
  accepted for ten minutes, with one minute of clock tolerance. A separate table
  retains only accepted IDs and retry deadlines for eleven minutes, capped at
  10,000 records. Consuming a note deletes its payload but leaves this short-lived
  receipt, preventing retries from reviving it. After receipt cleanup, the
  timestamp check rejects the old request. Existing shared links remain readable;
  pages loaded before this protocol update must reload before creating a note.
- Revealing a note uses a `POST` action and deletes the encrypted payload before
  returning it to the browser. This provides at-most-once access: a network or
  decryption failure after deletion burns the note without revealing it.
- Expired notes are deleted at startup, opportunistically on reveal and on
  creation, and by a periodic cleanup ticker.
- Creation is rate limited, and stored ciphertext is bounded by byte and item
  budgets so anonymous traffic cannot exhaust the host filesystem. Creation
  purges expired rows before measuring, so the budgets bound the database and
  not just its unexpired contents.
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
checksum, backs up the current binary and service definition, installs the new
binary, and verifies both the local service and public endpoint. It rolls back the
binary automatically if the restarted local service is unhealthy, or if the
public endpoint answers but reports an error or the wrong version. Both public
checks run on the server and are retried; an endpoint that cannot be reached
at all leaves the new binary in place, since that says nothing about the build.

The deployment script does not back up the secrets database. Database snapshots
retain ciphertext after a note is consumed or expires, so exclude it from host
backup jobs as well.
