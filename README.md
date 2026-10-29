# Gift Exchange Marketplace

A self-hosted, multi-user marketplace built with Python 3, SQLite and Pillow for safe image processing.

## Run locally

```sh
cd gift-marketplace
python3 -m pip install -r requirements.txt
python3 server.py
```

Open `http://localhost:8000`. Use two browser profiles or a private window to test separate accounts. The database in a fresh installation starts empty; list a gift in each account to test requests and chat. Data is stored on the server in `marketplace.sqlite3` and survives server restarts. Set `PORT` and `DB_PATH` to change the port or database location.

For an HTTPS reverse proxy, run with `SECURE_COOKIE=1` to enable Secure cookies and HSTS. Do not set this for plain HTTP local testing: browsers will not send secure cookies over HTTP. Ensure the proxy forwards the original Host header, serves only HTTPS, and applies a suitable HSTS policy. If your proxy rewrites Host, set `APP_ORIGIN` to the exact public origin, for example `https://gifts.example.com`; do not use a wildcard. Back up the database securely and never include it in a public code repository. Only the index, app.js and explicitly defined API routes are served.

## Try the app

1. Register two accounts in separate browser sessions. New passwords need at least 10 characters.
2. Each person lists an unopened gift, optionally uploads one photo (JPG, PNG or WebP, up to 8 MB), and completes the eligibility self-check. Photos appear on the discovery card and listing page.
3. Open a listing to message the owner, report the listing, or send a buy/swap request.
4. The recipient can accept or decline in Requests. Accepting reserves the gifts and declines conflicting pending requests.
5. Either party can propose a public pickup; the other party can confirm. Messages refresh every five seconds; the latest 500 are shown.
6. In a chat, either participant can block the other or report the conversation. A block prevents messages in either direction and prevents new requests between those two accounts. The blocker can unblock. Existing request status is not changed automatically.

Nearby uses the user's self-reported city, not GPS. An accepted request reserves the entire listing even if its quantity is greater than one. Payments are not processed. Food eligibility is self-attested, not verified or legal advice. Date checks do not establish food safety.

## Review reports

Reports are recorded in SQLite and must be reviewed by a responsible operator; filing a report does not automatically take down content or sanction anyone. On the server, using the same `DB_PATH` as the app:

```sh
python3 review_reports.py list
python3 review_reports.py show 1
python3 review_reports.py resolve 1
```

Replace `1` with an actual report ID. `show` can display private message content, so restrict access to trusted, trained moderators and handle output as sensitive data. `resolve` only marks the report closed; it does not remove content, ban accounts, or notify the reporter. Build appropriate moderation tools, policies, and staffing before public use.

## Security included

- New passwords are salted and hashed using scrypt; existing PBKDF2 hashes upgrade on successful login. Passwords are never stored in plaintext.
- Random server-side session tokens are stored hashed, expire after 30 days, and use HttpOnly/SameSite cookies; logout revokes the current session.
- JSON-only state-changing endpoints reject a supplied cross-origin Origin. Security headers include a a baseline CSP with same-origin scripts, no-sniff and referrer policy. Inline styles remain allowed; CSP is defense in depth and does not eliminate XSS risk.
- Basic in-process request limits cover login/registration, listings, conversation starts, messages, trade requests and reports. Authentication throttling uses the immediate network-peer IP, not untrusted forwarded IP headers. In a proxy deployment many people can share that IP and be limited together. Limits reset on restart, aren't shared between instances, and are not a substitute for edge/WAF and per-account abuse protection.
- Uploaded photos are resized in the browser and validated and re-encoded as JPEG on the server, removing embedded metadata. The database stores the resulting image. Photos are public while the listing is available; do not upload sensitive images. Photo moderation is not automatic.
- Participants have access control for chats and requests; blocking prevents new messages and requests in both directions. Reports require an account and relevant access.

## Before any public launch

This is a functional starting point, **not production-ready or independently security-audited**. It lacks email verification, password recovery, proper shared rate limiting, abuse investigation and enforcement tools, notifications, payments, food-safety verification, production-grade monitoring, data retention/deletion workflows, and comprehensive privacy and legal policies. In particular, the standard-library HTTP server and the in-process limits are intended for development/testing, not high-risk public deployment. Arrange professional security review, privacy/legal review for India, a hardened production server and HTTPS reverse proxy, monitoring, backups, and a real moderation process first.

## Chat privacy

Only conversation participants can access messages through the API. Messages are plaintext in SQLite and visible to the server operator; they are not end-to-end encrypted. Don't share secrets or financial details. There are no push notifications or attachments.

## Embedded preview login

The hosted preview may be embedded in a context where browsers block third-party cookies. The preview runs with `ALLOW_PREVIEW_TOKEN=1` to permit a per-tab token fallback in same-origin JSON request bodies and partitioned secure cookies. The body transport avoids collisions with preview-proxy authentication and never puts tokens in URLs. The token is held in sessionStorage when available (or memory otherwise), sent only to same-origin APIs, and revoked on logout. Unlike an HttpOnly cookie, JavaScript can read this token, so any XSS vulnerability could steal it. This compatibility mode is intended only for the preview, not a public deployment. When the flag is unset, the server does not return or accept bearer tokens and uses HttpOnly cookies only.
