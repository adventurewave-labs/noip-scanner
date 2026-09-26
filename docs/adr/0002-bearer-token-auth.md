# ADR-0002: A bearer token instead of a user/MFA stack

- **Status:** accepted, 2026-09-25
- **Decides:** PRD §10 D2 (option c)

Every `/api/*` route requires `Authorization: Bearer $NOIP_API_TOKEN`. The comparison is constant-time, and the token can also be supplied as a file via `NOIP_API_TOKEN_FILE`. The server refuses to start without a token of at least 16 characters. There are no users, sessions, MFA, Mongo or Redis. If a hosted multi-user demo is ever needed, put an identity proxy in front (Cloudflare Access or oauth2-proxy) rather than building an auth system. Old issue #5, "SMS/email MFA", is won't-do.
