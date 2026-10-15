# TODO: proof-of-work challenge kind via ALTCHA

Status: not started. Decided 2026-10-09. Slots into `models/Challenge.cfc`
(`issue()` has the `case "pow"` placeholder) as `challenge.kind: "altcha"`.

## Why ALTCHA

- Widget and server libraries are MIT, self-hosted, no account, no third-party calls.
- Classic scheme is implementable with CFML built-ins (`hash`, `hmac`, `toBase64`).
- Widget runs invisibly inside the existing "Checking your browser" page
  (`display="invisible"`, `auto="onload"`, inline challenge data, `workers`).
- Official Java lib `org.altcha:altcha` (Maven Central, MIT) can be loaded by Lucee
  if the v2 KDF modes (Argon2 / Scrypt, GPU-resistant) are ever needed.
- Same widget later protects forms (login, password reset, contact) via the
  standard hidden input, so the rate-limited user handlers get a second payoff.

Position it as the escalation step between the JS-cookie challenge and a deny.
PoW raises cost, it does not stop a scraper that implements SHA-256: a Go client
does a million hashes in well under a second. Its value is killing the
no-JavaScript tier cheaply and making headless browsers burn CPU per page.

## Protocol (classic SHA-256 scheme)

Mint (server):
```
salt      = randomHex(12) & "?expires=" & unixNow + expiresSeconds & "&ip=" & left( hash( clientIP & secret ), 16 )
number    = randRange( 0, maxNumber )          // secret
challenge = hash( salt & number, "SHA-256" )   // lowercase hex
signature = hmac( challenge, secret, "HMACSHA256" )
widget gets { algorithm: "SHA-256", challenge, maxnumber: maxNumber, salt, signature }
```
Solve (widget): brute-force `number` in `[0, maxnumber]` until
`SHA-256( salt & number ) == challenge`; returns base64 JSON
`{ algorithm, challenge, number, salt, signature, took }`.

Verify (server), all must hold:
1. `algorithm == "SHA-256"`
2. `hash( salt & number, "SHA-256" ) == challenge`
3. `hmac( challenge, secret, "HMACSHA256" ) == signature`
4. `expires` in salt is in the future
5. `ip` in salt equals `left( hash( clientIP & secret ), 16 )` (IP binding, our addition)
6. replay ledger: `store.get( "rg:pow:" & challenge )` is null; then
   `store.set( "rg:pow:" & challenge, 1, expiresSeconds )`

## Wiring in the package

- Config (`challenge` block):
  `kind: "altcha"`, `script: "/cfRequestGuard/altcha.min.js"` (or `inlineScript: true`),
  `maxNumber: 100000`, `maxNumberPerStrike: 100000`, `expiresSeconds: 120`,
  `payloadCookie: "rg_pow"`, `workers: 4`.
- `Challenge.issue( snap, rule )`: `case "altcha"` builds the page: widget tag
  with inline challenge JSON; on the `verified` event (or `statechange` with
  `state == "verified"`) read the hidden input named `altcha`, write it to the
  `rg_pow` cookie (`max-age` = expiresSeconds, SameSite=Lax, Secure), reload.
- `Challenge.isPassed( snap )`: keep the HMAC cookie check first. If absent and
  `rg_pow` is present, run verify. On success set `snap.powVerified = true`.
- `cfRequestGuard.inspect()`: when `snap.powVerified`, the returned allow decision
  carries `cookies: { rg_c: token( snap ), rg_pow: "" }` so `enforce()` sets the
  long-lived cookie and clears the payload cookie. This needs a `cookies` struct
  on `Decision.make()` and a loop in `enforce()` that emits `Set-Cookie`
  headers (enforce must not abort for allow; set cookies, then return).
- Difficulty ladder: `maxNumber + strikes( clientIP ) * maxNumberPerStrike`,
  capped. Needs `Strikes.count( ip )` (read-only accessor on the strike key).
- Rule side: `action: "challenge"` gains an optional `kind` override so Tier 1
  can stay `js-cookie` while hostile paths (sitemap, XHR endpoints) use `altcha`.

## Page requirements

- Secure context only (HTTPS or localhost): Web Crypto is required.
- Challenge response headers: `Cache-Control: no-store` (already set) and a CSP
  of its own that allows `worker-src blob:` and inline styles.
- Vendor a pinned `altcha.min.js` (check license file in the tarball) under
  `assets/` in this package; the host app serves it, or `inlineScript: true`
  embeds it (a few dozen kB per challenge response, no route needed).
- Pin the widget major version: attribute names changed between majors.

## Specs to add (`tests/specs/ChallengeSpec.cfc`)

- mint produces a payload the verify step accepts (solve in the spec by brute
  force with a tiny `maxNumber`).
- rejects: wrong signature, wrong secret, expired salt, other IP, replayed payload.
- `issue()` page contains the widget tag and the inline challenge JSON.
- strike count raises `maxnumber` in the issued challenge.

## References

- https://altcha.org/docs/server-integration
- https://altcha.org/docs/server-tldr
- https://altcha.org/docs/integration/widget.md
- https://altcha.org/docs/integration/security-recommendations.md
- https://central.sonatype.com/artifact/org.altcha/altcha
