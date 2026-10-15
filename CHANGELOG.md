# Changelog

## 0.1.0 (2026-10-15), first public release

Squashed from the private development history (2026-10-09 to 2026-10-15):

- Core: `inspect( snapshot ) -> decision` and `enforce( decision )`, ordered JSON rules with `when` / `unless`, actions allow, deny, ignore, challenge, ratelimit, tarpit, log; per-rule and global shadow mode.
- Trusted-proxy aware client IP resolution; verified crawlers by published IP lists (Google, Bing, Apple, OpenAI) or forward-confirmed rDNS.
- HMAC day-keyed challenge cookie bound to the client IP; the page reloads once per tab and then waits for a click, so a rejected cookie never loops. Challenge rules stay in shadow until a secret is configured.
- Progressive rate limiter and strike ladder on a pluggable store: memory, or a CacheBox region with memory fallback. Trusted bots are never struck or banned.
- IP lists with seed file, background refresh, minimum-size floor and store persistence.
- Sinks: log, OpenTelemetry (FusionReactor marking opt-in), HAProxy and CrowdSec stubs. Optional ColdBox module adapter.
- rDNS lookups fenced by per-bot ranges, an in-flight budget and a timeout; verdicts cached per IP.
- Config as `.json.cfm` (JSON wrapped in `<cfabort>` and a comment) so it cannot be fetched over HTTP; hot reload on file change is the host application's job (see README).
- Verified on Lucee 6.2.7 and BoxLang 1.18 with `bx-compat-cfml`.
