# Changelog

## Unreleased

- Strike weight: a deny rule's `strike` takes a number besides true/false, so one hit can count for several strikes (`strike: 10` bans on the first hit with the default threshold of 10). Meant for honeypot paths no browser and no well-behaved crawler ever requests.
- CrowdSec sink: besides the local JSON log for acquisition it can now push selected decisions (default: strike bans) as alerts with a ready decision to a CrowdSec Local API, local or remote (`lapi` block: url, machineId, password with `env:` support, labels, scenario, type, duration, timeout). Machine login with a cached token, one retry on 401, failures logged and never thrown into the request.
- docs/crowdsec.md: step-by-step for both paths (acquisition, parser, scenario, machine registration, verification); README "Edge feedback" section.

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
