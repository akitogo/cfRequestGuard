# Changelog

## Unreleased

- Challenge page: `challenge.botd: "report"` inlines [BotD](https://github.com/fingerprintjs/BotD) 2.0.0 (MIT, vendored under `vendor/botd`, built with its usage ping disabled) and posts the verdict to `challenge.botdPath` (`/__requestguard/botd`) before the cookie flow runs. The guard answers 204 ahead of any routing and hands the sinks a `BOTD-<kind>` decision (clean, headless_chrome, selenium, ..., timeout/error/nolib) with the issuing rule and the challenged page; no strike, nothing blocked. The post is bound by a nonce (HMAC over day, client IP, rule, page, today or yesterday); anything else is `BOTD-invalid`. Measurement only: a JS challenge is passed by any headless browser, this shows which share of the passes a client-side detector would have caught. Default `off`.
- `snapshot()` reads the request body only for that report request (capped at 4 kB).
- Specs: 5 for the report mode in `ChallengeSpec`.

## 0.2.3 (2026-10-29)

- Sinks that leave the JVM (`haproxy`, `crowdsec`) are delivered off the request thread. Until now every sink ran synchronously inside `emit()`, so a slow HAProxy stats socket or CrowdSec Local API (up to four HTTP calls of `timeoutSeconds` each on a cold token) was paid by the blocked request. New `models/sinks/AsyncSink.cfc` decorator: one short-lived thread per decision, at most `asyncMaxInFlight` (8) in flight per sink, decisions beyond that dropped and logged once a minute rather than queued or delivered inline; a throwing inner sink is counted and logged, never thrown. `"async": false` per sink entry opts out, `"async": true` moves a `log` sink off the thread too; `otel` is never wrapped. The sink list logged at load reads `HAProxySink (async)`.
- CrowdSec LAPI sink on BoxLang: a refused connection comes back as a synthetic 502 with body "Connection Failure", not status 0, so it was reported as a login failure (`CrowdSecLogin`, "login answered 502") instead of a connection failure; both shapes are now `CrowdSecHttp`.
- Specs: `AsyncSinkSpec` (4) with a `SlowSink` double. Kept out of `SinksSpec.cfc`: at that size Lucee 6.2.7 split the compiled class and the specs started calling the wrong closure.

## 0.2.2 (2026-10-28)

- CrowdSec LAPI sink: the login function was named `token()`, which Lucee resolves to the cached `variables.token` string inside the component, so every push failed with "No matching function [TOKEN]"; renamed, and a spec now drives the login path. Sink exceptions are logged once per sink and minute instead of being swallowed; the guard logs its sink list and the CrowdSec sink its LAPI target at load.

## 0.2.1 (2026-10-28)

- CrowdSec LAPI sink, from the first real deployment: one push per address and `repushSeconds` (default 600) instead of one per request of a banned client; `origin` configurable (`cscli` for bouncers that only act on known origins); `machineId` accepts `env:NAME` like the password, so one config serves several nodes; `User-Agent: cfRequestGuard/<version>`, which the LAPI's login parser requires; an information line per successful push.

## 0.2.0 (2026-10-28)

- Verifier: a crawler allow-list whose generation stamp is older than `maxAgeDays` is still used for verification. Before, a stale list made the bot "unusable" and every client wearing its UA was trusted unverified, skipping the strike ban and every `unless: trustedBot` rule; Bing's bingbot.json has carried `creationTime` 2024-01-03 for years, so a spoofed bingbot UA bypassed everything. Only a list with no data at all still disarms. The reason string carries "(list stale)". New `Lists.hasData()`.
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
