# Working notes

Where things stand and what to pick up next. Updated 2026-10-28. The README
"Status" section is the public summary; this file is the longer version for
whoever continues the work.

## State

- Released: 0.2.0 (2026-10-28), tag `v0.2.0`: CrowdSec LAPI sink (still
  unverified against a real Local API, marked experimental in the README),
  strike weight, stale allow-lists still verify (a stale list used to make
  every client wearing the bot's UA trusted). 63 specs green on Lucee 6.2.7,
  BoxLang check clean. 0.1.0 (2026-10-15) was the first public release.
- In production on a two-node Lucee 6.2.9 site behind HAProxy since
  2026-10-14, enforce mode, CacheBox store, log sink only. The site's own
  rules live in its private config and are not part of this repository.

## Not yet verified

- **CrowdSec LAPI sink against a real Local API.** The alert follows the v1
  alert model with every required field set (`scenario`, `scenario_hash`,
  `scenario_version`, `message`, `events_count`, `start_at`, `stop_at`,
  `capacity`, `leakspeed`, `simulated`, `source`, `events`, plus `decisions`).
  Specs check the shape and that an unreachable LAPI is swallowed; nobody has
  yet posted one to a running CrowdSec. First check on a CrowdSec host:
  1. `cscli machines add requestguard-test --password x`, point the sink at it
     with `labels: ["BLOCK-403-t"]` or trigger a real strike ban.
  2. Expect the address in `cscli decisions list` with reason
     `cfRequestGuard/strike-ban`; `cscli alerts inspect <id>` shows the meta.
  3. A 422 in the guard's log means the LAPI rejected a field; adjust
     `alert()` in `models/sinks/CrowdSecSink.cfc` and the payload sample in
     `docs/crowdsec.md` together.
  Also unverified: the parser and scenario YAML in `docs/crowdsec.md`
  (`JsonExtract` statics, `evt.StrTime` handling, `type: trigger` with
  `blackhole`). Run `cscli explain --file ... --type requestguard` once.
- Adobe ColdFusion: never run. `cfhttp` with a body param, `fileAppend`,
  `cfthread` with attributes and `createObject("java", ...)` for the atomics
  are the places to look first.

## Next release (0.3.0)

1. Verify the LAPI sink (above) and drop the "experimental" note in the README.
2. Bump `version` and the `location` tag in `box.json`, move the CHANGELOG
   "Unreleased" block under `## 0.2.0 (date)`.
3. `git tag v0.3.0 && git push --tags`, `gh release create v0.3.0 --notes-file CHANGELOG.md`
   (or paste the section), `box publish` from the package root.
4. Downstream clones: `git submodule update --remote` or pin the new SHA.

## Open items, rough priority

1. **CI workflow**: GitHub Actions running `tests/runner.cfm` on CommandBox
   with `lucee@6.2.7+16` and `boxlang@1.18`, text reporter, fail on
   `[Failed: 0]` missing. Skipped on purpose at release time; the local
   recipe is in the README "Tests" section.
2. **Config as a struct or `.cfc`**: the facade already accepts a struct;
   `Config.read()` could load a `.cfc` returning one (~20 lines). Decided
   2026-10-15 to keep JSON as the documented format for now.
3. **ALTCHA proof-of-work challenge kind**: design in
   `docs/altcha-pow-challenge.md`, placeholder `case "pow"` in
   `models/Challenge.cfc`.
4. **IPv6 in `Cidr`**: currently IPv4 only; swap the internals for seancfoley
   IPAddress or a 128-bit range table. Lists with IPv6 entries are skipped
   with a count today.
5. **Redis store with native INCR**, the first distributed store; the
   CacheBox store is only cluster-wide with a distributed provider.
6. **HAProxy renderer** for `exportable` rules (map/ACL snippets), a
   **yauaa** client-hints cross-check, a **Web Bot Auth** signature verifier.
7. **File-backed IStore**: only if someone asks; the seed file already covers
   a cold start without a shared store.

## Engine and platform quirks to remember

- Lucee compiles templates once per server; the test servers need a restart
  after CFC edits (`box server restart` forgets `cfengine=` when started with
  `saveSettings=false`, so start fresh with the full command).
- Lucee rejects `( x ?: {} ).key ?: d` ("left operand of Elvis must be a
  variable"); assign the struct to a variable first.
- `reFind( pattern, text, 1, true )`: the start position comes before the
  sub-expression flag; `reFind( p, t, true )` returns an integer.
- BoxLang `isJSON` rejects duplicate keys, date masks are java.time
  (`mm` is minutes), class identity is by resolved path, scopes must not be
  shadowed. Verify with `boxlang check` and a throwaway BoxLang server.
- `encodeForJavaScript` is ESAPI and missing on some installs; the challenge
  page escapes with its own `jsStr()`.
- rDNS: never resolve on the request thread without the fence
  (`rdns.maxInFlight`, `timeoutMs`); a single upstream resolver outage
  otherwise parks every Tomcat thread.
- Rules are first-match: a `ratelimit` rule must sit above the `challenge`
  tiers, or a client looping on the challenge page never reaches it.
- When a deploy "hangs" after a restart, read the application's own error
  handler first: an onError that logs at info level is invisible under a
  server log config that keeps only errors.

## Operating lessons from the first production weeks

- Shadow a new rule for a week; the log line pairs with the old rule's line.
- Google Lighthouse (PageSpeed) sends no Sec-Fetch headers and its own
  X-Forwarded-For; it is verified by the googleCrawler list, and the tiers
  skip `ipList:googleCrawler`.
- archive.org_bot was the only regular rate-limit customer; it is trusted via
  fenced rDNS within 204.62.248.0/23.
- A normal office behind one NAT shares the `limitWithSession` budget (60 per
  3 s window); raise it before lowering anything else if a customer reports
  503s.

## BotD report mode (unreleased, 2026-10-31)

- Why: a JS cookie challenge is passed by headless Chrome pools; measured on a
  live site, most challenged clients fetched the full page afterwards. Report
  mode shows what share a client-side detector would have flagged before anyone
  builds a gate on it.
- Gate mode is deliberately not built yet: it means the page no longer carries
  the token and the endpoint issues the cookie (Set-Cookie on a clean verdict),
  which also makes the verdict forgeable by anyone who reads the script. Decide
  after a week of `BOTD-` lines next to the `CHALLENGE-` lines of the same IPs.
- vendor/botd is a build artefact with one patch (monitoring default off);
  rebuild steps in vendor/botd/README.md. Check the upstream repo before a
  version bump: the roadmap is stability-only.
