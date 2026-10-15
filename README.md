# cfRequestGuard

Bot, scraper and abuse defence for CFML applications. No framework dependency:
it is a plain CFC package that runs in `Application.cfc` before any framework
bootstraps. ColdBox, CacheBox, HAProxy and CrowdSec are optional adapters.

## Design in one paragraph

`inspect()` decides, `enforce()` acts. `inspect()` takes a request *snapshot*
(a plain struct) and returns a *decision* (a plain struct). It never touches
`cgi`, headers or output, so it can be unit-tested by replaying recorded scraper
signatures and it can run in **shadow mode** next to existing code. `enforce()`
is the only place that sets headers, writes a body and aborts.

## Install

```
box install cfrequestguard
```

or clone this repository and add a mapping `/cfRequestGuard` to its root.

## Wire into Application.cfc

```cfml
boolean function onApplicationStart(){
    application.requestGuard = new cfRequestGuard.RequestGuard( expandPath( "/config/requestguard.json.cfm" ) );
    ...
}

boolean function onRequestStart( string targetPage ){
    var guard = application.requestGuard;
    try {
        var decision = guard.inspect( guard.snapshot() );
    } catch ( any e ) {
        writeLog( file = "requestguard", type = "error", text = "cfRequestGuard inspect failed: #e.message# | #cgi.PATH_INFO#" );
        return true;             // a broken guard must never take the site down
    }
    // session timeout is an engine setting, so the host applies it before enforce() aborts
    if ( decision.sessionTimeoutSeconds > 0 ) {
        this.sessionTimeout = createTimeSpan( 0, 0, 0, decision.sessionTimeoutSeconds );
    }
    guard.enforce( decision );   // no-op for allow / log / shadow
    ...
}
```

## Shadow and enforce

There are three switches, from coarse to fine:

1. **Global `mode`** at the top of the config: `"mode": "shadow"` or `"mode": "enforce"`.
   The example ships in shadow. In shadow the whole rule set runs, every decision
   is written to the sinks with a `SHADOW` prefix (`SHADOW BLOCK-403-fake-googlebot ...`)
   and `inspect()` returns allow with the would-be decision attached as
   `decision.shadow`. Nothing is blocked, challenged or rate-limited. Strikes are
   not counted either, so nobody gets banned by a rule you are only watching.
2. **Per-rule `mode`**: `{ "name": "new-signature", "action": "deny", "mode": "shadow", ... }`.
   Only that rule is reported instead of enforced; the rest of the config stays
   in enforce. This is how a new rule earns its place: shadow it for a week, read
   the log, then delete the `mode` key.
3. **Challenge rules without a secret** are shadowed automatically. Until
   `secret` resolves to a value, every `challenge` decision is logged as
   `SHADOW CHALLENGE-...` with "no secret configured", because a random per-start
   secret would bounce visitors between nodes.

To change the mode, edit the config file and let the host reload the guard. The
guard reads its config once, at `init()`; whether an edit is picked up without a
restart is the host's job. The wiring above only loads it at application start,
so either reinit the application or add a cheap mtime check:

```cfml
// in onRequestStart, before inspect(); checks the file date once a minute
if ( !structKeyExists( application, "requestGuardStamp" )
     || dateDiff( "s", application.requestGuardChecked ?: createDate( 2000, 1, 1 ), now() ) > 60 ) {
    var stamp = getFileInfo( expandPath( "/config/requestguard.json.cfm" ) ).lastModified;
    if ( !structKeyExists( application, "requestGuardStamp" ) || dateCompare( stamp, application.requestGuardStamp ) == 1 ) {
        lock name="loadRequestGuard" type="exclusive" timeout="30" {
            application.requestGuard      = new cfRequestGuard.RequestGuard( expandPath( "/config/requestguard.json.cfm" ) );
            application.requestGuardStamp = stamp;
        }
    }
    application.requestGuardChecked = now();
}
```

For a quick flip without touching the file, `application.requestGuard.setMode( "shadow" )`
or `setMode( "enforce" )` switches the running instance; the next reload reads the
file again. `isShadow()` tells you which mode is active.

Recommended rollout: install in shadow, run it beside whatever you have for a
week, compare the `SHADOW` lines with your own logs, then set `"mode": "enforce"`.
From then on, new rules go in with per-rule shadow.

## Config

The config is JSON inside a `.json.cfm` wrapper: first line `<cfabort>`, the JSON
inside a CFML comment. The engine executes the file, so an HTTP request for it
returns an empty page instead of your rule set and proxy ranges. Copy the
example to your application as `config/requestguard.json.cfm` and edit the JSON
between the braces only. A plain `.json` outside the webroot works too.

The package ships generic rules only. Rules that encode one site's paths,
cookies, attackers or infrastructure belong in that site's own config file.

See `config/requestguard.example.json.cfm`. Top-level keys:

| key | purpose |
|---|---|
| `mode` | `shadow` or `enforce` (the default when the key is missing). See "Shadow and enforce" above. |
| `secret` | HMAC secret for challenge cookies. `env:NAME` reads an environment variable / system property. Required for challenge rules: without a configured secret they run in shadow mode, because a random per-start secret would bounce visitors between nodes. |
| `trustedProxies` | CIDRs of your own proxies. Empty = trust `remote_addr` only and ignore forwarding headers. |
| `internalNetworks` | never rate-limited or banned (health checks, VPN, localhost). |
| `store` | state storage for counters, bans and list copies: `{ "type": "memory" }` (default, per node) or `{ "type": "cachebox", "cacheName": "requestguard" }`. The CacheBox store resolves the region from the running ColdBox controller and serves from memory until it is up. Give it a dedicated region (counters are one key per client address); with a distributed provider, limits and bans become cluster-wide. |
| `sinks` | where decisions go: `log`, `otel`, `haproxy`, `crowdsec`. |
| `lists` | named IP lists: seed file + refresh URLs + minimum-size floor. Refreshed data is kept in the store under `rg:list:<name>` for `keepDays` (7), so a shared or persistent store means a restart or a second node starts from the last good copy. |
| `bots` | trusted bots: UA pattern + optional verification: an IP list, or forward-confirmed rDNS (`verify.rdns`, optionally fenced by `verify.ranges` so addresses outside them are spoofed without a lookup). |
| `rdns` | fences for rDNS lookups, the only verification that touches the network: `maxInFlight` (4) lookups per node at once, `timeoutMs` (1500) per lookup in its own thread, verdicts cached per IP for `cacheSeconds` (86400), timeouts and budget misses for `unknownCacheSeconds` (60). Unknown means ordinary visitor: neither trusted nor spoofed, so a DNS outage can neither stall request threads nor turn the real crawler away. |
| `challenge` | cookie name, lifetime, IP binding, page texts (`title`, `continueText`, `retryText`, `cookieText`). The page sets the cookie and reloads once; a second render within `retryWindowSeconds` (600) in the same tab, or a cookie the browser refuses, stops the automatic reload and waits for a click, so a rejected cookie never loops. |
| `strikes` | threshold / window / ban length for the escalation ladder. |
| `rules` | ordered rules, first terminal match wins. Put `ratelimit` rules above `challenge` rules: an untripped limiter falls through, but a client looping on a challenge never reaches a limiter placed below it. |

Every rule may carry `mode: shadow`; such a rule is evaluated and reported to the
sinks but never enforced, whatever the global mode. Put a new rule in shadow for
a week, then remove the key.

## Rule vocabulary

`when` (all must match): `path`, `query`, `referer`, `ua` (regex), `uaEquals`,
`method`, `headerPresent` [any], `headerMissing` [all], `header` {name: regex},
`headerEquals` {name: value}, `headerNot` {name: regex}, `cookiePresent`,
`cookieMissing`, `ip` [CIDRs], `ipList` name, `claimsBot` name, `custom` name.

`unless` (any skips the rule): `trustedBot`, `verifiedBot`, `internalIP`,
`challengePassed`, `path:<regex>`, `custom:<name>`.

`action`: `allow`, `deny`, `ignore` (200 + abort), `challenge`, `ratelimit`,
`tarpit`, `log`. A deny rule may set `strike: false` to stay out of the ban ladder
(load protection rather than abuse). Trusted bots are never struck or banned.

## Layout

```
RequestGuard.cfc            facade: init / snapshot / inspect / enforce
ModuleConfig.cfc        optional ColdBox adapter (ignored elsewhere)
models/ClientIP.cfc     trusted-proxy aware client IP resolution
models/Cidr.cfc         IPv4 CIDR sets (sorted ranges, binary search)
models/Lists.cfc        named IP lists, seed + refresh + floor
models/Verifier.cfc     bot claims and verification
models/Rules.cfc        rule compiler + evaluator
models/Matchers.cfc     the `when` / `unless` vocabulary
models/Challenge.cfc    HMAC cookie challenge
models/RateLimiter.cfc  progressive limiter on top of the store
models/Strikes.cfc      strike counter + temporary bans
models/store/*          IStore, MemoryStore, CacheBoxStore
models/sinks/*          ISink, LogSink, OtelSink, HAProxySink, CrowdSecSink
config/                 example config + list seeds
tests/                  TestBox specs replaying recorded signatures
```

## Tests

```
box install                                   # TestBox into ./testbox (dev dependency, git-ignored)
box server start cfengine=lucee@6 port=60099 openbrowser=false saveSettings=false
curl "http://127.0.0.1:60099/tests/runner.cfm?reporter=text"
```

`tests/specs/RulesSpec.cfc` replays recorded scraper signatures against
`config/requestguard.example.json.cfm` with the network lists swapped for inline
entries. Add a new signature there before you add the rule.

## Status

0.1.0. 53 specs green on Lucee 6.2.7 and BoxLang 1.18 (with `bx-compat-cfml`).
Adobe ColdFusion is untested. In production on a two-node Lucee site behind
HAProxy since October 2026. The 0.x line may still change the config format
between minor versions.

Open: proof-of-work challenge kind via ALTCHA (design note: `docs/altcha-pow-challenge.md`), IPv6 matching (swap `Cidr` internals for
seancfoley IPAddress), Redis store with native INCR, a renderer that turns
`exportable` rules into HAProxy map/ACL snippets, optional yauaa client-hints
cross-check, Web Bot Auth signature verifier.

## Running on BoxLang

Verified with BoxLang 1.18 through CommandBox (`cfengine=boxlang`), which ships
`bx-compat-cfml`. Keep that module installed: the package uses CFML BIF names
(`chr`, `serializeJSON`, `deserializeJSON`). BoxLang 1.17.6 or newer is required
so `lock type="exclusive"` really is exclusive.

Things learned while verifying, now baked into the code:

- Date masks follow java.time on BoxLang even with the compat module: `mm` is
  minutes, `nn` is nanoseconds. Machine formats (challenge day key, RFC 3339
  timestamps) are built from `year()`, `month()`, `day()` and friends instead.
- BoxLang compares class identity by resolved name. Reach the package through
  one path only, the `/cfRequestGuard` mapping; never also by a webroot-relative path,
  or `implements` checks between the two copies fail.
- Never name a local variable after a scope (`url`, `form`, `cookie`): it shadows
  the scope on every engine.
- Never name a method after a built-in function (`extract`, `hash`, `compress`):
  Lucee refuses to compile it and BoxLang calls the BIF instead of your method.
- `boxlang check --source .` validates every `.cfc` / `.cfm` here; run it with
  the tests.

## Signatures

The example config ships the generic rules: verified crawlers, forged bot
claims, cloud ranges without cookies, the Sec-Fetch checks and the rate limit.
The header and path signatures of specific scraper families are deliberately
not published, because their value drops as soon as they are public. A curated
set, maintained from production logs, is available on request for sites that
run the package: write to info@akitogo.com and say where it would run. The
shadow mode and the `log` action are the tools for finding your own.

## License

Apache License 2.0, see `LICENSE` and `NOTICE`. Security reports: `SECURITY.md`.
