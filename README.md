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

1. Get the package: `box install cfrequestguard`, clone the repository, add it
   as a git submodule, or download the zip from GitHub and unpack it, e.g. into
   `modules_app/cfRequestGuard`.
2. If the folder is not in the webroot, map it in `Application.cfc` (the guard
   runs before any framework loads): `this.mappings[ "/cfRequestGuard" ] = "<path to the folder>"`.
3. Copy `config/requestguard.example.json.cfm` from the package to
   `config/requestguard.json.cfm` in your application. It ships in shadow mode.
4. In that file set `secret` (an environment variable; if you have multiple
   nodes, the same value on each) and, if you are behind a load balancer or
   reverse proxy, its address in `trustedProxies`. Lists without a seed file or
   sources stay empty and never match.
5. Wire it into `Application.cfc` as shown below.
6. Watch the `SHADOW` lines in the `requestguard` log for a week, then set
   `"mode": "enforce"` and reload the application.

ColdBox users may also register the folder as a module: it reuses the same
instance and exposes it to WireBox as `requestGuard@cfRequestGuard`.

## Wire into Application.cfc

```cfml
// only if the folder is not in the webroot (e.g. modules_app/cfRequestGuard):
this.mappings[ "/cfRequestGuard" ] = getDirectoryFromPath( getCurrentTemplatePath() ) & "modules_app/cfRequestGuard";

boolean function onApplicationStart(){
    application.requestGuard = new cfRequestGuard.RequestGuard( expandPath( "/config/requestguard.json.cfm" ) );
    ...
}

boolean function onRequestStart( string targetPage ){
   // should be first so requests could be blocked
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

    // your code follows here
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
   the log, then delete the `mode` key. A shadow match does not stop the chain:
   the rules below still run, so an enforced rule further down can still block
   the request. Shadow matches never count strikes.
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

## Reading the log

Every decision other than a plain allow is one line in the engine log named by
the `log` sink (`"sinks": [ { "type": "log", "file": "requestguard" } ]`),
written with `writeLog`. Where that file lives is up to the engine:

- Lucee: `<lucee-server>/context/logs/requestguard.log` for the server context,
  or `WEB-INF/lucee/logs/` for a web context; listed in the Lucee admin under Logging.
- BoxLang: the `logs/` directory of the runtime home (see `logging` in `boxlang.json`).
- Adobe ColdFusion: `cfusion/logs/requestguard.log`.

Startup and list maintenance write to the same file under the name in
`logFile`, which is why both default to `requestguard`. A healthy start looks like:

```
"INFO","http-nio-8888-exec-1","10/14/2026","23:15:21","myapp","cfRequestGuard list 'googleCrawler' loaded from store: 48 ranges from 557 entries (0 skipped)"
"INFO","http-nio-8888-exec-1","10/14/2026","23:15:21","myapp","cfRequestGuard loaded (mode: enforce) in 181 ms"
"INFO","cfthread-91193","10/15/2026","03:49:16","myapp","cfRequestGuard list 'googleCrawler' loaded from remote: 48 ranges from 558 entries (0 skipped)"
```

Decision lines, taken from a production log with the addresses replaced by
documentation ranges (Lucee's CSV log format; the columns before the message
are the engine's):

```
"WARN","http-nio-8888-exec-41","10/15/2026","16:29:51","myapp","BLOCK-403-cloud-no-cookies | rule=cloud-no-cookies | ip=203.0.113.17 | GET /products/5117765.html | ua=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
"WARN","http-nio-8888-exec-11","10/15/2026","19:34:54","myapp","BLOCK-403-fake-googlebot | rule=fake-googlebot | ip=203.0.113.44 | GET /userfiles?path=../../../.env | ua=Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
"WARN","http-nio-8888-exec-14","10/15/2026","14:05:30","myapp","CHALLENGE-safari-no-secfetch | rule=safari-no-secfetch | ip=198.51.100.30 | GET /products/8461063.html | ua=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15"
"WARN","http-nio-8888-exec-5","10/15/2026","17:58:23","myapp","CHALLENGE-chrome-no-secfetch | rule=chrome-no-secfetch | ip=203.0.113.91 | GET /blog/rss | ua=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
"WARN","http-nio-8888-exec-27","10/15/2026","19:30:38","myapp","BLOCK-503-global-ratelimit-tripped | rule=global-ratelimit | ip=198.51.100.31 | GET /catalog/people.html | ua=Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:143.0) Gecko/20100101 Firefox/143.0 | attempts=21 blockCount=1 retryAfter=6s"
"WARN","http-nio-8888-exec-23","10/15/2026","19:30:39","myapp","BLOCK-503-global-ratelimit-extended | rule=global-ratelimit | ip=198.51.100.31 | GET /catalog/travel.html | ua=Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:143.0) Gecko/20100101 Firefox/143.0 | attempts=22 blockCount=1 retryAfter=6s"
"WARN","http-nio-8888-exec-9","10/15/2026","19:31:02","myapp","BLOCK-403-banned | rule=strike-ban | ip=203.0.113.44 | GET /wp-content/plugins/hellopress/wp_filemanager.php | ua="
"INFO","http-nio-8888-exec-14","10/15/2026","19:34:53","myapp","SHADOW BLOCK-403-unwanted-bots | rule=unwanted-bots | ip=203.0.113.44 | GET /document.php?modulepart=systemtools&file=../conf/conf.php | ua=Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
"INFO","http-nio-8888-exec-5","10/15/2026","00:15:57","myapp","LOG-client-forwarding-header | rule=client-forwarding-header | ip=203.0.113.238 | GET /.svn/entries | ua=Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
```

What those lines say: a cloud address without cookies was denied; a Googlebot
claim from outside Google's ranges was denied; two browsers without Sec-Fetch
headers got the challenge page; one address tripped the rate limit at its 21st
request and was still inside the block a second later; a probing client reached
the strike threshold and is banned for the configured period; a rule in shadow
mode reported what it would have done; a `log` rule recorded a client-supplied
forwarding header without acting.

Read a line left to right:

| field | meaning |
|---|---|
| label | what was done, as `ACTION-STATUS-rule`: `BLOCK-403-<rule>` denied, `CHALLENGE-<rule>` served the challenge page, `BLOCK-503-<rule>-tripped` rate limit just hit, `BLOCK-503-<rule>-extended` still inside the block, `IGNORE-<rule>` quiet 200, `LOG-<rule>` observed only, `BLOCK-403-banned` the strike ladder. A rule may set its own `label`. |
| `SHADOW ` prefix | reported but not enforced: global shadow mode, a per-rule `mode: shadow`, or a challenge rule without a secret. Shadow and `LOG-` lines are `INFO`, enforced decisions `WARN`. |
| `rule=` | the rule name from the config. |
| `ip=` | the client address after trusted-proxy resolution, the one counters and bans are keyed on. |
| method and path | the request line, query string truncated to 200 characters. |
| `ua=` | the user agent, truncated to 160 characters. |
| trailing detail | present for rate limits (`attempts=21 blockCount=1 retryAfter=6s`) and bot verification. |

Things worth grepping for:

```
grep -c "SHADOW"                       # still in shadow? drops to zero after the flip
grep "BLOCK-503"                       # who hits the rate limit, with how many attempts
grep "BLOCK-403-banned"                # strike ladder bans; trusted bots never appear here
grep "cfRequestGuard list"             # refresh results and floor rejections
grep -v "SHADOW" | grep "CHALLENGE"    # challenged clients; a real browser appears once per day per IP
```

A client that shows up with the same `CHALLENGE-` line hundreds of times never
ran the page's JavaScript; the rate limit above the challenge tiers is what stops
it. Errors raised inside `inspect()` are the host's to log; the wiring example
above catches and logs them, and the request then proceeds as allowed.

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
| `sinks` | where decisions go: `log`, `otel`, `haproxy`, `crowdsec` (see [Edge feedback](#edge-feedback-haproxy-and-crowdsec)). |
| `lists` | named IP lists: seed file + refresh URLs + minimum-size floor. Refreshed data is kept in the store under `rg:list:<name>` for `keepDays` (7), so a shared or persistent store means a restart or a second node starts from the last good copy. |
| `bots` | trusted bots: UA pattern + optional verification: an IP list, or forward-confirmed rDNS (`verify.rdns`, optionally fenced by `verify.ranges` so addresses outside them are spoofed without a lookup). |
| `rdns` | fences for rDNS lookups, the only verification that touches the network: `maxInFlight` (4) lookups per node at once, `timeoutMs` (1500) per lookup in its own thread, verdicts cached per IP for `cacheSeconds` (86400), timeouts and budget misses for `unknownCacheSeconds` (60). Unknown means ordinary visitor: neither trusted nor spoofed, so a DNS outage can neither stall request threads nor turn the real crawler away. |
| `challenge` | cookie name, lifetime, IP binding, page texts (`title`, `continueText`, `retryText`, `cookieText`). The page sets the cookie and reloads once; a second render within `retryWindowSeconds` (600) in the same tab, or a cookie the browser refuses, stops the automatic reload and waits for a click, so a rejected cookie never loops. | `botd: "report"` adds the headless detector, see [Headless detection](#headless-detection-in-the-challenge-page). |
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
(load protection rather than abuse), or a number to weigh the deny: `strike: 10`
on a honeypot path bans on the first hit with the default threshold. Trusted bots are never struck or banned.

## A honeypot path

A link no visitor can see and no well-behaved crawler may follow. Whoever
requests it is a scraper that parses the HTML for links and ignores robots.txt,
so one hit is enough to ban the address. Three pieces:

1. **The rule**, near the top of the chain so nothing cheaper answers first.
   `strike: 10` with the default threshold of 10 bans on the first hit; verified
   crawlers and internal networks are exempt, so a mistake in step 3 can never
   lock out a search engine or your own monitoring:

   ```json
   { "name": "honeypot", "action": "deny", "strike": 10, "unless": [ "verifiedBot", "internalIP" ],
     "when": { "path": "^/example-trap(/|$)" } }
   ```

2. **The link**, in a template that every page renders, typically the footer.
   Hidden from eyes and screen readers, out of the tab order, and marked
   `nofollow` so a search engine that reads the HTML before robots.txt still
   has a reason not to follow it:

   ```html
   <a href="/example-trap/" rel="nofollow" tabindex="-1" aria-hidden="true" class="visually-hidden">Example</a>
   ```

   `visually-hidden` is the usual clip-rect class (Bootstrap ships one). Do not
   use `display: none`: some scrapers skip links that are not rendered, and a
   plain anchor that is only moved off-screen is what they follow.

3. **robots.txt**, so an honest crawler never requests it and the rule's
   exemptions are never needed:

   ```
   User-agent: *
   Disallow: /example-trap/
   ```

Pick a path that looks like real content and does not exist in the
application, so there is no handler to accidentally serve it, and never link it
from anywhere else: a sitemap entry or a stray menu link turns the honeypot
into a trap for your own visitors. A client that reaches it while logged in or
through a shared address (carrier-grade NAT, a corporate proxy) takes everyone
behind that address with it for `strikes.banSeconds`, which is the price of
any address-based ban; keep the ban length reasonable.

The hits read as `BLOCK-403-honeypot` in the log, the ban that follows as
`BLOCK-403-banned`. With the CrowdSec sink, add `BLOCK-403-honeypot` to its
`labels` so the first hit is pushed to the edge at once instead of waiting for
the client's next request.

## Edge feedback: HAProxy and CrowdSec

The guard decides inside the JVM. Two sinks hand its decisions to the edge so a
banned address is refused before it reaches a request thread. Both are optional,
both skip shadow decisions, and both are listed under `sinks`:

```json
"sinks": [
    { "type": "log", "file": "requestguard" },
    { "type": "haproxy", "host": "127.0.0.1", "port": 9999, "map": "/etc/haproxy/requestguard-bans.map" },
    { "type": "crowdsec",
      "file": "/var/log/requestguard/decisions.jsonl",
      "lapi": { "url": "http://lapi.internal:8080", "machineId": "env:CROWDSEC_MACHINE_ID", "password": "env:CROWDSEC_MACHINE_PASSWORD" } }
]
```

`haproxy` adds strike-banned addresses to a map over the HAProxy Runtime API.

Both run off the request thread: the guard wraps them in `AsyncSink`, which
starts a short-lived thread per decision and returns at once, so a slow stats
socket or Local API never adds to the response time of the blocked request.
At most `asyncMaxInFlight` (8) deliveries per sink run at once; beyond that
the decision is dropped for that sink and logged once a minute (a banned
client keeps sending requests, so the edge learns of it on the next one).
`"async": false` on a sink entry makes it inline again; `"async": true` on a
`log` sink moves it off the thread too. `otel` annotates the current request's
span and always stays inline. Your own sink: `guard.addSink( new models.sinks.AsyncSink( mySink ) )`.

`crowdsec` has two paths, usable alone or together:

- **Local, `file`**: one JSON line per decision into a file that the CrowdSec
  agent on the same host tails. A parser and a scenario on the CrowdSec side
  turn repeated denies and challenges into bans; whichever bouncer sits in
  front (HAProxy SPOA, nginx, firewall) enforces them. No credentials, and the
  file serves any other log consumer too.
- **Remote, `lapi`** (experimental: the alert follows the v1 model and is covered
  by specs, but has not yet been exercised against a running Local API; a 422 in
  the guard's log means a field was rejected): strike bans (configurable `labels`)
  are pushed as alerts with a ready decision to a CrowdSec Local API, which may
  run on another host.
  The sink logs in as a machine and keeps the token; a `ban` of `duration` 1h
  by default. One HTTP call per banned address and `repushSeconds`, off the
  request thread; failures are logged and the app-side ban still holds.

[docs/crowdsec.md](docs/crowdsec.md) walks through both setups: acquisition,
parser, scenario, machine registration, and how to verify each step.

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
models/Challenge.cfc    HMAC cookie challenge, BotD report endpoint
vendor/botd/            BotD 2.0.0 (MIT), inlined into the challenge page when enabled
models/RateLimiter.cfc  progressive limiter on top of the store
models/Strikes.cfc      strike counter + temporary bans
models/store/*          IStore, MemoryStore, CacheBoxStore
models/sinks/*          ISink, LogSink, OtelSink, HAProxySink, CrowdSecSink (file + LAPI), AsyncSink (off-thread decorator)
docs/                   CrowdSec setup, ALTCHA design note
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

0.2.3 plus unreleased changes. 75 specs green on Lucee 6.2.7 and BoxLang 1.18 (with `bx-compat-cfml`).
Adobe ColdFusion is untested. In production on a two-node Lucee site behind
HAProxy since October 2026. The 0.x line may still change the config format
between minor versions.

Open: proof-of-work challenge kind via ALTCHA (design note: `docs/altcha-pow-challenge.md`), IPv6 matching (swap `Cidr` internals for
seancfoley IPAddress), Redis store with native INCR, a renderer that turns
`exportable` rules into HAProxy map/ACL snippets, optional yauaa client-hints
cross-check, Web Bot Auth signature verifier.

## Headless detection in the challenge page

The JavaScript challenge proves that a client ran a script. A headless browser
runs scripts too, so a pool of real Chrome instances passes it and only pays one
extra round trip. `challenge.botd` adds [BotD](https://github.com/fingerprintjs/BotD)
(FingerprintJS, MIT, vendored under `vendor/botd`, inlined into the page, so the
page still loads nothing from the network and sends nothing to anyone but you):

```json
"challenge": { "cookie": "rg_c", "botd": "report" }
```

In `report` mode the page runs the detector first, posts the verdict to
`botdPath` (`/__requestguard/botd`) with `sendBeacon`, then continues with the
cookie flow exactly as before. The guard answers the post with 204 before any
routing, hands the sinks a decision labelled `BOTD-<kind>` and changes nothing
else: no strike, no block. Kinds are `clean`, one of BotD's bot kinds
(`headless_chrome`, `selenium`, `playwright`, `electron`, ...), or `timeout`,
`error` and `nolib` when the detector did not answer within `botdTimeoutMs`
(1500) or did not run. The log line carries the rule that issued the challenge
and the challenged page:

```
BOTD-headless_chrome | rule=chrome-no-secfetch | ip=203.0.113.91 | POST /__requestguard/botd | ua=Mozilla/5.0 ... | page=/products/8461063.html ms=118
```

The post carries a nonce, an HMAC over the day, the client address, the rule and
the page, so the endpoint only accepts verdicts for pages it rendered to that
client; anything else is logged as `BOTD-invalid`. The verdict itself is still
computed in the client's browser, so a determined operator can forge it: this is
a measurement and a filter for the common case, not proof. Run it in report mode
for a week against the `CHALLENGE-` lines of the same clients before deciding
whether a gate mode (cookie only on a clean verdict) is worth having for your
traffic:

```
grep "BOTD-" | grep -v "BOTD-clean"      # detected automation, by kind
grep -c "BOTD-clean"                     # browsers that passed the detector
```

`botdPath` must reach the application like any page request (the guard runs
inside `onRequestStart`); if a front proxy only forwards known extensions,
add the path.

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
