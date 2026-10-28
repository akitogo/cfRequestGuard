# Reporting to CrowdSec

cfRequestGuard can feed its decisions to [CrowdSec](https://www.crowdsec.net)
in two ways. Both are configured on the `crowdsec` sink and can be combined.

| | Local acquisition (`file`) | Remote LAPI (`lapi`) |
|---|---|---|
| What is sent | every enforced decision | the listed labels only, strike bans by default |
| Who decides on a ban | a CrowdSec scenario, counting repeats | the guard; the alert carries a ready decision |
| Needs | CrowdSec agent on the same host | network access to a Local API, a machine account |
| Latency to the edge | scenario capacity + bouncer poll | bouncer poll (10 s by default) |
| Credentials in the app | none | machine id + password |

Pick `file` when the agent runs next to the application and you want CrowdSec
to apply its own thresholds. Pick `lapi` when the agent lives elsewhere, or when
a ban the guard has already decided should reach the edge without a second
count. Use both when you want the full decision stream for CrowdSec's
scenarios and immediate enforcement of the bans.

Shadow decisions are never reported on either path.

## 1. Local: the agent tails a JSON log

### Sink

```json
"sinks": [
    { "type": "log", "file": "requestguard" },
    { "type": "crowdsec", "file": "/var/log/requestguard/decisions.jsonl" }
]
```

The directory must exist and be writable by the CFML engine's user; CrowdSec
only needs read access. Rotate the file with logrotate (`copytruncate` is
fine, the sink appends).

One line per decision:

```json
{"ts":"2026-10-16T07:12:03Z","label":"BLOCK-403-cloud-no-cookies","rule":"cloud-no-cookies","action":"deny","ip":"203.0.113.7","method":"GET","path":"/en/images/sunset.html","ua":"Mozilla/5.0 ..."}
```

`action` is one of `deny`, `challenge`, `ratelimit`, `tarpit`, `log`. Strike
bans arrive as `action: deny` with `rule: strike-ban` and
`label: BLOCK-403-banned`.

### Acquisition

`/etc/crowdsec/acquis.d/requestguard.yaml`:

```yaml
filenames:
  - /var/log/requestguard/decisions.jsonl
labels:
  type: requestguard
```

### Parser

`/etc/crowdsec/parsers/s01-parse/requestguard-logs.yaml`:

```yaml
name: akitogo/requestguard-logs
description: "cfRequestGuard decision lines (JSON)"
filter: "evt.Line.Labels.type == 'requestguard'"
onsuccess: next_stage
statics:
  - meta: log_type
    value: requestguard_decision
  - meta: source_ip
    expression: JsonExtract(evt.Line.Raw, "ip")
  - meta: rg_label
    expression: JsonExtract(evt.Line.Raw, "label")
  - meta: rg_rule
    expression: JsonExtract(evt.Line.Raw, "rule")
  - meta: rg_action
    expression: JsonExtract(evt.Line.Raw, "action")
  - meta: http_verb
    expression: JsonExtract(evt.Line.Raw, "method")
  - meta: http_path
    expression: JsonExtract(evt.Line.Raw, "path")
  - meta: http_user_agent
    expression: JsonExtract(evt.Line.Raw, "ua")
  - meta: service
    value: http
  - target: evt.StrTime
    expression: JsonExtract(evt.Line.Raw, "ts")
```

`evt.StrTime` in RFC 3339 is picked up by the stock `crowdsecurity/dateparse-enrich`
parser, so events keep the guard's timestamp when a backlog is replayed.

### Scenarios

`/etc/crowdsec/scenarios/requestguard.yaml`, two scenarios in one file:

```yaml
# An address the guard keeps denying or challenging: 20 decisions within a
# leaking minute ban it for the LAPI default duration (4 h).
type: leaky
name: akitogo/requestguard-repeat
description: "Repeatedly denied or challenged by cfRequestGuard"
filter: "evt.Meta.log_type == 'requestguard_decision' && evt.Meta.rg_action in ['deny', 'challenge', 'ratelimit']"
groupby: evt.Meta.source_ip
capacity: 20
leakspeed: 1m
blackhole: 10m
labels:
  service: http
  type: scan
  remediation: true
---
# A strike ban already decided by the guard: mirror it at the edge at once.
type: trigger
name: akitogo/requestguard-ban
description: "Strike-banned by cfRequestGuard"
filter: "evt.Meta.log_type == 'requestguard_decision' && evt.Meta.rg_rule == 'strike-ban'"
groupby: evt.Meta.source_ip
blackhole: 1h
labels:
  service: http
  type: scan
  remediation: true
```

Tune `capacity` to your rule set: a site that challenges every old browser
produces more `challenge` lines per honest visitor than one that only denies.
Count the lines per address in the file for a day before enabling
`remediation`.

### Verify

```sh
sudo systemctl reload crowdsec
cscli parsers list | grep requestguard        # loaded, no error
cscli scenarios list | grep requestguard
cscli metrics show acquisition              # lines read / parsed for the file
cscli explain --file /var/log/requestguard/decisions.jsonl --type requestguard   # one line through the pipeline
cscli alerts list                           # once a scenario fires
cscli decisions list                        # what the bouncers will enforce
```

If `metrics` shows lines read but none parsed, the acquisition label and the
parser filter do not match; if parsed but no alert, the scenario filter or the
threshold is the reason, `cscli explain` prints the stage where an event is
dropped.

## 2. Remote: alerts to a Local API

The guard logs in to a CrowdSec Local API (LAPI) as a machine and posts one
alert per decision whose label is listed, each alert carrying a ready
decision. The LAPI can be on the same host or anywhere reachable; bouncers
pick the decision up on their next poll.

### Register a machine

On the LAPI host:

```sh
cscli machines add requestguard-www1 --password 'long-random-string'
cscli machines list                 # status should be validated
```

One machine per application node keeps `cscli machines list` readable and
lets you revoke a node on its own.

### Expose the LAPI

Only needed when the application and the LAPI are on different hosts. In
`/etc/crowdsec/config.yaml` on the LAPI host:

```yaml
api:
  server:
    listen_uri: 0.0.0.0:8080
```

Restrict port 8080 to the application nodes in the firewall. For anything that
crosses an untrusted network put TLS in front (CrowdSec's own `tls` block or a
reverse proxy) and use an `https://` URL in the sink.

### Sink

```json
"sinks": [
    { "type": "log", "file": "requestguard" },
    { "type": "crowdsec",
      "lapi": {
        "url": "http://lapi.internal:8080",
        "machineId": "env:CROWDSEC_MACHINE_ID",
        "password": "env:CROWDSEC_MACHINE_PASSWORD",
        "labels": [ "BLOCK-403-banned" ],
        "scenario": "cfRequestGuard/strike-ban",
        "type": "ban",
        "duration": "1h",
        "timeoutSeconds": 2
      } }
]
```

| key | default | meaning |
|---|---|---|
| `url` | | LAPI base URL, no trailing path. |
| `machineId`, `password` | | the machine account; `env:NAME` reads an environment variable or JVM property. |
| `labels` | `["BLOCK-403-banned"]` | decision labels that become alerts. Add rule labels for immediate edge enforcement of specific denies; do not list challenge labels, every old browser would be banned. |
| `scenario` | `cfRequestGuard/strike-ban` | scenario name on the alert and its decision; what `cscli decisions list` shows as reason. |
| `type` | `ban` | decision type: `ban`, or `captcha` for bouncers that render one. |
| `duration` | `1h` | decision lifetime at the edge; CrowdSec expires it on its own. Match it to `strikes.banSeconds`. |
| `origin` | `cfRequestGuard` | decision origin. `cscli` makes bouncers and the console treat it like a manual ban, which some setups require. |
| `repushSeconds` | `600` | one push per address and window. A banned client keeps sending requests and every one is a ban decision; without this the LAPI would get one alert per request. |
| `timeoutSeconds` | `2` | per HTTP call. |

`machineId` and `password` accept `env:NAME`, so the same config file serves
every node when each sets its own `CROWDSEC_MACHINE_ID`. The sink sends
`User-Agent: cfRequestGuard/<version>`: the LAPI parses it as software/version
on login and answers a misleading 401 to anything else.

The sink keeps the login token for 50 minutes (LAPI tokens last an hour),
retries once after a 401, and writes a warning to the guard's log when the
LAPI is unreachable or rejects an alert. The request that triggered the ban
is never delayed by more than the timeout, and only once per banned address;
the app-side ban holds either way.

### What is sent

`POST /v1/alerts` with a one-element array:

```json
[{
  "scenario": "cfRequestGuard/strike-ban", "scenario_hash": "", "scenario_version": "",
  "message": "cfRequestGuard BLOCK-403-banned (strike-ban) from 203.0.113.7",
  "events_count": 1, "start_at": "2026-10-16T07:12:03Z", "stop_at": "2026-10-16T07:12:03Z",
  "capacity": 0, "leakspeed": "0s", "simulated": false, "remediation": true,
  "source": { "scope": "Ip", "value": "203.0.113.7", "ip": "203.0.113.7" },
  "events": [ { "timestamp": "2026-10-16T07:12:03Z",
                "meta": [ { "key": "source_ip", "value": "203.0.113.7" }, { "key": "rg_label", "value": "BLOCK-403-banned" },
                          { "key": "rg_rule", "value": "strike-ban" }, { "key": "rg_action", "value": "deny" },
                          { "key": "http_verb", "value": "GET" }, { "key": "http_path", "value": "/en/images/sunset.html" },
                          { "key": "http_user_agent", "value": "Mozilla/5.0 ..." } ] } ],
  "decisions": [ { "origin": "cfRequestGuard", "type": "ban", "scope": "Ip", "value": "203.0.113.7", "duration": "1h", "scenario": "cfRequestGuard/strike-ban" } ]
}]
```

### Verify

```sh
# from the application host: the machine can log in
curl -s -X POST http://lapi.internal:8080/v1/watchers/login \
  -H 'Content-Type: application/json' \
  -d '{"machine_id":"requestguard-www1","password":"long-random-string","scenarios":["cfRequestGuard/strike-ban"]}'
# {"code":200,"expire":"...","token":"..."}

# on the LAPI host, after the first strike ban
cscli alerts list --origin cfRequestGuard    # or without the filter on older cscli
cscli decisions list
```

`cscli decisions list` shows the address with reason `cfRequestGuard/strike-ban`
and the remaining duration; `cscli alerts inspect <id>` prints the meta
fields above. If nothing arrives, the guard's log has the warning with the
LAPI's status and body: 401 is a wrong machine id or password, 403 a machine
that is not validated, 422 a payload the LAPI version rejects (please report
the body).

## Remote agent reading the file

A third arrangement needs nothing in the guard beyond the `file` sink: ship
the JSON log to the host that runs the agent (rsyslog `imfile` with a JSON
template, Filebeat, Vector, or a shared mount) and use the acquisition from
section 1 there, with the `type: requestguard` label. Keep the line intact;
the parser reads the raw JSON.
