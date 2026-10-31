# BotD, vendored

`botd.min.js` is [BotD](https://github.com/fingerprintjs/BotD) by FingerprintJS,
Inc., MIT (see `LICENSE` here), built as a single IIFE that exposes `window.BotD`
so the challenge page can inline it and load nothing from the network. `VERSION`
holds the upstream version; the page sends it with every verdict (`botd=` in the
log line) so builds can be told apart.

The source of truth is the pin in `package.json` (`@fingerprintjs/botd`, exact
version, plus the esbuild used to build it). `scripts/update-botd.sh` rebuilds
this folder from that pin; `scripts/update-botd.sh <version>` bumps the pin and
the lock file first. Dependabot opens a pull request when upstream releases, and
the CI job `vendor` fails until the rebuilt files are committed, so this folder
can never drift from the pin.

The one change to upstream: `load()` defaults to `monitoring: false`. The
upstream default sends a usage ping to `m1.openfpcdn.io` from the visitor's
browser; the challenge page passes `monitoring:false` as well. The script stops
if that line is no longer found exactly once, so an upstream change to `load()`
is reviewed rather than vendored blind.
