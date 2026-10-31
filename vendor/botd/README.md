# BotD, vendored

`botd.min.js` is [BotD](https://github.com/fingerprintjs/BotD) 2.0.0 by
FingerprintJS, Inc., MIT (see `LICENSE` here), built as a single IIFE that
exposes `window.BotD` so the challenge page can inline it and load nothing
from the network.

Build, from the npm package `@fingerprintjs/botd@2.0.0`:

```
sed 's/async function load({ monitoring = true } = {})/async function load({ monitoring = false } = {})/' dist/botd.esm.js > botd.esm.js
esbuild botd.esm.js --bundle --format=iife --global-name=BotD --minify --target=es2017 --legal-comments=none --outfile=botd.min.js
```

The one change: `load()` defaults to `monitoring: false`. The upstream default
sends a usage ping to `m1.openfpcdn.io` from the visitor's browser; the
challenge page passes `monitoring:false` as well, the patched default is the
belt to that brace. Nothing else is modified.
