#!/usr/bin/env bash
# Rebuild vendor/botd from the @fingerprintjs/botd version pinned in package.json.
#
#   scripts/update-botd.sh            rebuild from the pin (CI runs this and fails if vendor/ changes)
#   scripts/update-botd.sh 2.1.0      bump the pin and the lock file, then rebuild
#
# Needs node + npm. The only change to upstream is the default of load():
# monitoring off, because the upstream default pings m1.openfpcdn.io from the
# visitor's browser. The script stops if that anchor moved, so a new upstream
# version is reviewed rather than vendored blind.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ $# -ge 1 ]; then
	npm install --save-dev --save-exact "@fingerprintjs/botd@$1"
fi
[ -d node_modules/@fingerprintjs/botd ] && [ -x node_modules/.bin/esbuild ] || npm ci

VERSION=$(node -p "require('./node_modules/@fingerprintjs/botd/package.json').version")
SRC=node_modules/@fingerprintjs/botd/dist/botd.esm.js
ANCHOR='async function load({ monitoring = true } = {})'
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

if [ "$(grep -cF "$ANCHOR" "$SRC")" != "1" ]; then
	echo "update-botd: patch anchor not found exactly once in $SRC; upstream changed load(), review before vendoring" >&2
	exit 1
fi
sed "s/${ANCHOR//\//\\/}/async function load({ monitoring = false } = {})/" "$SRC" > "$TMP/botd.esm.js"

./node_modules/.bin/esbuild "$TMP/botd.esm.js" --bundle --format=iife --global-name=BotD --minify \
	--target=es2017 --legal-comments=none --log-level=warning --outfile="$TMP/botd.min.js"

{
	printf '/*! BotD v%s (c) FingerprintJS, Inc., MIT, https://github.com/fingerprintjs/BotD . Built by scripts/update-botd.sh, see vendor/botd/README.md */\n' "$VERSION"
	cat "$TMP/botd.min.js"
} > vendor/botd/botd.min.js
cp node_modules/@fingerprintjs/botd/LICENSE vendor/botd/LICENSE
printf '%s\n' "$VERSION" > vendor/botd/VERSION

grep -qE 'monitoring:[A-Za-z_$]+=!1' vendor/botd/botd.min.js || { echo "update-botd: monitoring default is not off in the build" >&2; exit 1; }
if grep -q '</script' vendor/botd/botd.min.js; then echo "update-botd: build contains </script, cannot be inlined" >&2; exit 1; fi
grep -q 'BotD=' vendor/botd/botd.min.js || { echo "update-botd: global BotD missing" >&2; exit 1; }

echo "vendor/botd: BotD $VERSION, $(wc -c < vendor/botd/botd.min.js | tr -d ' ') bytes"
