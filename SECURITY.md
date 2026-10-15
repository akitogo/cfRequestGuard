# Security policy

cfRequestGuard is a defensive component: it decides which requests a site
answers. A way to make it decide wrongly is a vulnerability in it.

## What counts

- A request that bypasses a `deny`, `challenge` or `ratelimit` rule it should
  match (for example forging the trusted-proxy chain, the challenge cookie, or
  a verified-bot identity).
- A way to make the guard block, ban or challenge visitors it should not
  (false positives caused by the engine, not by a site's own rules).
- A way to exhaust resources through the guard: request threads, memory in
  the store, outbound DNS or HTTP from list refreshes.
- Information leaks: the secret, the config file, store contents.

Signatures that stop matching because a scraper changed its behaviour are not
vulnerabilities; open an ordinary issue or a pull request for those.

## Reporting

Please do not open a public issue for a bypass. Use GitHub's private
vulnerability reporting on this repository ("Report a vulnerability" under
the Security tab) or write to info@akitogo.com. Include the engine and version, the relevant rule or
config excerpt, and a request that demonstrates the problem.

You will get an acknowledgement, a fix or a workaround on a best-effort
basis, and credit in the release notes if you want it.

## Supported versions

The latest release on the `main` branch. The 0.x line may change the config
format between minor versions; the changelog says when.
