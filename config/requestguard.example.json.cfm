<cfabort>
<!--- cfRequestGuard example config. JSON between the braces, edit nothing else.
      Generic rules only: anything specific to one site belongs in that
      application's own requestguard.json.cfm, not in this package.
{
    "mode": "shadow",
    "note": "mode: shadow logs every decision as SHADOW ... and enforces nothing; switch to enforce once the log looks right. See README, Shadow and enforce",
    "secret": "env:REQUESTGUARD_SECRET",
    "logFile": "requestguard",
    "trustedProxies": [],
    "internalNetworks": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" ],
    "store": { "type": "memory", "maxEntries": 20000 },
    "sinks": [ { "type": "log", "file": "requestguard" } ],

    "lists": {
        "cloudASN": {
            "note": "hosting networks you see scraping from, one ipverse URL per ASN: https://raw.githubusercontent.com/ipverse/asn-ip/master/as/<ASN>/ipv4-aggregated.txt . Which ASNs is a per-site decision; the seed file carries the last good copy",
            "seed": "/config/requestguard/cloud-asn.txt",
            "format": "cidr-lines", "minEntries": 500, "refreshHours": 24,
            "sources": []
        },
        "googleCrawler": {
            "format": "google-json", "minEntries": 400, "refreshHours": 24,
            "sources": [
                "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
                "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
                "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json"
            ]
        },
        "bingCrawler":   { "format": "google-json", "minEntries": 20, "sources": [ "https://www.bing.com/toolbox/bingbot.json" ] },
        "appleCrawler":  { "format": "google-json", "minEntries": 20, "sources": [ "https://search.developer.apple.com/applebot.json" ] },
        "openaiCrawler": { "format": "google-json", "minEntries": 5,  "sources": [ "https://openai.com/searchbot.json", "https://openai.com/chatgpt-user.json" ] }
    },

    "bots": [
        { "name": "googlebot", "category": "search", "ua": "Googlebot|GoogleOther|Google-InspectionTool|Google-Extended|Google-CloudVertexBot|Google-Safety|APIs-Google|AdsBot-Google|Mediapartners-Google", "verify": { "ipList": "googleCrawler", "maxAgeDays": 30 } },
        { "name": "lighthouse", "category": "monitor", "ua": "Chrome-Lighthouse", "verify": { "ipList": "googleCrawler" } },
        { "name": "bingbot",   "category": "search", "ua": "bingbot",  "verify": { "ipList": "bingCrawler" } },
        { "name": "applebot",  "category": "search", "ua": "Applebot", "verify": { "ipList": "appleCrawler" } },
        { "name": "openai",    "category": "ai",     "ua": "OAI-SearchBot|ChatGPT-User", "verify": { "ipList": "openaiCrawler" } },
        { "name": "search-other", "category": "search",  "ua": "EcosiaBot|DuckDuckBot|DuckAssistBot|Slurp|Baiduspider|YandexBot" },
        { "name": "social",       "category": "social",  "ua": "facebookexternalhit|meta-webindexer|Twitterbot|LinkedInBot|TikTokSpider" },
        { "name": "ai-other",     "category": "ai",      "ua": "Amazonbot|PerplexityBot" },
        { "name": "archive",      "category": "archive", "ua": "archive\\.org_bot", "verify": { "rdns": "\\.archive\\.org$", "ranges": [ "204.62.248.0/23" ] } },
        { "name": "monitor",      "category": "monitor", "ua": "UptimeRobot|StatusCake|Pingdom|Site24x7" }
    ],

    "challenge": { "cookie": "rg_c", "maxAgeSeconds": 86400, "bindToIP": true, "secure": true, "title": "Checking your browser" },
    "strikes":   { "threshold": 10, "windowSeconds": 60, "banSeconds": 3600 },

    "rules": [
        { "name": "health-check", "action": "allow", "when": { "path": "^/health$" } },

        { "name": "header-signature-example", "action": "deny",
          "note": "placeholder showing headerPresent / headerEquals / headerNot / headerMissing; replace with signatures from your own logs (a curated set is available on request, see README)",
          "when": { "headerPresent": [ "x-scraper-sdk" ] } },

        { "name": "fake-googlebot", "action": "deny",
          "when": { "claimsBot": "googlebot", "spoofedBot": true } },

        { "name": "spoofed-bot", "action": "deny", "mode": "shadow",
          "note": "other verifiable bots, watch first, then flip to enforce",
          "when": { "spoofedBot": true } },

        { "name": "forged-forwarding-bot-claim", "action": "deny", "unless": [ "verifiedBot" ],
          "note": "behind a proxy that consumes X-Forwarded-For, a surviving forwarding header was supplied by the client; a bot claim on top of it is forged",
          "when": { "claimsBot": "any", "any": [ { "headerPresent": [ "x-forwarded-for" ] }, { "header": { "forwarded": "," } } ] } },

        { "name": "devtools", "action": "ignore",
          "when": { "path": "com\\.chrome\\.devtools\\.json|\\.css\\.map" } },

        { "name": "unwanted-bots", "action": "deny", "mode": "shadow",
          "note": "crawlers that bring nothing to a given site; the usual SEO examples, extend from your own logs",
          "when": { "ua": "AhrefsBot|SemrushBot|MJ12bot" } },

        { "name": "cloud-no-cookies", "action": "deny", "unless": [ "trustedBot" ],
          "when": { "ipList": "cloudASN", "headerMissing": [ "cookie" ] } },

        { "name": "global-ratelimit", "action": "ratelimit",
          "note": "above the challenge tiers on purpose: rules are first-match, so a client looping on a challenge must still be counted here. sessionCookie: jsessionid for J2EE sessions, cfid for engine sessions",
          "unless": [ "trustedBot", "internalIP" ],
          "limit": "20/3s", "limitWithSession": "60/3s", "sessionCookie": "jsessionid", "key": "ip",
          "message": "Too many requests, retry in {duration} seconds" },

        { "name": "chrome-no-secfetch", "action": "challenge", "respectChallenge": false, "unless": [ "trustedBot", "internalIP", "ipList:googleCrawler" ],
          "note": "Chrome 89+ always sends sec-fetch-dest to an https origin; a valid cookie does not excuse its absence",
          "when": { "ua": "Chrome/(89|9[0-9]|\\d{3,})\\.", "headerMissing": [ "sec-fetch-dest" ] } },

        { "name": "safari-no-secfetch", "action": "challenge", "respectChallenge": false, "unless": [ "trustedBot", "internalIP", "ipList:googleCrawler" ],
          "when": { "ua": "Version/(1[6-9]|[2-9][0-9])\\.", "header": { "user-agent": "Safari/" }, "headerNot": { "user-agent": "Chrome/|CriOS/" }, "headerMissing": [ "sec-fetch-dest" ] } }
    ]
}
--->
