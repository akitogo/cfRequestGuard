/**
 * Runs the generic example config (network lists replaced by inline entries)
 * against synthetic requests. Each denying case uses its
 * own IP so the strike ladder cannot bleed into the next case.
 */
component extends="testbox.system.BaseSpec" {

	function beforeAll(){
		var cfg = new cfRequestGuard.models.Config().read( expandPath( "/cfRequestGuard/config/requestguard.example.json.cfm" ) );
		for ( var name in cfg.lists ) { cfg.lists[ name ].sources = []; cfg.lists[ name ].seed = ""; }
		cfg.lists.googleCrawler.entries = [ "66.249.64.0/19" ];
		cfg.lists.cloudASN.entries      = [ "20.0.0.0/8", "129.226.0.0/16" ];
		cfg.secret  = "test-secret";
		cfg.sinks   = [];
		cfg.strikes = { threshold: 5, windowSeconds: 60, banSeconds: 60 };
		variables.guard = new cfRequestGuard.RequestGuard( cfg );
		variables.sink  = new tests.specs.support.CaptureSink();
		variables.guard.addSink( variables.sink );
	}

	private struct function chrome( struct over = {} ){
		var s = {
			method: "GET", path: "/products/123.html", query: "", host: "www.example.test", remoteAddr: "203.0.113.10",
			headers: {
				"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
				"accept": "text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8",
				"accept-language": "de-DE,de;q=0.9", "accept-encoding": "gzip, deflate, br, zstd", "connection": "keep-alive",
				"sec-fetch-dest": "document", "sec-fetch-mode": "navigate"
			},
			cookies: {}, now: now()
		};
		structAppend( s, arguments.over, true );
		s.ua = s.headers[ "user-agent" ] ?: ""; s.referer = s.headers[ "referer" ] ?: "";
		s.clientIP = variables.guard.getClientIP().resolve( s );
		return s;
	}

	private struct function withHeaders( required struct changes, array remove = [] ){
		var h = chrome().headers;
		structAppend( h, arguments.changes, true );
		for ( var r in arguments.remove ) structDelete( h, r );
		return h;
	}

	function run(){
		describe( "rule chain", function(){
			it( "lets a real browser through", function(){
				expect( guard.inspect( chrome() ).action ).toBe( "allow" );
			} );
			it( "allow rules are terminal", function(){
				expect( guard.inspect( chrome( { path: "/health", headers: { "user-agent": "x", "x-scraper-sdk": "blob" } } ) ).action ).toBe( "allow" );
			} );
			it( "serves the challenge page for a matched challenge rule", function(){
				var d = guard.inspect( chrome( { headers: withHeaders( {}, [ "sec-fetch-dest" ] ) } ) );
				expect( d.action ).toBe( "challenge" );
				expect( d.label ).toBe( "CHALLENGE-chrome-no-secfetch" );
				expect( d.body ).toInclude( "document.cookie" );
			} );
			it( "lets a challenged client through once the challenge cookie is valid", function(){
				var cfg2 = { secret: "test-secret", sinks: [], rules: [ { name: "chal", action: "challenge", when: { ua: "^curl" } } ] };
				var g2   = new cfRequestGuard.RequestGuard( cfg2 );
				var s    = chrome( { headers: { "user-agent": "curl/8" } } );
				expect( g2.inspect( s ).action ).toBe( "challenge" );
				s.cookies[ "rg_c" ] = g2.getChallenge().token( s );
				expect( g2.inspect( s ).action ).toBe( "allow" );
			} );
			it( "challenges a cookie replay that lacks sec-fetch-dest", function(){
				var s = chrome( { headers: withHeaders( { "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" }, [ "sec-fetch-dest" ] ) } );
				s.cookies[ "rg_c" ] = guard.getChallenge().token( s );
				expect( guard.inspect( s ).label ).toBe( "CHALLENGE-chrome-no-secfetch" );
			} );
			it( "challenges a Safari UA that lacks sec-fetch-dest", function(){
				var s = chrome( { headers: withHeaders( { "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15" }, [ "sec-fetch-dest" ] ) } );
				expect( guard.inspect( s ).label ).toBe( "CHALLENGE-safari-no-secfetch" );
			} );
			it( "denies a Googlebot claim from outside Google's ranges and allows a real one", function(){
				var ua = { "user-agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" };
				expect( guard.inspect( chrome( { remoteAddr: "203.0.113.11", headers: ua } ) ).label ).toBe( "BLOCK-403-fake-googlebot" );
				var real = chrome( { headers: ua, remoteAddr: "66.249.66.1" } );
				expect( guard.inspect( real ).action ).toBe( "allow" );
				expect( real.bot.verified ).toBeTrue();
			} );
			it( "denies the placeholder header signature", function(){
				expect( guard.inspect( chrome( { remoteAddr: "203.0.113.12", headers: { "user-agent": "x", "x-scraper-sdk": "blob" } } ) ).label ).toBe( "BLOCK-403-header-signature-example" );
			} );
			it( "denies a bot claim that arrives with a client-supplied forwarding header, unless verified", function(){
				var ua = { "user-agent": "Mozilla/5.0 (compatible; bingbot/2.0)", "x-forwarded-for": "1.2.3.4" };
				expect( guard.inspect( chrome( { remoteAddr: "203.0.113.13", headers: ua } ) ).label ).toBe( "BLOCK-403-forged-forwarding-bot-claim" );
			} );
			it( "denies cookie-less cloud clients unless they are a trusted bot", function(){
				expect( guard.inspect( chrome( { remoteAddr: "129.226.5.5", headers: { "user-agent": "curl/8" } } ) ).label ).toBe( "BLOCK-403-cloud-no-cookies" );
				expect( guard.inspect( chrome( { remoteAddr: "129.226.5.6", headers: { "user-agent": "Mozilla/5.0 (compatible; bingbot/2.0)" } } ) ).action ).toBe( "allow" );
			} );
			it( "ignores dev-tools probes with a quiet 200", function(){
				var d = guard.inspect( chrome( { remoteAddr: "203.0.113.16", path: "/.well-known/appspecific/com.chrome.devtools.json" } ) );
				expect( d.action ).toBe( "ignore" );
				expect( d.status ).toBe( 200 );
			} );
			it( "reports shadow rules without enforcing them", function(){
				var d = guard.inspect( chrome( { remoteAddr: "203.0.113.18", headers: withHeaders( { "user-agent": "Mozilla/5.0 (compatible; AhrefsBot/7.0)" } ) } ) );
				expect( d.action ).toBe( "allow" );
				expect( sink.labels() ).toInclude( "BLOCK-403-unwanted-bots" );
			} );
			it( "rate-limits an anonymous IP after 20 hits in 3 seconds with Retry-After", function(){
				var last = {};
				for ( var i = 1; i <= 25; i++ ) {
					last = guard.inspect( chrome( { remoteAddr: "198.51.100.7" } ) );
					if ( last.action != "allow" ) break;
				}
				expect( last.action ).toBe( "ratelimit" );
				expect( last.status ).toBe( 503 );
				expect( last.headers ).toHaveKey( "Retry-After" );
				expect( i ).toBe( 21 );
			} );
			it( "bans an IP after the strike threshold, internal networks never", function(){
				for ( var i = 1; i <= 5; i++ ) guard.inspect( chrome( { remoteAddr: "198.51.100.9", headers: { "user-agent": "x", "x-scraper-sdk": "blob" } } ) );
				expect( guard.inspect( chrome( { remoteAddr: "198.51.100.9" } ) ).label ).toBe( "BLOCK-403-banned" );
				for ( var i = 1; i <= 5; i++ ) guard.inspect( chrome( { remoteAddr: "10.0.0.5", headers: { "user-agent": "x", "x-scraper-sdk": "blob" } } ) );
				expect( guard.inspect( chrome( { remoteAddr: "10.0.0.5" } ) ).action ).toBe( "allow" );
			} );
		} );
	}

}
