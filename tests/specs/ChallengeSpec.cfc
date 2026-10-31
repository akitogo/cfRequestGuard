component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "challenge page", function(){
			var rules = [ { name: "chal", action: "challenge", when: { ua: "^curl" } } ];
			var snap  = function(){
				return { method: "GET", path: "/", query: "", host: "h", remoteAddr: "203.0.113.50", clientIP: "203.0.113.50",
					headers: { "user-agent": "curl/8" }, cookies: {}, ua: "curl/8", referer: "", now: now() };
			};

			it( "writes the bound cookie and reloads only once per tab", function(){
				var guard = new cfRequestGuard.RequestGuard( { secret: "s3cret", sinks: [], challenge: { cookie: "rg_c" }, rules: rules } );
				var d = guard.inspect( snap() );
				expect( d.action ).toBe( "challenge" );
				expect( d.body ).toInclude( 'n="rg_c"' );
				expect( d.body ).toInclude( 'SameSite=Lax;Secure"' );
				// loop breaker: remembers the automatic attempt, then waits for a click
				expect( d.body ).toInclude( 'sessionStorage.setItem(k,String(Date.now()))' );
				expect( d.body ).toInclude( 'if(tried()){manual("");return;}' );
				expect( d.body ).toInclude( 'id="rg-continue"' );
				// a cookie the browser refused never triggers a reload
				expect( d.body ).toInclude( 'if(!set()){manual(' );
				expect( d.body ).toInclude( '<noscript>' );
				expect( d.body ).toInclude( 'name="robots" content="noindex"' );
			} );
			it( "honours the configured texts and retry window", function(){
				var guard = new cfRequestGuard.RequestGuard( { secret: "s3cret", sinks: [], rules: rules,
					challenge: { title: "Einen Moment", continueText: "Weiter", retryText: "Bitte klicken.", cookieText: "Cookies <nötig>", retryWindowSeconds: 30, secure: false } } );
				var body = guard.inspect( snap() ).body;
				expect( body ).toInclude( "<title>Einen Moment</title>" );
				expect( body ).toInclude( ">Weiter</button>" );
				expect( body ).toInclude( "Bitte klicken." );
				expect( body ).toInclude( "Cookies \x3Cn" );   // JS-encoded inside the script
				expect( body ).notToInclude( "<nötig>" );
				expect( body ).toInclude( "w=30*1000" );
				expect( body ).notToInclude( 'SameSite=Lax;Secure"' );
			} );
		} );

		describe( "detector report (challenge.botd)", function(){
			var rules  = [ { name: "chal", action: "challenge", when: { ua: "^curl" } } ];
			var page   = function( path = "/", query = "" ){
				return { method: "GET", path: path, query: query, host: "h", remoteAddr: "203.0.113.50", clientIP: "203.0.113.50",
					headers: { "user-agent": "curl/8" }, cookies: {}, ua: "curl/8", referer: "", now: now() };
			};
			var post   = function( body ){
				return { method: "POST", path: "/__requestguard/botd", query: "", host: "h", remoteAddr: "203.0.113.50", clientIP: "203.0.113.50",
					headers: { "user-agent": "curl/8" }, cookies: {}, ua: "curl/8", referer: "", now: now(), body: body };
			};
			var make = function( botd ){
				var sink  = new tests.specs.support.CaptureSink();
				var guard = new cfRequestGuard.RequestGuard( { secret: "s3cret", sinks: [], rules: rules, challenge: { botd: botd } } );
				guard.addSink( sink );
				return { guard: guard, sink: sink };
			};

			it( "is off by default: no detector in the page, the report path is an ordinary request", function(){
				var t = make( "off" );
				var body = t.guard.inspect( page() ).body;
				expect( body ).notToInclude( "BotD" );
				expect( body ).toInclude( "}go();})();" );
				// the post is not intercepted: it runs down the normal chain like any request (and meets the curl rule)
				var d = t.guard.inspect( post( '{"n":"x"}' ) );
				expect( d.label ).toBe( "CHALLENGE-chal" );
			} );

			it( "report: inlines the detector with monitoring off, the nonce, rule and page, then runs the cookie flow", function(){
				var t    = make( "report" );
				var snap = page( "/items/42.html", "page=3" );
				var body = t.guard.inspect( snap ).body;
				var n    = t.guard.getChallenge().nonce( snap, "chal", "/items/42.html?page=3" );
				expect( body ).toInclude( "var BotD=" );
				expect( body ).toInclude( "BotD.load({monitoring:false})" );
				var ver = trim( fileRead( expandPath( "/cfRequestGuard/vendor/botd/VERSION" ) ) );
				expect( ver ).toMatch( "^\d+\.\d+\.\d+" );
				expect( body ).toInclude( 'var R={u:"/__requestguard/botd",n:"#n#",r:"chal",p:"/items/42.html?page=3",v:"#ver#"}' );
				expect( body ).toInclude( "/*! BotD v#ver# " );
				expect( body ).toInclude( "navigator.sendBeacon" );
				expect( body ).toInclude( 'setTimeout(function(){fin("timeout");},1500)' );
				// the cookie flow is unchanged, just deferred until the verdict is sent
				expect( body ).toInclude( 'function go(){if(!set()){manual(' );
				expect( body ).toInclude( 'function fin(k){if(done){return;}done=true;send(k);go();}' );
				expect( body ).notToInclude( "openfpcdn.io/botd/v${W}/npm-monitoring`,!0),e.send()}catch(e){console.error(e)}}async function S({monitoring:e=!0}" );
			} );

			it( "report: a verdict with a valid nonce becomes a 204 BOTD-<kind> decision for the sinks, no strike", function(){
				var t    = make( "report" );
				var n    = t.guard.getChallenge().nonce( page(), "chal", "/items/42.html" );
				var d    = t.guard.inspect( post( '{"n":"#n#","r":"chal","p":"/items/42.html","k":"headless_chrome","v":"2.0.0","t":131}' ) );
				expect( d.action ).toBe( "ignore" );
				expect( d.status ).toBe( 204 );
				expect( d.label ).toBe( "BOTD-headless_chrome" );
				expect( d.rule ).toBe( "chal" );
				expect( d.detail ).toBe( "page=/items/42.html ms=131 botd=2.0.0" );
				expect( d.strike ).toBe( 0 );
				expect( t.sink.labels() ).toBe( [ "BOTD-headless_chrome" ] );
				expect( t.guard.getStrikes().isBanned( "203.0.113.50" ) ).toBeFalse();
				// yesterday's nonce still counts, like the cookie
				var y = t.guard.getChallenge().nonce( page(), "chal", "/items/42.html", -1 );
				expect( t.guard.inspect( post( '{"n":"#y#","r":"chal","p":"/items/42.html","k":"clean"}' ) ).label ).toBe( "BOTD-clean" );
			} );

			it( "report: anything without a matching nonce is BOTD-invalid, still 204, still terminal", function(){
				var t = make( "report" );
				var n = t.guard.getChallenge().nonce( page(), "chal", "/items/42.html" );
				var bad = [
					"",
					"not json",
					'["list"]',
					'{"n":"#n#","r":"other","p":"/items/42.html","k":"clean"}',       // rule swapped
					'{"n":"#n#","r":"chal","p":"/items/43.html","k":"clean"}',        // page swapped
					'{"n":"#n#","r":"chal","p":"/items/42.html"}'                     // kind missing is fine, see below
				];
				for ( var i = 1; i <= 5; i++ ) {
					var d = t.guard.inspect( post( bad[ i ] ) );
					expect( d.action ).toBe( "ignore" );
					expect( d.status ).toBe( 204 );
					expect( d.label ).toBe( "BOTD-invalid" );
				}
				expect( t.guard.inspect( post( bad[ 6 ] ) ).label ).toBe( "BOTD-unknown" );
				// a nonce for another client address is worthless here (bindToIP)
				var other = post( '{"n":"#n#","r":"chal","p":"/items/42.html","k":"clean"}' );
				other.clientIP = "198.51.100.9";
				expect( t.guard.inspect( other ).label ).toBe( "BOTD-invalid" );
			} );

			it( "report: kind and page are sanitised before they reach a log line", function(){
				var t = make( "report" );
				var n = t.guard.getChallenge().nonce( page(), "chal", "/a" );
				var d = t.guard.inspect( post( '{"n":"#n#","r":"chal","p":"/a","k":"head<less>\n| rule=x","v":"<b>","t":"nope"}' ) );
				expect( d.label ).toBe( "BOTD-headlessrulex" );
				expect( d.detail ).toBe( "page=/a botd=b" );
				// the page text embedded in the challenge is already printable ASCII and capped, so it round-trips the nonce
				var long = page( "/" & repeatString( "x", 300 ), "q=" & chr( 10 ) & "é" );
				var body = t.guard.inspect( long ).body;
				expect( body ).toInclude( 'p:"/' & repeatString( "x", 199 ) & '",v:"' );
			} );
		} );
	}

}
