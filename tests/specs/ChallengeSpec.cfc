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
	}

}
