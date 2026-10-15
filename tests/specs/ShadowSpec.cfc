component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "global shadow mode", function(){
			var cfg = { secret: "x", mode: "shadow", sinks: [], strikes: { threshold: 2, windowSeconds: 60, banSeconds: 60 },
				rules: [ { name: "deny-curl", action: "deny", when: { ua: "^curl" } } ] };
			var guard = new cfRequestGuard.RequestGuard( cfg );
			var sink  = new tests.specs.support.CaptureSink();
			guard.addSink( sink );
			var snap = function(){
				return { method: "GET", path: "/", query: "", host: "h", remoteAddr: "203.0.113.50", clientIP: "203.0.113.50",
					headers: { "user-agent": "curl/8" }, cookies: {}, ua: "curl/8", referer: "", now: now() };
			};

			it( "returns allow, reports the shadowed decision, and never strikes", function(){
				for ( var i = 1; i <= 3; i++ ) {
					var d = guard.inspect( snap() );
					expect( d.action ).toBe( "allow" );
					expect( d.shadow.label ).toBe( "BLOCK-403-deny-curl" );
				}
				expect( sink.labels() ).toInclude( "BLOCK-403-deny-curl" );
				expect( sink.all()[ 1 ].mode ).toBe( "shadow" );
				expect( guard.getStrikes().isBanned( "203.0.113.50" ) ).toBeFalse();
			} );
			it( "serves no challenge without a configured secret, only reports it", function(){
				var rules = [ { name: "chal", action: "challenge", when: { ua: "^curl" } } ];
				var noSecret = new cfRequestGuard.RequestGuard( { secret: "", sinks: [], rules: rules } );
				var d = noSecret.inspect( snap() );
				expect( noSecret.hasSecret() ).toBeFalse();
				expect( d.action ).toBe( "allow" );
				expect( d.shadow.action ).toBe( "challenge" );
				var withSecret = new cfRequestGuard.RequestGuard( { secret: "s3cret", sinks: [], rules: rules } );
				expect( withSecret.hasSecret() ).toBeTrue();
				expect( withSecret.inspect( snap() ).action ).toBe( "challenge" );
			} );
			it( "enforces again after setMode( enforce )", function(){
				guard.setMode( "enforce" );
				expect( guard.inspect( snap() ).action ).toBe( "deny" );
				expect( guard.isShadow() ).toBeFalse();
			} );
		} );
	}

}
