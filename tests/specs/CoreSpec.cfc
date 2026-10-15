component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "Cidr", function(){
			var cidr = new cfRequestGuard.models.Cidr();
			it( "matches the full 32-bit range by arithmetic", function(){
				var set = cidr.compile( [ "20.0.0.0/8", "129.226.0.0/16", "203.0.113.0/24", "198.51.100.7" ] );
				expect( cidr.contains( set, "20.50.1.1" ) ).toBeTrue();
				expect( cidr.contains( set, "129.226.5.5" ) ).toBeTrue();
				expect( cidr.contains( set, "203.0.113.255" ) ).toBeTrue();
				expect( cidr.contains( set, "198.51.100.7" ) ).toBeTrue();
				expect( cidr.contains( set, "129.227.0.1" ) ).toBeFalse();
				expect( cidr.contains( set, "2001:db8::1" ) ).toBeFalse();
			} );
			it( "merges overlapping ranges and skips junk", function(){
				var set = cidr.compile( [ "10.0.0.0/8", "10.1.0.0/16", "not-an-ip", "300.1.1.1/8" ] );
				expect( set.count ).toBe( 1 );
				expect( set.skipped ).toBe( 2 );
			} );
		} );

		describe( "ClientIP", function(){
			var cidr = new cfRequestGuard.models.Cidr();
			var snap = function( remote, headers = {} ){ return { remoteAddr: remote, headers: headers }; };
			it( "ignores forwarding headers when no proxy is trusted", function(){
				var r = new cfRequestGuard.models.ClientIP( [], [ "10.0.0.0/8" ], cidr );
				expect( r.resolve( snap( "203.0.113.5", { "x-forwarded-for": "66.249.66.1" } ) ) ).toBe( "203.0.113.5" );
			} );
			it( "takes the rightmost foreign hop behind a trusted proxy", function(){
				var r = new cfRequestGuard.models.ClientIP( [ "10.0.0.0/24" ], [ "10.0.0.0/8" ], cidr );
				expect( r.resolve( snap( "10.0.0.118", { "x-forwarded-for": "66.249.66.1, 203.0.113.77" } ) ) ).toBe( "203.0.113.77" );
				expect( r.resolve( snap( "10.0.0.118", { "x-forwarded-for": "203.0.113.77, 10.0.0.5" } ) ) ).toBe( "203.0.113.77" );
				expect( r.resolve( snap( "10.0.0.118", { "forwarded": "for=203.0.113.9;proto=https" } ) ) ).toBe( "203.0.113.9" );
			} );
			it( "does not trust headers on a connection that bypassed the proxy", function(){
				var r = new cfRequestGuard.models.ClientIP( [ "10.0.0.0/24" ], [ "10.0.0.0/8" ], cidr );
				expect( r.resolve( snap( "203.0.113.5", { "x-forwarded-for": "66.249.66.1" } ) ) ).toBe( "203.0.113.5" );
			} );
		} );

		describe( "Challenge", function(){
			var ch = new cfRequestGuard.models.Challenge( { cookie: "rg_c" }, "test-secret", new cfRequestGuard.models.Decision() );
			var snap = function( ip, cookies = {} ){ return { clientIP: ip, cookies: cookies, now: now() }; };
			it( "accepts its own token for the same IP, today or yesterday", function(){
				var s = snap( "203.0.113.5" );
				expect( ch.isPassed( snap( "203.0.113.5", { "rg_c": ch.token( s ) } ) ) ).toBeTrue();
				expect( ch.isPassed( snap( "203.0.113.5", { "rg_c": ch.token( s, -1 ) } ) ) ).toBeTrue();
			} );
			it( "keys the token on the calendar day, not the minute", function(){
				var morning = { clientIP: "203.0.113.5", cookies: {}, now: createDateTime( 2026, 10, 9, 0, 1, 0 ) };
				var evening = { clientIP: "203.0.113.5", cookies: {}, now: createDateTime( 2026, 10, 9, 23, 58, 0 ) };
				var nextDay = { clientIP: "203.0.113.5", cookies: {}, now: createDateTime( 2026, 10, 10, 0, 1, 0 ) };
				expect( ch.token( morning ) ).toBe( ch.token( evening ) );
				expect( ch.token( morning ) ).notToBe( ch.token( nextDay ) );
				expect( ch.token( nextDay, -1 ) ).toBe( ch.token( morning ) );
			} );
			it( "rejects replay from another IP and tokens from another secret", function(){
				var tok   = ch.token( snap( "203.0.113.5" ) );
				var other = new cfRequestGuard.models.Challenge( { cookie: "rg_c" }, "other-secret", new cfRequestGuard.models.Decision() );
				expect( ch.isPassed( snap( "198.51.100.1", { "rg_c": tok } ) ) ).toBeFalse();
				expect( other.isPassed( snap( "203.0.113.5", { "rg_c": tok } ) ) ).toBeFalse();
			} );
		} );
	}

}
