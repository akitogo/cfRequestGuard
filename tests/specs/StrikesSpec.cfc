component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "strike ladder", function(){
			var base = { secret: "x", sinks: [], strikes: { threshold: 2, windowSeconds: 60, banSeconds: 60 },
				bots: [ { name: "monitor", category: "monitor", ua: "UptimeRobot" } ],
				rules: [
					{ name: "deny-curl",  action: "deny", when: { ua: "^curl" } },
					{ name: "deny-load",  action: "deny", strike: false, when: { path: "^/heavy" } },
					{ name: "deny-probe", action: "deny", when: { headerPresent: [ "x-probe" ] } }
				] };
			var snap = function( ip, ua = "curl/8", path = "/", headers = {} ){
				var h = duplicate( headers ); h[ "user-agent" ] = ua;
				return { method: "GET", path: path, query: "", host: "h", remoteAddr: ip, clientIP: ip, headers: h, cookies: {}, ua: ua, referer: "", now: now() };
			};

			it( "bans after the threshold of striking denies", function(){
				var guard = new cfRequestGuard.RequestGuard( base );
				guard.inspect( snap( "203.0.113.1" ) ); guard.inspect( snap( "203.0.113.1" ) );
				expect( guard.inspect( snap( "203.0.113.1", "Mozilla/5.0" ) ).label ).toBe( "BLOCK-403-banned" );
			} );
			it( "a deny with strike: false never feeds the ladder", function(){
				var guard = new cfRequestGuard.RequestGuard( base );
				for ( var i = 1; i <= 5; i++ ) expect( guard.inspect( snap( "203.0.113.2", "Mozilla/5.0", "/heavy" ) ).label ).toBe( "BLOCK-403-deny-load" );
				expect( guard.inspect( snap( "203.0.113.2", "Mozilla/5.0" ) ).action ).toBe( "allow" );
			} );
			it( "trusted bots are denied by matching rules but never struck or banned", function(){
				var guard = new cfRequestGuard.RequestGuard( base );
				for ( var i = 1; i <= 5; i++ ) expect( guard.inspect( snap( "203.0.113.3", "UptimeRobot/2.0", "/", { "x-probe": "1" } ) ).label ).toBe( "BLOCK-403-deny-probe" );
				expect( guard.inspect( snap( "203.0.113.3", "UptimeRobot/2.0" ) ).action ).toBe( "allow" );
				expect( guard.getStrikes().isBanned( "203.0.113.3" ) ).toBeFalse();
			} );
			it( "an existing ban does not apply to a trusted bot sharing the address", function(){
				var guard = new cfRequestGuard.RequestGuard( base );
				guard.inspect( snap( "203.0.113.4" ) ); guard.inspect( snap( "203.0.113.4" ) );
				expect( guard.inspect( snap( "203.0.113.4", "Mozilla/5.0" ) ).label ).toBe( "BLOCK-403-banned" );
				expect( guard.inspect( snap( "203.0.113.4", "UptimeRobot/2.0" ) ).action ).toBe( "allow" );
			} );
		} );
	}

}
