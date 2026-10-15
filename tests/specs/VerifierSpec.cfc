component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "rDNS bot verification", function(){
			var bots = [ { name: "archive", category: "archive", ua: "archive\.org_bot", verify: { rdns: "\.archive\.org$", ranges: [ "204.62.248.0/23" ] } } ];
			var snap = function( ip ){
				return { method: "GET", path: "/", query: "", host: "h", remoteAddr: ip, clientIP: ip, headers: {}, cookies: {},
					ua: "Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)", referer: "", now: now() };
			};
			var fakeDns = function( numeric delayMs = 0 ){
				var calls = { reverse: 0, forward: 0 };
				return {
					calls   : calls,
					reverse : function( ip ){ calls.reverse++; if ( delayMs ) sleep( delayMs ); return ip == "204.62.249.6" ? "k8s-worker.ca.archive.org" : ( ip == "204.62.248.9" ? "evil.example.net" : "" ); },
					forward : function( host ){ calls.forward++; return host == "k8s-worker.ca.archive.org" ? [ "204.62.249.6" ] : []; }
				};
			};
			var make = function( struct rdns = {} ){
				return new cfRequestGuard.RequestGuard( { secret: "x", sinks: [], rules: [], bots: bots, rdns: rdns } );
			};

			it( "trusts a forward-confirmed host and caches the verdict in the store", function(){
				var guard = make(); var dns = fakeDns(); guard.getVerifier().setResolver( dns );
				var r = guard.getVerifier().classify( snap( "204.62.249.6" ) );
				expect( r.trusted ).toBeTrue(); expect( r.verified ).toBeTrue(); expect( r.spoofed ).toBeFalse();
				guard.getVerifier().classify( snap( "204.62.249.6" ) );
				guard.getVerifier().classify( snap( "204.62.249.6" ) );
				expect( dns.calls.reverse ).toBe( 1 );   // later hits come from the store
				expect( guard.getStore().get( "rg:rdns:204.62.249.6:" & lCase( hash( "\.archive\.org$" ) ) ) ).toBe( "confirmed" );
				expect( guard.getVerifier().getInFlight().get() ).toBe( 0 );
			} );
			it( "marks a mismatching host as spoofed and caches that too", function(){
				var guard = make(); var dns = fakeDns(); guard.getVerifier().setResolver( dns );
				expect( guard.getVerifier().classify( snap( "204.62.248.9" ) ).spoofed ).toBeTrue();
				guard.getVerifier().classify( snap( "204.62.248.9" ) );
				expect( dns.calls.reverse ).toBe( 1 );
			} );
			it( "never resolves an address outside the bot's ranges", function(){
				var guard = make(); var dns = fakeDns(); guard.getVerifier().setResolver( dns );
				var r = guard.getVerifier().classify( snap( "198.51.100.9" ) );
				expect( r.spoofed ).toBeTrue(); expect( r.reason ).toInclude( "outside" );
				expect( dns.calls.reverse ).toBe( 0 );
			} );
			it( "gives up after timeoutMs, treats the bot as an ordinary visitor, and frees the slot when DNS finally answers", function(){
				var guard = make( { timeoutMs: 200, unknownCacheSeconds: 5 } ); var dns = fakeDns( 700 ); guard.getVerifier().setResolver( dns );
				var t0 = getTickCount();
				var r  = guard.getVerifier().classify( snap( "204.62.249.6" ) );
				expect( getTickCount() - t0 ).toBeLT( 650 );
				expect( r.trusted ).toBeFalse(); expect( r.spoofed ).toBeFalse(); expect( r.reason ).toInclude( "timeout" );
				expect( guard.getVerifier().getInFlight().get() ).toBe( 1 );        // worker still blocked in DNS
				guard.getVerifier().classify( snap( "204.62.249.6" ) );
				expect( dns.calls.reverse ).toBe( 1 );                                // unknown verdict is cached, no second lookup
				sleep( 800 );
				expect( guard.getVerifier().getInFlight().get() ).toBe( 0 );        // worker released its slot by itself
			} );
			it( "skips the lookup when the in-flight budget is used up", function(){
				var guard = make( { maxInFlight: 2 } ); var dns = fakeDns(); guard.getVerifier().setResolver( dns );
				guard.getVerifier().getInFlight().set( 2 );
				var r = guard.getVerifier().classify( snap( "204.62.249.6" ) );
				expect( r.trusted ).toBeFalse(); expect( r.spoofed ).toBeFalse(); expect( r.reason ).toInclude( "budget" );
				expect( dns.calls.reverse ).toBe( 0 );
				expect( guard.getVerifier().getInFlight().get() ).toBe( 2 );        // a refused attempt does not leak a slot
			} );
		} );
	}

}
