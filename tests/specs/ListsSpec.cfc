component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "Lists", function(){
			var cidr = new cfRequestGuard.models.Cidr();

			it( "loads a cidr-lines seed synchronously, stamped with the file date", function(){
				var lists = new cfRequestGuard.models.Lists( { cloud: { seed: expandPath( "/tests/fixtures/cloud.txt" ), format: "cidr-lines" } }, cidr, "requestguard-test" );
				expect( lists.contains( "cloud", "20.50.1.1" ) ).toBeTrue();
				expect( lists.contains( "cloud", "8.8.8.8" ) ).toBeFalse();
				expect( lists.info( "cloud" ).source ).toBe( "seed" );
				expect( lists.isUsable( "cloud" ) ).toBeTrue();
			} );

			it( "accepts a webroot-relative seed path", function(){
				var lists = new cfRequestGuard.models.Lists( { cloud: { seed: "/tests/fixtures/cloud.txt", format: "cidr-lines" } }, cidr, "requestguard-test" );
				expect( lists.contains( "cloud", "20.50.1.1" ) ).toBeTrue();
				expect( lists.info( "cloud" ).source ).toBe( "seed" );
			} );

			it( "parses Google's crawler JSON including its creationTime", function(){
				var lists = new cfRequestGuard.models.Lists( { google: { seed: expandPath( "/tests/fixtures/google.json" ), format: "google-json" } }, cidr, "requestguard-test" );
				var info  = lists.info( "google" );
				expect( info.entries ).toBe( 2 );
				expect( isDate( info.stamp ) ).toBeTrue();
				expect( year( info.stamp ) ).toBe( 2026 ); expect( month( info.stamp ) ).toBe( 10 ); expect( day( info.stamp ) ).toBe( 1 );
				expect( lists.contains( "google", "66.249.64.130" ) ).toBeTrue();
				expect( lists.contains( "google", "66.249.64.100" ) ).toBeFalse();
			} );

			it( "accepts a seed whose prefixes are plain strings with a generated stamp", function(){
				var lists = new cfRequestGuard.models.Lists( { google: { seed: "/tests/fixtures/google-seed.json", format: "google-json" } }, cidr, "requestguard-test" );
				expect( lists.info( "google" ).entries ).toBe( 2 );
				expect( month( lists.info( "google" ).stamp ) ).toBe( 9 );
				expect( lists.contains( "google", "66.249.64.5" ) ).toBeTrue();
			} );

			it( "persists a refresh in the store and a later instance starts from it", function(){
				var store = new cfRequestGuard.models.store.MemoryStore();
				var src   = "http://#cgi.http_host#/tests/fixtures/cloud.txt";
				var cfg   = { cloud: { sources: [ src ], format: "cidr-lines", minEntries: 2 } };
				var lists = new cfRequestGuard.models.Lists( cfg, cidr, "requestguard-test", store );
				var waited = 0;
				while ( lists.info( "cloud" ).refreshing && waited < 10000 ) { sleep( 100 ); waited += 100; }
				expect( lists.refreshNow( "cloud" ) ).toBeTrue();
				expect( isStruct( store.get( "rg:list:cloud" ) ) ).toBeTrue();
				var again = new cfRequestGuard.models.Lists( cfg, cidr, "requestguard-test", store );
				expect( again.info( "cloud" ).source ).toBe( "store" );
				expect( again.info( "cloud" ).refreshing ).toBeFalse();
				expect( again.contains( "cloud", "203.0.113.9" ) ).toBeTrue();
				expect( again.isUsable( "cloud" ) ).toBeTrue();
			} );

			it( "carries refreshed data into a store handed in later, but not seed data", function(){
				var seeded = new cfRequestGuard.models.Lists( { cloud: { seed: expandPath( "/tests/fixtures/cloud.txt" ), format: "cidr-lines" } }, cidr, "requestguard-test" );
				var store  = new cfRequestGuard.models.store.MemoryStore();
				seeded.setStore( store );
				expect( isNull( store.get( "rg:list:cloud" ) ) ).toBeTrue();
				var src     = "http://#cgi.http_host#/tests/fixtures/cloud.txt";
				var fetched = new cfRequestGuard.models.Lists( { cloud: { sources: [ src ], format: "cidr-lines", minEntries: 2 } }, cidr, "requestguard-test" );
				var waited  = 0;
				while ( fetched.info( "cloud" ).refreshing && waited < 10000 ) { sleep( 100 ); waited += 100; }
				fetched.refreshNow( "cloud" );
				fetched.setStore( store );
				expect( isStruct( store.get( "rg:list:cloud" ) ) ).toBeTrue();
			} );

			it( "refreshes in a background thread at init", function(){
				var src    = "http://#cgi.http_host#/tests/fixtures/cloud.txt";
				var lists  = new cfRequestGuard.models.Lists( { cloud: { sources: [ src ], format: "cidr-lines", minEntries: 2 } }, cidr, "requestguard-test" );
				var waited = 0;
				while ( lists.info( "cloud" ).source != "remote" && waited < 10000 ) { sleep( 100 ); waited += 100; }
				expect( lists.info( "cloud" ).source ).toBe( "remote" );
			} );

			it( "rejects a refresh below the minimum-size floor", function(){
				var src  = "http://#cgi.http_host#/tests/fixtures/cloud.txt";
				var tiny = new cfRequestGuard.models.Lists( { cloud: { sources: [ src ], format: "cidr-lines", minEntries: 100 } }, cidr, "requestguard-test" );
				expect( tiny.refreshNow( "cloud" ) ).toBeFalse();
				expect( tiny.info( "cloud" ).entries ).toBe( 0 );
				expect( tiny.isUsable( "cloud" ) ).toBeFalse();
			} );
		} );
	}

}
