component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "CacheBoxStore outside ColdBox", function(){
			it( "serves from memory until a CacheBox region is available", function(){
				var s = new cfRequestGuard.models.store.CacheBoxStore( { cacheName: "requestguard" } );
				expect( s.isLive() ).toBeFalse();
				s.set( "k", { a: 1 }, 60 );
				expect( s.get( "k" ).a ).toBe( 1 );
				expect( s.increment( "n", 60 ) ).toBe( 1 );
				expect( s.increment( "n", 60 ) ).toBe( 2 );
				s.delete( "k" );
				expect( isNull( s.get( "k" ) ) ).toBeTrue();
				expect( s.size() ).toBe( 1 );
			} );
		} );
		describe( "MemoryStore", function(){
			it( "expires entries", function(){
				var s = new cfRequestGuard.models.store.MemoryStore();
				s.set( "short", "v", 1 );
				expect( s.get( "short" ) ).toBe( "v" );
				sleep( 1100 );
				expect( isNull( s.get( "short" ) ) ).toBeTrue();
			} );
		} );
	}

}
