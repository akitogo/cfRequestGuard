component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "Config", function(){
			var reader = new cfRequestGuard.models.Config();

			it( "reads the wrapped example file", function(){
				var cfg = reader.read( expandPath( "/cfRequestGuard/config/requestguard.example.json.cfm" ) );
				expect( cfg ).toHaveKey( "rules" );
				expect( arrayLen( cfg.rules ) ).toBeGT( 5 );
				expect( cfg.challenge.cookie ).toBe( "rg_c" );
			} );
			it( "extracts plain JSON unchanged and tolerates a header without braces", function(){
				expect( reader.unwrap( '{ "a": 1 }' ) ).toBe( '{ "a": 1 }' );
				var wrapped = "<cfabort>" & chr( 10 ) & "<!--- header text" & chr( 10 ) & "{" & chr( 10 ) & '  "a": [ 1, 2 ]' & chr( 10 ) & "}" & chr( 10 ) & "--->" & chr( 10 );
				expect( deserializeJSON( reader.unwrap( wrapped ) ).a[ 2 ] ).toBe( 2 );
			} );
			it( "rejects a missing or non-JSON file", function(){
				expect( function(){ reader.read( expandPath( "/cfRequestGuard/config/nope.json.cfm" ) ); } ).toThrow( "RequestGuard.ConfigNotFound" );
				expect( function(){ reader.read( expandPath( "/cfRequestGuard/tests/fixtures/cloud.txt" ) ); } ).toThrow( "RequestGuard.ConfigInvalid" );
			} );
		} );
	}

}
