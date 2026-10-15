component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "sinks", function(){
			var decision = new cfRequestGuard.models.Decision().make( "deny", { rule: "t", label: "BLOCK-403-t", detail: "d" } );
			var snap     = { clientIP: "203.0.113.1", method: "GET", path: "/x", query: "a=1", ua: "ua", headers: {}, cookies: {} };

			it( "log sink writes without throwing", function(){
				new cfRequestGuard.models.sinks.LogSink( { file: "requestguard-test" } ).emit( decision, snap );
				expect( true ).toBeTrue();
			} );
			it( "otel sink is a no-op without an agent", function(){
				new cfRequestGuard.models.sinks.OtelSink().emit( decision, snap );
				expect( true ).toBeTrue();
			} );
			it( "haproxy sink swallows an unreachable edge", function(){
				new cfRequestGuard.models.sinks.HAProxySink( { port: 1, labels: [ "BLOCK-403-t" ], timeoutMs: 50 } ).emit( decision, snap );
				expect( true ).toBeTrue();
			} );
			it( "crowdsec sink appends one JSON line", function(){
				var f = getTempDirectory() & "requestguard-" & createUUID() & ".jsonl";
				new cfRequestGuard.models.sinks.CrowdSecSink( { file: f } ).emit( decision, snap );
				var line = deserializeJSON( trim( fileRead( f ) ) );
				expect( line.label ).toBe( "BLOCK-403-t" );
				expect( line.ip ).toBe( "203.0.113.1" );
				expect( line.ts ).toMatch( "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$" );
				fileDelete( f );
			} );
		} );
	}

}
