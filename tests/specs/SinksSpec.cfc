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
			it( "crowdsec sink skips shadow decisions and, for the LAPI, unlisted labels", function(){
				var f = getTempDirectory() & "requestguard-" & createUUID() & ".jsonl";
				var shadow = duplicate( decision ); shadow.mode = "shadow";
				new cfRequestGuard.models.sinks.CrowdSecSink( { file: f } ).emit( shadow, snap );
				expect( fileExists( f ) ).toBeFalse();
				// label not listed: no HTTP call, so an unreachable LAPI is never touched
				new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "m", password: "p", labels: [ "BLOCK-403-banned" ], timeoutSeconds: 1 } } ).emit( decision, snap );
				expect( true ).toBeTrue();
			} );
			it( "crowdsec sink builds a LAPI alert with a ready decision", function(){
				var sink = new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1/", machineId: "m", password: "p", duration: "2h", type: "captcha" } } );
				var a = sink.alert( decision, snap );
				expect( a.scenario ).toBe( "cfRequestGuard/strike-ban" );
				expect( a.source.value ).toBe( "203.0.113.1" );
				expect( a.events_count ).toBe( 1 );
				expect( a.simulated ).toBeFalse();
				expect( a.start_at ).toMatch( "^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$" );
				expect( a.decisions[ 1 ].type ).toBe( "captcha" );
				expect( a.decisions[ 1 ].duration ).toBe( "2h" );
				expect( a.decisions[ 1 ].value ).toBe( "203.0.113.1" );
				expect( a.events[ 1 ].meta[ 1 ].key ).toBe( "source_ip" );
				var json = serializeJSON( [ a ] );
				expect( json ).toInclude( '"scenario_hash":""' );
				expect( isJSON( json ) ).toBeTrue();
			} );
			it( "crowdsec sink takes origin and env: machineId from the config", function(){
				var sys = createObject( "java", "java.lang.System" );
				sys.setProperty( "RG_TEST_MACHINE", "requestguard-test" );
				var sink = new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "env:RG_TEST_MACHINE", password: "p", origin: "cscli" } } );
				expect( sink.alert( decision, snap ).decisions[ 1 ].origin ).toBe( "cscli" );
				expect( sink.getLapi().machineId ).toBe( "requestguard-test" );
				expect( new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "m", password: "p" } } ).alert( decision, snap ).decisions[ 1 ].origin ).toBe( "cfRequestGuard" );
			} );
			it( "crowdsec sink pushes an address once per repushSeconds, however many ban decisions it produces", function(){
				var sink = new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "m", password: "p", repushSeconds: 600 } } );
				expect( sink.recentlyPushed( "203.0.113.1" ) ).toBeFalse();   // first sight: push
				expect( sink.recentlyPushed( "203.0.113.1" ) ).toBeTrue();    // within the window: skip
				expect( sink.recentlyPushed( "203.0.113.2" ) ).toBeFalse();   // another address: push
				var short = new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "m", password: "p", repushSeconds: 0 } } );
				short.recentlyPushed( "203.0.113.1" );
				expect( short.recentlyPushed( "203.0.113.1" ) ).toBeFalse();  // window over: push again
			} );
			it( "crowdsec sink swallows an unreachable LAPI for a listed label", function(){
				new cfRequestGuard.models.sinks.CrowdSecSink( { lapi: { url: "http://127.0.0.1:1", machineId: "m", password: "p", labels: [ "BLOCK-403-t" ], timeoutSeconds: 1, logFile: "requestguard-test" } } ).emit( decision, snap );
				expect( true ).toBeTrue();
			} );
		} );
	}

}
