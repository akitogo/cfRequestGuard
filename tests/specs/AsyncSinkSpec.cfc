component extends="testbox.system.BaseSpec" {

	function run(){
		describe( "async sink", function(){
			var decision = new cfRequestGuard.models.Decision().make( "deny", { rule: "t", label: "BLOCK-403-t", detail: "d" } );
			var snap     = { clientIP: "203.0.113.1", method: "GET", path: "/x", query: "a=1", ua: "ua", headers: {}, cookies: {} };

			it( "returns before the inner sink has delivered, and the inner sink still gets the decision", function(){
				var slow  = new tests.specs.support.SlowSink( 400 );
				var async = new cfRequestGuard.models.sinks.AsyncSink( slow, { logFile: "requestguard-test" } );
				var t0 = getTickCount();
				async.emit( decision, snap );
				expect( getTickCount() - t0 ).toBeLT( 300 );
				expect( slow.count() ).toBe( 0 );
				expect( settle( slow, 1 ) ).toBe( 1 );
				expect( async.droppedCount() ).toBe( 0 );
				expect( async.failedCount() ).toBe( 0 );
			} );
			it( "drops beyond maxInFlight instead of queueing or blocking", function(){
				var slow  = new tests.specs.support.SlowSink( 400 );
				var async = new cfRequestGuard.models.sinks.AsyncSink( slow, { maxInFlight: 1, logFile: "requestguard-test" } );
				var t0 = getTickCount();
				async.emit( decision, snap );
				async.emit( decision, snap );
				async.emit( decision, snap );
				expect( getTickCount() - t0 ).toBeLT( 300 );
				expect( async.droppedCount() ).toBe( 2 );
				expect( settle( slow, 1 ) ).toBe( 1 );
				sleep( 100 );
				expect( slow.count() ).toBe( 1 );
				expect( async.inFlightCount() ).toBe( 0 );
				// slot free again: the next decision goes through
				async.emit( decision, snap );
				expect( settle( slow, 2 ) ).toBe( 2 );
			} );
			it( "counts a throwing inner sink as failed and never throws into the caller", function(){
				var broken = new tests.specs.support.SlowSink( 10, true );
				var async  = new cfRequestGuard.models.sinks.AsyncSink( broken, { logFile: "requestguard-test" } );
				async.emit( decision, snap );
				var until = getTickCount() + 3000;
				while ( async.failedCount() < 1 && getTickCount() < until ) sleep( 20 );
				expect( async.failedCount() ).toBe( 1 );
				expect( async.inFlightCount() ).toBe( 0 );
				expect( broken.count() ).toBe( 0 );
			} );
			it( "guard wraps haproxy and crowdsec by default, log and otel stay inline, async:false opts out", function(){
				var guard = new cfRequestGuard.RequestGuard( { secret: "s", rules: [], sinks: [
					{ type: "log", file: "requestguard-test" },
					{ type: "otel", async: true },
					{ type: "haproxy", port: 1, timeoutMs: 50 },
					{ type: "crowdsec", async: false },
					{ type: "log", file: "requestguard-test", async: true, asyncMaxInFlight: 2 }
				] } );
				var sinks = guard.getSinks();
				expect( nameOf( sinks[ 1 ] ) ).toBe( "LogSink" );
				expect( nameOf( sinks[ 2 ] ) ).toBe( "OtelSink" );
				expect( nameOf( sinks[ 3 ] ) ).toBe( "AsyncSink" );
				expect( nameOf( sinks[ 3 ].getInner() ) ).toBe( "HAProxySink" );
				expect( nameOf( sinks[ 4 ] ) ).toBe( "CrowdSecSink" );
				expect( nameOf( sinks[ 5 ] ) ).toBe( "AsyncSink" );
				expect( nameOf( sinks[ 5 ].getInner() ) ).toBe( "LogSink" );
			} );
		} );
	}

	/** Polls until the sink has seen `expected` decisions or maxMs passed; returns the count. */
	private numeric function settle( required any sink, required numeric expected, numeric maxMs = 3000 ){
		var until = getTickCount() + arguments.maxMs;
		while ( arguments.sink.count() < arguments.expected && getTickCount() < until ) sleep( 20 );
		return arguments.sink.count();
	}

	private string function nameOf( required any s ){ return listLast( getMetadata( arguments.s ).name, "." ); }

}
