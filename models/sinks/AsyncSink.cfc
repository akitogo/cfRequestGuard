/**
 * Decorator: hands each decision to the wrapped sink in a background thread,
 * so a slow edge (HAProxy stats socket, CrowdSec Local API) never adds to the
 * response time of the request that produced the decision. Fire and forget:
 * the request thread pays for starting a thread, nothing more.
 *
 * At most maxInFlight deliveries run at once per node. Beyond that the
 * decision is dropped for this sink and logged once a minute. Dropping is the
 * right failure mode: a banned client keeps sending requests and each one is
 * a ban decision, so the edge learns of it on the next one once the backlog
 * has drained, and the app-side decision holds regardless. Falling back to a
 * synchronous call would block requests exactly when the edge is slow.
 *
 * Configured per sink with `"async": true` (the default for haproxy and
 * crowdsec, off for log) and `"asyncMaxInFlight"` (8), or wrap your own:
 * guard.addSink( new models.sinks.AsyncSink( mySink ) ). The otel sink
 * annotates the current request's span and is never wrapped.
 */
component implements="ISink" {

	function init( required any inner, struct cfg = {} ){
		variables.inner    = arguments.inner;
		variables.cfg      = { maxInFlight: 8, logFile: "requestguard" };
		structAppend( variables.cfg, arguments.cfg, true );
		variables.name     = listLast( getMetadata( arguments.inner ).name, "." );
		variables.inFlight = createObject( "java", "java.util.concurrent.atomic.AtomicInteger" ).init( 0 );
		variables.dropped  = createObject( "java", "java.util.concurrent.atomic.AtomicInteger" ).init( 0 );
		variables.failed   = createObject( "java", "java.util.concurrent.atomic.AtomicInteger" ).init( 0 );
		variables.lastLog  = {};
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		if ( variables.inFlight.incrementAndGet() > variables.cfg.maxInFlight ) {
			variables.inFlight.decrementAndGet();
			variables.dropped.incrementAndGet();
			logOncePerMinute( "dropped", "cfRequestGuard sink #variables.name#: #variables.cfg.maxInFlight# deliveries in flight, decision for #arguments.snap.clientIP ?: '?'# dropped (#variables.dropped.get()# so far); the app-side decision still holds" );
			return;
		}
		// copies: the request goes on with its own decision struct while the thread reads this one
		var d     = duplicate( arguments.decision );
		var s     = duplicate( arguments.snap );
		var tname = "rgsink" & replace( createUUID(), "-", "", "all" );
		try {
			thread action="run" name=tname inner=variables.inner decision=d snap=s inFlight=variables.inFlight failed=variables.failed {
				try {
					attributes.inner.emit( attributes.decision, attributes.snap );
				} catch ( any e ) {
					attributes.failed.incrementAndGet();
					var where = arrayLen( e.tagContext ?: [] ) ? " at #listLast( e.tagContext[ 1 ].template, "/" )#:#e.tagContext[ 1 ].line#" : "";
					logOncePerMinute( "failed", "cfRequestGuard sink #variables.name# failed#where#: #e.message# #e.detail ?: ''#" );
				} finally {
					attributes.inFlight.decrementAndGet();
				}
			}
		} catch ( any e ) {
			// the thread could not be started: count it as dropped, the request must not wait
			variables.inFlight.decrementAndGet();
			variables.dropped.incrementAndGet();
			logOncePerMinute( "dropped", "cfRequestGuard sink #variables.name#: could not start a delivery thread (#e.message#), decision dropped" );
		}
	}

	any function getInner(){ return variables.inner; }
	numeric function inFlightCount(){ return variables.inFlight.get(); }
	numeric function droppedCount(){ return variables.dropped.get(); }
	numeric function failedCount(){ return variables.failed.get(); }

	private void function logOncePerMinute( required string kind, required string text ){
		var last = variables.lastLog[ arguments.kind ] ?: "";
		if ( isDate( last ) && dateDiff( "s", last, now() ) < 60 ) return;
		variables.lastLog[ arguments.kind ] = now();
		writeLog( file = variables.cfg.logFile, type = "warning", text = arguments.text );
	}

}
