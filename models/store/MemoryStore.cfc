/**
 * Per-node store on a ConcurrentHashMap. Lazy expiry on read, atomic
 * counters via AtomicLong, and a sweep of expired entries (no sort, no
 * global lock) once the map grows past maxEntries.
 */
component implements="IStore" {

	function init( struct cfg = {} ){
		variables.maxEntries   = arguments.cfg.maxEntries ?: 20000;
		variables.sweepSeconds = arguments.cfg.sweepSeconds ?: 30;
		variables.map          = createObject( "java", "java.util.concurrent.ConcurrentHashMap" ).init();
		variables.lastSweep    = getTickCount();
		return this;
	}

	any function get( required string key ){
		var e = variables.map.get( arguments.key );
		if ( isNull( e ) ) return javaCast( "null", "" );
		if ( e.expires < getTickCount() ) {
			variables.map.remove( arguments.key );
			return javaCast( "null", "" );
		}
		return e.value;
	}

	void function set( required string key, required any value, required numeric ttlSeconds ){
		variables.map.put( arguments.key, entry( arguments.value, arguments.ttlSeconds ) );
		sweepIfNeeded();
	}

	numeric function increment( required string key, required numeric ttlSeconds ){
		var nowMs = getTickCount();
		var e     = variables.map.get( arguments.key );
		if ( isNull( e ) || e.expires < nowMs ) {
			var fresh = entry( 0, arguments.ttlSeconds );
			var prev  = variables.map.putIfAbsent( arguments.key, fresh );
			e = isNull( prev ) ? fresh : prev;
			if ( e.expires < nowMs ) {
				// expired entry lost the race above: replace it (a lost increment here is acceptable for a counter)
				variables.map.put( arguments.key, fresh );
				e = fresh;
			}
			sweepIfNeeded();
		}
		return e.counter.incrementAndGet();
	}

	void function delete( required string key ){
		variables.map.remove( arguments.key );
	}

	numeric function size(){
		return variables.map.size();
	}

	/** Live entries as [ { key, value, ttlSeconds } ], counters exported as their count; used to migrate into a shared store. */
	array function export(){
		var out   = [];
		var nowMs = getTickCount();
		var it    = variables.map.entrySet().iterator();
		while ( it.hasNext() ) {
			var entry = it.next();
			var e     = entry.getValue();
			if ( e.expires < nowMs ) continue;
			var count = e.counter.get();
			arrayAppend( out, { key: entry.getKey(), value: count > 0 ? count : e.value, ttlSeconds: max( 1, int( ( e.expires - nowMs ) / 1000 ) ) } );
		}
		return out;
	}

	/* ------------------------------------------------------------------ */

	private struct function entry( required any value, required numeric ttlSeconds ){
		return {
			value   : arguments.value,
			counter : createObject( "java", "java.util.concurrent.atomic.AtomicLong" ).init( 0 ),
			expires : getTickCount() + ( arguments.ttlSeconds * 1000 )
		};
	}

	private void function sweepIfNeeded(){
		var nowMs = getTickCount();
		if ( variables.map.size() <= variables.maxEntries ) return;
		if ( nowMs - variables.lastSweep < variables.sweepSeconds * 1000 ) return;
		variables.lastSweep = nowMs;
		var it = variables.map.entrySet().iterator();
		while ( it.hasNext() ) {
			if ( it.next().getValue().expires < nowMs ) it.remove();
		}
	}

}
