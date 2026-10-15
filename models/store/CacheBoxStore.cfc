/**
 * Store on a CacheBox region. Hand in the cache object with setCache(), or
 * name the region and it is resolved from the running ColdBox controller on
 * first use. Until the controller exists (the first seconds of an
 * application start, when Application.cfc builds the guard before ColdBox
 * boots) an internal memory store serves the calls, so the guard never
 * waits for the framework.
 *
 * With a distributed provider behind the region, limits, bans and list
 * copies become cluster-wide. increment() is lock-protected
 * read-modify-write; a Redis-native store should use INCR instead.
 *
 * cfg: { cacheName: "requestguard" }
 */
component implements="IStore" {

	function init( struct cfg = {} ){
		variables.cacheName   = arguments.cfg.cacheName ?: "default";
		variables.regionCache       = "";
		variables.fallback    = new MemoryStore( arguments.cfg );
		variables.retryAfter  = "";
		return this;
	}

	any function setCache( required any cache ){
		variables.regionCache = arguments.cache;
		return this;
	}

	/** True once the CacheBox region is in use (the method is not named cache(): that is the script form of the cfcache tag). */
	boolean function isLive(){
		return !isNull( region() );
	}

	any function get( required string key ){
		var c = region();
		if ( isNull( c ) ) return variables.fallback.get( arguments.key );
		var v = c.get( arguments.key );
		return isNull( v ) ? javaCast( "null", "" ) : v;
	}

	void function set( required string key, required any value, required numeric ttlSeconds ){
		var c = region();
		if ( isNull( c ) ) { variables.fallback.set( arguments.key, arguments.value, arguments.ttlSeconds ); return; }
		c.set( arguments.key, arguments.value, minutes( arguments.ttlSeconds ), 0 );
	}

	numeric function increment( required string key, required numeric ttlSeconds ){
		var c = region();
		if ( isNull( c ) ) return variables.fallback.increment( arguments.key, arguments.ttlSeconds );
		var n = 0;
		lock name="requestguard-inc-#arguments.key#" type="exclusive" timeout="2" throwOnTimeout="false" {
			n = val( c.get( arguments.key ) ?: 0 ) + 1;
			c.set( arguments.key, n, minutes( arguments.ttlSeconds ), 0 );
		}
		return n;
	}

	void function delete( required string key ){
		var c = region();
		if ( isNull( c ) ) { variables.fallback.delete( arguments.key ); return; }
		c.clear( arguments.key );
	}

	numeric function size(){
		var c = region();
		return isNull( c ) ? variables.fallback.size() : c.getSize();
	}

	/* ------------------------------------------------------------------ */

	private any function region(){
		if ( isObject( variables.regionCache ) ) return variables.regionCache;
		if ( isDate( variables.retryAfter ) && dateCompare( now(), variables.retryAfter ) == -1 ) return javaCast( "null", "" );
		try {
			if ( !isNull( application.cbController ) ) {
				variables.regionCache = application.cbController.getCacheBox().getCache( variables.cacheName );
				migrate( variables.regionCache );
				return variables.regionCache;
			}
		} catch ( any e ) {
			// region missing or controller not ready: use memory, look again in a minute
			variables.retryAfter = dateAdd( "n", 1, now() );
		}
		return javaCast( "null", "" );
	}

	/** Move what the memory fallback collected before the region was available (list copies, early counters). */
	private void function migrate( required any target ){
		try {
			for ( var e in variables.fallback.export() ) {
				arguments.target.set( e.key, e.value, minutes( e.ttlSeconds ), 0 );
			}
		} catch ( any e ) {}
		variables.fallback = new MemoryStore();
	}

	private numeric function minutes( required numeric seconds ){
		return max( 1, ceiling( arguments.seconds / 60 ) );
	}

}
