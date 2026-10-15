/**
 * IPv4 CIDR sets: parse once into sorted, merged [start,end] ranges and
 * answer membership by binary search. Arithmetic only (no bitAnd/bitSHLN)
 * so it behaves the same on Lucee, ACF and BoxLang for the full 32-bit range.
 *
 * IPv6: not matched yet. contains() returns false for non-IPv4 input.
 * When needed, swap the internals for seancfoley's IPAddress (Java) which
 * gives v4+v6 tries without touching callers.
 */
component {

	variables.IPV4 = "^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$";

	function init(){
		return this;
	}

	boolean function isIPv4( required string ip ){
		return reFind( variables.IPV4, trim( arguments.ip ) ) > 0;
	}

	numeric function ipToLong( required string ip ){
		if ( !isIPv4( arguments.ip ) ) {
			throw( type = "RequestGuard.InvalidIP", message = "Not an IPv4 literal: #arguments.ip#" );
		}
		var o = listToArray( trim( arguments.ip ), "." );
		return ( o[ 1 ] * 16777216 ) + ( o[ 2 ] * 65536 ) + ( o[ 3 ] * 256 ) + o[ 4 ];
	}

	/** "a.b.c.d/n" or bare "a.b.c.d" -> { start, end } as longs */
	struct function parse( required string cidr ){
		var c      = trim( arguments.cidr );
		var ip     = listFirst( c, "/" );
		var prefix = find( "/", c ) ? val( listLast( c, "/" ) ) : 32;
		if ( prefix < 0 || prefix > 32 ) {
			throw( type = "RequestGuard.InvalidCIDR", message = "Bad prefix length in #c#" );
		}
		var size  = 2 ^ ( 32 - prefix );
		var start = int( ipToLong( ip ) / size ) * size;
		return { start: start, end: start + size - 1 };
	}

	/**
	 * Compile an array of CIDR / IP strings into a set. Invalid entries are
	 * skipped and counted so a list loader can report them.
	 */
	struct function compile( required array entries ){
		var ranges  = [];
		var skipped = 0;
		for ( var e in arguments.entries ) {
			try {
				arrayAppend( ranges, parse( e ) );
			} catch ( any ex ) {
				skipped++;
			}
		}
		arraySort( ranges, function( a, b ){
			return a.start < b.start ? -1 : ( a.start > b.start ? 1 : 0 );
		} );
		// merge overlapping / adjacent ranges
		var starts = [];
		var ends   = [];
		for ( var r in ranges ) {
			var n = arrayLen( ends );
			if ( n > 0 && r.start <= ends[ n ] + 1 ) {
				ends[ n ] = max( ends[ n ], r.end );
			} else {
				arrayAppend( starts, r.start );
				arrayAppend( ends, r.end );
			}
		}
		return { starts: starts, ends: ends, count: arrayLen( starts ), source: arrayLen( arguments.entries ), skipped: skipped };
	}

	boolean function contains( required struct set, required string ip ){
		if ( !isIPv4( arguments.ip ) ) {
			return false;
		}
		return containsLong( arguments.set, ipToLong( arguments.ip ) );
	}

	boolean function containsLong( required struct set, required numeric ipLong ){
		var lo = 1;
		var hi = arguments.set.count;
		while ( lo <= hi ) {
			var mid = int( ( lo + hi ) / 2 );
			if ( arguments.ipLong < arguments.set.starts[ mid ] ) {
				hi = mid - 1;
			} else if ( arguments.ipLong > arguments.set.ends[ mid ] ) {
				lo = mid + 1;
			} else {
				return true;
			}
		}
		return false;
	}

	struct function emptySet(){
		return { starts: [], ends: [], count: 0, source: 0, skipped: 0 };
	}

}
