/**
 * Bot claims and verification.
 *
 * bots config entry:
 *   { name: "googlebot", category: "search", ua: "Googlebot|GoogleOther|Google-InspectionTool",
 *     verify: { ipList: "googleCrawler", maxAgeDays: 30 } }      -> IP verified
 *   { name: "statuscake", category: "monitor", ua: "StatusCake" }  -> UA trusted only
 *   { name: "archive", ua: "archive\.org_bot",
 *     verify: { rdns: "\.archive\.org$", ranges: [ "204.62.248.0/23" ] } } -> forward-confirmed rDNS
 *
 * rDNS is the only verification that blocks on the network, so it is fenced in
 * three ways (settings under the top-level `rdns` key):
 *   ranges   : optional per bot; an address outside them is spoofed without a lookup
 *   budget   : at most maxInFlight lookups per node at any moment, the rest are "unknown"
 *   timeout  : a lookup runs in its own thread and is waited for timeoutMs at most
 * A verdict is cached per IP in the store: cacheSeconds for confirmed / mismatch,
 * unknownCacheSeconds for timeouts and budget misses. "Unknown" means the request
 * is handled like any ordinary visitor: not trusted, not spoofed.
 *
 * classify() -> { name, category, claims, trusted, verified, spoofed, reason }
 *   trusted  : may skip defensive rules (verified, or no verification possible: empty list)
 *   spoofed  : claims a verifiable bot and failed verification -> deny material
 */
component {

	function init( required array bots, required any lists, required any clientIP, any store, struct rdns = {}, any cidr ){
		variables.lists    = arguments.lists;
		variables.clientIP = arguments.clientIP;
		variables.cidr     = isNull( arguments.cidr ) ? new Cidr() : arguments.cidr;
		if ( !isNull( arguments.store ) ) variables.store = arguments.store;
		variables.resolver = new DnsResolver();
		variables.rdns     = { maxInFlight: 4, timeoutMs: 1500, cacheSeconds: 86400, unknownCacheSeconds: 60 };
		structAppend( variables.rdns, arguments.rdns, true );
		variables.inFlight = createObject( "java", "java.util.concurrent.atomic.AtomicInteger" ).init( 0 );
		variables.Pattern  = createObject( "java", "java.util.regex.Pattern" );
		variables.bots     = [];
		for ( var b in arguments.bots ) {
			var verify = b.verify ?: {};
			arrayAppend( variables.bots, {
				name     : b.name,
				category : b.category ?: "other",
				pattern  : variables.Pattern.compile( b.ua, variables.Pattern.CASE_INSENSITIVE ),
				verify   : verify,
				ranges   : structKeyExists( verify, "ranges" ) && arrayLen( verify.ranges ) ? variables.cidr.compile( verify.ranges ) : javaCast( "null", "" )
			} );
		}
		return this;
	}

	struct function classify( required struct snap ){
		var r = { name: "", category: "", claims: false, trusted: false, verified: false, spoofed: false, reason: "" };
		if ( !len( arguments.snap.ua ) ) return r;

		for ( var b in variables.bots ) {
			if ( !b.pattern.matcher( arguments.snap.ua ).find() ) continue;
			r.name = b.name; r.category = b.category; r.claims = true;

			if ( structKeyExists( b.verify, "ipList" ) ) {
				var maxAge = b.verify.maxAgeDays ?: 30;
				if ( !variables.lists.has( b.verify.ipList ) || !variables.lists.hasData( b.verify.ipList ) ) {
					// an allow-list with no data at all must disarm, never deny: nothing to check against
					r.trusted = true; r.reason = "list '#b.verify.ipList#' empty, UA trusted";
				} else {
					// stale data still verifies: trusting every claim instead would let any client
					// wearing the UA skip the strike ban and every trustedBot exemption
					var stale = variables.lists.isUsable( b.verify.ipList, maxAge ) ? "" : " (list stale)";
					if ( variables.lists.contains( b.verify.ipList, arguments.snap.clientIP ) ) {
						r.trusted = true; r.verified = true; r.reason = "ip in #b.verify.ipList##stale#";
					} else {
						r.spoofed = true; r.reason = "ip #arguments.snap.clientIP# not in #b.verify.ipList##stale#";
					}
				}
			} else if ( structKeyExists( b.verify, "rdns" ) ) {
				if ( !isNull( b.ranges ) && !variables.cidr.contains( b.ranges, arguments.snap.clientIP ) ) {
					r.spoofed = true; r.reason = "ip #arguments.snap.clientIP# outside the bot's ranges";
				} else {
					var verdict = cachedVerdict( arguments.snap.clientIP, b.verify.rdns );
					if ( verdict == "confirmed" )     { r.trusted = true; r.verified = true; r.reason = "rdns confirmed"; }
					else if ( verdict == "mismatch" ) { r.spoofed = true; r.reason = "rdns mismatch"; }
					else                              { r.reason = "rdns " & verdict; }   // unknown: ordinary visitor
				}
			} else {
				r.trusted = true; r.reason = "ua trusted";
			}
			return r;
		}
		return r;
	}

	any function setStore( required any store ){
		variables.store = arguments.store;
		return this;
	}

	/** Tests inject a fake resolver: { reverse( ip ) -> hostname|"", forward( host ) -> [ ip ] }. */
	any function setResolver( required any resolver ){
		variables.resolver = arguments.resolver;
		return this;
	}

	any function getInFlight(){ return variables.inFlight; }

	/**
	 * confirmed | mismatch | unknown-timeout | unknown-budget | unknown-error.
	 * One DNS round trip per IP and cache period; a mismatch is cached too, so a
	 * spoofer cannot make us resolve on every hit.
	 */
	private string function cachedVerdict( required string ip, required string hostPattern ){
		var key = "rg:rdns:" & lCase( arguments.ip ) & ":" & lCase( hash( arguments.hostPattern ) );
		if ( !isNull( variables.store ) ) {
			var cached = variables.store.get( key );
			if ( !isNull( cached ) ) return cached;
		}
		var verdict = guardedLookup( arguments.ip, arguments.hostPattern );
		if ( !isNull( variables.store ) ) {
			variables.store.set( key, verdict, left( verdict, 7 ) == "unknown" ? variables.rdns.unknownCacheSeconds : variables.rdns.cacheSeconds );
		}
		return verdict;
	}

	/** Budget gate + bounded wait. The worker thread releases its budget slot itself, however long DNS takes. */
	private string function guardedLookup( required string ip, required string hostPattern ){
		if ( variables.inFlight.incrementAndGet() > variables.rdns.maxInFlight ) {
			variables.inFlight.decrementAndGet();
			return "unknown-budget";
		}
		var result = createObject( "java", "java.util.concurrent.atomic.AtomicReference" ).init( javaCast( "null", "" ) );
		var tname  = "rgdns" & replace( createUUID(), "-", "", "all" );
		try {
			thread action="run" name=tname ip=arguments.ip hostPattern=arguments.hostPattern result=result inFlight=variables.inFlight {
				try {
					attributes.result.set( forwardConfirmed( attributes.ip, attributes.hostPattern ) ? "confirmed" : "mismatch" );
				} catch ( any e ) {
					attributes.result.set( "unknown-error" );
				} finally {
					attributes.inFlight.decrementAndGet();
				}
			}
			thread action="join" name=tname timeout=variables.rdns.timeoutMs;
		} catch ( any e ) {
			variables.inFlight.decrementAndGet();
			return "unknown-error";
		}
		var v = result.get();
		return isNull( v ) ? "unknown-timeout" : v;
	}

	/** Reverse lookup, hostname must match the pattern, forward lookup must return the IP. Blocking. */
	private boolean function forwardConfirmed( required string ip, required string hostPattern ){
		var host = variables.resolver.reverse( arguments.ip );
		if ( !len( host ) || host == arguments.ip || !reFindNoCase( arguments.hostPattern, host ) ) return false;
		for ( var addr in variables.resolver.forward( host ) ) {
			if ( addr == arguments.ip ) return true;
		}
		return false;
	}

}
