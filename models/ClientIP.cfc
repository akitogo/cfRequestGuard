/**
 * Client IP resolution with an explicit trusted-proxy list.
 *
 * With no trusted proxies configured the remote address is the client and
 * every forwarding header is ignored (direct exposure, or a proxy you have
 * not declared yet: the safe default).
 *
 * With trusted proxies configured, and only when the connection itself came
 * from one of them, X-Forwarded-For is walked from the RIGHT, skipping our
 * own hops; the first foreign address is the client. Anything a client
 * prepends sits to the left of that entry and can never be picked.
 */
component {

	function init( required array trustedProxies, required array internalNetworks, required any cidr ){
		variables.cidr     = arguments.cidr;
		variables.trusted  = variables.cidr.compile( arguments.trustedProxies );
		variables.internal = variables.cidr.compile( arguments.internalNetworks );
		return this;
	}

	string function resolve( required struct snap ){
		var remote = normalize( arguments.snap.remoteAddr );

		if ( variables.trusted.count == 0 || !variables.cidr.contains( variables.trusted, remote ) ) {
			return len( remote ) ? remote : "127.0.0.1";
		}

		var headers  = arguments.snap.headers;
		var leftmost = "";

		// X-Forwarded-For: grows left to right, one entry per hop
		var hops = listToArray( headers[ "x-forwarded-for" ] ?: "", "," );
		for ( var i = arrayLen( hops ); i >= 1; i-- ) {
			var hop = normalize( hops[ i ] );
			if ( !len( hop ) ) continue;
			if ( !variables.cidr.contains( variables.trusted, hop ) ) return hop;
			leftmost = hop;
		}

		// RFC 7239 Forwarded: take the LAST for= pair, i.e. the one our proxy added
		var pairs = reMatchNoCase( "for=""?\[?[0-9a-fA-F:\.]+", headers[ "forwarded" ] ?: "" );
		if ( arrayLen( pairs ) ) {
			var fwd = normalize( reReplaceNoCase( pairs[ arrayLen( pairs ) ], "^for=""?\[?", "" ) );
			if ( len( fwd ) && !variables.cidr.contains( variables.trusted, fwd ) ) return fwd;
		}

		// every hop was one of ours: an internal client came through the proxy
		return len( leftmost ) ? leftmost : remote;
	}

	boolean function isInternal( required string ip ){
		return variables.cidr.contains( variables.internal, arguments.ip );
	}

	boolean function isTrustedProxy( required string ip ){
		return variables.cidr.contains( variables.trusted, arguments.ip );
	}

	/** IP-based bot verification is only meaningful when the resolved IP cannot be forged. */
	boolean function hasTrustedProxies(){
		return variables.trusted.count > 0;
	}

	/**
	 * Trim one header entry down to a bare literal: strip quotes, brackets and
	 * an IPv4 port suffix. IPv6 literals pass through unchanged so they still
	 * make a stable rate-limit key even though CIDR matching ignores them.
	 */
	string function normalize( required string candidate ){
		var ip = reReplace( trim( arguments.candidate ), "[""\[\]]", "", "all" );
		if ( find( ":", ip ) && listLen( ip, ":" ) == 2 && variables.cidr.isIPv4( listFirst( ip, ":" ) ) ) {
			ip = listFirst( ip, ":" );
		}
		if ( variables.cidr.isIPv4( ip ) ) return ip;
		if ( reFind( "^[0-9a-fA-F:]+$", ip ) && find( ":", ip ) ) return lCase( ip );
		return "";
	}

}
