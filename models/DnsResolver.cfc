/** Default resolver for Verifier: java.net.InetAddress. Replaced in tests. */
component {
	function init(){ variables.InetAddress = createObject( "java", "java.net.InetAddress" ); return this; }
	string function reverse( required string ip ){
		return variables.InetAddress.getByName( arguments.ip ).getCanonicalHostName();
	}
	array function forward( required string host ){
		var out = [];
		for ( var addr in variables.InetAddress.getAllByName( arguments.host ) ) arrayAppend( out, addr.getHostAddress() );
		return out;
	}
}
