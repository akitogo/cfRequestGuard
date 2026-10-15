/**
 * Optional edge feedback: pushes banned IPs into an HAProxy map over the
 * Runtime API so the next request is refused before it reaches the JVM.
 *
 * haproxy.cfg side (example):
 *   http-request deny deny_status 403 if { src,map_ip(/etc/haproxy/requestguard-bans.map) -m found }
 *   stats socket ipv4@127.0.0.1:9999 level admin
 *
 * cfg: { host: "127.0.0.1", port: 9999, map: "/etc/haproxy/requestguard-bans.map", labels: [ "BLOCK-403-banned" ] }
 * Only decisions whose label is listed are forwarded (default: strike bans).
 * Entries expire on the HAProxy side only if you clear them; a cron doing
 * `clear map` daily, or a stick-table based variant, is the usual answer.
 */
component implements="ISink" {

	function init( struct cfg = {} ){
		variables.cfg = { host: "127.0.0.1", port: 9999, map: "/etc/haproxy/requestguard-bans.map", labels: [ "BLOCK-403-banned" ], timeoutMs: 200 };
		structAppend( variables.cfg, arguments.cfg, true );
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		var d = arguments.decision;
		if ( d.mode == "shadow" || !arrayFindNoCase( variables.cfg.labels, d.label ) ) return;
		send( "add map #variables.cfg.map# #arguments.snap.clientIP# #d.rule#" & chr( 10 ) );
	}

	private void function send( required string command ){
		var socket = "";
		try {
			socket = createObject( "java", "java.net.Socket" ).init();
			socket.connect( createObject( "java", "java.net.InetSocketAddress" ).init( variables.cfg.host, javaCast( "int", variables.cfg.port ) ), javaCast( "int", variables.cfg.timeoutMs ) );
			var out = socket.getOutputStream();
			out.write( arguments.command.getBytes( "UTF-8" ) );
			out.flush();
		} catch ( any e ) {
			// edge unreachable: the app-side ban still holds
		} finally {
			try { if ( isObject( socket ) ) socket.close(); } catch ( any e ) {}
		}
	}

}
