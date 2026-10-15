/**
 * Optional edge feedback via CrowdSec log acquisition: one JSON line per
 * decision into a file CrowdSec tails. A small parser + scenario on the
 * CrowdSec side turns repeated cfRequestGuard decisions into bans enforced by
 * whichever bouncer sits in front (HAProxy SPOA, nginx, firewall).
 * Writing a log is deliberately the integration point: no credentials,
 * no LAPI coupling, and the file works for any other consumer too.
 *
 * cfg: { file: "/var/log/requestguard/decisions.jsonl" }
 */
component implements="ISink" {

	function init( struct cfg = {} ){
		variables.file = arguments.cfg.file ?: "";
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		if ( !len( variables.file ) || arguments.decision.mode == "shadow" ) return;
		var line = serializeJSON( {
			"ts"     : rfc3339( now() ),
			"label"  : arguments.decision.label,
			"rule"   : arguments.decision.rule,
			"action" : arguments.decision.action,
			"ip"     : arguments.snap.clientIP,
			"method" : arguments.snap.method,
			"path"   : arguments.snap.path,
			"ua"     : arguments.snap.ua
		} );
		try {
			fileAppend( variables.file, line & chr( 10 ) );
		} catch ( any e ) {}
	}

	/** RFC 3339 in UTC from component functions: date masks differ between engines. */
	private string function rfc3339( required date d ){
		var u = dateConvert( "local2utc", arguments.d );
		return year( u ) & "-" & right( "0" & month( u ), 2 ) & "-" & right( "0" & day( u ), 2 )
			& "T" & right( "0" & hour( u ), 2 ) & ":" & right( "0" & minute( u ), 2 ) & ":" & right( "0" & second( u ), 2 ) & "Z";
	}

}
