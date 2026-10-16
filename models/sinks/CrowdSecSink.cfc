/**
 * Optional edge feedback into CrowdSec, two independent paths that can be
 * combined:
 *
 *  file  (local)  one JSON line per decision into a file the CrowdSec agent
 *                 on the same host tails (acquisition + a small parser and
 *                 scenario, see docs/crowdsec.md). No credentials, no coupling,
 *                 and the file works for any other consumer too.
 *
 *  lapi  (remote) selected decisions, by default the strike bans, are pushed
 *                 as alerts to a CrowdSec Local API over HTTP, which may live
 *                 on another host. The alert carries a ready decision, so the
 *                 bouncers at the edge act within their next poll. The sink
 *                 logs in as a machine (cscli machines add) and keeps the token.
 *
 * cfg: {
 *   "file": "/var/log/requestguard/decisions.jsonl",
 *   "lapi": {
 *     "url": "http://lapi.internal:8080", "machineId": "requestguard-www1", "password": "env:CROWDSEC_PASSWORD",
 *     "labels": [ "BLOCK-403-banned" ], "scenario": "cfRequestGuard/strike-ban",
 *     "type": "ban", "duration": "1h", "timeoutSeconds": 2
 *   }
 * }
 * The LAPI call is synchronous but only runs for the listed labels (one call
 * per banned address) and never throws into the request.
 */
component implements="ISink" {

	function init( struct cfg = {} ){
		variables.file    = arguments.cfg.file ?: "";
		variables.logFile = arguments.cfg.logFile ?: "requestguard";
		variables.lapi    = {};
		if ( isStruct( arguments.cfg.lapi ?: "" ) && len( arguments.cfg.lapi.url ?: "" ) ) {
			variables.lapi = {
				url: "", machineId: "", password: "", labels: [ "BLOCK-403-banned" ],
				scenario: "cfRequestGuard/strike-ban", type: "ban", duration: "1h", timeoutSeconds: 2
			};
			structAppend( variables.lapi, arguments.cfg.lapi, true );
			variables.lapi.url      = reReplace( variables.lapi.url, "/+$", "" );
			variables.lapi.password = resolve( variables.lapi.password );
		}
		variables.token      = "";
		variables.tokenSince = "";
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		if ( arguments.decision.mode == "shadow" ) return;
		if ( len( variables.file ) ) appendLine( arguments.decision, arguments.snap );
		if ( !structIsEmpty( variables.lapi ) && arrayFindNoCase( variables.lapi.labels, arguments.decision.label ) ) {
			pushAlert( arguments.decision, arguments.snap );
		}
	}

	/** The alert as sent to POST /v1/alerts (public so it can be inspected and tested). */
	struct function alert( required struct decision, required struct snap ){
		var ts = rfc3339( now() );
		var ip = arguments.snap.clientIP;
		var meta = [
			{ "key": "source_ip",       "value": ip },
			{ "key": "rg_label",        "value": arguments.decision.label },
			{ "key": "rg_rule",         "value": arguments.decision.rule },
			{ "key": "rg_action",       "value": arguments.decision.action },
			{ "key": "http_verb",       "value": arguments.snap.method ?: "" },
			{ "key": "http_path",       "value": arguments.snap.path ?: "" },
			{ "key": "http_user_agent", "value": arguments.snap.ua ?: "" }
		];
		return {
			"scenario"         : variables.lapi.scenario,
			"scenario_hash"    : "",
			"scenario_version" : "",
			"message"          : "cfRequestGuard #arguments.decision.label# (#arguments.decision.rule#) from #ip#",
			"events_count"     : 1,
			"start_at"         : ts,
			"stop_at"          : ts,
			"capacity"         : 0,
			"leakspeed"        : "0s",
			"simulated"        : false,
			"remediation"      : true,
			"source"           : { "scope": "Ip", "value": ip, "ip": ip },
			"events"           : [ { "timestamp": ts, "meta": meta } ],
			"decisions"        : [ {
				"origin"   : "cfRequestGuard",
				"type"     : variables.lapi.type,
				"scope"    : "Ip",
				"value"    : ip,
				"duration" : variables.lapi.duration,
				"scenario" : variables.lapi.scenario
			} ]
		};
	}

	/* ------------------------------------------------------------------ */

	private void function appendLine( required struct decision, required struct snap ){
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

	private void function pushAlert( required struct decision, required struct snap ){
		try {
			var body = serializeJSON( [ alert( arguments.decision, arguments.snap ) ] );
			var res  = post( "/v1/alerts", body, true );
			if ( res.status == 401 ) {
				// token expired or revoked: log in once more and retry
				variables.token = "";
				res = post( "/v1/alerts", body, true );
			}
			if ( res.status < 200 || res.status > 299 ) {
				writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard crowdsec: LAPI answered #res.status# for #arguments.snap.clientIP#: #left( res.body, 200 )#" );
			}
		} catch ( any e ) {
			writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard crowdsec: LAPI unreachable (#e.message#); the app-side ban still holds" );
		}
	}

	/** Machine login, token cached for 50 minutes (LAPI issues one-hour tokens). */
	private string function token(){
		if ( len( variables.token ) && isDate( variables.tokenSince ) && dateDiff( "n", variables.tokenSince, now() ) < 50 ) return variables.token;
		var res = post( "/v1/watchers/login", serializeJSON( {
			"machine_id" : variables.lapi.machineId,
			"password"   : variables.lapi.password,
			"scenarios"  : [ variables.lapi.scenario ]
		} ), false );
		if ( res.status != 200 ) throw( type = "cfRequestGuard.CrowdSecLogin", message = "login answered #res.status#: #left( res.body, 200 )#" );
		var parsed = deserializeJSON( res.body );
		variables.token      = parsed.token ?: "";
		variables.tokenSince = now();
		if ( !len( variables.token ) ) throw( type = "cfRequestGuard.CrowdSecLogin", message = "login returned no token" );
		return variables.token;
	}

	private struct function post( required string path, required string body, required boolean authed ){
		var bearer = arguments.authed ? token() : "";
		cfhttp( url = variables.lapi.url & arguments.path, method = "POST", timeout = variables.lapi.timeoutSeconds, result = "local.res" ) {
			cfhttpparam( type = "header", name = "Content-Type", value = "application/json" );
			cfhttpparam( type = "header", name = "User-Agent", value = "cfRequestGuard" );
			if ( len( bearer ) ) cfhttpparam( type = "header", name = "Authorization", value = "Bearer " & bearer );
			cfhttpparam( type = "body", value = arguments.body );
		}
		var status = val( res.statusCode ?: 0 );
		if ( status == 0 ) throw( type = "cfRequestGuard.CrowdSecHttp", message = ( res.errorDetail ?: "no response" ) );
		return { status: status, body: isSimpleValue( res.fileContent ?: "" ) ? res.fileContent : "" };
	}

	/** `env:NAME` -> environment variable or JVM system property, anything else verbatim. */
	private string function resolve( required string value ){
		var v = trim( arguments.value );
		if ( left( v, 4 ) != "env:" ) return v;
		var name = mid( v, 5, len( v ) );
		var sys  = createObject( "java", "java.lang.System" );
		var out  = sys.getenv( name );
		if ( isNull( out ) || !len( out ) ) out = sys.getProperty( name );
		return isNull( out ) ? "" : out;
	}

	/** RFC 3339 in UTC from component functions: date masks differ between engines. */
	private string function rfc3339( required date d ){
		var u = dateConvert( "local2utc", arguments.d );
		return year( u ) & "-" & right( "0" & month( u ), 2 ) & "-" & right( "0" & day( u ), 2 )
			& "T" & right( "0" & hour( u ), 2 ) & ":" & right( "0" & minute( u ), 2 ) & ":" & right( "0" & second( u ), 2 ) & "Z";
	}

}
