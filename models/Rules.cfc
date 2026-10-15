/**
 * Ordered rule chain. First terminal match wins. Rules in shadow mode are
 * evaluated and collected but never returned as the decision; `log` rules
 * and untripped `ratelimit` rules are non-terminal.
 *
 * rule: { name, label, mode: enforce|shadow, when: {}, unless: [], action,
 *         status, body, contentType, headers, sleepMs | [min,max],
 *         sessionTimeoutSeconds, message, strike (deny only, default true),
 *         respectChallenge (challenge only, default true),
 *         limit: "20/3s", limitWithSession: "60/3s", sessionCookie, key: ip|ip+ua|cookie:<n>|header:<n>|custom:<n> }
 */
component {

	function init( required array rules, required any guard ){
		variables.guard     = arguments.guard;
		variables.decision  = arguments.guard.getDecision();
		variables.challenge = arguments.guard.getChallenge();
		variables.limiter   = arguments.guard.getLimiter();
		variables.matchers  = new Matchers( arguments.guard );
		variables.rules     = [];
		var i = 0;
		for ( var r in arguments.rules ) {
			i++;
			if ( !len( r.name ?: "" ) ) throw( type = "RequestGuard.BadRule", message = "Rule ###i# has no name" );
			var action = lCase( r.action ?: "deny" );
			if ( !listFindNoCase( "allow,deny,ignore,challenge,ratelimit,tarpit,log", action ) ) {
				throw( type = "RequestGuard.BadRule", message = "Rule '#r.name#': unknown action '#action#'" );
			}
			var compiled = duplicate( r );
			compiled.action  = action;
			compiled.mode    = lCase( r.mode ?: "enforce" );
			compiled.label   = r.label ?: defaultLabel( r.name, action );
			compiled.whenFns = variables.matchers.compileWhen( r.when ?: {} );
			compiled.unlessFns = variables.matchers.compileUnless( r.unless ?: [] );
			if ( action == "ratelimit" ) {
				compiled.limitParsed = parseLimit( r.limit ?: "20/3s" );
				compiled.limitWithSessionParsed = len( r.limitWithSession ?: "" ) ? parseLimit( r.limitWithSession ) : "";
			}
			arrayAppend( variables.rules, compiled );
		}
		return this;
	}

	struct function evaluate( required struct snap ){
		var shadows = [];
		for ( var rule in variables.rules ) {
			if ( !matches( rule, arguments.snap ) ) continue;

			var d = resolve( rule, arguments.snap );

			if ( rule.action == "allow" ) return { decision: d, shadows: shadows };
			if ( rule.action == "log" ) { arrayAppend( shadows, d ); continue; }
			if ( d.action == "allow" ) continue;                       // untripped limiter, challenge already passed
			if ( rule.mode == "shadow" ) { d.mode = "shadow"; arrayAppend( shadows, d ); continue; }
			return { decision: d, shadows: shadows };
		}
		return { decision: variables.decision.allow(), shadows: shadows };
	}

	array function getRules(){
		return variables.rules;
	}

	/* ------------------------------------------------------------------ */

	private boolean function matches( required struct rule, required struct snap ){
		for ( var fn in arguments.rule.whenFns )   { if ( !fn( arguments.snap ) ) return false; }
		for ( var fn in arguments.rule.unlessFns ) { if ( fn( arguments.snap ) )  return false; }
		return true;
	}

	private struct function resolve( required struct rule, required struct snap ){
		var r = arguments.rule;
		switch ( r.action ) {
			case "allow":
			case "log":
				return variables.decision.make( r.action, { rule: r.name, label: r.label } );

			case "challenge":
				if ( ( r.respectChallenge ?: true ) && arguments.snap.challengePassed ) return variables.decision.allow();
				return variables.challenge.issue( arguments.snap, r );

			case "ratelimit":
				var limit = r.limitParsed;
				if ( isStruct( r.limitWithSessionParsed ) && structKeyExists( arguments.snap.cookies, lCase( r.sessionCookie ?: "jsessionid" ) ) ) {
					limit = r.limitWithSessionParsed;
				}
				return variables.limiter.check( r.limiter ?: r.name, limitKey( r.key ?: "ip", arguments.snap ), limit.count, limit.seconds, r );

			default: // deny, ignore, tarpit
				var over = { rule: r.name, label: r.label };
				for ( var k in [ "status", "statusText", "body", "contentType", "headers", "sessionTimeoutSeconds", "detail" ] ) {
					if ( structKeyExists( r, k ) ) over[ k ] = r[ k ];
				}
				// strike: false keeps a deny out of the ban ladder (load protection, not abuse)
				over.strike = r.strike ?: true;
				if ( structKeyExists( r, "sleepMs" ) ) {
					over.sleepMs = isArray( r.sleepMs ) ? randRange( r.sleepMs[ 1 ], r.sleepMs[ 2 ] ) : r.sleepMs;
				}
				return variables.decision.make( r.action, over );
		}
	}

	private string function limitKey( required string spec, required struct snap ){
		var kind = lCase( listFirst( arguments.spec, ":" ) );
		var arg  = find( ":", arguments.spec ) ? listRest( arguments.spec, ":" ) : "";
		switch ( kind ) {
			case "ip+ua": return arguments.snap.clientIP & ":" & hash( arguments.snap.ua );
			case "cookie": return hash( arguments.snap.cookies[ lCase( arg ) ] ?: arguments.snap.clientIP );
			case "header": return hash( arguments.snap.headers[ lCase( arg ) ] ?: arguments.snap.clientIP );
			case "custom": return toString( variables.guard.getCustomPredicates()[ lCase( arg ) ]( arguments.snap ) );
			default: return arguments.snap.clientIP;
		}
	}

	/** "20/3s", "60/1m", "500/1h" -> { count, seconds } */
	private struct function parseLimit( required string spec ){
		var m = reFindNoCase( "^\s*(\d+)\s*/\s*(\d+)\s*([smh])\s*$", arguments.spec, 1, true );
		if ( arrayLen( m.match ) < 4 ) throw( type = "RequestGuard.BadRule", message = "Bad limit '#arguments.spec#', expected e.g. 20/3s" );
		var mult = { s: 1, m: 60, h: 3600 }[ lCase( m.match[ 4 ] ) ];
		return { count: val( m.match[ 2 ] ), seconds: val( m.match[ 3 ] ) * mult };
	}

	private string function defaultLabel( required string name, required string action ){
		switch ( arguments.action ) {
			case "challenge": return "CHALLENGE-" & arguments.name;
			case "ratelimit": return "BLOCK-503-" & arguments.name;
			case "ignore":    return "IGNORE-" & arguments.name;
			case "allow":     return "ALLOW-" & arguments.name;
			case "log":       return "LOG-" & arguments.name;
			default:          return "BLOCK-403-" & arguments.name;
		}
	}

}
