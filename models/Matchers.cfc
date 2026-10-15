/**
 * Compiles the `when` / `unless` vocabulary of a rule into closures
 * ( snap ) => boolean. Regexes compile once here, never per request.
 */
component {

	function init( required any guard ){
		variables.guard   = arguments.guard;
		variables.cidr    = arguments.guard.getCidr();
		variables.lists   = arguments.guard.getLists();
		variables.Pattern = createObject( "java", "java.util.regex.Pattern" );
		return this;
	}

	/** `when` struct -> array of closures, all of which must be true */
	array function compileWhen( required struct when ){
		var fns = [];
		for ( var key in arguments.when ) {
			var v = arguments.when[ key ];
			switch ( lCase( key ) ) {
				case "path":          fns.append( regexOn( "path", v ) ); break;
				case "query":         fns.append( regexOn( "query", v ) ); break;
				case "referer":       fns.append( regexOn( "referer", v ) ); break;
				case "ua":            fns.append( regexOn( "ua", v ) ); break;
				case "uaequals":      fns.append( uaEquals( isArray( v ) ? v : [ v ] ) ); break;   // no list split: UAs contain commas
				case "method":        fns.append( method( toArray( v ) ) ); break;
				case "headerpresent": fns.append( headerPresent( toArray( v ) ) ); break;
				case "headermissing": fns.append( headerMissing( toArray( v ) ) ); break;
				case "header":        fns.append( headerRegex( v, true ) ); break;
				case "headernot":     fns.append( headerRegex( v, false ) ); break;
				case "headerequals":  fns.append( headerEquals( v ) ); break;
				case "cookiepresent": fns.append( cookies( toArray( v ), true ) ); break;
				case "cookiemissing": fns.append( cookies( toArray( v ), false ) ); break;
				case "ip":            fns.append( ipIn( variables.cidr.compile( toArray( v ) ) ) ); break;
				case "iplist":        fns.append( ipList( v ) ); break;
				case "claimsbot":     fns.append( claimsBot( v ) ); break;
				case "spoofedbot":    fns.append( function( snap ){ return snap.bot.spoofed; } ); break;
				case "custom":        fns.append( custom( v ) ); break;
				case "any":           fns.append( anyOf( v ) ); break;
				default:
					throw( type = "RequestGuard.BadRule", message = "Unknown `when` key: #key#" );
			}
		}
		return fns;
	}

	/** `unless` array of strings -> array of closures, any of which skips the rule */
	array function compileUnless( required array unless ){
		var fns = [];
		for ( var item in arguments.unless ) {
			var kind = lCase( listFirst( item, ":" ) );
			var arg  = find( ":", item ) ? listRest( item, ":" ) : "";
			switch ( kind ) {
				case "trustedbot":      fns.append( function( snap ){ return snap.bot.trusted; } ); break;
				case "verifiedbot":     fns.append( function( snap ){ return snap.bot.verified; } ); break;
				case "internalip":      fns.append( function( snap ){ return snap.internalIP; } ); break;
				case "challengepassed": fns.append( function( snap ){ return snap.challengePassed; } ); break;
				case "path":            fns.append( regexOn( "path", arg ) ); break;
				case "cookie":          fns.append( cookies( [ arg ], true ) ); break;
				case "iplist":          fns.append( ipList( arg ) ); break;
				case "custom":          fns.append( custom( arg ) ); break;
				default:
					throw( type = "RequestGuard.BadRule", message = "Unknown `unless` entry: #item#" );
			}
		}
		return fns;
	}

	/* ------------------------------------------------------------------ */

	private any function regexOn( required string field, required string regex ){
		var p = variables.Pattern.compile( arguments.regex, variables.Pattern.CASE_INSENSITIVE );
		var f = arguments.field;
		return function( snap ){ return p.matcher( snap[ f ] ).find(); };
	}

	private any function uaEquals( required array values ){
		var list = arguments.values;
		return function( snap ){
			for ( var v in list ) { if ( compareNoCase( snap.ua, v ) == 0 ) return true; }
			return false;
		};
	}

	private any function method( required array methods ){
		var list = arrayToList( arguments.methods );
		return function( snap ){ return listFindNoCase( list, snap.method ) > 0; };
	}

	private any function headerPresent( required array names ){
		var list = arguments.names;
		return function( snap ){
			for ( var n in list ) { if ( len( snap.headers[ lCase( n ) ] ?: "" ) ) return true; }
			return false;
		};
	}

	private any function headerMissing( required array names ){
		var list = arguments.names;
		return function( snap ){
			for ( var n in list ) { if ( len( trim( snap.headers[ lCase( n ) ] ?: "" ) ) ) return false; }
			return true;
		};
	}

	/** {name: regex}; mustMatch=true: all present and matching. false: none may match (absent is fine). */
	private any function headerRegex( required struct spec, required boolean mustMatch ){
		var compiled = {};
		for ( var n in arguments.spec ) compiled[ lCase( n ) ] = variables.Pattern.compile( arguments.spec[ n ], variables.Pattern.CASE_INSENSITIVE );
		var positive = arguments.mustMatch;
		return function( snap ){
			for ( var n in compiled ) {
				var v  = snap.headers[ n ] ?: "";
				var ok = len( v ) && compiled[ n ].matcher( v ).find();
				if ( positive && !ok ) return false;
				if ( !positive && ok ) return false;
			}
			return true;
		};
	}

	private any function headerEquals( required struct spec ){
		var s = {};
		for ( var n in arguments.spec ) s[ lCase( n ) ] = arguments.spec[ n ];
		return function( snap ){
			for ( var n in s ) { if ( compareNoCase( trim( snap.headers[ n ] ?: "" ), s[ n ] ) != 0 ) return false; }
			return true;
		};
	}

	private any function cookies( required array names, required boolean present ){
		var list = arguments.names;
		var want = arguments.present;
		return function( snap ){
			for ( var n in list ) {
				var has = structKeyExists( snap.cookies, lCase( n ) );
				if ( has != want ) return false;
			}
			return true;
		};
	}

	private any function ipIn( required struct set ){
		var s = arguments.set;
		return function( snap ){ return variables.cidr.contains( s, snap.clientIP ); };
	}

	private any function ipList( required string name ){
		var n = arguments.name;
		return function( snap ){ return variables.lists.contains( n, snap.clientIP ); };
	}

	private any function claimsBot( required string name ){
		var n = lCase( arguments.name );
		return function( snap ){ return snap.bot.claims && ( n == "any" || lCase( snap.bot.name ) == n ); };
	}

	private any function custom( required string name ){
		var n = lCase( arguments.name );
		return function( snap ){
			var preds = variables.guard.getCustomPredicates();
			if ( !structKeyExists( preds, n ) ) throw( type = "RequestGuard.BadRule", message = "Custom predicate '#n#' is not registered" );
			return preds[ n ]( snap ) ? true : false;
		};
	}

	/** [ {when}, {when} ]: true when at least one sub-group matches completely */
	private any function anyOf( required array groups ){
		var compiled = [];
		for ( var g in arguments.groups ) arrayAppend( compiled, compileWhen( g ) );
		return function( snap ){
			for ( var fns in compiled ) {
				var ok = true;
				for ( var fn in fns ) { if ( !fn( snap ) ) { ok = false; break; } }
				if ( ok ) return true;
			}
			return false;
		};
	}

	private array function toArray( required any v ){
		return isArray( arguments.v ) ? arguments.v : listToArray( arguments.v );
	}

}
