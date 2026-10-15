/**
 * Named IP lists (cloud ASNs, crawler ranges, ad-hoc blocks).
 *
 * Each list loads synchronously at init, from the store (the last good
 * refresh) or else from its seed file / inline entries, so it is never
 * empty; then it refreshes from its URLs in a background thread at most
 * every refreshHours. A refresh that yields fewer than `minEntries` is
 * rejected and the previous data kept, because a half-fetched allow-list
 * turns into 403s for the crawler the site depends on.
 *
 * Refreshed data is written back to the store under rg:list:<name> (lower-cased:
 * CFML uppercases unquoted struct keys and store maps are case-sensitive). With a
 * shared or persistent store (CacheBox on a distributed provider) a second
 * node or a restarted guard starts from that copy instead of the network.
 *
 * list config: { seed, entries: [], sources: [], format: cidr-lines|google-json|json-array,
 *                refreshHours: 24, minEntries: 0, timeoutSeconds: 10, keepDays: 7 }
 */
component {

	function init( required struct cfg, required any cidr, string logFile = "requestguard", any store ){
		variables.cidr    = arguments.cidr;
		variables.logFile = arguments.logFile;
		variables.store   = isNull( arguments.store ) ? new store.MemoryStore() : arguments.store;
		variables.cfg     = {};
		variables.state   = {};
		for ( var name in arguments.cfg ) {
			var c = { seed: "", entries: [], sources: [], format: "cidr-lines", refreshHours: 24, minEntries: 0, timeoutSeconds: 10, keepDays: 7 };
			structAppend( c, arguments.cfg[ name ], true );
			c.seed = resolvePath( c.seed );
			variables.cfg[ name ]   = c;
			variables.state[ name ] = emptyState();
			if ( !loadStored( name ) ) loadSeed( name );
			if ( arrayLen( c.entries ) ) apply( name, c.entries, now(), "inline", "" );
			refreshIfDue( name );
		}
		return this;
	}

	/** Swap the store (the ColdBox adapter does this) and carry the current data over. */
	any function setStore( required any store ){
		variables.store = arguments.store;
		for ( var name in variables.state ) {
			if ( variables.state[ name ].set.count > 0 && isDate( variables.state[ name ].refreshedAt ) ) persist( name );
		}
		return this;
	}

	boolean function contains( required string name, required string ip ){
		var s = variables.state[ arguments.name ] ?: "";
		if ( !isStruct( s ) ) return false;
		refreshIfDue( arguments.name );
		return variables.cidr.contains( s.set, arguments.ip );
	}

	boolean function has( required string name ){
		return structKeyExists( variables.state, arguments.name );
	}

	/** Data present and its generation stamp younger than maxAgeDays. */
	boolean function isUsable( required string name, numeric maxAgeDays = 30 ){
		var s = variables.state[ arguments.name ] ?: "";
		if ( !isStruct( s ) || s.set.count == 0 || !isDate( s.stamp ) ) return false;
		return dateDiff( "d", s.stamp, now() ) <= arguments.maxAgeDays;
	}

	struct function info( required string name ){
		var s = variables.state[ arguments.name ];
		return { entries: s.set.count, stamp: s.stamp, loaded: s.loaded, refreshedAt: s.refreshedAt, source: s.source, refreshing: s.refreshing };
	}

	/** Synchronous refresh: for tests, scheduled tasks and admin tooling. Returns true when new data was applied. */
	boolean function refreshNow( required string name ){
		return fetchAndApply( arguments.name );
	}

	/* ------------------------------------------------------------------ */

	private struct function emptyState(){
		return { set: variables.cidr.emptySet(), entries: [], stamp: "", loaded: "", refreshedAt: "", source: "none", refreshing: false };
	}

	/** Last good refresh from the store, if any. */
	private boolean function loadStored( required string name ){
		try {
			var v = variables.store.get( "rg:list:" & lCase( arguments.name ) );
			if ( isNull( v ) || !isStruct( v ) || !isArray( v.entries ?: "" ) ) return false;
			return apply( arguments.name, v.entries, v.stamp ?: "", "store", v.refreshedAt ?: "" );
		} catch ( any e ) {
			return false;
		}
	}

	private void function loadSeed( required string name ){
		var c = variables.cfg[ arguments.name ];
		if ( !len( c.seed ) || !fileExists( c.seed ) ) return;
		try {
			var parsed = parse( fileRead( c.seed ), c.format );
			// a list without its own generation stamp is as old as the file
			var stamp  = isDate( parsed.stamp ) ? parsed.stamp : getFileInfo( c.seed ).lastModified;
			apply( arguments.name, parsed.entries, stamp, "seed", "" );
		} catch ( any e ) {
			writeLog( file = variables.logFile, type = "error", text = "cfRequestGuard list '#arguments.name#' seed unreadable: #e.message#" );
		}
	}

	private void function refreshIfDue( required string name ){
		var s = variables.state[ arguments.name ];
		var c = variables.cfg[ arguments.name ];
		if ( !arrayLen( c.sources ) || s.refreshing ) return;
		if ( isDate( s.refreshedAt ) && dateDiff( "h", s.refreshedAt, now() ) < c.refreshHours ) return;
		refresh( arguments.name );
	}

	/** Background refresh. The request that triggers it never waits on the network. */
	private void function refresh( required string name ){
		variables.state[ arguments.name ].refreshing = true;
		var listName = arguments.name;
		thread name="requestguard-list-#listName#-#createUUID()#" action="run" listName="#listName#" {
			fetchAndApply( attributes.listName );
		}
	}

	private boolean function fetchAndApply( required string name ){
		var c       = variables.cfg[ arguments.name ];
		var applied = false;
		try {
			var entries = [];
			var stamp   = now();
			for ( var src in c.sources ) {
				try {
					cfhttp( url = src, method = "GET", timeout = c.timeoutSeconds, redirect = true, result = "local.res" );
					if ( val( res.statusCode ) != 200 || !isSimpleValue( res.fileContent ) ) {
						writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard list '#arguments.name#': #src# returned #res.statusCode#" );
						continue;
					}
					var parsed = parse( res.fileContent, c.format );
					arrayAppend( entries, parsed.entries, true );
					if ( isDate( parsed.stamp ) ) stamp = parsed.stamp;
				} catch ( any e ) {
					writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard list '#arguments.name#': #src# failed: #e.message#" );
				}
			}
			if ( arrayLen( entries ) >= max( 1, c.minEntries ) ) {
				applied = apply( arguments.name, entries, stamp, "remote", now() );
				if ( applied ) persist( arguments.name );
			} else {
				writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard list '#arguments.name#': refresh rejected, only #arrayLen( entries )# entries (floor #c.minEntries#), keeping previous" );
			}
		} catch ( any e ) {
			writeLog( file = variables.logFile, type = "error", text = "cfRequestGuard list '#arguments.name#' refresh failed: #e.message#" );
		}
		variables.state[ arguments.name ].refreshing = false;
		return applied;
	}

	/** Write the current data to the store so a later instance or node starts from it. */
	private void function persist( required string name ){
		var s = variables.state[ arguments.name ];
		var c = variables.cfg[ arguments.name ];
		try {
			variables.store.set( "rg:list:" & lCase( arguments.name ), { entries: s.entries, stamp: s.stamp, refreshedAt: s.refreshedAt }, c.keepDays * 86400 );
		} catch ( any e ) {
			writeLog( file = variables.logFile, type = "warning", text = "cfRequestGuard list '#arguments.name#': store write failed: #e.message#" );
		}
	}

	private boolean function apply( required string name, required array entries, required any stamp, required string source, required any refreshedAt ){
		var set = variables.cidr.compile( arguments.entries );
		if ( set.count == 0 ) return false;
		// whole-struct swap: readers never see a half-built list
		variables.state[ arguments.name ] = { set: set, entries: arguments.entries, stamp: arguments.stamp, loaded: now(), refreshedAt: arguments.refreshedAt, source: arguments.source, refreshing: false };
		writeLog( file = variables.logFile, type = "information", text = "cfRequestGuard list '#arguments.name#' loaded from #arguments.source#: #set.count# ranges from #set.source# entries (#set.skipped# skipped)" );
		return true;
	}

	/** -> { entries: [cidr strings], stamp: date|'' } */
	private struct function parse( required string content, required string format ){
		var out = { entries: [], stamp: "" };
		switch ( lCase( arguments.format ) ) {
			case "google-json":
				var data = deserializeJSON( arguments.content );
				// Google / Bing / Apple / OpenAI publish { ipv4Prefix } objects; a seed may hold plain strings
				for ( var p in data.prefixes ?: [] ) {
					if ( isSimpleValue( p ) ) arrayAppend( out.entries, p );
					else if ( structKeyExists( p, "ipv4Prefix" ) ) arrayAppend( out.entries, p.ipv4Prefix );
				}
				if ( structKeyExists( data, "creationTime" ) ) out.stamp = parseDateTime( data.creationTime );
				if ( structKeyExists( data, "generated" ) ) out.stamp = parseDateTime( data.generated );
				break;
			case "json-array":
				out.entries = deserializeJSON( arguments.content );
				break;
			default:
				for ( var line in listToArray( arguments.content, chr( 10 ) & chr( 13 ) ) ) {
					line = trim( line );
					if ( len( line ) && left( line, 1 ) != "##" ) arrayAppend( out.entries, listFirst( line, " " & chr( 9 ) ) );
				}
		}
		return out;
	}

	/**
	 * Accept OS paths and webroot / mapping paths alike. "/config/x" is expanded
	 * when it is not an existing OS path. An absolute OS path whose root segment
	 * exists (/var/..., /Users/..., C:\...) stays as it is.
	 */
	private string function resolvePath( required string path ){
		var p = trim( arguments.path );
		if ( !len( p ) || fileExists( p ) || directoryExists( p ) ) return p;
		var isAbsolute = reFind( "^([A-Za-z]:[\\/]|/)", p ) > 0;
		var root       = reFind( "^[A-Za-z]:", p ) ? left( p, 3 ) : "/" & listFirst( p, "/\" );
		if ( isAbsolute && directoryExists( root ) ) return p;
		return expandPath( p );
	}

}
