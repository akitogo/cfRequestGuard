/**
 * cfRequestGuard facade.
 *
 * Framework independent: instantiate once (application scope) from
 * Application.cfc, before any framework bootstraps.
 *
 *   inspect( snapshot ) -> decision     pure, testable, shadow-able
 *   enforce( decision )                 the only method with side effects
 */
component {

	function init( required any config ){
		var cfg = isStruct( arguments.config ) ? duplicate( arguments.config ) : new models.Config().read( arguments.config );
		variables.config = applyDefaults( cfg );
		variables.secretConfigured = true;
		variables.config.secret    = resolveSecret( variables.config.secret );

		variables.customPredicates = {};
		variables.decision  = new models.Decision();
		variables.cidr      = new models.Cidr();
		variables.store     = createStore( variables.config.store );
		variables.clientIP  = new models.ClientIP( variables.config.trustedProxies, variables.config.internalNetworks, variables.cidr );
		variables.lists     = new models.Lists( variables.config.lists, variables.cidr, variables.config.logFile, variables.store );
		variables.verifier  = new models.Verifier( variables.config.bots, variables.lists, variables.clientIP, variables.store, variables.config.rdns, variables.cidr );
		variables.challenge = new models.Challenge( variables.config.challenge, variables.config.secret, variables.decision );
		variables.limiter   = new models.RateLimiter( variables.store, variables.decision );
		variables.strikes   = new models.Strikes( variables.config.strikes, variables.store );
		variables.sinks     = createSinks( variables.config.sinks );
		variables.rules     = new models.Rules( variables.config.rules, this );
		return this;
	}

	/* ------------------------------------------------------------------ */
	/* Request lifecycle                                                   */
	/* ------------------------------------------------------------------ */

	/**
	 * Build a plain-struct snapshot of the current request. Everything
	 * inspect() needs, nothing engine-specific after this point.
	 */
	struct function snapshot(){
		var req     = getHttpRequestData( false );
		var headers = {};
		for ( var name in req.headers ) {
			headers[ lCase( name ) ] = req.headers[ name ];
		}
		var cookies = {};
		for ( var name in cookie ) {
			cookies[ lCase( name ) ] = cookie[ name ];
		}
		var snap = {
			method     : cgi.request_method,
			path       : len( cgi.path_info ) ? cgi.path_info : cgi.script_name,
			query      : cgi.query_string,
			host       : cgi.http_host,
			remoteAddr : cgi.remote_addr,
			headers    : headers,
			cookies    : cookies,
			ua         : headers[ "user-agent" ] ?: "",
			referer    : headers[ "referer" ] ?: "",
			now        : now()
		};
		snap.clientIP = variables.clientIP.resolve( snap );
		return snap;
	}

	/**
	 * Decide. Cheap checks first, then the ordered rule chain.
	 */
	struct function inspect( required struct snap ){
		snap.internalIP = variables.clientIP.isInternal( snap.clientIP );

		// 1. derived facts the rules may consult (bot classification is a few regexes)
		snap.challengePassed = variables.challenge.isPassed( snap );
		snap.bot             = variables.verifier.classify( snap );

		// 2. strike ban: one lookup. Never for internal networks and never for a
		// trusted bot: a verified crawler denied by a load-protection rule must
		// not lose the whole site for an hour.
		if ( !snap.internalIP && !snap.bot.trusted && variables.strikes.isBanned( snap.clientIP ) ) {
			var banned = variables.decision.make( "deny", { rule: "strike-ban", label: "BLOCK-403-banned" } );
			return finish( banned, snap );
		}

		// 3. ordered rules; shadow matches are reported, never returned
		var result = variables.rules.evaluate( snap );
		for ( var shadow in result.shadows ) {
			emit( shadow, snap );
		}

		var d = result.decision;
		if ( d.action == "allow" ) return d;
		if ( d.action == "deny" && d.strike && !snap.internalIP && !snap.bot.trusted && !isShadow() ) {
			variables.strikes.strike( snap.clientIP );
		}
		return finish( d, snap );
	}

	/**
	 * Act. Sets headers / body and aborts for every terminal action.
	 * allow and log return without touching the response.
	 */
	void function enforce( required struct d ){
		if ( listFindNoCase( "allow,log", arguments.d.action ) ) {
			return;
		}
		if ( arguments.d.sleepMs > 0 ) {
			sleep( arguments.d.sleepMs );
		}
		cfheader( statusCode = arguments.d.status, statusText = arguments.d.statusText );
		for ( var name in arguments.d.headers ) {
			cfheader( name = name, value = arguments.d.headers[ name ] );
		}
		if ( len( arguments.d.contentType ) ) {
			cfcontent( type = arguments.d.contentType );
		}
		if ( len( arguments.d.body ) ) {
			writeOutput( arguments.d.body );
		}
		abort;
	}

	/* ------------------------------------------------------------------ */
	/* Extension points                                                    */
	/* ------------------------------------------------------------------ */

	/** Global mode switch at runtime: "enforce" or "shadow". */
	RequestGuard function setMode( required string mode ){
		variables.config.mode = lCase( arguments.mode ) == "shadow" ? "shadow" : "enforce";
		return this;
	}

	boolean function hasSecret(){
		return variables.secretConfigured;
	}

	boolean function isShadow(){
		return lCase( variables.config.mode ?: "enforce" ) == "shadow";
	}

	/** Register a closure ( snap ) => boolean usable as `custom` matcher / `custom:` unless. */
	RequestGuard function registerPredicate( required string name, required any fn ){
		variables.customPredicates[ lCase( arguments.name ) ] = arguments.fn;
		return this;
	}

	/** Swap the counter store after init (e.g. the ColdBox adapter hands in a CacheBox-backed store). */
	RequestGuard function setStore( required any store ){
		variables.store = arguments.store;
		variables.limiter.setStore( arguments.store );
		variables.strikes.setStore( arguments.store );
		variables.lists.setStore( arguments.store );
		variables.verifier.setStore( arguments.store );
		return this;
	}

	RequestGuard function addSink( required any sink ){
		arrayAppend( variables.sinks, arguments.sink );
		return this;
	}

	// getters used by Rules / Matchers
	any function getConfig(){ return variables.config; }
	any function getDecision(){ return variables.decision; }
	any function getCidr(){ return variables.cidr; }
	any function getLists(){ return variables.lists; }
	any function getVerifier(){ return variables.verifier; }
	any function getChallenge(){ return variables.challenge; }
	any function getLimiter(){ return variables.limiter; }
	any function getStrikes(){ return variables.strikes; }
	any function getStore(){ return variables.store; }
	any function getClientIP(){ return variables.clientIP; }
	struct function getCustomPredicates(){ return variables.customPredicates; }

	/* ------------------------------------------------------------------ */
	/* Internals                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Terminal step for every non-allow decision. In global shadow mode the
	 * decision is reported to the sinks with mode "shadow" and an allow is
	 * returned with the shadowed decision attached as `shadow`, so the host
	 * can run the whole rule set beside existing code and compare logs.
	 */
	private struct function finish( required struct d, required struct snap ){
		// a challenge needs a stable, shared secret; without one it is reported, not served
		if ( arguments.d.action == "challenge" && !variables.secretConfigured ) {
			arguments.d.detail = "not enforced: no secret configured";
			arguments.d.mode   = "shadow";
			emit( arguments.d, arguments.snap );
			var allowedNoSecret = variables.decision.allow();
			allowedNoSecret.shadow = arguments.d;
			return allowedNoSecret;
		}
		if ( isShadow() ) {
			arguments.d.mode = "shadow";
			emit( arguments.d, arguments.snap );
			var allowed = variables.decision.allow();
			allowed.shadow = arguments.d;
			return allowed;
		}
		emit( arguments.d, arguments.snap );
		return arguments.d;
	}

	private void function emit( required struct d, required struct snap ){
		for ( var sink in variables.sinks ) {
			try {
				sink.emit( arguments.d, arguments.snap );
			} catch ( any e ) {
				// a broken sink must never break the request
			}
		}
	}

	private any function createStore( required struct cfg ){
		switch ( lCase( arguments.cfg.type ?: "memory" ) ) {
			case "cachebox":
				return new models.store.CacheBoxStore( arguments.cfg );
			default:
				return new models.store.MemoryStore( arguments.cfg );
		}
	}

	private array function createSinks( required array cfgs ){
		var out = [];
		for ( var cfg in arguments.cfgs ) {
			switch ( lCase( cfg.type ?: "log" ) ) {
				case "otel":     arrayAppend( out, new models.sinks.OtelSink( cfg ) ); break;
				case "haproxy":  arrayAppend( out, new models.sinks.HAProxySink( cfg ) ); break;
				case "crowdsec": arrayAppend( out, new models.sinks.CrowdSecSink( cfg ) ); break;
				default:         arrayAppend( out, new models.sinks.LogSink( cfg ) );
			}
		}
		return out;
	}

	/** `env:NAME` -> environment variable or JVM system property. Missing secret -> random per start, with a warning. */
	private string function resolveSecret( required string value ){
		var v = trim( arguments.value );
		if ( left( v, 4 ) == "env:" ) {
			var name   = mid( v, 5, len( v ) );
			var system = createObject( "java", "java.lang.System" );
			v = system.getenv( name ) ?: ( system.getProperty( name ) ?: "" );
		}
		if ( !len( v ) ) {
			variables.secretConfigured = false;
			writeLog( file = variables.config.logFile, type = "warning", text = "cfRequestGuard: no secret configured. Challenge cookies signed with a random per-start secret would bounce visitors between nodes, so challenge rules run in shadow mode until a secret is set (REQUESTGUARD_SECRET or config.secret)." );
			v = hash( createUUID() & getTickCount(), "SHA-256" );
		}
		return v;
	}

	private struct function applyDefaults( required struct cfg ){
		var defaults = {
			mode             : "enforce",
			secret           : "env:REQUESTGUARD_SECRET",
			logFile          : "requestguard",
			trustedProxies   : [],
			internalNetworks : [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" ],
			store            : { type: "memory", maxEntries: 20000 },
			sinks            : [ { type: "log", file: "requestguard" } ],
			lists            : {},
			bots             : [],
			rdns             : { maxInFlight: 4, timeoutMs: 1500, cacheSeconds: 86400, unknownCacheSeconds: 60 },
			challenge        : { cookie: "rg_c", maxAgeSeconds: 86400, bindToIP: true, kind: "js-cookie" },
			strikes          : { threshold: 10, windowSeconds: 60, banSeconds: 3600 },
			rules            : []
		};
		structAppend( defaults, arguments.cfg, true );
		return defaults;
	}

}
