<cfscript>
	// Harness for the BotD report endpoint over real HTTP, local requests only (see tests/Application.cfc).
	// GET  ?nonce=1  -> prints the nonce for rule "r", page "/p" bound to this client
	// POST JSON body -> the guard reads the body in snapshot(), answers 204 and puts the label in X-RG-Label
	guard = new cfRequestGuard.RequestGuard( { secret: "s3cret", sinks: [], rules: [], challenge: { botd: "report", botdPath: cgi.script_name } } );
	snap  = guard.snapshot();
	if ( cgi.request_method == "GET" ) {
		writeOutput( guard.getChallenge().nonce( snap, "r", "/p" ) );
		abort;
	}
	d = guard.inspect( snap );
	cfheader( name = "X-RG-Label", value = d.label );
	cfheader( name = "X-RG-Detail", value = d.detail );
	guard.enforce( d );
</cfscript>
