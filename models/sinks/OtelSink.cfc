/**
 * Names the active OpenTelemetry span (EDOT / OTel Java agent) and the
 * FusionReactor transaction after the decision label, and stamps block.*
 * attributes, so aborted requests show up in APM as named transactions.
 * Best effort: silently no-ops when neither agent is attached.
 * cfg: { fusionreactor: false (set true only with the FusionReactor agent installed) }
 */
component implements="ISink" {

	function init( struct cfg = {} ){
		// Opt-in: the FRAPI class lookup is not free when FusionReactor is absent (on one Lucee 6.2.5
		// node it silently ended the request), so never touch it unless the agent is really installed.
		variables.useFR = arguments.cfg.fusionreactor ?: false;
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		var d = arguments.decision;
		if ( d.mode == "shadow" || d.action == "log" ) {
			// keep the real transaction name; only annotate
			annotate( d, arguments.snap, false );
			return;
		}
		annotate( d, arguments.snap, true );
		if ( variables.useFR ) {
			try {
				var frapi = createObject( "java", "com.intergral.fusionreactor.api.FRAPI" ).getInstance();
				if ( !isNull( frapi ) ) frapi.setTransactionName( d.label );
			} catch ( any e ) {}
		}
	}

	private void function annotate( required struct d, required struct snap, required boolean rename ){
		try {
			var span = createObject( "java", "io.opentelemetry.api.trace.Span" ).current();
			if ( arguments.rename ) span.updateName( arguments.d.label );
			var prefix = arguments.rename ? "block" : "requestguard.shadow";
			span.setAttribute( prefix & ".reason", arguments.d.label );
			span.setAttribute( prefix & ".rule", arguments.d.rule );
			span.setAttribute( prefix & ".client_ip", arguments.snap.clientIP );
			span.setAttribute( prefix & ".user_agent", arguments.snap.ua );
			span.setAttribute( prefix & ".path", arguments.snap.path );
			if ( arguments.rename && arguments.d.action != "ignore" ) span.setAttribute( "block", "true" );
		} catch ( any e ) {}
	}

}
