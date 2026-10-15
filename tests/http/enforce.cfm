<cfscript>
	// HTTP-level check of enforce(): the one method that talks to the response.
	// /tests/http/enforce.cfm?kind=deny|challenge|ratelimit|allow
	param name="url.kind" default="deny";
	guard    = new cfRequestGuard.RequestGuard( { secret: "x", sinks: [], rules: [] } );
	factory  = new cfRequestGuard.models.Decision();
	switch ( url.kind ) {
		case "challenge": decision = guard.getChallenge().issue( guard.snapshot(), { name: "c", label: "CHALLENGE-c" } ); break;
		case "ratelimit": decision = factory.make( "ratelimit", { headers: { "Retry-After": 7 }, body: "slow down" } ); break;
		case "allow":     decision = factory.allow(); break;
		default:          decision = factory.make( "deny", { body: "nope" } );
	}
	guard.enforce( decision );
	writeOutput( "after-enforce" );
</cfscript>
