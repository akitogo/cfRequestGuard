/**
 * Decision factory. A decision is a plain struct so it can be logged,
 * serialized, compared in tests and handed to any sink.
 */
component {

	function init(){
		return this;
	}

	/**
	 * @action  allow | deny | ignore | challenge | ratelimit | tarpit | log
	 * @over    per-rule overrides (status, body, label, sleepMs, ...)
	 */
	struct function make( required string action, struct over = {} ){
		var d = {
			action                : lCase( arguments.action ),
			rule                  : "",
			label                 : "",
			mode                  : "enforce",
			status                : 200,
			statusText            : "OK",
			contentType           : "",
			body                  : "",
			headers               : {},
			sleepMs               : 0,
			sessionTimeoutSeconds : 0,
			strike                : true,
			detail                : ""
		};
		switch ( d.action ) {
			case "deny":
				d.status = 403; d.statusText = "Forbidden"; d.sessionTimeoutSeconds = 1;
				break;
			case "ignore":
				// swallow quietly (dev-tools probes, known-noise referers)
				d.status = 200; d.statusText = "OK"; d.sessionTimeoutSeconds = 1;
				break;
			case "challenge":
				d.status = 200; d.statusText = "OK"; d.sessionTimeoutSeconds = 60;
				d.contentType = "text/html; charset=utf-8";
				d.headers[ "Cache-Control" ] = "no-store";
				break;
			case "ratelimit":
				d.status = 503; d.statusText = "Service Unavailable"; d.sessionTimeoutSeconds = 1;
				break;
			case "tarpit":
				d.status = 403; d.statusText = "Forbidden"; d.sessionTimeoutSeconds = 1; d.sleepMs = 1000;
				break;
			default:
				d.action = ( d.action == "log" ) ? "log" : "allow";
		}
		structAppend( d, arguments.over, true );
		return d;
	}

	struct function allow(){
		return make( "allow" );
	}

}
