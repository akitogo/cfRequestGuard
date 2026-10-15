/**
 * Progressive per-key limiter on top of the store, following the widely used
 * CFML rate-limiter pattern (Charlie Arehart's and Luis Majano's write-ups):
 * more than `count` hits with no `duration`-second gap trips a block; each
 * trip lowers the next threshold by two and lengthens the block, and a quiet
 * period resets the penalty. Written from scratch for this package.
 *
 * check() returns a `ratelimit` decision when the caller must stop, or an
 * `allow` decision otherwise. It never aborts.
 */
component {

	function init( required any store, required any decision ){
		variables.store    = arguments.store;
		variables.decision = arguments.decision;
		return this;
	}

	any function setStore( required any store ){
		variables.store = arguments.store;
		return this;
	}

	/**
	 * @name      limiter name (separate buckets per purpose: "global", "login", "sitemap")
	 * @key       what is being limited: an IP, a username hash, ...
	 * @count     hits allowed inside duration
	 * @duration  window in seconds
	 * @rule      the matched rule (name / label / message are copied onto the decision)
	 */
	struct function check( required string name, required string key, required numeric count, required numeric duration, struct rule = {} ){
		var storeKey = "rg:rl:" & arguments.name & ":" & arguments.key;
		var result   = variables.decision.allow();

		lock name="requestguard-rl-#storeKey#" type="exclusive" timeout="5" throwOnTimeout="false" {
			var t = variables.store.get( storeKey );
			if ( isNull( t ) ) {
				t = { attempts: 0, lastAttempt: now(), blockCount: 0, lastBlockTime: "" };
			}
			var progressiveCount    = max( 1, arguments.count - ( t.blockCount * 2 ) );
			var progressiveDuration = arguments.duration * ( 1 + t.blockCount );
			var ttl                 = arguments.duration * ( 3 + t.blockCount ) + 60;

			if ( isDate( t.lastBlockTime ) && dateDiff( "s", t.lastBlockTime, now() ) < progressiveDuration ) {
				// still inside an earlier block
				var remaining = progressiveDuration - dateDiff( "s", t.lastBlockTime, now() );
				t.attempts++; t.lastAttempt = now();
				result = limited( arguments.rule, remaining, t, "extended" );
			} else if ( dateDiff( "s", t.lastAttempt, now() ) < arguments.duration ) {
				t.attempts++; t.lastAttempt = now();
				if ( t.attempts > progressiveCount ) {
					t.blockCount++; t.lastBlockTime = now();
					progressiveDuration = arguments.duration * ( 1 + t.blockCount );
					result = limited( arguments.rule, progressiveDuration, t, "tripped" );
				}
			} else {
				// quiet window: reset, and forgive old blocks after 2x duration of good behaviour
				t.attempts = 1; t.lastAttempt = now();
				if ( isDate( t.lastBlockTime ) && dateDiff( "s", t.lastBlockTime, now() ) > arguments.duration * 2 ) {
					t.blockCount = 0; t.lastBlockTime = "";
				}
			}
			variables.store.set( storeKey, t, ttl );
		}
		return result;
	}

	private struct function limited( required struct rule, required numeric retryAfter, required struct t, required string phase ){
		var message = replaceNoCase( arguments.rule.message ?: "Too many requests, retry in {duration} seconds", "{duration}", arguments.retryAfter, "all" );
		return variables.decision.make( "ratelimit", {
			rule    : arguments.rule.name ?: "ratelimit",
			label   : ( arguments.rule.label ?: "BLOCK-503-ratelimit" ) & "-" & arguments.phase,
			headers : { "Retry-After": arguments.retryAfter },
			body    : message,
			detail  : "attempts=#arguments.t.attempts# blockCount=#arguments.t.blockCount# retryAfter=#arguments.retryAfter#s"
		} );
	}

}
