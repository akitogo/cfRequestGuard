/**
 * Escalation ladder: every deny is a strike; `threshold` strikes inside
 * `windowSeconds` earn a ban of `banSeconds`. The ban is one store lookup
 * at the top of inspect(), so repeat offenders cost almost nothing even on
 * deployments with no edge in front. threshold 0 disables the ladder.
 */
component {

	function init( required struct cfg, required any store ){
		variables.cfg = { threshold: 10, windowSeconds: 60, banSeconds: 3600 };
		structAppend( variables.cfg, arguments.cfg, true );
		variables.store = arguments.store;
		return this;
	}

	any function setStore( required any store ){
		variables.store = arguments.store;
		return this;
	}

	boolean function isBanned( required string ip ){
		if ( variables.cfg.threshold <= 0 ) return false;
		return !isNull( variables.store.get( "rg:ban:" & arguments.ip ) );
	}

	/** @return strike count inside the current window */
	numeric function strike( required string ip ){
		if ( variables.cfg.threshold <= 0 ) return 0;
		var count = variables.store.increment( "rg:strike:" & arguments.ip, variables.cfg.windowSeconds );
		if ( count >= variables.cfg.threshold ) {
			variables.store.set( "rg:ban:" & arguments.ip, now(), variables.cfg.banSeconds );
		}
		return count;
	}

	void function unban( required string ip ){
		variables.store.delete( "rg:ban:" & arguments.ip );
		variables.store.delete( "rg:strike:" & arguments.ip );
	}

}
