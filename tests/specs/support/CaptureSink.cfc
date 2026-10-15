/** Test double: remembers every emitted decision. */
component implements="cfRequestGuard.models.sinks.ISink" {
	function init(){ variables.seen = []; return this; }
	void function emit( required struct decision, required struct snap ){ arrayAppend( variables.seen, arguments.decision ); }
	array function all(){ return variables.seen; }
	array function labels(){ return variables.seen.map( function( d ){ return d.label; } ); }
}
