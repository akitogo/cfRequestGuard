/** Test double: a sink that takes `ms` to deliver (or throws), then remembers the decision. */
component implements="cfRequestGuard.models.sinks.ISink" {
	function init( numeric ms = 300, boolean fail = false ){
		variables.ms   = arguments.ms;
		variables.fail = arguments.fail;
		variables.seen = createObject( "java", "java.util.concurrent.CopyOnWriteArrayList" ).init();
		return this;
	}
	void function emit( required struct decision, required struct snap ){
		sleep( variables.ms );
		if ( variables.fail ) throw( type = "SlowSink.Boom", message = "sink broke" );
		variables.seen.add( arguments.decision.label );
	}
	numeric function count(){ return variables.seen.size(); }
}
