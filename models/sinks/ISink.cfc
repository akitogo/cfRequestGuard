/**
 * Receives every non-allow decision (and every shadow / log match).
 * Must never throw into the request. emit() runs on the request thread unless
 * the sink is wrapped in AsyncSink (the guard does that for haproxy and
 * crowdsec), so anything that touches the network belongs behind that wrapper.
 */
interface {
	void function emit( required struct decision, required struct snap );
}
