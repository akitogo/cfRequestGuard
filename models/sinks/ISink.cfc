/**
 * Receives every non-allow decision (and every shadow / log match).
 * Must be cheap and must never throw into the request.
 */
interface {
	void function emit( required struct decision, required struct snap );
}
