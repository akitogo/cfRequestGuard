/**
 * Counter / state store contract. Values are plain CFML values.
 * TTLs are seconds. increment() must be atomic per node at minimum;
 * a shared implementation (CacheBox + distributed provider, Redis)
 * makes limits and bans cluster-wide.
 */
interface {
	any     function get( required string key );
	void    function set( required string key, required any value, required numeric ttlSeconds );
	numeric function increment( required string key, required numeric ttlSeconds );
	void    function delete( required string key );
	numeric function size();
}
