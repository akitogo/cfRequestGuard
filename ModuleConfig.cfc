/**
 * Optional ColdBox adapter. Ignored outside ColdBox.
 *
 * Reuses the instance Application.cfc already created (so the pre-framework
 * request filter and the handlers share one store and one rule set), swaps
 * the store for a CacheBox-backed one when asked, and exposes it to WireBox
 * as `requestGuard@cfRequestGuard` so handlers can call the same limiter:
 *
 *   property name="requestGuard" inject="requestGuard@cfRequestGuard";
 *   var d = requestGuard.getLimiter().check( "login", username, 5, 60, { message: "Too many logins" } );
 *   if ( d.action != "allow" ) requestGuard.enforce( d );
 */
component {

	this.title         = "cfRequestGuard";
	this.author        = "akitogo";
	this.webURL        = "https://github.com/akitogo/cfRequestGuard";
	this.description   = "Bot, scraper and abuse defence";
	this.version       = "0.1.0";
	this.cfmapping     = "cfRequestGuard";
	this.modelNamespace = "cfRequestGuard";
	this.autoMapModels = false;

	function configure(){
		settings = {
			configFile  : "/config/requestguard.json.cfm",
			// Prefer `"store": { "type": "cachebox", "cacheName": "..." }` in the guard config:
			// that store resolves the region itself once ColdBox is up and also covers the
			// instance Application.cfc builds. This switch only swaps the store at module load.
			// Always use a dedicated region: counters are one key per client address.
			useCacheBox : false,
			cacheName   : "default"
		};
	}

	function onLoad(){
		// Never let a guard problem break the framework load: log it and carry on
		// without the WireBox mapping. Application.cfc keeps its own guarded loader.
		try {
			var guard = structKeyExists( application, "requestGuard" ) ? application.requestGuard : new RequestGuard( expandPath( settings.configFile ) );
			if ( settings.useCacheBox ) {
				var store = new models.store.CacheBoxStore( { cacheName: settings.cacheName } );
				store.setCache( controller.getCacheBox().getCache( settings.cacheName ) );
				guard.setStore( store );
			}
			application.requestGuard = guard;
			binder.map( "requestGuard@cfRequestGuard" ).toValue( guard );
		} catch ( any e ) {
			log.error( "cfRequestGuard module could not initialise: #e.message#", e );
		}
	}

	function onUnload(){
		// the application-scope instance stays: Application.cfc owns its lifecycle
	}

}
