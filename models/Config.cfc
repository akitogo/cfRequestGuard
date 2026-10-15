/**
 * Config file reader.
 *
 * The config is JSON, stored in a `.json.cfm` file so the CFML engine
 * executes it instead of the web server serving it: the first line is
 * `<cfabort>`, the JSON sits inside a CFML comment. Anyone requesting the
 * file over HTTP gets an empty 200. A plain `.json` file is read as well,
 * for configs that live outside the webroot.
 *
 * Layout of a wrapped file:
 *
 *   <cfabort>
 *   <!--- cfrequestguard config, JSON between the braces, edit nothing else
 *   {
 *       ...
 *   }
 *   --->
 *
 * The JSON is taken from the first line that starts with `{` to the last
 * line that ends with `}`, so the header must not start a line with a brace.
 */
component {

	function init(){
		return this;
	}

	struct function read( required string path ){
		var resolved = fileExists( arguments.path ) ? arguments.path : expandPath( arguments.path );
		if ( !fileExists( resolved ) ) {
			throw( type = "RequestGuard.ConfigNotFound", message = "cfRequestGuard config not found: #arguments.path#" );
		}
		var json = unwrap( fileRead( resolved, "utf-8" ) );
		if ( !isJSON( json ) ) {
			throw( type = "RequestGuard.ConfigInvalid", message = "cfRequestGuard config is not valid JSON: #arguments.path#" );
		}
		return deserializeJSON( json );
	}

	/** Strip the .cfm wrapper, if any. Public so tests and tooling can reuse it. */
	string function unwrap( required string raw ){
		var lines = listToArray( arguments.raw, chr( 10 ), true );
		var first = 0;
		var last  = 0;
		for ( var i = 1; i <= arrayLen( lines ); i++ ) {
			var t = trim( lines[ i ] );
			if ( first == 0 && left( t, 1 ) == "{" ) first = i;
			if ( right( t, 1 ) == "}" ) last = i;
		}
		if ( first == 0 || last < first ) return "";
		return arrayToList( arraySlice( lines, first, last - first + 1 ), chr( 10 ) );
	}

}
