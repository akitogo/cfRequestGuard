/** One line per decision in the engine log. cfg: { file: "requestguard" } */
component implements="ISink" {

	function init( struct cfg = {} ){
		variables.file = arguments.cfg.file ?: "requestguard";
		return this;
	}

	void function emit( required struct decision, required struct snap ){
		var d = arguments.decision;
		var s = arguments.snap;
		var mode = d.mode == "shadow" ? "SHADOW " : "";
		var line = "#mode##d.label# | rule=#d.rule# | ip=#s.clientIP# | #s.method# #s.path#" & ( len( s.query ) ? "?#left( s.query, 200 )#" : "" )
			& " | ua=#left( s.ua, 160 )#" & ( len( d.detail ) ? " | #d.detail#" : "" );
		writeLog( file = variables.file, type = d.mode == "shadow" || d.action == "log" ? "information" : "warning", text = line );
	}

}
