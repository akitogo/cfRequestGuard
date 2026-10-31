/**
 * JavaScript cookie challenge.
 *
 * The token is an HMAC over (day, client IP, purpose) with the configured
 * secret, so it cannot be minted from public inputs. Today's and yesterday's
 * tokens are both accepted, which removes the midnight re-challenge flash.
 * Binding to the client IP stops cookie replay across exit nodes; a roaming
 * user simply sees the transparent challenge once on the new IP.
 *
 * kind: js-cookie (default). Hooks left for pow / metarefresh variants.
 *
 * botd: "off" (default) or "report". With "report" the page also runs the
 * BotD detector (vendor/botd, MIT) and posts its verdict to botdPath before
 * it continues; the guard answers 204, logs BOTD-<kind> and changes nothing
 * else. The post carries a nonce, an HMAC over (day, client IP, rule, page),
 * so the endpoint only accepts verdicts for pages it rendered to that client.
 */
component {

	function init( required struct cfg, required string secret, required any decision ){
		variables.cfg      = {
			cookie: "rg_c", maxAgeSeconds: 86400, bindToIP: true, secure: true, kind: "js-cookie",
			title: "Checking your browser",
			continueText: "Continue",
			retryText: "Please click to continue.",
			cookieText: "Your browser is blocking cookies. Please allow cookies for this site, then continue.",
			retryWindowSeconds: 600,
			botd: "off", botdPath: "/__requestguard/botd", botdTimeoutMs: 1500
		};
		structAppend( variables.cfg, arguments.cfg, true );
		variables.secret   = arguments.secret;
		variables.decision = arguments.decision;
		variables.cfg.botd = lCase( variables.cfg.botd ) == "report" ? "report" : "off";
		variables.botdJs   = "";
		variables.botdVer  = "";
		return this;
	}

	string function token( required struct snap, numeric dayOffset = 0 ){
		var day = dayKey( dateAdd( "d", arguments.dayOffset, arguments.snap.now ) );
		var msg = day & "|" & ( variables.cfg.bindToIP ? arguments.snap.clientIP : "" ) & "|challenge";
		return lCase( hmac( msg, variables.secret, "HMACSHA256" ) );
	}

	boolean function isPassed( required struct snap ){
		var c = arguments.snap.cookies[ lCase( variables.cfg.cookie ) ] ?: "";
		if ( !len( c ) ) return false;
		return c == token( arguments.snap ) || c == token( arguments.snap, -1 );
	}

	/** Build the challenge decision for a matched rule. */
	struct function issue( required struct snap, required struct rule ){
		var d = variables.decision.make( "challenge", { rule: arguments.rule.name, label: arguments.rule.label } );
		switch ( lCase( variables.cfg.kind ) ) {
			// case "altcha": TODO proof-of-work variant, see docs/altcha-pow-challenge.md
			default:
				d.body = jsCookiePage( token( arguments.snap ), arguments.snap, arguments.rule.name );
		}
		return d;
	}

	/* ------------------------------------------------------------------ */
	/* Detector report (challenge.botd = report)                           */
	/* ------------------------------------------------------------------ */

	/** True for the POST the challenge page sends with its detector verdict. */
	boolean function isReportRequest( required struct snap ){
		return variables.cfg.botd != "off"
			&& uCase( arguments.snap.method ?: "" ) == "POST"
			&& ( arguments.snap.path ?: "" ) == variables.cfg.botdPath;
	}

	/** Nonce the page carries: HMAC over day, client IP, rule and page, today or yesterday. */
	string function nonce( required struct snap, required string rule, required string page, numeric dayOffset = 0 ){
		var day = dayKey( dateAdd( "d", arguments.dayOffset, arguments.snap.now ) );
		var msg = day & "|" & ( variables.cfg.bindToIP ? arguments.snap.clientIP : "" ) & "|botd|" & arguments.rule & "|" & arguments.page;
		return lCase( hmac( msg, variables.secret, "HMACSHA256" ) );
	}

	/**
	 * Turn the posted verdict into a terminal 204 decision for the sinks.
	 * Label BOTD-<kind>: clean, a BotD bot kind (headless_chrome, selenium, ...),
	 * or what the page reported when the detector did not run (timeout, error,
	 * nolib). Anything without a valid nonce is BOTD-invalid. Never a strike.
	 */
	struct function report( required struct snap ){
		var d = variables.decision.make( "ignore", { rule: "botd", label: "BOTD-invalid", status: 204, statusText: "No Content", strike: 0 } );
		var p = "";
		try { p = deserializeJSON( arguments.snap.body ?: "" ); } catch ( any e ) { return d; }
		if ( !isStruct( p ) ) return d;
		var rule = left( reReplace( toString( p.r ?: "" ), "[^A-Za-z0-9_-]", "", "all" ), 64 );
		var page = pageText( toString( p.p ?: "" ) );
		var n    = lCase( trim( toString( p.n ?: "" ) ) );
		if ( !len( rule ) || !len( n ) ) return d;
		if ( n != nonce( arguments.snap, rule, page ) && n != nonce( arguments.snap, rule, page, -1 ) ) return d;
		var kind = lCase( left( reReplace( toString( p.k ?: "" ), "[^A-Za-z0-9_-]", "", "all" ), 32 ) );
		var ver  = left( reReplace( toString( p.v ?: "" ), "[^A-Za-z0-9.-]", "", "all" ), 20 );
		d.rule   = rule;
		d.label  = "BOTD-" & ( len( kind ) ? kind : "unknown" );
		d.detail = "page=" & page & ( isNumeric( p.t ?: "" ) ? " ms=" & int( p.t ) : "" ) & ( len( ver ) ? " botd=" & ver : "" );
		return d;
	}

	/** The challenged request as one printable line for nonce and log: path, query, ASCII only, 200 chars. */
	private string function pageText( required string s ){
		return left( reReplace( arguments.s, "[^ -~]", "", "all" ), 200 );
	}

	/** The vendored detector, read once; an unreadable file is logged and the page reports "nolib". */
	private string function detectorJs(){
		if ( len( variables.botdJs ) ) return variables.botdJs;
		try {
			variables.botdJs = fileRead( vendorPath( "botd.min.js" ) );
		} catch ( any e ) {
			writeLog( file = "requestguard", type = "warning", text = "cfRequestGuard challenge: vendor/botd/botd.min.js unreadable (#e.message#), pages report nolib" );
		}
		return variables.botdJs;
	}

	/** Vendored BotD version (vendor/botd/VERSION, written by scripts/update-botd.sh); travels with the verdict so log lines tell builds apart. */
	private string function detectorVersion(){
		if ( len( variables.botdVer ) ) return variables.botdVer;
		try {
			variables.botdVer = left( reReplace( trim( fileRead( vendorPath( "VERSION" ) ) ), "[^A-Za-z0-9.-]", "", "all" ), 20 );
		} catch ( any e ) {}
		return variables.botdVer;
	}

	private string function vendorPath( required string file ){
		return getDirectoryFromPath( getCurrentTemplatePath() ) & "../vendor/botd/" & arguments.file;
	}

	/** JS string-literal escaping without the ESAPI dependency (not shipped on every engine install). */
	private string function jsStr( required string v ){
		var out = replace( arguments.v, "\", "\\", "all" );
		out = replace( out, '"', '\"', "all" );
		out = replace( out, "'", "\'", "all" );
		out = replace( out, "<", "\x3C", "all" );
		out = replace( out, ">", "\x3E", "all" );
		out = replace( out, chr( 13 ), "\r", "all" );
		out = replace( out, chr( 10 ), "\n", "all" );
		return out;
	}

	/** yyyymmdd from component functions: date masks differ between engines (BoxLang reads mm as minutes). */
	private string function dayKey( required date d ){
		return year( arguments.d ) & right( "0" & month( arguments.d ), 2 ) & right( "0" & day( arguments.d ), 2 );
	}

	/**
	 * The page writes the cookie and reloads once. It never loops: the first
	 * automatic attempt is remembered per tab (sessionStorage, retryWindowSeconds),
	 * and any later render in that window waits for a click. A cookie that cannot
	 * be read back (cookies blocked, Secure cookie on a plain-HTTP origin) also
	 * stops the automatic reload and explains why.
	 */
	private string function jsCookiePage( required string tok, required struct snap, required string rule ){
		var attrs = "path=/;max-age=#variables.cfg.maxAgeSeconds#;SameSite=Lax" & ( variables.cfg.secure ? ";Secure" : "" );
		var js = '(function(){'
			& 'var n="#jsStr( variables.cfg.cookie )#",t="#jsStr( arguments.tok )#",a="#attrs#",k="rg_attempt",w=#int( variables.cfg.retryWindowSeconds )#*1000;'
			& 'var W=document.getElementById("rg-wait"),M=document.getElementById("rg-manual"),G=document.getElementById("rg-msg"),B=document.getElementById("rg-continue");'
			& 'function set(){document.cookie=n+"="+t+";"+a;return document.cookie.indexOf(n+"=")>-1;}'
			& 'function mark(){try{sessionStorage.setItem(k,String(Date.now()));}catch(e){}}'
			& 'function tried(){try{var v=parseInt(sessionStorage.getItem(k)||"0",10);return v>0&&Date.now()-v<w;}catch(e){return false;}}'
			& 'function manual(m){W.style.display="none";M.style.display="block";if(m){G.textContent=m;}}'
			& 'B.onclick=function(){mark();if(set()){location.reload();}else{manual("#jsStr( variables.cfg.cookieText )#");}};'
			& 'function go(){'
			& 'if(!set()){manual("#jsStr( variables.cfg.cookieText )#");return;}'
			& 'if(tried()){manual("");return;}'
			& 'mark();location.reload();'
			& '}'
			& ( variables.cfg.botd == "off" ? 'go();' : reportJs( arguments.snap, arguments.rule ) )
			& '})();';
		var lib = variables.cfg.botd == "off" ? "" : '<script>' & detectorJs() & '</script>';
		return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="viewport" content="width=device-width,initial-scale=1"><title>#encodeForHTML( variables.cfg.title )#</title></head>'
			& '<body style="font-family:sans-serif;text-align:center;margin-top:20vh">'
			& '<p id="rg-wait">#encodeForHTML( variables.cfg.title )#&hellip;</p>'
			& '<div id="rg-manual" style="display:none"><p id="rg-msg">#encodeForHTML( variables.cfg.retryText )#</p>'
			& '<p><button id="rg-continue" type="button" style="font-size:1rem;padding:.5em 1.5em">#encodeForHTML( variables.cfg.continueText )#</button></p></div>'
			& '<noscript><p>Please enable JavaScript to continue.</p></noscript>'
			& lib & '<script>#js#</script></body></html>';
	}

	/**
	 * Report mode: run the detector first, post the verdict (sendBeacon, which
	 * survives the reload; fetch keepalive as fallback), then continue with the
	 * cookie flow exactly as before. A detector that does not answer within
	 * botdTimeoutMs reports "timeout" and the page goes on; nothing here can
	 * hold a visitor back.
	 */
	private string function reportJs( required struct snap, required string rule ){
		var page = pageText( arguments.snap.path & ( len( arguments.snap.query ?: "" ) ? "?" & arguments.snap.query : "" ) );
		return 'var R={u:"#jsStr( variables.cfg.botdPath )#",n:"#nonce( arguments.snap, arguments.rule, page )#",r:"#jsStr( arguments.rule )#",p:"#jsStr( page )#",v:"#jsStr( detectorVersion() )#"},t0=Date.now(),done=false;'
			& 'function send(k){var b=JSON.stringify({n:R.n,r:R.r,p:R.p,k:k,v:R.v,t:Date.now()-t0});'
			& 'try{if(navigator.sendBeacon&&navigator.sendBeacon(R.u,new Blob([b],{type:"application/json"}))){return;}}catch(e){}'
			& 'try{fetch(R.u,{method:"POST",body:b,keepalive:true,headers:{"Content-Type":"application/json"}});}catch(e){}}'
			& 'function fin(k){if(done){return;}done=true;send(k);go();}'
			& 'setTimeout(function(){fin("timeout");},#int( variables.cfg.botdTimeoutMs )#);'
			& 'try{if(window.BotD&&BotD.load){BotD.load({monitoring:false}).then(function(a){return a.detect();})'
			& '.then(function(r){fin(r&&r.bot?String(r.botKind||"bot"):"clean");},function(e){fin("error");});}else{fin("nolib");}}catch(e){fin("error");}';
	}

}
