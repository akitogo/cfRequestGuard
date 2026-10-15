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
 */
component {

	function init( required struct cfg, required string secret, required any decision ){
		variables.cfg      = {
			cookie: "rg_c", maxAgeSeconds: 86400, bindToIP: true, secure: true, kind: "js-cookie",
			title: "Checking your browser",
			continueText: "Continue",
			retryText: "Please click to continue.",
			cookieText: "Your browser is blocking cookies. Please allow cookies for this site, then continue.",
			retryWindowSeconds: 600
		};
		structAppend( variables.cfg, arguments.cfg, true );
		variables.secret   = arguments.secret;
		variables.decision = arguments.decision;
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
				d.body = jsCookiePage( token( arguments.snap ) );
		}
		return d;
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
	private string function jsCookiePage( required string tok ){
		var attrs = "path=/;max-age=#variables.cfg.maxAgeSeconds#;SameSite=Lax" & ( variables.cfg.secure ? ";Secure" : "" );
		var js = '(function(){'
			& 'var n="#jsStr( variables.cfg.cookie )#",t="#jsStr( arguments.tok )#",a="#attrs#",k="rg_attempt",w=#int( variables.cfg.retryWindowSeconds )#*1000;'
			& 'var W=document.getElementById("rg-wait"),M=document.getElementById("rg-manual"),G=document.getElementById("rg-msg"),B=document.getElementById("rg-continue");'
			& 'function set(){document.cookie=n+"="+t+";"+a;return document.cookie.indexOf(n+"=")>-1;}'
			& 'function mark(){try{sessionStorage.setItem(k,String(Date.now()));}catch(e){}}'
			& 'function tried(){try{var v=parseInt(sessionStorage.getItem(k)||"0",10);return v>0&&Date.now()-v<w;}catch(e){return false;}}'
			& 'function manual(m){W.style.display="none";M.style.display="block";if(m){G.textContent=m;}}'
			& 'B.onclick=function(){mark();if(set()){location.reload();}else{manual("#jsStr( variables.cfg.cookieText )#");}};'
			& 'if(!set()){manual("#jsStr( variables.cfg.cookieText )#");return;}'
			& 'if(tried()){manual("");return;}'
			& 'mark();location.reload();'
			& '})();';
		return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><meta name="viewport" content="width=device-width,initial-scale=1"><title>#encodeForHTML( variables.cfg.title )#</title></head>'
			& '<body style="font-family:sans-serif;text-align:center;margin-top:20vh">'
			& '<p id="rg-wait">#encodeForHTML( variables.cfg.title )#&hellip;</p>'
			& '<div id="rg-manual" style="display:none"><p id="rg-msg">#encodeForHTML( variables.cfg.retryText )#</p>'
			& '<p><button id="rg-continue" type="button" style="font-size:1rem;padding:.5em 1.5em">#encodeForHTML( variables.cfg.continueText )#</button></p></div>'
			& '<noscript><p>Please enable JavaScript to continue.</p></noscript>'
			& '<script>#js#</script></body></html>';
	}

}
