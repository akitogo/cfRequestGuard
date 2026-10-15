component {
	this.name              = "requestguard-tests-" & hash( getCurrentTemplatePath() );

	// Test harness only: 404 for anything that is not a local request, so the
	// test pages are inert when the package is deployed inside a webroot.
	if ( !listFind( "127.0.0.1,::1,0:0:0:0:0:0:0:1", cgi.remote_addr ) ) {
		cfheader( statusCode = 404, statusText = "Not Found" );
		abort;
	}
	this.sessionManagement = false;
	this.applicationTimeout = createTimeSpan( 0, 1, 0, 0 );

	testsRoot = getDirectoryFromPath( getCurrentTemplatePath() );
	this.mappings[ "/tests" ]    = testsRoot;
	this.mappings[ "/cfRequestGuard" ] = reReplace( testsRoot, "tests[\\/]$", "" );
	this.mappings[ "/testbox" ]  = this.mappings[ "/cfRequestGuard" ] & "testbox";   // box install (devDependencies) puts it at the package root
}
