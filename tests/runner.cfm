<cfsetting showdebugoutput="false">
<cfparam name="url.reporter" default="simple">
<cfparam name="url.directory" default="tests.specs">
<cfscript>
	testbox = new testbox.system.TestBox( directory = url.directory, reporter = url.reporter, options = { coverage: { enabled: false } } );
	writeOutput( testbox.run() );
</cfscript>
