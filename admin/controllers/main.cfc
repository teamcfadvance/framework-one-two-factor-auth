/**
*
* @file admin/controllers/main.cfc
* @author Denard Springle ( denard.springle@gmail.com )
* @description I am the controller for the admin:main section
*
*/

component accessors="true" {

	property userService;
	property smsProviderService;
	property mailService;

	/**
	* @displayname init
	* @description I am the constructor method for main
	* @return 	   this
	*/	
	public any function init( fw ) {
		variables.fw = fw;
		return this;
	}

	/**
	* @displayname default
	* @description I clear session data and present the login view
	*/	
	public void function default( rc ) {

		// disable the admin layout since the login page has it's own html
		variables.fw.disableLayout();
        
        // set a zero session cookie when hitting the login page (federate the login)
        getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=0;path=/;domain=.#CGI.HTTP_HOST#;HTTPOnly");

        // lock and clear the sessionObj
		lock scope='session' timeout='10' {			
            session.sessionObj = createObject( 'component', 'model.beans.Session').init();
		}

		// get a hash for use in preventing password disclosure
		rc.heartbeat = application.securityService.getHeartbeat();

	}

    /**
    * @displayname dashboard
    * @description I present the dashbaord view
    */ 
	public void function dashboard( rc ) {

		rc.product = server.coldfusion.productname;

		if( findNoCase( 'lucee', rc.product ) ) {
			rc.version = server.lucee.version;
		} else if( findNoCase( 'railo', rc.product ) ) {
			rc.version = server.railo.version;			
		} else {
			rc.version = listFirst( server.coldfusion.productversion );
		}

	}

	/**
	* @displayname authenticate
	* @description I authenticate a user login and redirect to the dashboard view if valid
	*/	
	public void function authenticate( rc ) {

		var qGetUser = '';
		var hashedPwd = '';

		// check if the host and referrer match (federate the login)
		if( !findNoCase( CGI.HTTP_HOST, CGI.HTTP_REFERER ) ) {
			// they don't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '503: Your session has timed out. Please log in again to continue.' )#' );		
		}

		// check if the session cookie exists (federate the login)
		if( !structKeyExists( cookie, application.cookieName ) ) {
			// it doesn't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '504: Your session has timed out. Please log in again to continue.' )#' );			
		}

		// ensure a username and password were sent
		if( !len( rc.username ) OR !len( rc.password ) ) {
			// they weren't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '500: Email and Password required to login.' )#' );
		}

		// ensure the CSRF token is provided and valid
		if( !structKeyExists( rc, 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1500 ) ) OR !CSRFVerifyToken( rc[ 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1500 ) ] ) ) {
			// it doesn't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '505: Your session has timed out. Please log in again to continue.' )#' );
		}

		// get the user from the database by encrypted username
		qGetUser = userService.filter( username = application.securityService.dataEnc( rc.username, 'repeatable' ) );

		// check if there is a record for the passed username
		if( !qGetUser.recordCount ) {
			// there isn't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '404: Account not found with provided credentials. Please try again.' )#' );
		}

		// check to be sure this user has an active account
		if( !qGetUser.isActive ) {
			// they don't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '500: Account is disabled. Please contact your system administrator.' )#' );
		}

		// hash the users stored password with the passed heartbeat for comparison
		hashedPwd = hash( lcase( application.securityService.dataDec( qGetUser.password, 'db' ) ) & rc.heartbeat, 'SHA-384' );

		// compare the hashed stored password with the passed password
		if( !findNoCase( hashedPwd, rc.password ) ) {
			// they don't match, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '403: Account not found with provided credentials. Please try again.' )#' );
		}

		// lock the session scope and create a sessionObj for this user
		lock scope='session' timeout='10' {
			session.sessionObj = application.securityService.createUserSession(
				userId = qGetUser.userId,
				role = qGetUser.role,
				firstName = application.securityService.dataDec( qGetUser.firstName, 'db' ),
				lastName = application.securityService.dataDec( qGetUser.lastName, 'db' )
			);
		}

		// send the mfa code to this user for this session
		mailService.sendMfaCode( phone = application.securityService.dataDec( qGetUser.phone, 'db' ), providerEmail = variables.smsProviderService.getSmsProviderById( qGetUser.providerId ).getEmail(), mfaCode = session.sessionObj.getMfaCode() );

		// set the session cookie with the new encrypted session id
        getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=#application.securityService.setSessionIdForCookie( session.sessionObj.getSessionId() )#;path=/;domain=.#CGI.HTTP_HOST#;HTTPOnly");

        // and go to the twofactor view
		variables.fw.redirect( 'main.twofactor' );

	}

	/**
	* @displayname twofactor
	* @description I present the two-factor view
	*/	
	public void function twofactor( rc ) {

		// disable the admin layout since the two-factor page has it's own html
		variables.fw.disableLayout();

	}

	/**
	* @displayname authfactor
	* @description I authenticate the second factor
	*/	
	public void function authfactor( rc ) {

		if( !structKeyExists( rc, 'twofactor' ) OR !len( rc.twofactor ) ) {
			// they don't match, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '410: Second factor was not provided. Please login again.' )#' );			
		}

		// ensure the CSRF token is provided and valid
		if( !structKeyExists( rc, 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1700 ) ) OR !CSRFVerifyToken( rc[ 'f' & application.securityService.uberHash( 'token', 'SHA-512', 1700 ) ] ) ) {
			// it doesn't, redirect to the login page
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '510: Your session has timed out. Please log in again to continue.' )#' );
		}

		if( compareNoCase( rc.twofactor, session.sessionObj.getMfaCode() ) NEQ 0 ) {
			variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '410: Second factor does not match. Please login again.' )#' );	
		}

		// lock the session scope and create a sessionObj for this user
		lock scope='session' timeout='10' {
			session.sessionObj.setMfaCode( '' );
			session.sessionObj.setIsAuthenticated( true );
		}

        // and go to the dashboard view
		variables.fw.redirect( 'main.dashboard' );

	}

	/**
	* @displayname logout
	* @description I clear session data and present the login view
	*/	
	public void function logout( rc ) {

		// clear the users session object from cache
		application.securityService.clearUserSession( session.sessionObj );

        // lock and clear the sessionObj
		lock scope='session' timeout='10' {			
            session.sessionObj = createObject( 'component', 'model.beans.Session').init();
		}

        // set a zero session cookie when hitting the login page (federate the login)
        getPageContext().getResponse().addHeader("Set-Cookie", "#application.cookieName#=0;path=/;domain=.#CGI.HTTP_HOST#;HTTPOnly");

        // go to the login page
		variables.fw.redirect( action = 'main.default', queryString = 'msg=#urlEncodedFormat( '200: You have been successfully logged out.' )#' );

	}
	
}
