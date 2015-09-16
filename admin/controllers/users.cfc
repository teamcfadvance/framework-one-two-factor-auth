component accessors="true" {

    property userService;
    //property mailService;

	public any function init( fw ) {
		variables.fw = fw;
		return this;
	}
	
	public void function default( rc ) {
		var isActive = true;
		if( structKeyExists( rc, 'userState') AND rc.userState EQ 'inactive' ) { 
			isActive = false; 
		}
		rc.title = ' &raquo; Admin Users';
		rc.qGetUsers = userService.filter( isActive = isActive, orderBy = 'userId' );
	}

	public void function edit(rc) {
		rc.uid = rc[ 'v' & application.securityService.uberHash( 'userId', 'MD5', 1000 ) ];
		rc.title = ' &raquo; Admin Users &raquo; #( ( rc.uid EQ 0 ) ? 'Add' : 'Edit' )#';
		if( rc.uid NEQ 0 ) {
			rc.userObj = userService.getUserById( application.securityService.dataDec( rc.uid, 'url' ) );
			rc.username = application.securityService.dataDec( rc.userObj.getUsername(), 'repeatable' );
			rc.firstName = application.securityService.dataDec( rc.userObj.getFirstName(), 'db' );
			rc.lastName = application.securityService.dataDec( rc.userObj.getLastName(), 'db' );
		} else {
			rc.userObj = userService.getUserById( 0 );
			rc.username = '';
			rc.firstName = '';
			rc.lastName = '';
		}
	}

	public void function update( rc ) {
		var randomPassword = application.securityService.getRandomPassword();
		rc.uid = rc[ 'f' & application.securityService.uberHash( 'userId', 'MD5', 1000 ) ];
		rc.userObj = userService.getUserById( application.securityService.dataDec( rc.uid, 'form' ) );

		rc.userObj.setUsername( application.securityService.dataEnc( rc.username, 'repeatable' ) );
		rc.userObj.setFirstName( application.securityService.dataEnc( rc.firstName, 'db' ) );
		rc.userObj.setLastName( application.securityService.dataEnc( rc.lastName, 'db' ) );
		rc.userObj.setRole( rc.role );
		rc.userObj.setIsActive( 1 );

		if( rc.uid EQ 0 OR ( isDefined( 'rc.resetPassword' ) AND rc.resetPassword ) ) {
			rc.userObj.setPassword( application.securityService.dataEnc( application.securityService.uberHash( randomPassword, 'SHA-384', 1 ), 'db' ) );
			//mailService.sendUserPassword( rc.userObj, randomPassword );
		}

		userService.saveUser( rc.userObj );

		variables.fw.redirect( action = 'users.default', queryString = '?msg=#( ( rc.uid EQ 0 ) ? 'add' : 'update' )#' );
	}

	public function confirm(rc) {
		rc.title = ' &raquo; Admin Users &raquo; Confirm';
		rc.userObj = userService.getUserById( application.securityService.dataDec( rc[ 'v' & application.securityService.uberHash( 'userId', 'MD5', 1000 ) ], 'url' ) );
		rc.firstName = application.securityService.dataDec( rc.userObj.getFirstName() );
		rc.lastName = application.securityService.dataDec( rc.userObj.getLastName() );


	}

	public function deactivate( rc ) {
		rc.userObj = userService.getUserById( application.securityService.dataDec( rc[ 'v' & application.securityService.uberHash( 'userId', 'MD5', 1000 ) ], 'url' ) );

		rc.userObj.setIsActive( 0 );

		userService.saveUser( rc.userObj );
 
		variables.fw.redirect( action = 'users.default', queryString = '?msg=deactivate' );
	}

	public function reactivate( rc ) {
		rc.userObj = userService.getUserById( application.securityService.dataDec( rc[ 'v' & application.securityService.uberHash( 'userId', 'MD5', 1000 ) ], 'url' ) );

		rc.userObj.setIsActive( 1 );

		userService.saveUser( rc.userObj );

		variables.fw.redirect( action = 'users.default', queryString = '?msg=reactivate' );
	}
	
}
