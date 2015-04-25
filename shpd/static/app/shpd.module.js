(function(){
	'use strict';

	angular
		.module('shpd', [
			'shpd.domains',
			'shpd.services',
			'shpd.layout',
			'shpd.login',
                        'angular-jwt',
			'ui.router'
		]);
		
})();
