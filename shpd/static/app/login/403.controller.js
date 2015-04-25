(function(){
	'use strict';

	angular
	    .module('shpd.login')
	    .controller('AccessDeniedController', AccessDeniedController);

	AccessDeniedController.$inject = ['$stateParams'];
	function AccessDeniedController($stateParams) {
            var vm = this;
	}
})();
