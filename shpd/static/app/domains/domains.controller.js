(function(){
	'use strict';

	angular
	    .module('shpd.domains')
	    .controller('DomainsController', DomainsController);

	DomainsController.$inject = ['domains', '$stateParams'];
	function DomainsController(domains, $stateParams) {
            var vm = this;
            vm.domains = domains;
            console.log(vm.domains);
	}
})();
