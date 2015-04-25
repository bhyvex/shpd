(function(){
	'use strict';

	angular
	    .module('shpd.domains')
	    .controller('DomainsController', DomainsController);

	DomainsController.$inject = ['domains', 'DomainsService', '$stateParams'];
	function DomainsController(domains, DomainsService, $stateParams) {
            var vm = this;
            vm.domains = domains;
            vm.selectedDomain = null;
            vm.refresh = refresh;
            vm.showRemoveDomainDialog = showRemoveDomainDialog;
            vm.removeDomain = removeDomain;

            function refresh() {
                DomainsService.list()
                    .then(function(data) {
                        vm.domains = data; 
                    }, function(data) {
                        vm.error = data;
                    });
                vm.error = "";
            };

            function showRemoveDomainDialog(domain) {
                vm.selectedDomain = domain;
                $('.ui.small.remove.modal').modal('show');
            };

            function removeDomain() {
                DomainsService.remove(vm.selectedDomain)
                    .then(function(data) {
                        vm.refresh();
                    }, function(data) {
                        vm.error = data;
                    });
            }

	}
})();
