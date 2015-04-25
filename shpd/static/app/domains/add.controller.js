(function(){
	'use strict';

	angular
	    .module('shpd.domains')
	    .controller('AddDomainController', AddDomainController);

	AddDomainController.$inject = ['$state', '$stateParams', '$http'];
	function AddDomainController($state, $stateParams, $http) {
            var vm = this;
            vm.name = "";
            vm.description = "";
            vm.domain = "";
            vm.endpoint = "";
            vm.creating = false;
            vm.addDomain = addDomain;

            function isFormValid() {
                return $('.ui.form').form('validate form');
            }

            function addDomain() {
                if (!isFormValid()) {
                    return;
                }

                vm.request = {
                    name: vm.name,
                    description: vm.description,
                    domain: vm.domain,
                    endpoint: vm.endpoint
                }

                vm.creating = true;
                $http
                    .post('/api/domains', vm.request)
                    .success(function(data, status, headers, config) {
                        if (status > 200) {
                            vm.error = "Error: " + data;
                            return;
                        }
                        $state.transitionTo('dashboard.domains');
                    })
                    .error(function(data, status, headers, config) {
                        vm.error = data;
                        vm.creating = false;
                    });
            }

	}
})();
