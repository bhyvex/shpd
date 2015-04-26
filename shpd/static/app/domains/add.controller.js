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
            vm.prefix = "";
            vm.endpoint = "";
            vm.creating = false;
            vm.detectedIP = "";
            vm.addDomain = addDomain;
            vm.getIP = getIP;

            // attempt to get remote IP to preload form
            getIP();

            function getIP() {
                $http
                    .get('/api/ip')
                    .success(function(data, status, headers, config) {
                        vm.detectedIP = data;
                    });
            }
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
                    prefix: vm.prefix,
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
