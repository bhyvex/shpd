(function(){
	'use strict';

	angular
		.module('shpd.login')
		.controller('LoginController', LoginController);

    LoginController.$inject = ['AuthService', '$state'];
	function LoginController(AuthService, $state) {
            var vm = this;
            vm.error = "";
            vm.username = "";
            vm.password = "";
            vm.login = login;

            function isValid() {
                return $('.ui.form').form('validate form');
            }

            function login() {
                if (!isValid()) {
                    return;
                }

                vm.error = "";
                AuthService.login({
                    username: vm.username, 
                    password: vm.password
                }).then(function(response) {
                    if (response.token == null) {
                        vm.error = response;
                        return;
                    }
                    $state.transitionTo('dashboard.domains');
                }, function(response) {
                    vm.error = response.data;
                    console.log('error:' + response.data);
                });
            }
        }
})();

