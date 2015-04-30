(function(){
	'use strict';

	angular
		.module('shpd.login')
		.controller('LoginController', LoginController);

    LoginController.$inject = ['AuthService', '$state', '$http', '$window'];
	function LoginController(AuthService, $state, $http, $window) {
            var vm = this;
            vm.login = login;

            function login() {
                $window.location.href = "/auth/login";
            }
        }
})();

