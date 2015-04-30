(function(){
    'use strict';

    angular
        .module('shpd.login')
	.controller('LogoutController', LogoutController);

        LogoutController.$inject = ['AuthService', '$state', '$window'];
            function LogoutController(AuthService, $state, $window) {
                var vm = this;
                $window.location.href = "/auth/logout";
            }
})();

