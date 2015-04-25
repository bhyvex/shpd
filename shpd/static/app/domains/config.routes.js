(function(){
    'use strict';
    
    angular
        .module('shpd.domains')
        .config(getRoutes);
    
    getRoutes.$inject = ['$stateProvider', '$urlRouterProvider'];
    
    function getRoutes($stateProvider, $urlRouterProvider) {
    	$stateProvider
        .state('dashboard.domains', {
            url: '^/domains',
            templateUrl: 'app/domains/domains.html',
            controller: 'DomainsController',
            controllerAs: 'vm',
            authenticate: true,
            resolve: {
                domains: ['DomainsService', '$state', '$stateParams', function (DomainsService, $state, $stateParams) {
                    return DomainsService.list().then(null, function(errorData) {	                            
                        $state.go('error');
                    }); 
                }] 
            }
        })
    }
})();
