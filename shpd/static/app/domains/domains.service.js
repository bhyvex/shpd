(function(){
	'use strict';

	angular
    	    .module('shpd.domains')
            .factory('DomainsService', DomainsService);

	DomainsService.$inject = ['$http'];
        function DomainsService($http) {
            return {
                list: function() {
                    var promise = $http
                        .get('/api/domains')
                        .then(function(response) {
                            return response.data;
                        });
                    return promise;
                }
            } 
        } 
})();
