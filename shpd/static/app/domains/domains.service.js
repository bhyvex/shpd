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
                },
                remove: function(domain) {
                    var promise = $http
                        .delete('/api/domains/'+domain.prefix)
                        .then(function(response) {
                            return response.data;
                        });
                    return promise;
                },
            } 
        } 
})();
