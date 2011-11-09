var router = require('connect').router;

module.exports = function(options){
  options = options || {};
  options.prefix = options.prefix || 'oauth2';

  return function(req, res, next){
    
    // if(!options.backend) options.backend = require('./backends/default');
  };  
};
