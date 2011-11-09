var exRouter = require('connect').router;

module.exports = function(options){
  options = options || {};
  options.prefix = options.prefix || 'oauth2';
  options.grants = options.grants || 'all'; // ['authorization_grant', 'implicit', 'password', 'client_credentials', 'refresh_token']
  
  options.response_types = [];
  options.grant_types = [];

  if(options.grants == 'all') options.grants = ['authorization_grant', 'implicit', 'password', 'client_credentials'];

  if(options.grants.indexOf('authorization_grant') != -1) {
    options.response_types.push('code');
    options.grant_types.push('authorization_code');
  }

  if(options.grants.indexOf('implicit') != -1) options.response_types.push('token');
  if(options.grants.indexOf('password') != -1) options.grant_types.push('password');
  if(options.grants.indexOf('client_credentials') != -1) options.grant_types.push('client_credentials');
  if(options.grants.indexOf('refresh_token') != -1) options.grant_types.push('refresh_token');

  var routes = router(options);


  return function(req, res, next){
    // if(!options.backend) options.backend = require('./backends/default');
    req.auth = parseAuth(req);
    routes(req, res, next);
  };
};

function router(options) {
  var prefix = '/' + options.prefix;
  return exRouter(function(route){

    route.get(prefix + '/authorize', function(req, res, next){
      
      if(options.response_types.indexOf(req.query.response_type) != -1) { // authorization_code: 'code', implicit: 'token', 
        var redirect_uri = req.query.redirect_uri || 'http://example.com/cb';
        var state = req.query.state;
      
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.statusCode = 200;
        res.end(JSON.stringify({get: '/authorize'}));  

      } else {

        //return error, server does not support response_type
        redirect_uri += '?error=invalid_request&error_description=response_type_must_equal_code'
        if(state) { redirect_uri += '&state='+state; }
        res.setHeader('Location', redirect_uri);
        res.statusCode = 302;
        res.end(); 
      }

    });

    route.post(prefix + '/token', function(req, res, next){
      options.backend.authenticateClient(req, function(err, client) {
        if(err) {
          console.log('err: ', err);
          token_error(res, 'access_denied', err);
        } else {
      
          if(options.grant_types.indexOf(req.body.grant_type) != -1) {
            
            switch(req.body.grant_type) {
              case 'password':
                if(req.body.username && req.body.password) {
                  var params = { username: req.body.username
                                , password: req.body.password
                                , client_id: client.id };
                  options.backend.passwordToken(params, function(err, responseVars) {
                    if(err) { token_error(res, 'invalid_grant', err); } 
                    else { oauth_return(res, responseVars); }
                  });
                } else {
                  token_error(res, 'invalid_grant', 'Username and password are required');
                }
                
                break;
              case 'client_credentials':
                options.backend.clientToken(req, function(err, responseVars) {
                  if(err) { token_error(res, 'invalid_client', err); } 
                  else { oauth_return(res, responseVars); }
                });
                break;
              case 'authorization_code':
                // options.backend.authToken()
                break;
              case 'refresh_token':
                // options.backend.refreshToken()
                break;
              default:
                token_error(res, 'unsupported_grant_type', 'The server only supports the following grant types:' + options.grant_types.toString());
            }
            
          } else {
            token_error(res, 'unsupported_grant_type', 'The server only supports the following grant types:' + options.grant_types.toString());
          }
        }
      });

    });      
  });
}

function token_error(res, type, msg){
  var options = {}
  options.error = type;
  if(msg) options.error_description = msg;

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.statusCode = 400;
  res.end(JSON.stringify(options));
}

function oauth_return(res, params) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.statusCode = 200;
  res.end(JSON.stringify(params));  
}

function parseAuth(req) {
  var auth
    , type
    , token;

  if((auth = req.headers['authorization']) &&
     (auth = auth.split(' ')).length > 1) {
    type = auth[0].toLowerCase();
    token = auth[1];
  }
  
  if(token) return {type: type, token: token};
  return false;
}