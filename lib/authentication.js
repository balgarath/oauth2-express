var connect = require('connect')
  , base64 = {
  encode: function (unencoded) {
    return new Buffer(unencoded || '').toString('base64');
  }
, decode: function (encoded) {
    return new Buffer(encoded || '', 'base64').toString('utf8');
  }
};

module.exports = function(options){
  options = options || {};
  options.prefix = options.prefix || 'oauth';
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
  var prefix = '/' + options.prefix
    , backend = options.backend;
  return connect.router(function(route){

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
      
      var clientCreds = parseClientCredentials(req);
      if(!clientCreds) {
        token_error(res, 'Invalid client credentials');
      }
      
      backend.authenticateClient(clientCreds, function(err, authenticated) {
        if(err || !authenticated) {
          token_error(res, 'access_denied', err || 'Invalid client credentials');
        } else {
          if(options.grant_types.indexOf(req.body.grant_type) == -1) {
            return token_error(res, 'unsupported_grant_type', 'Only the following grant types are supported:' + options.grant_types.toString());
          }
          
          switch(req.body.grant_type) {
            case 'password':
              if(req.body.username && req.body.password) {
                var params = {
                  username: req.body.username
                , password: req.body.password
                , client_id: clientCreds.client_id
                };
                backend.grantPasswordToken(params, handleTokenResponse(res));
              } else {
                token_error(res, 'invalid_grant', 'Invalid credentials');
              }
              
              break;
            case 'client_credentials':
              backend.grantClientToken(req, handleTokenResponse(res));
              break;
            case 'authorization_code':
              if(body.code) {
                  // must ensure that the "redirect_uri" parameter is present if the
                  // "redirect_uri" parameter was included in the initial authorization
                  // request as described in Section 4.1.1, and if included ensure
                  // their values are identical.
                var params = {
                  code: body.code
                , redirect_uri: body.redirect_uri
                };

                backend.authenticateToken(params, handleTokenResponse(res));
              } else {
                token_error(res, 'invalid_request', 'POST body must contain code');
              }
              break;
            case 'refresh_token':
              if(req.body.refresh_token){
                var params = {
                  refresh_token: req.body.refresh_token
                , client_id: clientCreds.client_id
                };
                backend.grantRefreshToken(params, handleTokenResponse(res));
              }
              else { token_error(res, 'invalid_request', 'POST body must include refresh_token'); }
              break;
            default:
              // shouldnt be able to get to this part of the code?
              token_error(res, 'unsupported_grant_type', 'The server only supports the following grant types:' + options.grant_types.toString());
          }
        }
      });

    });      
  });
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

function parseClientCredentials(req) {
  var clientCreds;
  
  if(req.auth && req.auth.type == 'basic') {
    creds = base64.decode(auth.token).split(':');
    if(creds.length != 2) { return null }  
    else {
      clientCreds = {client_id: creds[0], client_secret: creds[0]};
    }  
  } else if(req.body && req.body.client_id && req.body.client_secret) {
      clientCreds = {client_id: req.body.client_id, client_secret: req.body.client_secret};
  } 
  
  return clientCreds;
}

function handleTokenResponse(res) {
  return function(err, response) {
    if(err || !response.access_token) { token_error(res, 'invalid_grant', err); } 
    else { oauth_return(res, response); }
  };
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
