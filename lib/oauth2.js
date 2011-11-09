var authentication = require('./authentication')
  , authorization = require('./authorization')
  , model;

var oauth = {
  authentication:  authentication
  , authorization: authorization
  , model:         model
}

module.exports = oauth;