var OpenIDStrategy = require('passport-openid').Strategy;
var openid = require('openid');
var util = require('util');
var querystring = require('querystring');

function UbuntuStrategy(options, verify) {
  options.profile = false; //Don't use the OpenIDStrategy's profile
  options.providerURL = options.providerURL || 'https://login.ubuntu.com/';
  OpenIDStrategy.call(this, options, verify);
  this.name = 'ubuntu';

  var sreg = new openid.SimpleRegistration({
    'fullname' : true,
    'nickname' : 'required',
    'email' : 'required',
    'dob' : true,
    'gender' : true,
    'postcode' : true,
    'country' : true,
    'timezone' : true,
    'language' : true
  });
  this._relyingParty.extensions.push(sreg);

  var ax = new openid.AttributeExchange({
    'http://axschema.org/namePerson' : 'required',
    'http://axschema.org/namePerson/first': 'required',
    'http://axschema.org/namePerson/last': 'required',
    'http://axschema.org/contact/email': 'required',
    'http://axschema.org/namePerson/friendly': 'required'
  });
  this._relyingParty.extensions.push(ax);
}

util.inherits(UbuntuStrategy, OpenIDStrategy);

UbuntuStrategy.prototype._parseProfileExt = function(params) {
  return params;
};

UbuntuStrategy.prototype.authenticate = function(req) {
  if (req.method == 'POST') {
    //This tricks the openid passport strategy into using the body data
    //It seems passport's openid isn't setup to handle POST requests properly

    req.query = req.body;
    req.url = req.url + '?' + querystring.stringify(req.body);
  }

  return UbuntuStrategy.super_.prototype.authenticate.call(this, req);
}

module.exports = UbuntuStrategy;
