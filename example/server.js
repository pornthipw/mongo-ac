var express = require("express");
var mongoac = require("../index");
var passport = require('passport');
var config = require('./config');
var app = express();

var OpenIDStrategy = require('passport-openid').Strategy;



var access_control = new mongoac.MongoAC({
  host:config.authorization.mongodb.server, 
  port:config.authorization.mongodb.port,
  db:config.authorization.mongodb.db,
  collection_name:config.authorization.mongodb.collection
});


app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  
  //app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
    
  app.use(express.static(__dirname + '/public'));    
  
  
  app.use(express.session({ secret: 'keyboard cat' }));
  
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(access_control.guard());
  app.use(app.router);
  
});

app.use(function(err,req,res,next) {
    if(err instanceof Error){
        if(err.message === '401'){
            res.json({'error':401});
            //res.render();
        }
    }
});


access_control.protect('/allow/access', 'POST');
access_control.protect('/notallow/access', 'GET');
access_control.protect('/protect', 'POST');
access_control.protect('/', 'GET');

access_control.allow('pornthip.wong@gmail.com','/allow/access','POST');

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(identifier, done) {
  done(null, { identifier: identifier });
});

passport.use(new OpenIDStrategy({
    returnURL: config.site.baseUrl+'auth/openid/return',
    realm: config.site.baseUrl,
    profile: true
  },
  function(identifier, profile, done) {
    process.nextTick(function () {
      //console.log(profile);
      return done(null, { identifier: identifier, profile:profile })
    });
  }
));


app.post('/auth/openid', 
  passport.authenticate('openid', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect(config.site.baseUrl);
  });
  
app.get('/auth/openid/return', 
  passport.authenticate('openid', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect(config.site.baseUrl);
});


app.get('/login', function(req, res){
  res.send('<form action="'+
        config.site.baseUrl+
        'auth/openid" method="post">'+
  '<div>'+
  '<label>OpenID:</label>'+
  '<input type="text" name="openid_identifier"/><br/>'+
  '</div>'+
  '<div>'+
  '<input type="submit" value="Submit"/>'+
  '</div>'+
  '</form>');
});

app.get('/allow/access', function(req, res) {
  access_control.allow(req.body.user,req.body.url,req.body.method, function(user) {
    res.json({'test':'ok'});
  });  
});

app.get('/notallow/access', function(req, res) {
  access_control.allow(req.query.user,req.query.url,req.query.method, function(user) {
    res.json({'test':'ok'});
  });  
});

app.get('/users', function(req, res) {
  access_control.users(function(users) {
    res.json(users);
  });
});

app.get('/users/:user', function(req, res) {
  console.log('get user <'+req.params.user+'>');
  access_control.get_user(req.params.user, function(user) {
    res.json(user);
  });
});

app.get('/protect', function(req, res) {
  access_control.protect(req.query.url, req.query.method);
});

app.get('/users', function(req, res) {
  var users = access_control.getUsers();
  
});

app.get('/', function(req, res) {
  console.log('User ');
  //console.log(req.user.identifier.profile.emails[0].value);
  res.json({'test':'ok'});
});


app.listen(config.site.port);

console.log("Mongo Express server listening on port " + config.site.port);
