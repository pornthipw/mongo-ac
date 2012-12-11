var express = require("express");
var mongoac = require("mongo-ac");
var passport = require('passport');
var app = express();

var OpenIDStrategy = require('passport-openid').Strategy;

var access_control = new mongoac.MongoAC({
	host:'10.10.20.75', 
	port:27017,
	db:'projectplan',
	collection_name:'nook_ac_1'
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
    returnURL: 'http://localhost:3000/auth/openid/return',
    realm: 'http://localhost:3000',
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
    res.redirect('http://localhost:3000');
  });
  
app.get('/auth/openid/return', 
  passport.authenticate('openid', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('http://localhost:3000');
});


app.get('/login', function(req, res){
console.log('rendering');
//res.json({'test':'ok'});
  res.send('<form action="/auth/openid" method="post">'+
	'<div>'+
	'<label>OpenID:</label>'+
	'<input type="text" name="openid_identifier"/><br/>'+
	'</div>'+
	'<div>'+
	'<input type="submit" value="Submit"/>'+
	'</div>'+
	'</form>');
});


app.get('/allow/access', function(req, res){
console.log('rendering');
//res.json({'test':'ok'});
  res.send('<form action="/allow/access" method="post">'+
	'<div>'+
	'<label>OpenID:</label>'+
	'<input type="text" name="user"/><br/>'+
	'<input type="text" name="url"/><br/>'+
	'<input type="text" name="method"/><br/>'+
	'</div>'+
	'<div>'+
	'<input type="submit" value="Submit"/>'+
	'</div>'+
	'</form>');
});

app.post('/allow/access', function(req, res) {
	console.log('POST allow/access');
	access_control.allow(req.body.user,req.body.url,req.body.method, function(user) {
		res.json({'test':'ok'});
	});	
});

app.get('/notallow/access', function(req, res) {
	access_control.allow(req.query.user,req.query.url,req.query.method, function(user) {
		res.json({'test':'ok'});
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


app.listen(3000);

console.log("Mongo Express server listening on port " + 3000);
