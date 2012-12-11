var util    = require('util');
var crypto  = require('crypto');
var events  = require('events');
var mongodb = require('mongodb');
var BSON = require('mongodb').pure().BSON;


var db_config = {
	safe:false,'auto_reconnect':true,poolSize: 4
	};

var MongoAC = function(config) {
  events.EventEmitter.call(this);
  self = this;
         
  
  this.guard = function() {    
    var secureFn = function(req, res, next) {
    	var url = req.url;
    	var idx = req.url.indexOf('?'); 
    	if(idx > -1) {
    		url = url.slice(0,idx);    	
    	} 
      var hash = crypto.createHash('md5').update(url + req.method).digest('hex');
      
      var spec = {'_id': hash};
      console.log(url + ' <'+req.method+'>');
      console.log(hash);
      var db = new mongodb.Db(config.db, new mongodb.Server(config.host, config.port), db_config);      
      db.open(function(err, db) {
      	db.collection(config.collection_name, function(err, collection) {
      		collection.findOne(spec, function(err, doc) {
      			if(doc) {
      				if(typeof req.user !== "undefined") {
      					console.log('User -> 1' );      					
      					collection.findOne({"username":req.user.identifier.profile.emails[0].value}, function(err, doc) {
      						if(!doc) {
      							db.close();      					
      							next(new Error(401));
      						} else {
      							if(doc.allow.indexOf(hash) !== -1) {
      								db.close();
      								next();
      							} else {
										db.close();
										console.log("test");      					
      								next(new Error(401));
      							}
      						}
      					});      					
      				} else {      					  				
      					db.close();      					
      					next(new Error(401));
      				}
      			} else {
      				db.close();      		      					      			      				
      				next();   
      			}   			      			
      		});
      	});      	
      });            
    };
    return secureFn;
  };    

  this.protect = function(url, method, callback) {
    var hash = crypto.createHash('md5').update(url + method).digest('hex');
    console.log("Protecting url: " + url);
    var spec = {'_id': hash,'method':method, 'url':url};
    var db = new mongodb.Db(config.db, new mongodb.Server(config.host, config.port), db_config);      
    db.open(function(err, db) {    	
    	db.collection(config.collection_name, function(err, collection) {
    		collection.findOne(spec, function(err, doc) {
     			if(!doc) {
     				collection.insert(spec, function(err, result) {     					
     					db.close();      			  
     					if(callback) {    			      				
     						callback(hash);
     					}
     				});     				     				   
     			} else {     				
     				db.close();
     				if(callback) {
     					callback(hash);
     				}
     			}		
     		});
     	});
    });                
  };
  
	this.release = function(url, method, callback) {
    var hash = crypto.createHash('md5').update(url + method).digest('hex');
    console.log("Releasing url: " + url);
    var spec = {'_id': hash,'method':method, 'url':url};
    var db = new mongodb.Db(config.db, new mongodb.Server(config.host, config.port), db_config);      
    db.open(function(err, db) {    	
    	db.collection(config.collection_name, function(err, collection) {
    		collection.remove(spec, function(err, doc) {     				
     			db.close();
     			if(callback) {
     				callback(hash);
     			}     					
     		});
     	});
    });                
  };
    
  this.allow = function(user, url, method, callback) {
  	spec = {'username':user};
  	var hash = crypto.createHash('md5').update(url + method).digest('hex');
  	var db = new mongodb.Db(config.db, new mongodb.Server(config.host, config.port), db_config);      
  	db.open(function(err, db) {
  		db.collection(config.collection_name, function(err, collection) {
  			collection.findOne(spec, function(err, doc) {
     			if(!doc) {
     				spec['allow'] = [hash];
     				collection.insert(spec, function(err, result) {     					
     					db.close();      			  
     					if(callback) {    			      				
     						callback(user);
     					}
     				});     				     				   
     			} else {     				     				     				
     				if(doc.allow.indexOf(hash) == -1) {
     					doc.allow.push(hash);
     					collection.save(doc, function(err, result) {
     						if(callback) {
		     					callback(user);
     						}
     					});
     				} else {
     					if(callback) {
		     				callback(user);
     					}
     				}     				
     			}		
     		});
  		});
  	});
  };
  
  this.not_allow = function(user, url, method, callback) {
  	spec = {'username':user};
  	var hash = crypto.createHash('md5').update(url + method).digest('hex');
  	var db = new mongodb.Db(config.db, new mongodb.Server(config.host, config.port), db_config);  
  	db.open(function(err, db) {
  		db.collection(config.collection_name, function(err, collection) {
  			collection.findOne(spec, function(err, doc) {
  				if(doc) {
     				var idx = doc.allow.indexOf(hash);
     				if(idx != -1) {
     					doc.allow.splice(idx,1);
     					//console.log(doc.allow);
     					collection.save(doc, function(err, result) {     					
     						db.close();      			  
     						callback(user);
     					});
     				} else {
     					db.close();  
     					callback(user);
     				}
     			} else {
     				db.close();  
     				callback(user);
     			}     				     				      			     				     				        			
  			});
  		});
  	});  
  };
  
  this.getUsers = function() {
  };
  
      
}

util.inherits(MongoAC, events.EventEmitter);
exports.MongoAC = MongoAC;