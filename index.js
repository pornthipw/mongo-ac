var util    = require('util');
var crypto  = require('crypto');
var events  = require('events');
var mongodb = require('mongodb');
var BSON = require('mongodb').pure().BSON;
var generic_pool = require('generic-pool');

var MongoAC = function(config) {
  events.EventEmitter.call(this);
  self = this;
  
  var pool = generic_pool.Pool({
    name: 'mongodb',
    max: 2,
    create: function(callback) {
      var db = new mongodb.Db(config.db, 
        new mongodb.Server(config.host, config.port),
        {safe:false, auto_reconnect:true,poolSize:4
      });      
      db.open(function(err,db) {
        console.log('Open DB');
        if(err) {
          console.log(err);
        }
        callback(err,db);
      });
    },
    destroy: function(db) {
      db.close();
    }
  });

  this.native_handlers = function(req, res, callback) {
    var url_user = /^\/mongo-ac\/users$/;
    var url_allow = /^\/mongo-ac\/allow$/; // {'user':'kphongph@gmail.com', 'url':'/login', 'method':'GET'}
    var url_notallow = /^\/mongo-ac\/notallow$/; // {'user':'kphongph@gmail.com', 'url':'xxxx', 'method':'GET'}
    var url_protect = /^\/mongo-ac\/protect$/; // {'url':'/', 'method':'GET'}
    var url_release = /^\/mongo-ac\/release$/; // {'url':'/'}
    
    // var url_release= /^\/mongo-ac\/notallow$/; // {'user':'kphongph@gmail.com', 'url':'xxxx', 'method':'GET'}

    if(url_user.test(req.url)) {
      self.users(function(users) {
        callback(true);
        res.json(users);
      });
    } else { 
      if(url_allow.test(req.url)) {                
        var obj =req.body;
        console.log(req.body);        
        self.allow(obj.user, obj.url, obj.method, function(user) {
          callback(true);
          res.json({'ok':'1'});
        });        
      } else {
      	if(url_notallow.test(req.url)) {                
        		var obj =req.body;
        		console.log(req.body);        
        		self.not_allow(obj.user, obj.url, obj.method, function(user) {
          		callback(true);
          		res.json({'ok':'1'});
        		});        
      	} else {
      		if(url_protect.test(req.url)) {                
        			var obj =req.body;
        			console.log(req.body); 
        			self.protect(obj.url, obj.method, function(){
        				callback(true);
          			res.json({'ok':'1'});
        			}); 
      		} else {
      			if(url_release.test(req.url)) {                
        				var obj =req.body;
        				console.log(req.body); 
        				self.release(obj.url,obj.method, function(){
        					callback(true);
          				res.json({'ok':'1'});
        				});
      			} else {
        				callback(false);
        			}
        		}
        	}
      }
    }
  };
  
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
      pool.acquire(function(err,db) {
        db.collection(config.collection_name, function(err, collection) {
          collection.findOne(spec, function(err, doc) {
            if(doc) {
              if(typeof req.user !== "undefined") {
                collection.findOne({"username":req.user.identifier.profile.emails[0].value}, function(err, doc) {
                  pool.release(db);
                  if(!doc) {
                    next(new Error(401));
                  } else {
                    if(doc.allow.indexOf(hash) !== -1) {
                      self.native_handlers(req,res,function(handle) {
                        if(!handle) {
                          next();
                        }
                      });
                    } else {
                      next(new Error(401));
                    }
                  }
                });                
              } else {                          
                pool.release(db);
                next(new Error(401));
              }
            } else {
              pool.release(db);
              self.native_handlers(req,res,function(handle) {
                if(!handle) {
                  next();
                }
              });
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
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.findOne(spec, function(err, doc) {
           pool.release(db);
           if(!doc) {
             collection.insert(spec, function(err, result) {               
               if(callback) {                        
                 callback(hash);
               }
             });                             
           } else {             
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
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.remove(spec, function(err, doc) {             
           if(callback) {
             pool.release(db);
             callback(hash);
           }               
         });
       });
    });                
  };
    
  this.allow = function(user, url, method, callback) {
    spec = {'username':user};
    var hash = crypto.createHash('md5').update(url + method).digest('hex');
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.findOne(spec, function(err, doc) {
           if(!doc) {
             spec['allow'] = [hash];
             collection.insert(spec, function(err, result) {               
               if(callback) {                        
                 pool.release(db);
                 callback(user);
               }
             });                             
           } else {                                       
             if(doc.allow.indexOf(hash) == -1) {
               doc.allow.push(hash);
               collection.save(doc, function(err, result) {
                 if(callback) {
                   pool.release(db);
                   callback(user);
                 }
               });
             } else {
               if(callback) {
                 pool.release(db);
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
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.findOne(spec, function(err, doc) {
          if(doc) {
             var idx = doc.allow.indexOf(hash);
             if(idx != -1) {
               doc.allow.splice(idx,1);
               collection.save(doc, function(err, result) {               
                 pool.release(db);
                 callback(user);
               });
             } else {
               pool.release(db);
               callback(user);
             }
           } else {
             pool.release(db);
             callback(user);
           }                                                      
        });
      });
    });  
  };
  
  this.get_user = function(username,callback) {
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.findOne({'username':username}, function(err, user) {
          if(user) {
            collection.find({'_id':{'$in':user.allow}}).toArray(function(err, docs) {
 
              pool.release(db);
              callback(docs);
            });
          } else {
            pool.release(db);
            callback(null);
          }
        });
      });
    });
  };
  
      
  this.users = function(callback) {
    pool.acquire(function(err,db) {
      db.collection(config.collection_name, function(err, collection) {
        collection.find({'username':{'$exists':true}}).toArray(function(err, users) {
          pool.release(db);
          callback(users);
        });
      });
    });
  };
}

util.inherits(MongoAC, events.EventEmitter);
exports.MongoAC = MongoAC;
