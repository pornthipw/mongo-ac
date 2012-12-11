module.exports = {
  authorization: {
    mongodb:{
     server: 'localhost',
     port: 27017,
     autoReconnect: true,
     poolSize: 4
    }
  },
  site: {
    //baseUrl: the URL that mongo express will be located at
    //Remember to add the forward slash at the end!
    baseUrl: 'http://localhost:8083/',
    port: 8083,
    cookieSecret: 'cookiesecret',
    sessionSecret: 'sessionsecret'
  }
};
