module.exports = {
  authorization: {
    mongodb:{
     server: '10.10.20.75',
     port: 27017,
     db: 'projectplan',
     collection: 'nook_ac_1',
     autoReconnect: true,
     poolSize: 4
    }
  },
  site: {
    //baseUrl: the URL that mongo express will be located at
    //Remember to add the forward slash at the end!
    baseUrl: 'http://www.db.grad.nu.ac.th/apps/demo/',
    port: 9011,
    cookieSecret: 'cookiesecret',
    sessionSecret: 'sessionsecret'
  }
};
