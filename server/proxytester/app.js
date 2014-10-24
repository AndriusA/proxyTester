var express = require('express'),
    http = require('http'),
    app = express(),
    opts = require(__dirname + '/config/opts.js');
    

var db;
var database = require(__dirname + '/libs/database.js');
db = database.initialize();

// Load express configuration
require(__dirname + '/config/env.js')(express, app);

// Load routes
require(__dirname + '/routes')(app);

// Start the server
http.createServer(app).listen(opts.port, function () {
    console.log("Express server listening on port %d in %s mode",
                opts.port, app.settings.env);
});

