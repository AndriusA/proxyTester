var util = require(__dirname + '/../libs/util.js'),
    exphbs = require('express-handlebars');

module.exports = function (express, app) {

    // Common configuration
    app.configure(function () {
        var handlebars = exphbs.create({
            partialsDir: 'views/partials/'
        });
        
        app.set('view engine', 'handlebars');
        app.engine('handlebars', handlebars.engine);
        app.use(app.router);        

        // Make sure build folders exist
        util.mkdir(__dirname + '/../build');
        util.mkdir(__dirname + '/../build/css');

        // Configure LESS compiler
+       app.use('/css', require('less-middleware')(__dirname + '/../src/less', {
            dest: __dirname + '/../build/css'
        }));

        // Create static file servers for the build and public folders
        app.use(express.static(__dirname + '/../build'));
        app.use(express.static(__dirname + '/../public'));
    });

    // Development specific configuration
    app.configure('development', function () {
        app.use(express.errorHandler({
            dumpExceptions: true,
            showStack: true
        }));
        app.use(express.logger('dev'));
    });

    // Production specific configuration
    app.configure('production', function () {
        app.use(express.errorHandler());
    });

};
