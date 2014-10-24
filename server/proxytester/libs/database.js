var fs = require("fs"),
    sqlite3 = require("sqlite3").verbose();

var file = __dirname + "/../db/test.db";

module.exports = function () {
    return undefined;
};

module.exports.initialize = function() {
    var exists = fs.existsSync(file);
    if(!exists) {
        console.log("Creating DB file.");
        fs.openSync(file, "w");
    }

    var db = new sqlite3.Database(file);
    if(!exists) {
        db.serialize(function() {
            console.log("Creating database tables");
            db.run("CREATE TABLE testset (uuid TEXT, result TEXT)");
            db.run("CREATE TABLE anonymised (uuid TEXT, country TEXT, city TEXT, networkType TEXT, networkName TEXT)");
        });
    }
    db.close();
    return db;
}

module.exports.connect = function() {
    var db = new sqlite3.Database(file);
    return db;
}