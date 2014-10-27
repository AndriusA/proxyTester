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
            db.run("CREATE TABLE anonymised (uuid TEXT, country TEXT, city TEXT, networkType TEXT, networkName TEXT, summary TEXT)");
        });
        fillInData(db);
    }
    db.close();
    return db;
}

module.exports.connect = function() {
    var db = new sqlite3.Database(file);
    return db;
}

function fillInData(db) {
    var anonymisedQuery = db.prepare("INSERT INTO anonymised (uuid, country, city, networkType, networkName, summary) VALUES (?,?,?,?,?,?)");

    db.serialize(function() {
        anonymisedQuery.run("a1", "Lithuania", "Vilnius", "WIFI", "TEO-LT", "Moderate firewalls present");
        anonymisedQuery.run("a2", "Lithuania", "Vilnius", "mobile", "Omnitel-LT", "Close to none communication interference");
        anonymisedQuery.run("a3", "Finland", "Helsinki", "mobile", "Saunalahti", "No interference");
        anonymisedQuery.run("a4", "Finland", "Helsinki", "WIFI", "HELSINKI-UNI", "Moderate firewalls present");
        anonymisedQuery.run("a5", "Spain", "Barcelona", "WIFI", "Telefonica-Free", "Moderate firewalls present");
        anonymisedQuery.run("a6", "Germany", "Berlin", "mobile", "E-Plus", "Moderate packet rewriting");
        anonymisedQuery.run("a7", "United Kingdom", "Cambridge", "mobile", "GiffGaff", "Aggressive firewalls, secure communications affected on most ports. Proxies all ports except 443, 993");
        anonymisedQuery.run("a8", "United Kingdom", "Cambridge", "mobile", "T-Mobile", "Aggressive firewalls and proxies, secure communications affected on certain ports: 80, 443");
        anonymisedQuery.run("a9", "United Kingdom", "Cambridge", "mobile", "three.co.uk", "Close to none communication interference");
        anonymisedQuery.run("a10", "United Kingdom", "Cambridge", "WIFI", "Virgin", "Close to none communication interference");
        anonymisedQuery.run("a11", "Germany", "Berlin", "WIFI", "MKSW", "Moderate firewalls present");
    });
}
