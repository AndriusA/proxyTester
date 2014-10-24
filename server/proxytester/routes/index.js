var whois = require('node-whois'),
    prettyjson = require('prettyjson'),
    _ = require('lodash-node');

module.exports = function (app) {
    app.get('/', index);
    app.post('/data/', putData);
    app.get('/data/', getAnonymisedData)
};

require(__dirname+'/../libs/lodash-mixins.js')(_);
var database = require(__dirname + '/../libs/database.js');
var db = database.connect();

var index = function (req, res) {
    res.render('index', { title: 'ProxyTester' });
};

var putData = function (req, res) {
    var data = "";
    req.addListener('data', function(chunk) { data += chunk; });
    req.addListener('end', function() {
        var parsed = JSON.parse(data);
        // console.log("received:" + data);
        // placeholders (?) are auto-escaped!
        db.run("INSERT INTO testset (uuid, result) VALUES (?, ?)", parsed.uuid, data);
    	res.json(parsed);

        reverseLocation(parsed, function(country, city) {
            var insertQuery = db.prepare("INSERT INTO anonymised (uuid, country, city, networkType, networkName) VALUES (?,?,?,?,?)");
            // WiFi network names/SSID may be privacy-sensitive; use whois-based network name
            if (parsed.networkInfo.type == "WIFI") {
                whoisNetworkName(parsed, function(networkName) {
                    insertQuery.run(parsed.uuid, country, city, parsed.networkInfo.type, networkName);    
                });
            } else {
                insertQuery.run(parsed.uuid, country, city, parsed.networkInfo.type, parsed.networkInfo.extra);    
            }
        });

    });
};

function reverseLocation(data, callback) {
    var geocoderProvider = 'google';
    var httpAdapter = 'https';
    var extra = {
        apiKey: 'AIzaSyAc95by91bSjfLG8dmU3AafsNZ6skDugMs',
    };
    var geocoder = require('node-geocoder').getGeocoder(geocoderProvider, httpAdapter, extra);
    // console.log("location", data.location);
    geocoder.reverse(data.location.latitude, data.location.longitude, function(err, res) {
        // console.log(err, res);
        var city;
        var country;
        // console.log(res);
        if (res !== undefined) {
            // take the first result
            city = res[0].city;
            country = res[0].country;
        } else {
            city = "UNKNOWN";
            country = "UNKNOWN";
        }

        callback(country, city);
    });
}

function whoisNetworkName(data, callback) {
    // Find the global IP
    var result = _.find(data.results, { 'name': "CheckLocalAddressTest-GLOBAL" });
    var networkName = "UNKNOWN";
    if (result) {
        whois.lookup(result.srcAddress, function(err, whoisData) {
            if (!err) {
                var regexp = /netname:\s*([A-Za-z0-9_-]*)/i;
                var match = whoisData.match(regexp);
                if (match && match.length >= 1)
                    networkName = match[1];
                callback(networkName);
            } else {
                console.log("Error performing a whois lookup:", err);
            }
        });
    }
    callback(networkName);
}

var getAnonymisedData = function(req, res) {
    db.all("SELECT country, city, networkType, networkName FROM anonymised", function(err, data) {
        if (err)
            return res.json({});
        
        // console.log("SQL data:", data);
        // country
        // country code (3 letter)
        // number of tests
        // 3g/WiFi tests list:
        // - network name
        // - number of tets
        // - summary
        // - TODO: proxied ports, global IP
        
        var countries = require(__dirname + '/../libs/countryLatLong.json');
        
        // From the full list of country information, extract country:countryCode pairs
        var countriesT = _.zip(countries);
        var countryCodes = _.zipObject(countriesT[8], countriesT[10]);

        // Exclude results with unknown location
        data = _.reject(data, {'country': 'UNKNOWN'});        


        // TODO: extract summary from DB data
        data = _.mapValues(data, function(val) {
            return _.assign(val, {'summary': 'empty'});     // Add the summary description
        })

        // Count the number of tests per country
        var countryResults = _.chain(data)
            .countBy('country')
            .transform(function(result, value, key) {
                result[key] = {country: key, numberOfTests: value};
            })
            .value();

        // Collect the cities per country
        var countryCities = _.chain(data)
            .groupBy('country')
            .mapValues( function(val){ return {cities: _.uniq(_.pluck(val, 'city'))} })
            .value();

        // Aggregate network data:
        var mobile = {}
        for (i in data) {
            var item = data[i];
            if (!mobile[item.country]) {
                mobile[item.country] = {};
            }
            if (!mobile[item.country][item.networkType]) {
                mobile[item.country][item.networkType] = {};
            }
            // Aggregate results by the network
            var aggr;
            // Initialise a new aggregate data element for the network
            if (!mobile[item.country][item.networkType][item.networkName]) {
                mobile[item.country][item.networkType][item.networkName] = {};
                aggr = mobile[item.country][item.networkType][item.networkName];
                aggr.numberOfTests = 0;
                aggr.testedCities = [];
                aggr.summaries = [];
            }
            aggr = mobile[item.country][item.networkType][item.networkName];
            aggr.numberOfTests++;
            aggr.testedCities.push(item.city);
            aggr.testedCities = _.uniq(aggr.testedCities);
            aggr.summaries.push(item.summary);
            aggr.summaries = _.uniq(aggr.summaries);
            aggr.summary = aggr.summaries.join("; ");
        }
        // console.log("MOBILE", prettyjson.render(mobile));

        var output = {};
        output = _.chain(output)
            .merge(countryResults)
            .merge(countryCities)
            .merge(mobile)
            .value()

        // console.log("merged", prettyjson.render(output));

        // Assign country codes
        output = _.mapValues(output, function(val) {
            return _.assign(val, {countryCode : countryCodes[val.country]})
        })

        // Re-key by country code rather than country - needed for visualisation
        output = _.indexBy(output, 'countryCode');
        console.log("output", prettyjson.render(output));
        res.json(output);
        
    });
}

    