/*
 * Copyright (c) 2014 Andrius Aucinas <andrius.aucinas@cl.cam.ac.uk>
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
            var insertQuery = db.prepare("INSERT INTO anonymised (uuid, country, city, networkType, networkName, summary, globalIP) VALUES (?,?,?,?,?,?,?)");
            // WiFi network names/SSID may be privacy-sensitive; use whois-based network name
            var global = _.find(data.results, { 'name': "checkLocalAddr-GLOBAL" });
            var local = _.find(data.results, { 'name': "checkLocalAddr-GLOBAL" });
            var isGlobal = global.extras == local.extras;
            // TODO: get the summary
            var summary = "empty";

            if (parsed.networkInfo.type == "WIFI") {
                whoisNetworkName(parsed, function(networkName) {
                    console.log("Inserting record with ", parsed.networkInfo.type, ", name", networkName);
                    insertQuery.run(parsed.uuid, country, city, parsed.networkInfo.type, networkName, summary, isGlobal);    
                });
            } else {
                insertQuery.run(parsed.uuid, country, city, parsed.networkInfo.type, parsed.networkInfo.extra, summary, isGlobal);    
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
    var result = _.find(data.results, { 'name': "checkLocalAddr-GLOBAL" });
    var networkName = "UNKNOWN";
    if (result) {
	// console.log("whois lookup for", result.extras);
        whois.lookup(result.extras, function(err, whoisData) {
            if (!err) {
                var regexp = /netname:\s*([A-Za-z0-9_-]*)/i;
                var match = whoisData.match(regexp);
                if (match && match.length >= 1){
                    networkName = match[1];
                    // console.log("networkname for", result.extras, "found to be", networkName);
                }
            } else {
                console.log("Error performing a whois lookup:", err);
            }
            callback(networkName);
        });
    } else {
        callback(networkName);
    }
}

var getAnonymisedData = function(req, res) {
    db.all("SELECT country, city, networkType, networkName, summary FROM anonymised", function(err, data) {
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
            return _.defaults(val, {'summary': 'empty'});     // Add the summary description
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

    
