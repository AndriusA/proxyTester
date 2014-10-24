module.exports = function (_) {
    _.mixin({groupByMulti: function (obj, values, context) {
        if (!values.length)
            return obj;
        var byFirst = _.groupBy(obj, values[0], context),
            rest = values.slice(1);
        for (var prop in byFirst) {
            byFirst[prop] = _.groupByMulti(byFirst[prop], rest, context);
        }
        return byFirst;
    }});

    _.mixin({log: function(value, extra) {
        if (extra)
            console.log("LOG", extra, value);
        else 
            console.log("LOG", value);
        return value;
    }});
};