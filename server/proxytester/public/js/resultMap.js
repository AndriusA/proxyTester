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

d3.xhr("http://proxytester.smart-e.org/data/", "application/json", function(err, val) {
  var proxyData = JSON.parse(val.response);
  console.log("proxyData", proxyData);
  
    mapData = proxyData;
    _.map(mapData, function(val){
      return _.defaults(val, {fillKey: "HasData"});
    })
    
    console.log(mapData);
    
    var element = document.querySelector('#map');
    var width = element.offsetWidth;
    var mapRatio = 0.37
    var height = width * mapRatio;
    var projection = d3.geo.equirectangular()
          .center([0, 8])
          .scale((width/600)*100)         // unscaled map size is 640x360, hence the /600
          .translate([width/2, height/2]);
    var path = d3.geo.path()
          .projection(projection);

    this.map = new Datamap({
      scope: 'world',
      element: document.getElementById('map'),
      setProjection: function(element) {
          return {path: path, projection: projection};
      },
      geographyConfig: {
        hideAntarctica: true,
        highlightBorderColor: '#bada55',
        highlightFillColor: '#1d1',
        highlightOnHover: true,
        popupOnHover: false,
        highlightBorderWidth: 1
      },

      fills: {
        HasData: '#8d8',
        'Selected': '#1d1',
        'Visitors': '#dcd',
        defaultFill: '#ddd',
      },
      data: mapData,
      done: addCountryInfo
    });

    // var inLabelCanvas = d3.select('#map').select("svg").append("g");
    // var outLabelCanvas = d3.select('#map').select("svg").append("g");
    // var inList = d3.select('#arrivals').append("ul")
    // var outList = d3.select('#departures').append("ul")
    d3.select('#map').select("svg").style("height", height);
    renderTemplate("countryDetail", {})

    function addCountryInfo(datamap) {
      datamap.svg.selectAll('.datamaps-subunit').on('click', countryInfoClick);
      datamap.svg.selectAll('.datamaps-subunit').on('mouseover', countryInfo);
      datamap.svg.selectAll('.datamaps-subunit').on('mouseout', hideCountryInfoOut);
    }

    var clicked = false;
    function countryInfoClick(geography, i) {
      clicked = true;
      return countryInfo.bind(this)(geography, i);
    }
    function countryInfo(geography, i) {
      var hasdata = this.getAttribute("data-info");
      if (hasdata) {
        var data = JSON.parse(hasdata);
        console.log("country info", i, hasdata, data);
        var element = document.querySelector("#countryDetail");
        var width = document.querySelector("#map svg").clientWidth;
        var mouse = d3.mouse(this);
        var offset = 100;
        if (element) {
          var rendered = renderTemplate('countryDetail', data);
          document.querySelector("#countryDetail").innerHTML = rendered;
          element.classList.remove('hidden');

          if (mouse[0] >= width/2 && mouse[0] >= 400) {
            element.style.left = "20px";  
            element.style.top = offset+"px";
          } else if (mouse[0] <= width-400 ){    
            element.style.right = "20px";
            element.style.top = offset+"px";
          } else {
            element.style.top = mouse[1]+offset+"px";
          }
        }
        document.querySelector("#countryDetail button.close").addEventListener("click", hideCountryInfo, false);
      }
    }

    function hideCountryInfoOut() {
      if (!clicked)
        hideCountryInfo();
    }
    
    function hideCountryInfo() {
      clicked = false;
      var element = document.querySelector("#countryDetail");
      if (element) {
        element.classList.add('hidden');
        this.removeEventListener("click", hideCountryInfo);
      }
    }
});

function numberWithCommas(x) {
  return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

var tmpl_cache = {};
function renderTemplate(tmpl_name, tmpl_data) {
  if (!tmpl_cache[tmpl_name]) {
    var tmpl_dir = '/template';
    var tmpl_url = tmpl_dir + '/' + tmpl_name + '.html';
    var tmpl_string;

    d3.xhr(tmpl_url, function(err, res){
      console.log(err, res);
      if (!err) {
        tmpl_string = res.response;
        tmpl_cache[tmpl_name] = Handlebars.compile(tmpl_string);
      }
    });
  }

  return tmpl_cache[tmpl_name](tmpl_data);
}

Handlebars.registerHelper('ifCond', function(v1, v2, options) {
  if(v1 === v2) {
    return options.fn(this);
  }
  return options.inverse(this);
});
  
