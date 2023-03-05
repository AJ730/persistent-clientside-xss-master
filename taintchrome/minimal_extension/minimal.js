console.log('Injecting Helper functionality into ', window.location.href);
var sc = document.createElement('script');
sc.textContent = '(' + (function(){
window.getSourcename = function (sourceId) {
    switch (sourceId) {
        case 0:
            return "benign";
        case 1:
            return "document.location.href";
        case 2:
            return "document.location.pathname";
        case 3:
            return "document.location.search";
        case 4:
            return "document.location.hash";
        case 5:
            return "document.URL";
        case 6:
            return "document.documentURI";
        case 7:
            return "document.baseURI";
        case 8:
            return "document.cookie";
        case 9:
            return "document.referrer";
        case 10:
            return "document.domain";
        case 11:
            return "window.name";
        case 12:
            return "postMessage";
        case 13:
            return "localStorage";
        case 14:
            return "sessionStorage";
        case 255:
            return "unknown";
        default:
            return "unknown code" + sourceId;
    }
};
var counter = 0
window.getSourceInfo = function (source, value, start, end) {
    var sourcePart = value.substring(start, end);
    if (source === 255) {
        var hasEscaping = 0;
        var hasEncodeURI = 0;
        var hasEncodeURIComponent = 0;
        var realSource = source;
        var isSameFrame = 1;
        var sourcename = getSourcename(realSource);
    } else {
        var hasEscaping = (source >> 4) & 1;
        var hasEncodeURI = (source >> 5) & 1;
        var hasEncodeURIComponent = (source >> 6) & 1;
        var realSource = source & 15;
        var sourcename = getSourcename(realSource);
        var isSameFrame = 1;
        if (source >> 7 == 1) // MSB is set to 1
            isSameFrame = 0;
    }

    return {
        "sourceId": realSource,
        "sourceName": sourcename,
        "start": start,
        "end": end,
        "hasEscaping": hasEscaping,
        "hasEncodeURI": hasEncodeURI,
        "hasEncodeURIComponent": hasEncodeURIComponent,
        "sourcePart": sourcePart,
        "isSameFrame": isSameFrame
    };
};

window.repackSources = function (value, sources) {
    var sourceInfo;
    var repackedSources = {};
    var oldsource = sources[0];
    var start = 0;
    var end = 0;
    var x;
    if (typeof(sources) == 'string')
        sources = JSON.parse(sources);
    for (var i = 0; i < sources.length; i++) {
        var source = sources[i];

        if (source !== oldsource) {
            end = i;

            sourceInfo = getSourceInfo(oldsource, value, start, i);
            if (parseInt(start) > -1 && parseInt(end) > -1)
                repackedSources[start] = sourceInfo;

            start = i;
        }

        oldsource = source;
        x = i;
    }
    sourceInfo = getSourceInfo(oldsource, value, start, parseInt(x) + 1);

    if (parseInt(start) > -1 && parseInt(x) > -1)
        repackedSources[start] = sourceInfo;


    return repackedSources;
};

window.___DOMXSSFinderReport = function (sinkId, value, sources, details, loc) {
    // typically, details contains additional information about a sink. For example, sink ID 1
    // is eval-like sinks, so it would have additional information if instead Function, setTimeout, or setInterval was invoked
    // for details on sink IDs see https://github.com/cispa/persistent-clientside-xss/blob/master/src/constants/sources.py
    var detail1 = details[0];
    var detail2 = details[1];
    var detail3 = loc;

    sinkTypeToName = {
        '1': 'eval',
        '2': 'document.write',
        '3': 'innerHTML',
        '5': 'script.text',
        '8': 'script.src',
        '21': 'Window.LocalStorage'
    };


    var args = Array();
    var s = repackSources(value, sources);
    for (var e in s) {

        var source_text = s[e].sourcePart
        if (source_text.indexOf("http") > -1) {
            source_text = source_text.replace("://", ":__");
            source_text = source_text.replace(".", "_")
        }
        if (s[e].source !== 0 && s[e].source !== 255) {
            args.push({
                'finding_id':counter,
                'source': s[e].sourceId,
                'start':s[e].start,
                'end':s[e].end,
                'value_part':source_text,
                'source_name':s[e].sourceName,
                'has_escaping':s[e].hasEscaping,
                'hasEncodingURI':s[e].hasEncodeURI,
                'hasEncodingURIComponent':s[e].hasEncodeURIComponent
            });
        }
    }
    var finding = {
        finding_id: counter,
        sink_id: sinkId,
        sources: args,
        url : window.location.href,
        domain: document.domain,
    };

    if (sinkTypeToName[sinkId] !== null && sinkTypeToName[sinkId] !== undefined && args.length > 0) {
        var cookie_archive = Array(), all_cookies = document.cookie.split('; '), cookie_i = all_cookies.length;
        while ( cookie_i-- ) {
            var component = all_cookies[cookie_i].split('=');
            component.push(-1);
            cookie_archive.push(component);
        }
        var local_archive = Array(), local_i = localStorage.length;
        while ( local_i-- ) {
            var local_component = Array(localStorage.key(local_i), localStorage.getItem( localStorage.key(local_i) ), 1);
            local_archive.push(local_component);
        }
        var session_archive = Array(), session_i = sessionStorage.length;
        while ( session_i-- ) {
            var session_component = Array(sessionStorage.key(session_i), sessionStorage.getItem( sessionStorage.key(session_i) ), 0);
            session_archive.push(session_component);
        }

        finding['storage'] = {"cookies": cookie_archive, "storage": local_archive.concat(session_archive)};
        finding['value'] = value
        finding['d1'] =  detail1 || ''
        finding['d2'] =  detail2 || ''
        finding['d3'] =  detail3 || ''


        console.log("TAINTFINDING" + JSON.stringify(finding, null, "\t"));
        counter++;
    }
};

}).toString() + ')()';
document.body.appendChild(sc);
