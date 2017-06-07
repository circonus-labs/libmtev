var mtev = {};

(function() {
  var defaultUI = {
    tabs: [
      {
        "name": "Internals",
        "id": "internals",
        "url": "/internals.html",
        "active": true,
        "callback": "mtev.driveInternalsTab"
      },
      {
        "name": "Docs",
        "url": "http://circonus-labs.github.io/libmtev/"
      }
    ]
  };

  mtev.hist = CirconusHistogram({ minbarwidth: 5, width: 600, height: 200, yaxis: true, xaxis: true, hudlegend: true });
  
  // Follow NIST/IEC prefixes for binary magnitude (http://physics.nist.gov/cuu/Units/binary.html)
  mtev.pretty_bytes = function(b) {
    var d = function(a) { return '<span class="text-muted">'+a+'</span>'; };
    if(b < 1024) return parseFloat(b).toFixed(0) + d("B");
    if(b < 1024*1024) return (b / 1024).toFixed(0) + d("KiB");
    if(b < 1024*1024*1024) return (b / (1024*1024)).toFixed(0) + d("MiB");
    if(b < 1024*1024*1024*1024) return (b / (1024*1024*1024)).toFixed(0) + d("GiB");
    return (b / (1024*1024*1024*1024)).toFixed(0) + d("TiB");
  }
  mtev.nice_date = function(m) {
    if(typeof(m) == 'number') m = new Date(m);
    return  m.getUTCFullYear() +"/"+
     ("0" + (m.getUTCMonth()+1)).slice(-2) +"/"+
     ("0" + m.getUTCDate()).slice(-2) + " " +
     ("0" + m.getUTCHours()).slice(-2) + ":" +
     ("0" + m.getUTCMinutes()).slice(-2) + ":" +
     ("0" + m.getUTCSeconds()).slice(-2);
  }
  mtev.nice_time = function(s) {
    var days, hours, minutes, seconds;
    days = Math.floor(s/86400); s -= (86400*days);
    hours = Math.floor(s/3600); s -= (3600*hours);
    minutes = Math.floor(s/60); s -= (60*minutes);
    seconds = s;
    var time = "";
    var d = function(a) { return '<span class="text-muted">'+a+'</span>'; };
    if(days) time = time + days + d("d ")
    if(hours) time = time + hours + d("h ")
    if(minutes) time = time + minutes + d("m ")
    if(seconds) time = time + seconds + d("s ")
    return time;
  }
  
  function $modalButton(n, id) {
    return $('<button type="button" class="tag tag-primary" data-toggle="modal" data-target="#' + id + '"/>').html(n);
  }
  mtev.displayHistogram = function(name, data, subname) {
    var d = {}
    if (data && data._value && Array.isArray(data._value)) {
      for(var i=0;i<data._value.length;i++) {
        var bin = data._value[i]
        var eidx = bin.indexOf('=');
        if(eidx > 0) {
          d[bin.substring(2,eidx-1)] = parseInt(bin.substring(eidx+1));
        }
      }
    }
    $("span#histogram-name").text(name + " " + subname);
    $("#modal-histogram").empty();
    mtev.hist.render("#modal-histogram", d);
  }
  function $hist_button(name, stats, subname) {
    if(stats && stats.hasOwnProperty(name)) {
      var $perf = $modalButton(" ", "histModal").on('click', function() {
        var v = stats[name];
        if(subname) v = v[subname];
        mtev.displayHistogram(name, v, subname || "");
      });
      $perf.addClass("glyphicon");
      $perf.addClass("glyphicon-stats");
      return $perf;
    }
    return null;
  }
  function $badge(n) {
    return $("<span class=\"tag tag-pill tag-default\"/>").text(n);
  }
  function mk_jobq_row(jobq,detail) {
    var $tr = $("<tr/>"), $td, $cb;
    $tr.append($("<td/>").html($badge(detail.backlog+detail.inflight)));
    $tr.append($("<td/>").html(jobq));
    var $conc = $("<td class=\"text-center\"/>");
    if(detail.desired_concurrency == 0) {
      $tr.attr("class", "backq");
      $conc.html("N/A");
    }
    else if(detail.concurrency == detail.desired_concurrency)
      $conc.html(detail.concurrency);
    else
      $conc.html(detail.concurrency + " &rarr; " + detail.desired_concurrency);
    $tr.append($conc);
    $tr.append($("<td class=\"text-right\"/>").append($badge(detail.total_jobs)));
    $cb = $("<small/>").text(parseFloat(detail.avg_wait_ms).toFixed(3) + "ms");
    var $perf, $td;
    $td = $("<td class=\"text-right\"/>");
    $perf = $hist_button(jobq, eventer_stats.jobq, "wait");
    if($perf) $td.append($perf);
    $td.append($cb);
    $tr.append($td);
    $tr.append($("<td class=\"text-left\"/>").append($badge(detail.backlog)));
    $cb = $("<small/>").text(parseFloat(detail.avg_run_ms).toFixed(3) + "ms");
    $perf = $hist_button(jobq, eventer_stats.jobq, "latency");
    $td = $("<td class=\"text-right\"/>");
    if($perf) $td.append($perf);
    $td.append($cb);
    $tr.append($td);
    $tr.append($("<td class=\"text-left\"/>").append($badge(detail.inflight)));
    return $tr;
  }
  function mk_timer_row(event) {
    var $tr = $("<tr/>");
    var $cb = $("<span/>").text(event.callback);
    var $perf = $hist_button(event.callback, eventer_stats.callbacks);
    var $td = $("<td/>");
    if ($perf !== null) { $td.append($perf); }
    $td.append($cb)
    $tr.append($td);
    $tr.append($("<td/>").html(new Date(event.whence)));
    return $tr;
  }
  function mk_socket_row(event) {
    var $tr = $("<tr/>");
    var mask = [];
    if(event.mask & 1) mask.push("R");
    if(event.mask & 2) mask.push("W");
    if(event.mask & 4) mask.push("E");
    $tr.append($("<td/>").html(event.fd + "&nbsp").append($badge(mask.join("|")).addClass('pull-right')));
    $tr.append($("<td/>").html('<small>'+event.impl+'</small>'));
    var $cb = $("<span/>").text(event.callback);
    var $perf = $hist_button(event.callback, eventer_stats.callbacks);
    var $td = $("<td/>");
    if ($perf !== null) { $td.append($perf); }
    $td.append($cb)
    $tr.append($td);
    $tr.append($("<td/>").html(event.local ? event.local.address+":"+event.local.port : "-"));
    $tr.append($("<td/>").html(event.remote ? event.remote.address+":"+event.remote.port : "-"));
    return $tr;
  }
  
  function update_eventer(uri, id, mkrow) {
    return function() {
      var $table = $("div#"+id+" table:visible");
      if($table.length == 0) return;
      var st = jQuery.ajax(uri);
      st.done(function( events ) {
        var $tbody = $("<tbody/>");
        if(events.hasOwnProperty('length')) {
          events.forEach(function(event) {
            $tbody.append(mkrow(event));
          });
        } else {
          var keys = [];
          for(var name in events) keys.push(name);
          keys.sort().forEach(function(name) {
            $tbody.append(mkrow(name, events[name]));
          });
        }
        $table.find("tbody").replaceWith($tbody);
      });
    };
  }

  var last_log_idx;
  function refresh_logs(force) {
    var qs = "";
    var $c = $("#main-log-window");
    if($c.length < 1) return;
    if(typeof(last_log_idx) !== 'undefined')
      qs = "?since=" + last_log_idx;
    else
      qs = "?last=100";
    $.ajax("/eventer/logs/internal.json" + qs).done(function (logs) {
      var atend = force || Math.abs(($c[0].scrollTop + $c[0].clientHeight - $c[0].scrollHeight));
      for(var i in logs) {
        var log = logs[i];
        $row = $("<div class=\"row\"/>");
        $row.append($("<div class=\"col-md-2 text-muted\"/>").text(mtev.nice_date(log.whence)));
        $row.append($("<div class=\"col-md-10\"/>").text(log.line));
        $c.append($row);
        last_log_idx = log.idx;
        if(atend < 20) {
          $c[0].scrollTop = $c[0].scrollHeight;
          $c[0].scrollLeft = 0;
        }
      }
      var rows = $c.find("> div");
      var cnt = 0;
      for(var i = rows.length ; i > 1000; i--)
        rows[cnt++].remove();
    });
}
  function setupInternals() {
    // Pull sockets every 5 seconds
    setInterval(update_eventer("/eventer/sockets.json",
                               "eventer-sockets", mk_socket_row),
                5000);
    // And also on-demand
    $('#eventer-sockets').on('shown.bs.collapse', function () {
      update_eventer("/eventer/sockets.json",
                     "eventer-sockets", mk_socket_row)();
    });
    
    // Pull timers every 5 seconds
    setInterval(update_eventer("/eventer/timers.json",
                               "eventer-timers", mk_timer_row),
                5000);
    // And also on-demand
    $('#eventer-timers').on('shown.bs.collapse', function () {
      update_eventer("/eventer/timers.json",
                     "eventer-timers", mk_timer_row)();
    });
    
    // jobq is initially visible, pull it once up front
    update_eventer("/eventer/jobq.json",
                   "eventer-jobq", mk_jobq_row)();
    // Then evey 5 second
    setInterval(update_eventer("/eventer/jobq.json",
                               "eventer-jobq", mk_jobq_row),
                5000);
    // And also on-demand
    $('#eventer-jobq').on('shown.bs.collapse', function () {
      update_eventer("/eventer/jobq.json",
                     "eventer-jobq", mk_jobq_row)();
    });

    refresh_logs(1);
    setInterval(refresh_logs, 1000);
  }
   
  var eventer_stats = { jobq: {}, callbacks: {} };
  function refreshMtevStats(cb) {
    jQuery.ajax("/mtev/stats.json").done(function(r) {
      eventer_stats = r.mtev.eventer;
      if(cb) cb();
    });
  }
  
  mtev.driveInternalsTab = function() {
    refreshMtevStats(setupInternals);
    setInterval(refreshMtevStats, 20000);
  };

  mtev.start = function(uijson) {
    var processUI = function(r) {
      if(r.tabs) {
        for(var i=r.tabs.length-1;i>=0;i--) {
          var tab = r.tabs[i];
          var cb = null;
          if(tab.callback) try { cb = eval(tab.callback); } catch(e) {}
          mtev.ui_load(tab.name, tab.id, tab.url, tab.active, cb)
        }
      }
    }
    if(uijson) {
      jQuery.ajax(uijson).done(processUI).fail(function() {
        processUI(defaultUI);
      });
    }
  };

  mtev.setNodeName = function(name) {
    $("#headerinfo span.nodename").text(name);
  }
  mtev.setVersion = function(name) {
    $("#headerinfo span.version").text(name);
  }
  
  mtev.ui_load = function(tabName, id, url, active, cb) {
    if(!tabName) return null;

    // Add out elements into the DOM
    var $link = $('<li class="nav-item"><a class="nav-link">' +
                  tabName + '</a></li>');
    $("#viewTab").prepend($link);

    if(!id && url) {
      $($link).find("a").attr('href', url);
      if(cb) cb();
      return;
    }

    if(!tabName || !id || $('#' + id).length > 0) return null;
    $($link).find("a").attr('href', '#' + id);
    $($link).find("a").attr('data-toggle', 'tab');
    var $div = $('<div class="tab-pane fade in"></div>').attr('id',id);
    $("#viewTabContent").prepend($div);

    if(active) {
      $("#viewTabContent > div").removeClass("active");
      $("#viewTab > li > a").removeClass("active");
      $link.addClass("active");
      $div.addClass("active");
    }

    if(url) {
      $div.load(url, function() {
        $(document).ready(function() {
          setTimeout(function() {
            if(cb) cb();
          }, 100);
        });
      });
    }
    else {
      if(cb) cb();
    }
  };
})();

$(document).ready(function() {
  $('.navbar-nav a.nav-link')
    .filter(function(i,a) { return $(a).attr('href').startsWith('#') })
    .click(function (e) {
      $(this).tab('show');
      var scrollmem = $('body').scrollTop();
      window.location.hash = this.hash;
      $('html,body').scrollTop(scrollmem);
    });

  var hash = window.location.hash.substring(1);
  if(!hash) return;
  var nav = hash.split(/:/);

  if(nav[0]) $('ul.nav a[href="#' + nav[0] + '"]').tab('show');
});

