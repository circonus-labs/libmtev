var mtev = { loaded: false, stats: { eventer: { jobq: {}, callbacks: {} } } };

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

  mtev.toHex = function(s) {
    var s = unescape(encodeURIComponent(s))
    var h = ''
    for (var i = 0; i < s.length; i++) {
      h += s.charCodeAt(i).toString(16)
    }
    return h
  };

  mtev.fromHex = function(h) {
    var s = ''
    for (var i = 0; i < h.length; i+=2) {
      s += String.fromCharCode(parseInt(h.substr(i, 2), 16))
    }
    return decodeURIComponent(escape(s))
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
     ("0" + m.getUTCDate()).slice(-2) + "&nbsp;" +
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
    if(seconds || time == "") time = time + seconds + d("s ")
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
  mtev.$hist_button = function(name, stats, subname) {
    if(!Array.isArray(name)) {
      name = [name];
    }
    var display_name = name.join(".");
    while(name.length > 0) {
      if(!stats || !stats.hasOwnProperty(name[0])) return null;
      stats = stats[name.shift()];
    }
    if(stats) {
      var $perf = $modalButton(" ", "histModal").on('click', function() {
        var v = stats;
        if(subname) v = v[subname];
        mtev.displayHistogram(display_name, v, subname || "");
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
    $perf = mtev.$hist_button(jobq, mtev.stats.eventer.jobq, "wait");
    if($perf) $td.append($perf);
    $td.append($cb);
    $tr.append($td);
    $tr.append($("<td class=\"text-left\"/>").append($badge(detail.backlog)));
    $cb = $("<small/>").text(parseFloat(detail.avg_run_ms).toFixed(3) + "ms");
    $perf = mtev.$hist_button(jobq, mtev.stats.eventer.jobq, "latency");
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
    var $perf = mtev.$hist_button(event.callback, mtev.stats.eventer.callbacks);
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
    var $perf = mtev.$hist_button(event.callback, mtev.stats.eventer.callbacks);
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
        $row.append($("<div class=\"col-md-3 col-lg-2 text-muted\"/>").html(mtev.nice_date(log.whence)));
        $row.append($("<div class=\"col-md-9 col-lg-10\"/>").text(log.line));
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
  function handlePerfData(obj, path, ptr) {
    var dname = path.join(".");
    var added = false;
    var id = "stat-id-" + mtev.toHex(dname);
    var $tbl = $("#internal-stats tbody");
    var $item = $tbl.find("#" + id);
    if($item.length == 0) {
      $item = $("#internal-stat-template").clone();
      $item.attr('id', id);
      added = true;
    }
    $item.find("span.stat-name").text(dname);
    if(ptr._type == "s") $item.find("span.stat-value").text(ptr._value);
    else if(!Array.isArray(ptr._value)) {
      $item.find("span.stat-value").text(ptr._value);
    }
    else {
      $item.find("span.stat-value").empty().append(mtev.$hist_button(path.slice(), obj));
    }
    if(added) {
      var appended = false;
      // stick it in the right place.
      var $r = $tbl.find("tr").get().reverse();
      for(var i=0; i<$r.length; i++) {
        var name = mtev.fromHex($r[i].getAttribute('id').substring(8));
        if(name.localeCompare(dname) < 0) {
          $item.insertAfter($($r[i]));
          appended = true;
          break;
        }
      }
      if(!appended) $tbl.prepend($item);
    }
  }
  mtev.updatePerfUI = function(stats, path, ptr) {
    if(!$("#internal-stats").hasClass("show")) return;
    if(path == undefined) path = [];
    if(ptr == undefined) {
      ptr = stats;
      for(var i=0;i<path.length;i++) ptr = ptr[path[i]];
    }
    if(ptr.hasOwnProperty("_type") && ptr.hasOwnProperty("_value")) {
      handlePerfData(stats,path,ptr);
    }
    else {
      for(var name in ptr) {
        var child = path.slice()
        child.push(name)
        mtev.updatePerfUI(stats, child, ptr[name])
      }
    }
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
  
  function refreshMtevStats(cb) {
    jQuery.ajax("/mtev/stats.json").done(function(r) {
      mtev.stats = r.mtev;
      mtev.updatePerfUI(r, ["mtev"]);
      if(cb) cb();
    });
  }
  
  mtev.driveInternalsTab = function() {
    refreshMtevStats(setupInternals);
    setInterval(refreshMtevStats, 20000);
  };

  $(document).on('mtev-loaded', function() {
    $("#internal-stats").on("shown.bs.collapse", function() {
      refreshMtevStats();
    });
  });
  mtev.start = function(uijson) {
    var processUI = function(r) {
      var pending = 0;
      if(r.scripts) {
        for(var i=0;i<r.scripts.length;i++) {
          pending++;
          jQuery.getScript(r.scripts[i], function() { pending--; });
        }
      }
      var load_pending = 1;
      var finish_load = function(cb) {
        return function() {
          load_pending--;
          if(cb) cb();
          if(load_pending == 0) {
            mtev.loaded = true;
            $(document).trigger("mtev-loaded");
          }
        }
      }
      if(r.tabs) {
        var keepTrying;
        load_pending++;
        keepTrying = setInterval(function() {
          if(pending > 0) return;
          for(var i=r.tabs.length-1;i>=0;i--) {
            var tab = r.tabs[i];
            var cb = null;
            if(tab.callback) try { cb = eval(tab.callback); }
                             catch(e) { console.log(tab.callback, e); }
            load_pending++;
            mtev.ui_load(tab.name, tab.id, tab.url, tab.active, finish_load(cb))
          }
          mtev.initialTabSelect();
          clearInterval(keepTrying);
          finish_load(null)();
        }, 10);
      }
      finish_load(null)();
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
    var $li = $('<li class="nav-item"/>');
    var $link = $('<a class="nav-link">' +
                  tabName + '</a>');
    $li.prepend($link);
    $("#viewTab").prepend($li);

    if(!id && url) {
      $($link).attr('href', url);
      if(cb) cb();
      return;
    }

    if(!tabName || !id || $('#' + id).length > 0) return null;
    $($link).attr('href', '#' + id);
    $($link).attr('data-toggle', 'tab');
    $($link).attr('role', 'tab');
    var $div = $('<div class="tab-pane fade in" role="tabpanel"></div>').attr('id',id);
    $("#viewTabContent").prepend($div);

    if(active) {
      $("#viewTabContent > div").removeClass("active");
      $("#viewTab a.nav-link").removeClass("active");
      $link.addClass("active");
      $div.removeClass("fade");
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

  mtev.initialTabSelect = function() {
    $('.navbar-nav a.nav-link')
      .filter(function(i,a) { return $(a).attr('href').startsWith('#') })
      .click(function (e) {
        e.preventDefault();
        $(this).tab('show');
        var scrollmem = $('body').scrollTop();
        var loc_no_qs = window.location.href.replace(/\?.*$/, '');
        if(loc_no_qs != window.location.href)
          window.history.pushState({},"",loc_no_qs);
        window.location.hash = this.hash;
        $('html,body').scrollTop(scrollmem);
      });

    var hash = window.location.hash.substring(1);
    if(!hash) return;
    var nav = hash.split(/:/);
    if(nav[0]) $('nav a[href="#' + nav[0] + '"]').tab('show');
  };
})();

