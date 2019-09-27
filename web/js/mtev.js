var mtev = { loaded: false, capa: {}, stats: { eventer: { jobq: {}, callbacks: {} } } };

(function() {
  var track_once = {}
  var filter_expr = null;
  var defaultUI = {
    tabs: [
      {
        "name": "Clients",
        "id": "http",
        "url": "/http.html",
        "condition": "mtev.http_observer_loaded",
        "callback": "mtev.driveHTTPObserver"
      },
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

  function findKey(obj, str) {
    var v = obj;
    try {
      var p = str.split(".");
      while(p.length) {
        v = v[p.shift()];
      }
    } catch(e) { v = null; }
    return v;
  }

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
    else if(typeof(m) == 'string') m = new Date(parseFloat(m));
    return  m.getUTCFullYear() +"/"+
     ("0" + (m.getUTCMonth()+1)).slice(-2) +"/"+
     ("0" + m.getUTCDate()).slice(-2) + "&nbsp;" +
     ("0" + m.getUTCHours()).slice(-2) + ":" +
     ("0" + m.getUTCMinutes()).slice(-2) + ":" +
     ("0" + m.getUTCSeconds()).slice(-2);
  }
  mtev.nice_timeofday = function(m) {
    if(typeof(m) == 'number') m = new Date(m);
    else if(typeof(m) == 'string') m = new Date(parseFloat(m));
    return ("0" + m.getUTCHours()).slice(-2) + ":" +
     ("0" + m.getUTCMinutes()).slice(-2) + ":" +
     ("0" + m.getUTCSeconds()).slice(-2);
  }
  mtev.nice_duration = function(s, inu) {
    var d = function(a) { return '<span class="text-muted">'+a+'</span>'; };
    s = 0 + parseFloat(s);
    var units = [ "s", "ms", "μs", "ns", "ps", "fs", "as", "zs", "ys" ];
    if(s == 0) return s.toFixed(0) + d(units[0]);
    var i = 0;
    while(i < units.length) {
      if(s >= 1) {
        return s.toFixed(0) + d(units[i]);
      }
      s *= 1000;
      i++;
    }
    return s;
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
  
  mtev.format = {
    "nice-time-s": mtev.nice_time,
    "nice-time-ms": (a) => mtev.nice_time(a/1000),
    "nice-date": mtev.nice_date,
    "tofixed": (a) => a.toFixed(0),
    "tofixed-1": (a) => a.toFixed(1),
    "tofixed-2": (a) => a.toFixed(2),
    "tofixed-3": (a) => a.toFixed(3),
    pretty_bytes: mtev.pretty_bytes
  };

  mtev.auto_age_element = function($elem) {
    var time = $elem.data("timestamp");
    var skew = $elem.data("skew");
    if(skew == null) skew = mtev.cluster_skew;
    if(skew == null) skew = 0;
    if(time != null && time != 0) {
      var age = Math.floor(((+new Date()) - time - skew)/1000);
      $elem.html((age >= 0) ? mtev.nice_time(Math.floor(((+new Date()) - time - skew)/1000)) : "future");
    } else {
      $elem.text("-");
    }
  }

  mtev.jsonDomInjector = function(r) {
    return function() {
      var text = "-";
      var key = $(this).attr('data');
      var transform = $(this).attr('data-transform');
      var format = $(this).attr('data-format');
      var value = findKey(r.current.data, key);
      if(transform == "rate" && r.prev.whence) {
        var oldValue = findKey(r.prev.data, key);
        value = parseFloat(value);
        oldValue = parseFloat(oldValue);
        if(!isNaN(value) && !isNaN(oldValue)) {
          text = (value - oldValue) / ((r.current.whence - r.prev.whence) / 1000);
        }
      } else if(value != null) {
        text = value;
      }
      if(format && mtev.format[format])
        try { text = mtev.format[format](text); } catch(e) {}
      $(this).html(text);
    };
  }

  mtev.makeDataHandler = function(hname) {
    var info = { current: {}, prev: {} };
    return function(r) {
      info.current.whence = +(new Date());
      info.current.data = r;
      $("*[data-handler='" + hname + "']").each(mtev.jsonDomInjector(info));
      info.prev.data = info.current.data;
      info.prev.whence = info.current.whence;
    };
  }

  mtev.SetVersionFromStats = function(r) {
    var vers = r.version._value;
    var bits = /^([a-f0-9]{8})[a-f0-9]{32}\.(\d+)$/.exec(vers);
    if(bits) vers = bits[1] + "." + bits[2];
    if(r.branch._value != "branches/master" && r.branch._value != "master") {
      var p = r.branch._value.split("/");
      var tag = (p && p.length == 2) ? p[1] : r.branch_value;
      if(p && p[0] == 'tag')
        mtev.setVersion("version: " + tag)
      else
        mtev.setVersion("version: " + tag + '/' + vers)
    }
    else {
      mtev.setVersion("version: " + vers);
    }
  }

  var clusterHandler = mtev.makeDataHandler("cluster-inject");

  mtev.cluster_skew = 0;
  mtev.updateCluster = function(r, name) {
    if(r.my_id) {
      var cn = null;
      for(i=0;i<r.clusters[name].nodes.length;i++) {
        var node = r.clusters[name].nodes[i];
        if(node.id == r.my_id) {
          cn = node.cn;
          break;
        }
      }
      if(cn) mtev.setNodeName(cn + "/" + r.my_id);
      else mtev.setNodeName(r.my_id);
      clusterHandler(r);

      var $oldBody = $("#cluster-" + name + " tbody");
      if($oldBody.length > 0) {
        var now = +(new Date())/1000;
        var $newBody = $oldBody.clone().empty();
        var nodes = r.clusters[name].nodes;
        nodes.sort((a,b) => a.cn.localeCompare(b.cn));
        for(i=0; i<nodes.length; i++) {
          var node = nodes[i];
          var $tr = $("<tr/>");
          var $icon = $('<span class="glyphicon" aria-hidden="true"></span>');
          var $me = $('<span class="glyphicon" aria-hidden="true"></span>');
          $tr.append($("<td/>").addClass("px-0").append($me));
          $tr.append($("<td/>").addClass("px-0").append($icon));
          $tr.append($("<td/>").append($("<span/>").html(node.cn)));
          $tr.append($("<td/>").addClass("hidden-lg-down").append($("<span/>").html(node.id)));
          $tr.append($("<td/>").append($("<span/>").html(node.address + ":" + node.port)));
          if(!node.reference_time) node.reference_time = +new Date();
          var skew = +new Date() - (node.reference_time * 1000);
          var $bspan = $('<span class="auto-age"/>').data("timestamp", node.boot_time * 1000)
                                                    .data("skew", skew);
          var $sspan = $('<span class="auto-age"/>').data("timestamp", node.last_contact * 1000)
                                                    .data("skew", skew);
          mtev.cluster_skew = skew;
          $tr.append($("<td/>").append($bspan));
          $tr.append($("<td/>").append($sspan));


          if(r.clusters[name].oldest_node == node.id) {
            $icon.addClass("glyphicon-hand-right");
          }
          if(node.dead) {
            $icon.addClass("glyphicon-remove");
          }
          if(node.id == r.my_id) {
            $me.addClass("glyphicon-star");
          }
          $newBody.append($tr);
        }
        $newBody.find(".auto-age").each(function() {
          mtev.auto_age_element($(this))
        });
        $newBody.find(".auto-age").each(function() {
          mtev.auto_age_element($(this))
        });
        $oldBody.replaceWith($newBody);
      }
    }
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
  function $badge(n, t) {
    if(!t) t = "default";
    return $("<span class=\"badge badge-pill badge-" + t + "\"/>").text(n);
  }

  mtev.$badge = $badge;

  var jobq_hidden = true;
  function jobq_hider() {
    jobq_hidden = $(this).prop('checked');
    $(this).text(jobq_hidden ? "showing used" : "showing all");
    if(jobq_hidden) $("#eventer-jobq tr.jobq-unused").addClass("hidden");
    else $("#eventer-jobq tr.jobq-unused").removeClass("hidden");
  }
  function mk_jobq_row(jobq,detail) {
    var used = 0;
    var $tr = $("<tr/>"), $td, $cb;
    if(false && detail.max_backlog) {
      var t = "default";
      if(detail.backlog+detail.inflight > detail.max_backlog) t = "danger";
      $tr.append($("<td/>").html($badge((detail.backlog+detail.inflight) + "/" + detail.max_backlog, t)));
    } else {
      $tr.append($("<td/>").html($badge(detail.backlog+detail.inflight)));
    }
    used += detail.backlog+detail.inflight+detail.total_jobs+detail.concurrency;
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
    if(used == 0) $tr.addClass("jobq-unused");
    if(used == 0 && jobq_hidden) $tr.addClass("hidden");
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
      if(track_once[uri] == true) return;
      track_once[uri] = true;
      var st = jQuery.ajax(uri);
      st.always(function() { track_once[uri] = false; });
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
    if(track_once.logs == true) return;
    track_once.logs = true;
    var st = $.ajax("/eventer/logs/internal.json" + qs);
    st.always(function() { track_once.logs = false; })
    st.done(function (logs) {
      var atend = force || Math.abs(($c[0].scrollTop + $c[0].clientHeight - $c[0].scrollHeight));
      var begin = 0;
      if (logs.length > 1000) {
        begin = logs.length - 1000;
      }
      for (var i = begin; i < logs.length; i++) {
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
    if(filter_expr) {
      if(!filter_expr.exec(dname)) {
        $item.addClass("hidden");
      }
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
    $('#eventer-jobq-hider').bootstrapToggle({ on: "Used", off: "All" });
    $('#eventer-jobq-hider').change(jobq_hider);

    refresh_logs(1);
    setInterval(refresh_logs, 1000);
  }
  
  function refreshMtevStats(cb) {
    if(track_once.mtevstats == true) return;
    track_once.mtevstats = true;
    var st = jQuery.ajax("/mtev/stats.json");
    st.always(function() { track_once.mtevstats = false; });
    st.done(function(r) {
      mtev.stats = r.mtev;
      mtev.updatePerfUI(r, ["mtev"]);
      $("#internal-stats tbody").removeClass("d-none");
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
    $("#stats-filter").on('input', function() {
      filter_expr = RegExp($(this).val());
      $("#internal-stats tr").each(function() {
        if(filter_expr.exec($(this).find("span.stat-name").text())) {
          $(this).removeClass("hidden");
        } else {
          $(this).addClass("hidden");
        }
      });
    });
  });
  mtev.start = function(uijson) {
    var processUI = function(r) {
      var pending = 1;
      jQuery.ajax("/capa.json").done(function(data) { mtev.capa = data; pending--; }).fail(function() { pending--; });
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
            var cond = null;
            if(tab.callback) {
              try { cb = eval(tab.callback); }
              catch(e) { console.log(tab.callback, e); }
              if(cb == null) continue;
            }
            if(tab.condition) {
              try { cond = eval(tab.condition); }
              catch(e) { console.log(tab.callback, e); }
              if(cond == null) cond = function() { return false; }
            }
            if(cond == null || cond() == true) {
              load_pending++;
              mtev.ui_load(tab.name, tab.id, tab.url, tab.active, finish_load(cb))
            }
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
    $($link).attr('aria-controls', id);
    $($link).attr('data-toggle', 'tab');
    $($link).attr('role', 'tab');
    var $div = $('<div class="tab-pane" role="tabpanel"></div>').attr('id',id);
    $("#viewTabContent").prepend($div);

    if(active) {
      $("#viewTabContent > div").removeClass("active");
      $("#viewTab a.nav-link").removeClass("active");
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

