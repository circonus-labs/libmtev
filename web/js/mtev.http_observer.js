(function() {
  var interval = null;
  var filter_field = null;
  var filter_expr = null;
  function filter_client(d) {
    if(filter_expr) {
      for(var name in d) {
        if(filter_field == null || filter_field.exec(name)) {
          if(filter_expr.exec(d[name])) return false;
        }
      }
      return true;
    }
    return false;
  }
  mtev.http_observer_nice_bytes = function(b) {
    if(isNaN(parseFloat(b)) || b == "0") return "-";
    return mtev.pretty_bytes(b);
  }
  mtev.http_observer_nice_duration_ns = function(ns) {
    var s = parseFloat(ns)/1000000000.0;
    return mtev.nice_duration(s);
  }
  mtev.http_observer_loaded = function() {
    return (mtev && mtev.capa && mtev.capa.modules && mtev.capa.modules.http_observer &&
            mtev.capa.modules.http_observer.type == "generic");
  }
  var update = function(clients) {
    var $tbody = $("table#http-client-table tbody");
    var $ttr = $("#http-client-row-template");
    var seen = {}
    for (var i=0; i<clients.length; i++) {
      var needs_append = false;
      var client = clients[i];
      seen["" + client.request_id] = true;
      var $tr = $("#http-client-" + client.request_id);
      if($tr && $tr.length == 1) {
        //update
      } else {
        $tr.remove() // a noop unless there was > 1?
        $tr = $ttr.clone();
        $tr.attr("id", "http-client-" + client.request_id);
        $tr.find("button.http-client-info").on("click", function() {
          $(this).parent().find(".http-client-modal-popup").toggleClass("d-none");
        })
        needs_append = true;
      }
      $tr.data('client-info', client);
      if(filter_client(client)) $tr.addClass("d-none");
      var $fields = $tr.find("[data-format]");
      for(var fi=0; fi<$fields.length; fi++) {
        var fmt = $($fields[fi]).data("format");
        if(fmt) {
          fmt = fmt.replace(/\{([^\}]+)\}/g, function(m, ok) {
            if(ok == "full_json") return JSON.stringify(client, null, 2);
            var s = ok.split(':')
            var k = s.shift()
            var r = s.length > 0 ? s.join(":") : "";
            return client.hasOwnProperty(k) ? client[k] : r;
          });
          var fmtf = $($fields[fi]).data("format-formatter");
          if(fmtf) {
            var cb;
            try { cb = eval(fmtf); }
            catch(e) {}
            if(cb && typeof(cb) === "function") {
              fmt = cb(fmt);
            }
          }
          $($fields[fi]).html(fmt);
        }
      }
      if(client.response_complete_offset_ns) {
        $tr.removeClass("in-progress");
      }
      if(client.status) {
        var className = "status-" + client.status.substring(0,1);
        if(!$tr.hasClass(className)) $tr.addClass(className);
      }
      if(needs_append) {
        if(i == 0) $tbody.prepend($tr);
        else {
          $tr.insertAfter($("#http-client-" + clients[i-1].request_id));
        }
      }
    }
    $tbody.find("tr").each(function(i,o) {
      if(!seen[$(o).attr("id").substring(12)]) $(o).remove();
    });
  }
  var updateHTTPClients = function() {
    var st = jQuery.ajax("/module/http_observer/requests.json");
    st.done(function( events ) {
      events.sort(function(a,b) {
        return parseFloat(b.request_start_ms) - parseFloat(a.request_start_ms)
      });
      update(events);
    });
  }
  mtev.driveHTTPObserver = function() {
    var observer = new MutationObserver(function(mutations) {
      var d = $("#http").css("display") == "none";
      if(d) {
        if(interval) clearInterval(interval);
        interval = null;
      }
      else {
        if(interval == null) {
          interval = setInterval(updateHTTPClients, 30000);
        }
      }
    });
    $("#http-client-filter").on('input', function() {
      var str = $(this).val();
      var parts = str.split(":");
      var re1 = parts.shift();
      var re2 = parts.join(":");
      if(re2 == "") re2 = null;
      if(re2 == null) {
        re2 = re1;
        re1 = null
      }
      if(re1) filter_field = RegExp(re1);
      else filter_field = null;
      filter_expr = RegExp(re2);
      $("#http-client-table tbody tr").each(function(i,o) {
        var data = $(o).data('client-info');
        if(filter_client(data)) {
          $(o).addClass("d-none");
        } else {
          $(o).removeClass("d-none");
        }
      });
    });
    var target = document.getElementById('http');
    observer.observe(target, { attributes: true });
    if($("#http").hasClass("active")) {
      updateHTTPClients();
      interval = setInterval(updateHTTPClients, 30000);
    }
    updateHTTPClients();
  };
})();
