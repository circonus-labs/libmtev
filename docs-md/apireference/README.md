# Programmer's Reference Manual

## C

##### A

[mtev_amqp_send](c.md#mtevamqpsend), [mtev_amqp_send_data](c.md#mtevamqpsenddata)

##### B

[mtev_b32_decode](c.md#mtevb32decode), [mtev_b32_encode](c.md#mtevb32encode), [mtev_b32_encode_len](c.md#mtevb32encodelen), [mtev_b32_max_decode_len](c.md#mtevb32maxdecodelen), [mtev_b64_decode](c.md#mtevb64decode), [mtev_b64_encode](c.md#mtevb64encode), [mtev_b64_encode_len](c.md#mtevb64encodelen), [mtev_b64_encodev](c.md#mtevb64encodev), [mtev_b64_max_decode_len](c.md#mtevb64maxdecodelen)

##### C

[mtev_cluster_alive_filter](c.md#mtevclusteralivefilter), [mtev_cluster_am_i_oldest_node](c.md#mtevclusteramioldestnode), [mtev_cluster_by_name](c.md#mtevclusterbyname), [mtev_cluster_do_i_own](c.md#mtevclusterdoiown), [mtev_cluster_enabled](c.md#mtevclusterenabled), [mtev_cluster_filter_owners](c.md#mtevclusterfilterowners), [mtev_cluster_find_node](c.md#mtevclusterfindnode), [mtev_cluster_get_config_seq](c.md#mtevclustergetconfigseq), [mtev_cluster_get_heartbeat_payload](c.md#mtevclustergetheartbeatpayload), [mtev_cluster_get_my_boot_time](c.md#mtevclustergetmyboottime), [mtev_cluster_get_name](c.md#mtevclustergetname), [mtev_cluster_get_node](c.md#mtevclustergetnode), [mtev_cluster_get_nodes](c.md#mtevclustergetnodes), [mtev_cluster_get_oldest_node](c.md#mtevclustergetoldestnode), [mtev_cluster_get_self](c.md#mtevclustergetself), [mtev_cluster_init](c.md#mtevclusterinit), [mtev_cluster_node_get_id](c.md#mtevclusternodegetid), [mtev_cluster_node_has_payload](c.md#mtevclusternodehaspayload), [mtev_cluster_node_is_dead](c.md#mtevclusternodeisdead), [mtev_cluster_set_heartbeat_payload](c.md#mtevclustersetheartbeatpayload), [mtev_cluster_set_node_update_callback](c.md#mtevclustersetnodeupdatecallback), [mtev_cluster_set_self](c.md#mtevclustersetself), [mtev_cluster_size](c.md#mtevclustersize), [mtev_cluster_unset_heartbeat_payload](c.md#mtevclusterunsetheartbeatpayload), [mtev_cluster_update](c.md#mtevclusterupdate), [mtev_confstr_parse_duration](c.md#mtevconfstrparseduration), [mtev_confstr_parse_duration_ms](c.md#mtevconfstrparsedurationms), [mtev_confstr_parse_duration_ns](c.md#mtevconfstrparsedurationns), [mtev_confstr_parse_duration_s](c.md#mtevconfstrparsedurations), [mtev_confstr_parse_duration_us](c.md#mtevconfstrparsedurationus), [mtev_curl_write_callback](c.md#mtevcurlwritecallback)

##### D

[mtev_dyn_buffer_add](c.md#mtevdynbufferadd), [mtev_dyn_buffer_add_printf](c.md#mtevdynbufferaddprintf), [mtev_dyn_buffer_advance](c.md#mtevdynbufferadvance), [mtev_dyn_buffer_data](c.md#mtevdynbufferdata), [mtev_dyn_buffer_destroy](c.md#mtevdynbufferdestroy), [mtev_dyn_buffer_ensure](c.md#mtevdynbufferensure), [mtev_dyn_buffer_init](c.md#mtevdynbufferinit), [mtev_dyn_buffer_reset](c.md#mtevdynbufferreset), [mtev_dyn_buffer_size](c.md#mtevdynbuffersize), [mtev_dyn_buffer_used](c.md#mtevdynbufferused), [mtev_dyn_buffer_write_pointer](c.md#mtevdynbufferwritepointer)

##### E

[eventer_accept](c.md#eventeraccept), [eventer_add](c.md#eventeradd), [eventer_add_asynch](c.md#eventeraddasynch), [eventer_add_asynch_dep](c.md#eventeraddasynchdep), [eventer_add_at](c.md#eventeraddat), [eventer_add_in](c.md#eventeraddin), [eventer_add_in_s_us](c.md#eventeraddinsus), [eventer_add_recurrent](c.md#eventeraddrecurrent), [eventer_add_timed](c.md#eventeraddtimed), [eventer_alloc](c.md#eventeralloc), [eventer_alloc_asynch](c.md#eventerallocasynch), [eventer_alloc_asynch_timeout](c.md#eventerallocasynchtimeout), [eventer_alloc_copy](c.md#eventeralloccopy), [eventer_alloc_fd](c.md#eventerallocfd), [eventer_alloc_recurrent](c.md#eventerallocrecurrent), [eventer_alloc_timer](c.md#eventeralloctimer), [eventer_allocations_current](c.md#eventerallocationscurrent), [eventer_allocations_total](c.md#eventerallocationstotal), [eventer_at](c.md#eventerat), [eventer_callback](c.md#eventercallback), [eventer_callback_for_name](c.md#eventercallbackforname), [eventer_callback_ms](c.md#eventercallbackms), [eventer_callback_us](c.md#eventercallbackus), [eventer_choose_owner](c.md#eventerchooseowner), [eventer_choose_owner_pool](c.md#eventerchooseownerpool), [eventer_close](c.md#eventerclose), [eventer_deref](c.md#eventerderef), [eventer_fd_opset_get_accept](c.md#eventerfdopsetgetaccept), [eventer_fd_opset_get_close](c.md#eventerfdopsetgetclose), [eventer_fd_opset_get_read](c.md#eventerfdopsetgetread), [eventer_fd_opset_get_write](c.md#eventerfdopsetgetwrite), [eventer_find_fd](c.md#eventerfindfd), [eventer_foreach_fdevent](c.md#eventerforeachfdevent), [eventer_foreach_timedevent](c.md#eventerforeachtimedevent), [eventer_free](c.md#eventerfree), [eventer_get_callback](c.md#eventergetcallback), [eventer_get_closure](c.md#eventergetclosure), [eventer_get_context](c.md#eventergetcontext), [eventer_get_epoch](c.md#eventergetepoch), [eventer_get_fd](c.md#eventergetfd), [eventer_get_fd_opset](c.md#eventergetfdopset), [eventer_get_mask](c.md#eventergetmask), [eventer_get_owner](c.md#eventergetowner), [eventer_get_pool_for_event](c.md#eventergetpoolforevent), [eventer_get_this_event](c.md#eventergetthisevent), [eventer_get_thread_name](c.md#eventergetthreadname), [eventer_get_whence](c.md#eventergetwhence), [eventer_gettimeofcallback](c.md#eventergettimeofcallback), [eventer_impl_propset](c.md#eventerimplpropset), [eventer_impl_setrlimit](c.md#eventerimplsetrlimit), [eventer_in](c.md#eventerin), [eventer_in_s_us](c.md#eventerinsus), [eventer_init_globals](c.md#eventerinitglobals), [eventer_is_loop](c.md#eventerisloop), [eventer_loop](c.md#eventerloop), [eventer_loop_concurrency](c.md#eventerloopconcurrency), [eventer_name_callback](c.md#eventernamecallback), [eventer_name_callback_ext](c.md#eventernamecallbackext), [eventer_name_for_callback](c.md#eventernameforcallback), [eventer_pool](c.md#eventerpool), [eventer_pool_concurrency](c.md#eventerpoolconcurrency), [eventer_pool_name](c.md#eventerpoolname), [eventer_pool_watchdog_timeout](c.md#eventerpoolwatchdogtimeout), [eventer_read](c.md#eventerread), [eventer_ref](c.md#eventerref), [eventer_register_context](c.md#eventerregistercontext), [eventer_remove](c.md#eventerremove), [eventer_remove_fd](c.md#eventerremovefd), [eventer_remove_fde](c.md#eventerremovefde), [eventer_remove_recurrent](c.md#eventerremoverecurrent), [eventer_remove_timed](c.md#eventerremovetimed), [eventer_run_in_thread](c.md#eventerruninthread), [eventer_set_callback](c.md#eventersetcallback), [eventer_set_closure](c.md#eventersetclosure), [eventer_set_context](c.md#eventersetcontext), [eventer_set_fd_blocking](c.md#eventersetfdblocking), [eventer_set_fd_nonblocking](c.md#eventersetfdnonblocking), [eventer_set_mask](c.md#eventersetmask), [eventer_set_owner](c.md#eventersetowner), [eventer_thread_check](c.md#eventerthreadcheck), [eventer_trigger](c.md#eventertrigger), [eventer_update](c.md#eventerupdate), [eventer_update_whence](c.md#eventerupdatewhence), [eventer_wakeup](c.md#eventerwakeup), [eventer_write](c.md#eventerwrite)

##### F

[mtev_flow_regulator_ack](c.md#mtevflowregulatorack), [mtev_flow_regulator_create](c.md#mtevflowregulatorcreate), [mtev_flow_regulator_destroy](c.md#mtevflowregulatordestroy), [mtev_flow_regulator_lower](c.md#mtevflowregulatorlower), [mtev_flow_regulator_raise_one](c.md#mtevflowregulatorraiseone), [mtev_flow_regulator_stable_lower](c.md#mtevflowregulatorstablelower), [mtev_flow_regulator_stable_try_raise_one](c.md#mtevflowregulatorstabletryraiseone)

##### G

[mtev_get_durations_ms](c.md#mtevgetdurationsms), [mtev_get_durations_ns](c.md#mtevgetdurationsns), [mtev_get_durations_s](c.md#mtevgetdurationss), [mtev_get_durations_us](c.md#mtevgetdurationsus), [mtev_get_nanos](c.md#mtevgetnanos), [mtev_getip_ipv4](c.md#mtevgetipipv4), [mtev_gettimeofday](c.md#mtevgettimeofday)

##### L

[mtev_lockfile_acquire](c.md#mtevlockfileacquire), [mtev_lockfile_acquire_owner](c.md#mtevlockfileacquireowner), [mtev_lockfile_release](c.md#mtevlockfilerelease), [mtev_lua_lmc_alloc](c.md#mtevlualmcalloc), [mtev_lua_lmc_free](c.md#mtevlualmcfree), [mtev_lua_lmc_L](c.md#mtevlualmcL), [mtev_lua_lmc_resume](c.md#mtevlualmcresume), [mtev_lua_lmc_setL](c.md#mtevlualmcsetL)

##### M

[mtev_main](c.md#mtevmain), [mtev_main_status](c.md#mtevmainstatus), [mtev_main_terminate](c.md#mtevmainterminate), [MTEV_MAYBE_DECL](c.md#MTEVMAYBEDECL), [MTEV_MAYBE_DECL_VARS](c.md#MTEVMAYBEDECLVARS), [MTEV_MAYBE_FREE](c.md#MTEVMAYBEFREE), [MTEV_MAYBE_INIT_VARS](c.md#MTEVMAYBEINITVARS), [MTEV_MAYBE_REALLOC](c.md#MTEVMAYBEREALLOC), [MTEV_MAYBE_SIZE](c.md#MTEVMAYBESIZE), [mtev_merge_sort](c.md#mtevmergesort), [mkdir_for_file](c.md#mkdirforfile)

##### N

[mtev_now_ms](c.md#mtevnowms), [mtev_now_us](c.md#mtevnowus)

##### S

[mtev_security_chroot](c.md#mtevsecuritychroot), [mtev_security_setcaps](c.md#mtevsecuritysetcaps), [mtev_security_usergroup](c.md#mtevsecurityusergroup), [mtev_sem_destroy](c.md#mtevsemdestroy), [mtev_sem_getvalue](c.md#mtevsemgetvalue), [mtev_sem_init](c.md#mtevseminit), [mtev_sem_post](c.md#mtevsempost), [mtev_sem_trywait](c.md#mtevsemtrywait), [mtev_sem_wait](c.md#mtevsemwait), [mtev_sort_compare_function](c.md#mtevsortcomparefunction), [mtev_sort_next_function](c.md#mtevsortnextfunction), [mtev_sort_set_next_function](c.md#mtevsortsetnextfunction), [mtev_sys_gethrtime](c.md#mtevsysgethrtime)

##### T

[mtev_time_fast_mode](c.md#mtevtimefastmode), [mtev_time_maintain](c.md#mtevtimemaintain), [mtev_time_start_tsc](c.md#mtevtimestarttsc), [mtev_time_stop_tsc](c.md#mtevtimestoptsc), [mtev_time_toggle_require_invariant_tsc](c.md#mtevtimetogglerequireinvarianttsc), [mtev_time_toggle_tsc](c.md#mtevtimetoggletsc)

##### W

[mtev_watchdog_child_eventer_heartbeat](c.md#mtevwatchdogchildeventerheartbeat), [mtev_watchdog_child_heartbeat](c.md#mtevwatchdogchildheartbeat), [mtev_watchdog_create](c.md#mtevwatchdogcreate), [mtev_watchdog_disable](c.md#mtevwatchdogdisable), [mtev_watchdog_enable](c.md#mtevwatchdogenable), [mtev_watchdog_heartbeat](c.md#mtevwatchdogheartbeat), [mtev_watchdog_override_timeout](c.md#mtevwatchdogoverridetimeout), [mtev_watchdog_prefork_init](c.md#mtevwatchdogpreforkinit), [mtev_watchdog_recurrent_heartbeat](c.md#mtevwatchdogrecurrentheartbeat), [mtev_watchdog_start_child](c.md#mtevwatchdogstartchild), [mtev_websocket_client_free](c.md#mtevwebsocketclientfree), [mtev_websocket_client_get_closure](c.md#mtevwebsocketclientgetclosure), [mtev_websocket_client_init_logs](c.md#mtevwebsocketclientinitlogs), [mtev_websocket_client_is_closed](c.md#mtevwebsocketclientisclosed), [mtev_websocket_client_is_ready](c.md#mtevwebsocketclientisready), [mtev_websocket_client_new](c.md#mtevwebsocketclientnew), [mtev_websocket_client_new_noref](c.md#mtevwebsocketclientnewnoref), [mtev_websocket_client_send](c.md#mtevwebsocketclientsend), [mtev_websocket_client_set_cleanup_callback](c.md#mtevwebsocketclientsetcleanupcallback), [mtev_websocket_client_set_closure](c.md#mtevwebsocketclientsetclosure), [mtev_websocket_client_set_msg_callback](c.md#mtevwebsocketclientsetmsgcallback), [mtev_websocket_client_set_ready_callback](c.md#mtevwebsocketclientsetreadycallback)

##### Z

[mtev_zipkin_active_span](c.md#mtevzipkinactivespan), [mtev_zipkin_annotation_set_endpoint](c.md#mtevzipkinannotationsetendpoint), [mtev_zipkin_attach_to_eventer](c.md#mtevzipkinattachtoeventer), [mtev_zipkin_bannotation_set_endpoint](c.md#mtevzipkinbannotationsetendpoint), [mtev_zipkin_client_drop](c.md#mtevzipkinclientdrop), [mtev_zipkin_client_new](c.md#mtevzipkinclientnew), [mtev_zipkin_client_parent_hdr](c.md#mtevzipkinclientparenthdr), [mtev_zipkin_client_publish](c.md#mtevzipkinclientpublish), [mtev_zipkin_client_sampled_hdr](c.md#mtevzipkinclientsampledhdr), [mtev_zipkin_client_span](c.md#mtevzipkinclientspan), [mtev_zipkin_client_span_hdr](c.md#mtevzipkinclientspanhdr), [mtev_zipkin_client_trace_hdr](c.md#mtevzipkinclienttracehdr), [mtev_zipkin_default_endpoint](c.md#mtevzipkindefaultendpoint), [mtev_zipkin_default_service_name](c.md#mtevzipkindefaultservicename), [mtev_zipkin_encode](c.md#mtevzipkinencode), [mtev_zipkin_encode_list](c.md#mtevzipkinencodelist), [mtev_zipkin_event_trace_level](c.md#mtevzipkineventtracelevel), [mtev_zipkin_eventer_init](c.md#mtevzipkineventerinit), [mtev_zipkin_get_sampling](c.md#mtevzipkingetsampling), [mtev_zipkin_sampling](c.md#mtevzipkinsampling), [mtev_zipkin_span_annotate](c.md#mtevzipkinspanannotate), [mtev_zipkin_span_attach_logs](c.md#mtevzipkinspanattachlogs), [mtev_zipkin_span_bannotate](c.md#mtevzipkinspanbannotate), [mtev_zipkin_span_bannotate_double](c.md#mtevzipkinspanbannotatedouble), [mtev_zipkin_span_bannotate_i32](c.md#mtevzipkinspanbannotatei32), [mtev_zipkin_span_bannotate_i64](c.md#mtevzipkinspanbannotatei64), [mtev_zipkin_span_bannotate_str](c.md#mtevzipkinspanbannotatestr), [mtev_zipkin_span_default_endpoint](c.md#mtevzipkinspandefaultendpoint), [mtev_zipkin_span_drop](c.md#mtevzipkinspandrop), [mtev_zipkin_span_get_ids](c.md#mtevzipkinspangetids), [mtev_zipkin_span_logs_attached](c.md#mtevzipkinspanlogsattached), [mtev_zipkin_span_new](c.md#mtevzipkinspannew), [mtev_zipkin_span_publish](c.md#mtevzipkinspanpublish), [mtev_zipkin_span_ref](c.md#mtevzipkinspanref), [mtev_zipkin_span_rename](c.md#mtevzipkinspanrename), [mtev_zipkin_str_to_id](c.md#mtevzipkinstrtoid), [mtev_zipkin_timeval_to_timestamp](c.md#mtevzipkintimevaltotimestamp)

## Lua

##### D

[mtev.dns](lua.md#mtev.dns), [mtev.dns:is_valid_ip](lua.md#mtev.dns:isvalidip), [mtev.dns:lookup](lua.md#mtev.dns:lookup)

##### E

[mtev.enable_log](lua.md#mtev.enablelog)

##### G

[mtev.gettimeofday](lua.md#mtev.gettimeofday)

##### J

[mtev.json:document](lua.md#mtev.json:document), [mtev.json:tostring](lua.md#mtev.json:tostring)

##### L

[mtev.log](lua.md#mtev.log)

##### P

[mtev.parsejson](lua.md#mtev.parsejson), [mtev.pcre](lua.md#mtev.pcre), [mtev.print](lua.md#mtev.print), [mtev.process:kill](lua.md#mtev.process:kill), [mtev.process:pid](lua.md#mtev.process:pid), [mtev.process:wait](lua.md#mtev.process:wait)

##### R

[mtev.realpath](lua.md#mtev.realpath)

##### S

[mtev.sleep](lua.md#mtev.sleep), [mtev.spawn](lua.md#mtev.spawn)

##### T

[mtev.tojson](lua.md#mtev.tojson)

