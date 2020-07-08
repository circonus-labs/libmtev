# Jemalloc

libmtev has some special support available if you are running with the jemalloc allocator loaded.

> Note that if your application isn't statically linked with jemalloc, libmtev will still notice its presence at run-time if loaded via `LD_PRELOAD`.  So, the following can be used in conjunction with an operator's forced preloading of libjemalloc.so

## General malloc statistics.

Malloc statistics (in JSON) are available at the URL: `/mtev/memory.json`

## Activating jemalloc heap profiling

To perform heap profiling you must have jemalloc heap profiling enabled via environment variable:

`export MALLOC_CONF="prof:true,prof_active:false"`

Or via the special `/etc/malloc.conf` string file:

`sudo ln -s 'prof:true,prof_active:false' /etc/malloc.conf`

You can then flip on heap profiling in your mtev app by curling:

`curl yourmachine:yourport/mtev/heap_profile?active=true`

This will turn on profiling from that moment until you disable it via:

`curl yourmachine:yourport/mtev/heap_profile?active=false`

In a variety of cases, it might be desirable to have profiling active from the point of application start.  To do this set `prof_active:true` in the `MALLOC_CONF`.  However keep in mind that there is some performance cost while profiling is active, so you may only want to keep profiling active when you are gathering memory usage information.  And you may also want to adjust the sampling if performance is adversely affected (see the jemalloc link below if this is a concern).

**NOTE:** It is a good idea to confirm these settings changes and check status (at any time) by simply curling:

`curl yourmachine:yourport/mtev/heap_profile`

The output from that curl will look something like the following:

```
opt.prof: true
prof.active: false
prof.thread_active_init: true
```

The first setting `opt.prof: true` will be displayed if `prof:true` was properly set in the MALLOC_CONF or /etc/malloc.conf as shown above.

The second setting `prof.active` is initialized by the MALLOC_CONF or /etc/malloc.conf, and it can be toggled to `true` or `false` at runtime by using the `heap_profile` curl shown above.  Both settings must be `true` or nothing will be captured when triggering a heap profile.

## Heap Profiling

To get periodic heap profile dumps from your running application do:

`curl yourmachine:yourport/mtev/heap_profile?trigger_dump=true > profile.prof`

This will spit back jeprof format heap information which can then be passed to the `jeprof` analysis program for further analysis.  For example, to show allocations by source code line, but from a perspective outside of libmtev's use of SMR (`mtev_memory_`) and libck's hash tables (`ck_hs_`), one could run:

`jeprof --text --lines --exclude='(mtev_memory_|ck_hs_)' /path/to/your/executable profile.prof`

To compare two heap profiles (which helps reduce the noise) you can add the `--base=baseline.prof` switch to the commandline.

For more information on jemalloc heap profiling, see: [jemalloc heap profiling](https://github.com/jemalloc/jemalloc/wiki/Use-Case%3A-Heap-Profiling)


