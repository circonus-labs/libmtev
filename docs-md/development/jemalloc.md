# jemalloc

libmtev has some special support available if you are running with the jemalloc
allocator loaded.

> Note that if your application isn't directly linked with jemalloc, libmtev will
> still notice its presence at run-time if loaded via `LD_PRELOAD`.  So, the following
> can be used in conjunction with an operator's force loading of libjemalloc.so

## malloc statistics.

Malloc statistics (in JSON) are available at the URL: `/mtev/memory.json`

## Activating jemalloc profiling

To perform heap profiling you must have jemalloc heap profiling enabled 
via environment variable:

`export MALLOC_CONF="prof:true,prof_active:false"`

Or via the special `/etc/malloc.conf` string file:

`sudo ln -s 'prof:true,prof_active:false' /etc/malloc.conf`

You can then flip on heap profiling in your mtev app by curling:

`/mtev/heap_profile?active=true`

This will turn on profiling from that moment until you disable it via:

`/mtev/heap_profile?active=false`

In a variety of cases, it might be desirable to have profiling active from the point
of application start.  To do this set `prof_active:true` in the `MALLOC_CONF`.

## Heap Profiling

To get periodic heap profile dumps from your running application do:

`curl yourmachine:yourport/mtev/heap_profile?trigger_dump=true > profile.prof`

This will spit back jeprof format heap information which can then be passed
to the `jeprof` analysis program for further analysis.  For example, to show
allocations by source code line, but from a perspective outside of libmtev's use of
SMR (`mtev_memory_`) and libck's hash tables (`ck_hs_`), one could run:

`jeprof --text --lines --exclude='(mtev_memory_|ck_hs_)' /path/to/your/executable profile.prof`

For more information on jemalloc heap profiling, see here: [jemalloc heap profiling](https://github.com/jemalloc/jemalloc/wiki/Use-Case%3A-Heap-Profiling)


