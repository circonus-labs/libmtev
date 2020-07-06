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
However keep in mind that there is some performance cost while profiling is active,
so you may only want to keep profiling active when you are gathering memory usage
information.  And you may also want to adjust the sampling if performance is adversely
affected (see the jemalloc link below if this is a concern).

NOTE: It is a good idea to confirm these settings changes and check status (at any
time) by simply curling:

`/mtev/heap_profile`

In order to be able to get a heap profile snapshot, you must have `opt.prof` set to
`true` (or you'll get an error when trying to trigger a dump).  While profiling is
active, `prof.active` will also be `true` (and this is also required to get a valid
capture in the next step).

## Heap Profiling

To get periodic heap profile dumps from your running application do:

`curl yourmachine:yourport/mtev/heap_profile?trigger_dump=true > profile.prof`

This will spit back jeprof format heap information which can then be passed
to the `jeprof` analysis program for further analysis.  For example, to show
allocations by source code line, but from a perspective outside of libmtev's use of
SMR (`mtev_memory_`) and libck's hash tables (`ck_hs_`), one could run:

`jeprof --text --lines --exclude='(mtev_memory_|ck_hs_)' /path/to/your/executable profile.prof`

To compare two heap profiles (which helps reduce the noise) you can use the "--base" switch:

`jeprof --text --lines --exclude=&apos;(mtev_memory_|ck_hs_)&apos; --base=baseline.prof /path/to/your/executable profile.prof`

For more information on jemalloc heap profiling, see here: [jemalloc heap profiling](https://github.com/jemalloc/jemalloc/wiki/Use-Case%3A-Heap-Profiling)


