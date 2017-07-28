![](https://github.com/circonus-labs/libmtev/blob/master/docs-md/assets/mtev-logo.png?raw=true)

<a href="https://scan.coverity.com/projects/circonus-labs-libmtev">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/10772/badge.svg"/>
</a>


libmtev - a toolkit for building high-performance servers.

[Read the documentation.](http://circonus-labs.github.io/libmtev/)

To build, check out the instructions in [BUILDING](./BUILDING.md).

Enjoy.

## An incomplete list of features.

  * process manager/watchdog/monitor/crash catcher
  * powerful config system with write-back on changes
  * eventing system for sockets, timers and asynch jobs
    * Multi-Threaded EVent loops - (mtev)
    * dynamically scaling asynchronous jobqs
  * module system
  * network listener system (w/ TLS)
    * REST/http routing convenience layer
    * channelized reverse tunneling of TCP.
  * telnet-accessible command-control system
  * epoch memory reclamation
  * clustering subsystem
  * robust rest-accessible statistics (w/ histograms)
  * fq and amqp connectors
  * DTrace (and Systemtap/eBPF) USDT probes
  * opentracing (zipkin thrift) support
  * mdb helpers (Illumos)
  * various data structures
  * accelerated timing support (faster than OS)
  * dynamic hooks and runtime resolveable callsites
  * embedded luajit w/ stand-alone lua runtime
  * mtevbusted (mtev capable lua busted testing suite)
