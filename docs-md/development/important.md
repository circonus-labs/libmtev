# Important Notes

In this section we will call out important notes that affect all developers
that will integrate libmtev.  These notes will be reinforced in other more
specific sections, but often deal with the interaction between components.

### The Eventer and the Watchdog and You

The eventer is the core operational concept of libmtev; it is its heart.
Unlike some simple event loops out there, libmtev uses multi-threaded
event loops (called eventer\_pools).  By default, there is one eventer\_pool
in the system, but more can be configured.  In addition to the traditional
event loop concept, asynchronous job queues ("eventer\_jobq") are available
for operations having the potential to block the normal event loops.  These
queues are named and can have different concurrencies based on work load.

So you have multiple asynch queues, each with configurable and
run-time-adjustable concurrency plus multiple pools each with multiple threads
running a "traditional" event loop.

In evented systems, it is important that you don't "block" the loop.  It is
so important, in fact, that the watchdog exists to ensure that you don't
mistakenly do so.  The watchdog is responsible for making sure that the
program does not stall in the event loop.  This also means that your event
loops are responsible for issuing a heartbeat such that the watchdog knows
you have not stalled.  While this is C, and you can do almost anything, if
you attempt to disable the heartbeats, you're doing it wrong and things will
break unexpectedly and often in ways that will adversely affect production
applications. Don't do that.  You can set different watchdog timeouts per
eventer\_pool.

### Multi-thread Safety

#### Memory Management

Multi-threaded apps can be hard, specifically in the area of memory management.
The `safe_` memory management routines in `mtev_memory.h` are there to help,
but they are not a silver bullet.  They wrap
[libck](http://concurrencykit.org/) epoch memory reclamation and make it such
that memory touched _inside_ an event callback will not be freed until the
callback returns.  Again, not a silver bullet.

#### Configuration

The `mtev_conf_` subsystem is based on libxml2 and has certain nuances to its thread-safety.  In order to interoperate with the configuration system you must
acquire and release sections of the config in either read (concurrent) or write (single access) mode.  If you make any changes to the XML structure you *must* acquire a section in write mode or undefinied behavior may ensue.  All locks are recusively safe and a write-lock will serve as a read-lock, but a read-lock will not upgrade to a write-lock.

#### Keep Related Events Together

The event system is thread-safe, but that doesn't mean you can't do bad things.
Specifically, one should only manipulate events in the current event loop.
Case in point, if you have a read/write event and a timeout event that can
shutdown the read/write event, the two events should exist in the same event
loop thread.  Complications arise if the timeout fires and attempts to manipulate
the read/write event if the read/write event is currently in its callback. It
can be done safely, but it is complicated to get right and one should just
make life simple if possible.
