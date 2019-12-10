/*
 * Copyright (c) 2005-2007, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *      of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MTEV_WATCHDOG_H
#define _MTEV_WATCHDOG_H

#include <time.h>
#include <signal.h>
#include "mtev_config.h"
#include "mtev_defines.h"
#include "mtev_log.h"
#include "eventer/eventer.h"
#include "mtev_stacktrace.h"

/*! \fn int mtev_watchdog_prefork_init()
    \brief Prepare the program to split into a child/parent-monitor relationship.
    \return Returns zero on success.
    
    mtev_watchdog_prefork_init sets up the necessary plumbing to bridge across a
child to instrument watchdogs.
 */
API_EXPORT(int)
  mtev_watchdog_prefork_init(void);

/*! \fn int mtev_watchdog_start_child(const char *app, int (*func)(), int child_watchdog_timeout)
    \brief Starts a function as a separate child under close watch.
    \param app The name of the application (for error output).
    \param func The function that will be the child process.
    \param child_watchdog_timeout The number of seconds of lifelessness before the parent reaps and restarts the child.
    \return Returns on program termination.
    
    mtev_watchdog_start_child will fork and run the specified function in the child process.  The parent will watch.  The child process must initialize the eventer system and then call mtev_watchdog_child_hearbeat to let the parent know it is alive.  If the eventer system is being used to drive the child process, mtev_watchdog_child_eventer_heartbeat may be called once after the eventer is initalized.  This will induce a regular heartbeat.
 */
API_EXPORT(int)
  mtev_watchdog_start_child(const char *app, int (*func)(void), int child_watchdog_timeout);

/*! \fn int mtev_watchdog_child_heartbeat()
    \return Returns zero on success

    mtev_watchdog_child_heartbeat is called within the child function to alert the parent that the child is still alive and functioning correctly.
 */
API_EXPORT(int)
  mtev_watchdog_child_heartbeat(void);

typedef struct mtev_watchdog_t mtev_watchdog_t;

/*! \fn mtev_watchdog_t *mtev_watchdog_create()
    \return a new heartbeat identifier (or null, if none could be allocated)

    mtev_watchdog_create creates a new heartbeat that must be assessed for liveliness by the parent.
 */

API_EXPORT(mtev_watchdog_t *)
  mtev_watchdog_create(void);

/*! \fn void mtev_watchdog_set_name(mtev_watchdog_t *hb, const char *name)
    \param hb the heart to name
    \param name a new name for this heart
 */

API_EXPORT(void)
  mtev_watchdog_set_name(mtev_watchdog_t *hb, const char *name);

/*! \fn const char *mtev_watchdog_get_name(mtev_watchdog_t *hb)
    \param hb the heart from which to retrieve a name
    \return the name of the heart (or NULL)
 */

API_EXPORT(const char *)
  mtev_watchdog_get_name(mtev_watchdog_t *hb);

/*! \fn int mtev_watchdog_heartbeat(mtev_watchdog_t *hb)
    \param hb is the heart on which to pulse.  If null, the default heart is used.
    \return Returns zero on success

    mtev_watchdog_heartbeat will pulse on the specified heart.
 */

API_EXPORT(int)
  mtev_watchdog_heartbeat(mtev_watchdog_t *hb);

/*! \fn int mtev_watchdog_child_eventer_heartbeat()
    \return Returns zero on success

    mtev_watchdog_child_eventer_heartbeat registers a periodic heartbeat through the eventer subsystem.  The eventer must be initialized before calling this function.
 */
API_EXPORT(int)
  mtev_watchdog_child_eventer_heartbeat(void);

/*! \fn eventer_t mtev_watchdog_recurrent_heartbeat(mtev_watchdog_t *hb)
    \param hb is the heart on which to beat.
    \return Returns and event that the caller must schedule.

    mtev_watchdog_recurrent_heartbeat creates a recurrent eventer_t to beat a heart.
 */
API_EXPORT(eventer_t)
  mtev_watchdog_recurrent_heartbeat(mtev_watchdog_t *hb);

/*! \fn void mtev_watchdog_enable(mtev_watchdog_t *hb)
    \param hb the heart on which to act

    mtev_watchdog_enable will make the parent respect and act on failed heartbeats.
 */
API_EXPORT(void)
  mtev_watchdog_enable(mtev_watchdog_t *hb);

/*! \fn void mtev_watchdog_disable(mtev_watchdog_t *hb)
    \param hb the heart on which to act

    mtev_watchdog_disable will make the parent ignore failed heartbeats.
 */
API_EXPORT(void)
  mtev_watchdog_disable(mtev_watchdog_t *hb);

/*! \fn void mtev_watchdog_override_timeout(mtev_watchdog_t *hb, double timeout)
    \param hb the heart on which to act
    \param timeout the timeout in seconds for this heart (0 for default)

    mtev_watchdog_override_timeout will allow the caller to override the timeout
    for a specific heart in the system.
 */
API_EXPORT(void)
  mtev_watchdog_override_timeout(mtev_watchdog_t *hb, double timeout);

/*! \fn double mtev_watchdog_get_timeout(mtev_watchdog_t *hb)
    \brief returns the timeout configured for this watchdog.
    \param hb the heart on which to act
    \return A timeout in seconds, 0 if hb is NULL.
 */
API_EXPORT(double)
  mtev_watchdog_get_timeout(mtev_watchdog_t *hb);

/*! \fn struct timeval mtev_watchdog_get_timeout_timeval(mtev_watchdog_t *hb)
    \brief returns the timeout configured for this watchdog.
    \param hb the heart on which to act
    \param dur a struct timeval to populate with the timeout
    \return mtev_true if there is a watchog, mtev_false if not.
 */
API_EXPORT(mtev_boolean)
  mtev_watchdog_get_timeout_timeval(mtev_watchdog_t *hb, struct timeval *dur);

/*! \fn uint32_t mtev_watchdog_number_of_starts(void)
    \brief Determine the number of times a child has been lauched.
    \return The number of times fork has returned in the parent.  In a running server, 0 means you're the first generation.
 */
API_EXPORT(uint32_t)
  mtev_watchdog_number_of_starts(void);

/*! \fn int mtev_watchdog_glider(const char *path)
    \brief Sets a glider command.
    \param path the full path to the executable.
    \return 0 on success, non-zero on failure.

    `path` is invoked with two parameters, the process id of the faulting child, and the reason for the fault (one of `crash`, `watchdog`, or `unknown`.
 */
API_EXPORT(int)
  mtev_watchdog_glider(const char *path);

/*! \fn int mtev_watchdog_glider_trace_dir(const char *path)
    \brief Set the directory to store glider output.
    \param path a full path to a directory.
    \return 0 on success, non-zero on failure.
 */
API_EXPORT(int)
  mtev_watchdog_glider_trace_dir(const char *path);

/*! \fn void mtev_watchdog_ratelimit(int retry_val, int span_val)
    \brief Set rate limiting for child restarting.
    \param retry_val the number of times to retry in the given `span_val`
    \param span_val the number of seconds over which to attempt retries.
 */
API_EXPORT(void)
  mtev_watchdog_ratelimit(int retry_val, int span_val);

/* \fn void mtev_watchdog_on_crash_close_add_fd(int fd)
   \brief registers a file descriptor for close on crash
   \param fd the file descripto

   Registers a file descriptor to be close on crash in the event that async core dumping is enabled.
 */
API_EXPORT(void)
  mtev_watchdog_on_crash_close_add_fd(int fd);

/* \fn void mtev_watchdog_on_crash_close_remove_fd(int fd)
   \brief deregisters a file descriptor for close on crash
   \param fd the file descripto

   Deregisters a file descriptor to be close on crash in the event that async core dumping is enabled.
 */
API_EXPORT(void)
  mtev_watchdog_on_crash_close_remove_fd(int fd);

API_EXPORT(void)
  mtev_self_diagnose(int sig, siginfo_t *si, void *uc);

API_EXPORT(void)
  mtev_external_diagnose(int sig, siginfo_t *si, void *uc);

API_EXPORT(int)
  mtev_setup_crash_signals(void (*)(int, siginfo_t *, void *));

/*! \fn void mtev_watchdog_disable_asynch_core_dump(void)
    \brief Disable asynchronous core dumps.

    Disable starting a new child while a faulting prior child is still dumping.  This must be called
    before `mtev_main` and will be overridden by the MTEV_ASYNCH_CORE_DUMP environment variable.
 */
API_EXPORT(void)
  mtev_watchdog_disable_asynch_core_dump(void);
  
API_EXPORT(void)
  mtev_watchdog_disable_trace_output(void);

API_EXPORT(void)
  mtev_watchdog_shutdown_handler(int);

#endif
