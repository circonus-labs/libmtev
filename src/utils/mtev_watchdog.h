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

/*! \fn int update_retries(int retries, int span, retry_data** data)
    \brief Updates the list of retries and signals to quit if the limit is exceeded
    \param offset The current location in the data array to place the new time in
    \param times An array of times used to determine if there have been too many restarts
    \return Returns 1 to signal a quit, 0 otherwise

.

    update_retries will iterate through a list of times the task has restarted. If it determines that the system has been restarted too many times in too short a period, it will return 1 and the program will terminate. Otherwise, it will return 0 and the program will restart.
 */

API_EXPORT(int)
  update_retries(int* offset, time_t times[]);

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

/*! \fn void mtev_watchdog_override_timeout(mtev_watchdog_t *lifeline, double timeout)
    \param hb the heart on which to act
    \param timeout the timeout in seconds for this heart (0 for default)

    mtev_watchdog_override_timeout will allow the caller to override the timeout
    for a specific heart in the system.
 */
API_EXPORT(void)
  mtev_watchdog_override_timeout(mtev_watchdog_t *lifeline, double timeout);

API_EXPORT(int)
  mtev_watchdog_glider(const char *path);

API_EXPORT(int)
  mtev_watchdog_glider_trace_dir(const char *path);

API_EXPORT(void)
  mtev_watchdog_ratelimit(int retry_val, int span_val);

/* \fn void mtev_watchdog_on_crash_close_add_fd(int fd)
   \brief registers a file descriptor for close on crash
   \param fd the file descripto

   Registers a file descriptor to be close on crash in the event that ASYNCH_CORE_DUMP is set in the environment.
 */
API_EXPORT(void)
  mtev_watchdog_on_crash_close_add_fd(int fd);

/* \fn void mtev_watchdog_on_crash_close_remove_fd(int fd)
   \brief deregisters a file descriptor for close on crash
   \param fd the file descripto

   Deregisters a file descriptor to be close on crash in the event that ASYNCH_CORE_DUMP is set in the environment.
 */
API_EXPORT(void)
  mtev_watchdog_on_crash_close_remove_fd(int fd);

API_EXPORT(void)
  mtev_self_diagnose(int sig, siginfo_t *si, void *uc);

API_EXPORT(int)
  mtev_setup_crash_signals(void (*)(int, siginfo_t *, void *));
  
#endif
