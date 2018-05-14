/*
 * Copyright (c) 2011, OmniTI Computer Consulting, Inc.
 * All rights reserved.
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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

#ifndef _MTEV_MAIN_H
#define _MTEV_MAIN_H

typedef enum {
  MTEV_LOCK_OP_NONE = 0,
  MTEV_LOCK_OP_LOCK,
  MTEV_LOCK_OP_WAIT
} mtev_lock_op_t;

API_EXPORT(void)
  mtev_init_globals(void);

/*! \fn int mtev_main_status(const char *appname, const char *config_filename, int debug, pid_t *pid, pid_t *pgid)
    \brief Determine if that application is already running under this configuration.
    \param appname The application name (should be the config root node name).
    \param config_filename The path the the config file.
    \param debug Enable debugging (logging).
    \param pid If not null, it is populated with the process id of the running instance.
    \param pgid If not null, it is populated with the process group id of the running instance.
    \return 0 on success, -1 on failure.
 */
API_EXPORT(int)
  mtev_main_status(const char *appname,
                   const char *config_filename, int debug,
                   pid_t *pid, pid_t *pgid);

/*! \fn int mtev_main_terminate(const char *appname, const char *config_filename, int debug)
    \brief Terminate an already running application under the same configuration.
    \param appname The application name (should be the config root node name).
    \param config_filename The path the the config file.
    \param debug Enable debugging (logging).
    \return 0 on success, -1 on failure.  If the application is not running at the time of invocation, termination is considered successful.
 */
API_EXPORT(int)
  mtev_main_terminate(const char *appname,
                      const char *config_filename, int debug);


/*! \fn void mtev_main_eventer_config(const char *name, const char *value)
    \brief Set <eventer><config> options for an app that need not be specified explicitly in a config.
    \param name The config key name
    \param value The value of the config option
*/
API_EXPORT(void)
  mtev_main_eventer_config(const char *name, const char *value);

/*! \fn int mtev_main(const char *appname, const char *config_filename, int debug, int foreground, mtev_log_op_t lock, const char *glider, const char *drop_to_user, const char *drop_to_group, int (*passed_child_main)(void))
    \brief Run a comprehensive mtev setup followed by a "main" routine.
    \param appname The application name (should be the config root node name).
    \param config_filename The path the the config file.
    \param debug Enable debugging (logging).
    \param foreground 0 to daemonize with watchdog, 1 to foreground, 2 to foreground with watchdog.
    \param lock Specifies where to not lock, try lock or exit, or lock or wait.
    \param glider A path to an executable to invoke against the process id on crash. May be NULL.
    \param drop_to_user A target user for dropping privileges when under watchdog. May be NULL.
    \param drop_to_group A target group for dropping privileges when under watchdog. May be NULL.
    \param passed_child_main A programmers supplied main function.
    \return -1 on failure, 0 on success if `foreground==1`, or the return value of `main` if run in the foreground.
 */
API_EXPORT(int)
  mtev_main(const char *appname,
            const char *config_filename, int debug, int foreground,
            mtev_lock_op_t lock, const char *glider,
            const char *drop_to_user, const char *drop_to_group,
            int (*passed_child_main)(void));

API_EXPORT(void)
  mtev_main_enable_log(const char *);

API_EXPORT(void)
  mtev_main_disable_log(const char *);

#endif
