# mtev_main

Every C application starts with `main()`.  In order to make life easier, libmtev provides an `mtev_main` that
facilitates configuration loading, logging setup, privilege separation and watchdog orchestration.

##### simple.c
```c
#include <mtev_main.h>
#include <mtev_memory.h>

#define APPNAME "simple"
static char *config_file = "/path/to/simple.conf";
static int debug = 0;
static int foreground = 0;
static cahr *glider = NULL;
static char *droptouser = NULL;
static char *droptogroup = NULL;
static mtev_lock_op_t lockop = MTEV_LOCK_OP_LOCK;
static int usage(const char *execname) {
  /* relevant usage output */
  return 2; /* returning 2 will avoid a watchdog restart */
}
static void parse_cli_args(int argc, char **argv) {
  /* left as an excercise to the reader */
}
int child_main() {
  /* implement your application here */
  /* typically: init things and start the event loop */
  return 0;
}
int main(int argc, char **argv) {
  parse_cli_args(argc, argv);
  if(!config_file) exit(usage(argv[0]));

  mtev_memory_init();
  mtev_main(APPNAME, config_file, debug, foreground,
            lockop, glider, droptouser, droptogroup,
            child_main);
  return 0;
}
```

The arguments to `mtev_main` are what is important here.

 * ##### APPNAME

   This is a simple name of your app, it must match the name of the root node in your XML configuration document.

 * ##### config_file

   The path to the config file. It is highly recommended that libmtev applications tie this to the `-c` CLI flag.

 * ##### debug

   If 0, the "debug" log_stream remains disabled.  If non-zero, the "debug" log_stream is enabled. It is highly recommended
   that libmtev applications tie this to the `-d` CLI flag.

 * ##### foreground

   If 0, the application will run in the background and be monitored by the watchdog subsystem.  This is a reasonable
   behavior for almost all libmtev applications.  If set to 1, the application will run in the foreground and not be
   monitored by the watchdog subsystem.  It is highly recommended that libmtev applications tie this behavior to a single `-D`
   CLI argument.  If set to 2, the application will be run under the watchdog subsystem, but the watchdog monitoring process will remain in the foreground.  It is highly recommended that libmtev applications tie this behavior to repeated `-D -D` CLI arguments.
   When applications are run in the foreground, file descriptors 0, 1 and 2 remain pointing to the stdin, stdout and and stderr
   of the invoking context.  If, the application is run in the background, all are replaced with file descriptors pointing to `/dev/null`.

 * ##### lockop

   This argument controls how `mtev_main` will respect the lockfile specified at the configuration root.  If `MTEV_LOCK_OP_NONE` is
   used, then locking will be skipped; only do this if you know what you are doing as it could lead to application inconsistency.
   If `MTEV_LOCK_OP_LOCK` is used, the lockfile will be locked prior to starting; if locking fails, the application will exit immediately.
   If `MTEV_LOCK_OP_WAIT` is used, the application will wait for the lockfile to be available and then lock it before starting the application.

 * ##### glider

   An optional override for the `gilder` attribute of the [watchdog configuration](../config/watchdog.md).

 * ##### droptouser & droptogroup

   If the application is run as the root user and these are specified, this informs `mtev_main` and its
   initialization routines that you intend to drop privileges and ensures that initialization processes
   that must be performed as the specified user and group are done so as in that context.

   > #### Caution::Security Warning
   > The developer is responsible for dropping privileges during the initialization sequence in
   > `child_main` via the `mtev_conf_security_init(...)` API call.

 * ##### child_main

   This is the surrogate main where the application should be initialized and run.  Note that it should
   not return.  Typically this function will end with an `event_loop()` which is non-returning.
