#include "mtev_defines.h"
#include "mtev_conf.h"
#include "mtev_console.h"
#include "mtev_dso.h"
#include "mtev_listener.h"
#include "mtev_main.h"
#include "mtev_memory.h"
#include "mtev_rest.h"
#include "mtev_security.h"
#include "mtev_stacktrace.h"
#include "eventer/eventer.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <lua.h>
#include <lauxlib.h>
#include "luamtev.conf.tmpl"

#define APPNAME "cli"
char **cli_argv = { NULL };
static char **global_envp;
static bool interactive = false;
static bool needs_unlink = false;
static bool dump_template = false;
static char *modules_path = NULL;
static char *config_file = NULL;
static char *lua_cpath = NULL;
static char *lua_addcpath = NULL;
static char *lua_lpath = NULL;
static char *lua_addlpath = NULL;
static char *lua_file = NULL;
/* This is mainly used for scripting and a single
 * eventer thread is a more-than-sufficient default. */
static int concurrency = 1;
static int debug = 0;
static char *function = "main";
static int foreground = 1;
static char *droptouser = NULL, *droptogroup = NULL;

static mtev_log_stream_t cli_stdout;

static int
usage(const char *prog) {
  fprintf(stderr,
  "%s [-i] [-L luapath] [-C luacpath] [-M dir] [-d] [-e function]\n\tluafile\n\n", prog);
  fprintf(stderr, "\t-u\t\t\tdrop to user\n");
  fprintf(stderr, "\t-g\t\t\tdrop to group\n");
  fprintf(stderr, "\t-i\t\t\tturn on interactive console\n");
  fprintf(stderr, "\t-c <file>\t\tcustom mtev config\n");
  fprintf(stderr, "\t-l <logname>\t\tenable the an mtev log stream\n");
  fprintf(stderr, "\t-L <path>\t\tlua package.path\n");
  fprintf(stderr, "\t-L +<path>\t\tappend to package.path\n");
  fprintf(stderr, "\t-C <path>\t\tlua package.cpath\n");
  fprintf(stderr, "\t-C +<path>\t\tappend to package.cpath\n");
  fprintf(stderr, "\t-M <path>\t\tmtev modules path\n");
  fprintf(stderr, "\t-m\t\t\tdaemonize and run managed\n");
  fprintf(stderr, "\t-m -m\t\t\trun managed\n");
  fprintf(stderr, "\t-n <#threads>\t\tspecify concurrency\n");
  fprintf(stderr, "\t-d\t\t\tturn on debugging\n");
  fprintf(stderr, "\t-e <func>\t\tspecify a function entrypoint (default: main)\n");
  fprintf(stderr, "\n%s -T\n", prog);
  fprintf(stderr, "\tDumps the auto-generated config file for reference.\n");
  return 2;
}
static void
make_config(void) {
  int fd, len;
  char filename[] = "/tmp/clicmdXXXXXX";
  char *outbuf = NULL;
  char lpath[PATH_MAX], cwd[PATH_MAX];

  if(!modules_path) modules_path = MTEV_MODULES_DIR;

  if(!lua_lpath) lua_lpath = MTEV_MODULES_DIR "/lua/?.lua;%s/?.lua;{package.path}";
  if(getcwd(cwd, sizeof(cwd)) == NULL) memcpy(cwd, ".", 2);
  snprintf(lpath, sizeof(lpath), lua_lpath, cwd);

  if(!lua_cpath) lua_cpath = MTEV_LIB_DIR "/mtev_lua/?.so;{package.cpath}";
  if(!modules_path || !lua_lpath || !lua_cpath) {
    fprintf(stderr, "Trouble finding paths, use -L or -C to fix this.\n");
    exit(-2);
  }
  len = strlen(CONFIG_TMPL) + strlen(modules_path) + strlen(lpath) +
        strlen(lua_cpath) + strlen(lua_file) + strlen(function);
  if(lua_addlpath) len += 1 + strlen(lua_addlpath);
  if(lua_addcpath) len += 1 + strlen(lua_addcpath);
  outbuf = malloc(len+1);
  len = snprintf(outbuf, len, CONFIG_TMPL,
                 concurrency,
                 modules_path, lpath,
                 lua_addlpath ? ";" : "",
                 lua_addlpath ? lua_addlpath : "",
                 lua_cpath,
                 lua_addcpath ? ";" : "",
                 lua_addcpath ? lua_addcpath : "",
                 lua_file, function);
  if(len == -1) {
    fprintf(stderr, "Failed to generate config\n");
    free(outbuf);
    exit(-2);
  }
  if(dump_template) {
    if(write(STDOUT_FILENO, outbuf, len) < 0) {
      free(outbuf);
      exit(-1);
    }
    free(outbuf);
    exit(0);
  }
  mode_t old_umask = umask(077);
  fd = mkstemp(filename);
  umask(old_umask);
  if(fd < 0) {
    fprintf(stderr, "Faile to open config: %s\n", filename);
    free(outbuf);
    exit(-2);
  }
  if(write(fd, outbuf, len) != len) {
    fprintf(stderr, "Faile to write config: %s\n", filename);
    unlink(filename);
    free(outbuf);
    exit(-2);
  }
  close(fd);
  needs_unlink = true;
  config_file = strdup(filename);
  free(outbuf);
}

#if defined(__GLIBC__) && __GLIBC__ >= 2
#define POSIXLY_COMPLIANT_PLUS "+"
#else
#define POSIXLY_COMPLIANT_PLUS ""
#endif

static void
parse_cli_args(int argc, char * const *argv) {
  int c;
  while((c = getopt(argc, argv, POSIXLY_COMPLIANT_PLUS "c:de:g:l:mn:iu:C:L:M:T")) != EOF) {
    switch(c) {
      case 'd': debug = 1; break;
      case 'i': interactive = 1; break;
      case 'f': function = strdup(optarg); break;
      case 'l': mtev_main_enable_log(optarg); break;
      case 'C':
        if(optarg[0] == '+') lua_addcpath = strdup(optarg+1);
        else lua_cpath = strdup(optarg);
        break;
      case 'L':
        if(optarg[0] == '+') lua_addlpath = strdup(optarg+1);
        else lua_lpath = strdup(optarg);
        break;
      case 'M': modules_path = strdup(optarg); break;
      case 'c': config_file = strdup(optarg); break;
      case 'T': dump_template = true; break;
      case 'u': droptouser = strdup(optarg); break;
      case 'g': droptogroup = strdup(optarg); break;
      case 'm':
        if(foreground == 1) foreground = 0;
        else foreground = 2;
        break;
      case 'n': concurrency = atoi(optarg); break;
    }
  }
  if(optind > (argc-1) && !dump_template) {
    exit(usage(argv[0]));
  }
  cli_argv = calloc(argc - optind + 1, sizeof(char *));
  for(c = 0; optind != argc; c++, optind++)
    cli_argv[c] = strdup(argv[optind]);
  lua_file = realpath(cli_argv[0], NULL);
  if(lua_file == NULL && errno == ENOENT) lua_file = cli_argv[0];
  if(!lua_file) {
    fprintf(stderr, "Bad file: %s\n", cli_argv[0]);
    exit(2);
  }
}

/* We just need to push the command line args onto an array */
int luaopen_hostcli(lua_State *L) {
  int i;
  lua_newtable(L);
  for(i=0; cli_argv[i]; i++) {
    lua_pushstring(L, cli_argv[i]);
    lua_rawseti(L, -2, i+1);
  }
  lua_setglobal(L, "arg");

  lua_newtable(L);
  i = 0;
  for(char *ekv = global_envp[0]; ekv; ekv = global_envp[++i]) {
    char key[1024];
    char *eq = strchr(ekv, '=');
    if(!eq) continue;
    if(eq-ekv >= 1024) continue;
    memcpy(key, ekv, eq-ekv);
    key[eq-ekv] = '\0';
    lua_pushstring(L, eq+1);
    lua_setfield(L, -2, key);
  }
  lua_setglobal(L, "ENV");
  return 0;
}

static int
child_main(void) {
  int log_flags;
  mtev_conf_section_t section;
  char *err = NULL;

  cli_stdout = mtev_log_stream_new_on_fd("stdout", 1, NULL);

  log_flags = mtev_log_stream_get_flags(mtev_stderr);
  log_flags &= ~(MTEV_LOG_STREAM_FACILITY|MTEV_LOG_STREAM_TIMESTAMPS);
  mtev_log_stream_set_flags(mtev_stderr, log_flags);

  /* reload our config, to make sure we have the most current */
  if(mtev_conf_load(NULL) == -1) {
    mtevL(mtev_error, "Cannot load config: '%s'\n", config_file);
    if(needs_unlink) unlink(config_file);
    exit(2);
  }

  mtev_conf_security_init(APPNAME, droptouser, droptogroup, NULL);

  if(mtev_conf_write_file(&err) != 0) {
    if(err) {
      mtevL(mtev_stderr, "Error: '%s'\n", err);
      free(err);
    }
    mtevL(mtev_stderr, "Permissions issue, are you running as the right user?\n");
    exit(2);
  }
  free(err);
  if(needs_unlink) {
    mtev_conf_disable_writes(mtev_true);
    unlink(config_file);
  }

  /* update the lua module */
  section = mtev_conf_get_section_read(MTEV_CONF_ROOT, "/cli/modules/generic[@name=\"lua_general\"]/config");
  if(mtev_conf_section_is_empty(section) ||
     !mtev_conf_set_string(section, "lua_module", lua_file)) {
    mtevL(mtev_stderr, "Cannot set target lua module, invalid config.\n");
    mtev_conf_release_section_read(section);
    exit(2);
  }
  mtev_conf_release_section_read(section);

  eventer_init();
  mtev_dso_init();
  mtev_dso_post_init();
  if(mtev_dso_load_failures() > 0) {
    mtevL(mtev_stderr, "Failed to initialize.\n");
    exit(2);
  }

  if(interactive) {
    mtev_console_init(APPNAME);
    mtev_console_conf_init();
    if(eventer_set_fd_nonblocking(STDIN_FILENO) != 0 ||
       mtev_console_std_init(STDIN_FILENO, STDOUT_FILENO)) {
      mtevL(mtev_stderr, "Failed to initialize IO\n");
      exit(2);
    }
  }
  /* Lastly, spin up the event loop */
  eventer_loop();
  return 0;
}

static int lua_direct_loader(lua_State *L) {
  const char *filename = luaL_checkstring(L, 1);
  if (filename == NULL) return 1;  /* library not found in this path */
  if (luaL_loadfile(L, filename) != 0) {
    luaL_error(L, "error loading module '%s' from file '%s':\n\t%s",
               lua_tostring(L, 1), filename, lua_tostring(L, -1));
  }
  return 1;  /* library loaded successfully */
}
int luaopen_LuaMtevDirect(lua_State *L) {
  lua_getglobal(L, "package");
  lua_getfield(L, -1, "loaders");
  lua_pushcfunction(L, lua_direct_loader);
  lua_rawseti(L, -2, 5); /* there are 4 default loaders in luajit */
  lua_pop(L,1); /* loaders */
  lua_pop(L,1); /* package */
  lua_pushnil(L);
  return 1;
}

static mtev_boolean dwarf_filter_all(const char *file) {
  (void)file;
  return mtev_false;
}

int main(int argc, char **argv, char **envp) {
  parse_cli_args(argc, argv);
  if(!config_file) make_config();

  global_envp = envp;
  mtev_memory_init();
  if(NULL == getenv("MTEV_DWARF")) {
    mtev_dwarf_filter(dwarf_filter_all);
    mtev_dwarf_filter_symbols(dwarf_filter_all);
  }
  mtev_main(APPNAME, config_file, debug, foreground,
            MTEV_LOCK_OP_LOCK, NULL, droptouser, droptogroup,
            child_main);

  free(function);
  free(lua_addcpath);
  free(lua_cpath);
  free(lua_addlpath);
  free(lua_lpath);
  free(modules_path);
  free(config_file);
  free(droptouser);
  free(droptogroup);
  return 0;
}
