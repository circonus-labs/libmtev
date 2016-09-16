#include <sys/time.h>
#include <dlfcn.h>

#define MAX_STARTUP_TIME    2
#define MAX_STARTUP_TIME_NS (MAX_STARTUP_TIME * 1000000000)
static hrtime_t (*fast_gethrtime)(void);
static hrtime_t (*real_gethrtime)(void);

static int (*fast_gettimeofday)(struct timeval *, void *);
static int (*real_gettimeofday)(struct timeval *, void *);

static hrtime_t initial = 0;
hrtime_t gethrtime() {
  if(fast_gethrtime) return fast_gethrtime();

  hrtime_t rv = real_gethrtime();
  if(!initial) initial = rv;
  else if (rv - initial > MAX_STARTUP_TIME_NS) {
    /* screwed it, we're just not going to win */
    fast_gethrtime = real_gethrtime;
  }
  fast_gethrtime = dlsym(RTLD_NEXT, "mtev_gethrtime");
  return rv;
}

static struct timeval initial_tv = { 0 };
int gettimeofday(struct timeval *t, void *ttp) {
  if(fast_gettimeofday) return fast_gettimeofday(t, ttp);

  int rv = real_gettimeofday(t, ttp);
  if(!initial) initial_tv.tv_sec = t->tv_sec;
  else if (t->tv_sec - initial_tv.tv_sec > (MAX_STARTUP_TIME+1)) {
    /* screwed it, we're just not going to win */
    fast_gettimeofday = real_gettimeofday;
  }
  fast_gettimeofday = dlsym(RTLD_NEXT, "mtev_gettimeofday");
  return rv;
}

void time_fast_init(void) __attribute__ ((constructor));
void time_fast_init(void) {
  real_gethrtime =  dlsym(RTLD_NEXT, "gethrtime");
  real_gettimeofday =  dlsym(RTLD_NEXT, "gettimeofday");
}
