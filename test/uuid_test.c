#include <uuid/uuid.h>
#include <mtev_uuid.h>
#include <mtev_time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>

#define FAIL(...)                           \
  printf("** ");                            \
  printf( __VA_ARGS__);                     \
  printf("\n** FAILURE\n"); \
  exit(1);


static mtev_hrtime_t total_time = 0;

int (*uuid_parse_fn)(const char *in, uuid_t out) = NULL;



int parse_both(const char *in, uuid_t out) 
{
  uuid_t again;
  int x = mtev_uuid_parse(in, out);

  int y = uuid_parse(in, again);

  int z = memcmp(out, again, sizeof(uuid_t));
  if (z != 0) {
    FAIL("mtev_uuid_parse does not match uuid_parse for '%s'", in);
    return 1;
  }
  return 0;
}

void parse_file(void)
{
  char uuid[UUID_STR_LEN + 1];
  uuid_t result;
  FILE *f = fopen("uuids.txt", "r");

  char c = getc(f);
  int i = 0;
   
  while ((c != (char)EOF)) {
    if (c == '\n') {

      uuid[UUID_STR_LEN] = '\0';
      mtev_hrtime_t now = mtev_gethrtime();
      int x = uuid_parse_fn(uuid, result);
      mtev_hrtime_t end = mtev_gethrtime();
      total_time += end - now;
      if (x != 0) {
        FAIL("Cannot parse!");
      }
      i = 0;
    } else {
      uuid[i++] = c;
    }
    c = getc(f);
  }
  fclose(f);

}

int main(int argc, char **argv) 
{
  uuid_parse_fn = mtev_uuid_parse;
  for (int i = 0; i < 1000000/500; i++) {
    parse_file();
  }

  printf("* Total parse time (mtev): %llu\n", total_time);
  uint64_t mtev_time = total_time;
  total_time = 0;

  uuid_parse_fn = uuid_parse;
  for (int i = 0; i < 1000000/500; i++) {
    parse_file();
  }

  printf("* Total parse time (libuuid): %llu\n", total_time);

  printf("* Speedup: %3.2fx\n", (double)total_time / (double) mtev_time);

  uuid_parse_fn = parse_both;
  for (int i = 0; i < 1000000/500; i++) {
    parse_file();
  }

  printf("* mtev_uuid_parse and uuid_parse achieve same memory\n");

  /* test upcase */
  const char *upcase = "2F711A8C-E6A1-CE2E-CC52-82AAC2906D08";
  uuid_t uc;

  if (mtev_uuid_parse(upcase, uc) != 0) {
    FAIL("Failed to parse upcase!");
  }

  uuid_t uc2;
  if (uuid_parse(upcase, uc2) != 0) {
    FAIL("libuuid failed to parse upcase, wat?");
  }

  if (memcmp(uc, uc2, sizeof(uuid_t)) != 0) {
    FAIL("libuuid and mtev parse do not match on UPCASE");
  }

  printf("* UPCASE parse succeeds\n");

  /* 'hyphen' separator missing */
  const char *broken = "2f711a8c-e6a1-ce2ecc52-82aac2906d08";
  if (mtev_uuid_parse(broken, uc) != -1) {
    FAIL("Expected parse failure 1!");
  }

  /* contains non-hex digit */
  const char *broken2 = "2f711a8c-e6a1-ce2e-hc52-82aac2906d08";
  if (mtev_uuid_parse(broken2, uc) != -1) {
    FAIL("Expected parse failure 2!");
  }

  /* input length one-too-small */
  const char *broken3 = "2f711a8c-e6a1-ce2e-ec52-82aac2906d0";
  if (mtev_uuid_parse(broken3, uc) != -1) {
    FAIL("Expected parse failure 3!");
  }

  /* input length two-too-small */
  const char *broken4 = "2f711a8c-e6a1-ce2e-ec52-82aac2906d";
  if (mtev_uuid_parse(broken4, uc) != -1) {
    FAIL("Expected parse failure 4!");
  }

  /* input length one-too-large */
  const char *broken5 = "2f711a8c-e6a1-ce2e-ec52-82aac2906d080";
  if (mtev_uuid_parse(broken3, uc) != -1) {
    FAIL("Expected parse failure 5!");
  }

  /* input length two-too-large */
  const char *broken6 = "2f711a8c-e6a1-ce2e-ec52-82aac2906d0801";
  if (mtev_uuid_parse(broken6, uc) != -1) {
    FAIL("Expected parse failure 6!");
  }

  printf("* Broken UUIDs expectedly fail\n");

  mtev_hrtime_t libuuid_time = 0;
  mtev_hrtime_t gstart, gend;

  gstart = mtev_gethrtime();
  for (int i = 0; i < 10000; i++) {
    uuid_t x;
    uuid_generate(x);
  }
  libuuid_time = mtev_gethrtime() - gstart;

  gstart = mtev_gethrtime();
  uuid_t last_uuid;
  mtev_uuid_clear(last_uuid);
  gstart = mtev_gethrtime();
  for (int i = 0; i < 10000; i++) {
    uuid_t x;
    mtev_uuid_generate(x);
    if(mtev_uuid_compare(x, last_uuid) == 0) {
      abort();
      FAIL("mtev_uuid_generate failed");
    }
    char expected[UUID_STR_LEN + 1];
    mtev_uuid_unparse(x, expected);
    mtev_uuid_copy(last_uuid, x);
  }
  mtev_time = mtev_gethrtime() - gstart;
  printf("* generate speedup: %3.2fx\n", (double)libuuid_time / (double) mtev_time);
  

  libuuid_time = mtev_gethrtime() - gstart;
  mtev_time = 0;
  libuuid_time = 0;
  for (int i = 0; i < 5000; i++) {
    uuid_t x;
    uuid_generate(x);
    char expected[UUID_STR_LEN + 1];
    mtev_hrtime_t now = mtev_gethrtime();
    uuid_unparse_lower(x, expected);
    mtev_hrtime_t end = mtev_gethrtime();
    libuuid_time += end - now;

    char test[UUID_STR_LEN + 1];
    now = mtev_gethrtime();
    mtev_uuid_unparse_lower(x, test);
    end = mtev_gethrtime();
    mtev_time += end - now;
    
    if (strncmp(expected, test, UUID_STR_LEN) != 0) {
      FAIL("uuid_unparse_lower and mtev_variant do not equal: %s : %s\n", expected, test);
    }

    now = mtev_gethrtime();
    uuid_unparse_upper(x, expected);
    end = mtev_gethrtime();
    libuuid_time += end - now;

    now = mtev_gethrtime();
    mtev_uuid_unparse_upper(x, test);
    end = mtev_gethrtime();
    mtev_time += end - now;
    
    if (strncmp(expected, test, UUID_STR_LEN) != 0) {
      FAIL("uuid_unparse_upper and mtev_variant do not equal: %s : %s\n", expected, test);
    }

    now = mtev_gethrtime();
    uuid_unparse(x, expected);
    end = mtev_gethrtime();
    libuuid_time += end - now;

    now = mtev_gethrtime();
    mtev_uuid_unparse(x, test);
    end = mtev_gethrtime();
    mtev_time += end - now;
    
    if (strncasecmp(expected, test, UUID_STR_LEN) != 0) {
      printf("Expected: %s, got: %s\n", expected, test);
      FAIL("uuid_unparse and mtev_variant do not equal: %s : %s\n", expected, test);
    }
  }
  printf("libuuid unparse time: %llu\n", libuuid_time);
  printf("mtev unparse time: %" PRIu64 "\n", mtev_time);
  printf("* Speedup: %3.2fx\n", (double)libuuid_time / (double) mtev_time);
  
  printf("* SUCCESS\n");
}
