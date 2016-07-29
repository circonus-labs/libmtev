#include <mtev_uuid_parse.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>

static mtev_hrtime_t total_time = 0;

int (*uuid_parse_fn)(const char *in, uuid_t out) = NULL;

int parse_both(const char *in, uuid_t out) 
{
  uuid_t again;
  int x = mtev_uuid_parse(in, out);

  int y = uuid_parse(in, again);

  int z = memcmp(out, again, sizeof(uuid_t));
  if (z != 0) {
    printf("mtev_uuid_parse does not match uuid_parse for '%s'\n", in);
    return 1;
  }
  return 0;
}

void parse_file()
{
  char uuid[UUID_STR_LEN + 1];
  uuid_t result;
  FILE *f = fopen("uuids.txt", "r");

  char c = getc(f);
  int i = 0;
   
  while ((c != EOF)) {
    if (c == '\n') {

      uuid[UUID_STR_LEN] = '\0';
      mtev_hrtime_t now = mtev_gethrtime();
      int x = uuid_parse_fn(uuid, result);
      mtev_hrtime_t end = mtev_gethrtime();
      total_time += end - now;
      if (x != 0) {
        printf("Cannot parse!");
        abort();
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

  printf("Total parse time (mtev): %llu\n", total_time);
  uint64_t mtev_time = total_time;
  total_time = 0;

  uuid_parse_fn = uuid_parse;
  for (int i = 0; i < 1000000/500; i++) {
    parse_file();
  }

  printf("Total parse time (libuuid): %llu\n", total_time);

  printf("Speedup: %3.2fx\n", (double)total_time / (double) mtev_time);

  uuid_parse_fn = parse_both;
  for (int i = 0; i < 1000000/500; i++) {
    parse_file();
  }

  printf("mtev_uuid_parse and uuid_parse achieve same memory\n");
  printf("SUCCESS\n");
}
