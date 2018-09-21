#include <stdio.h>
#include <mtev_defines.h>
#include <mtev_compress.h>
#include <curl/curl.h>

static size_t print_data(void *buff, size_t s, size_t n, void *vd) {
  return write(1, buff, s*n);
}
int main(int argc, char **argv) {
  int rv = 0;
  if(argc != 2) {
    fprintf(stderr, "%s <url>\n", argv[0]);
    exit(-1);
  }
  CURL *curl = curl_easy_init();
  mtev_decompress_curl_helper_t *data_helper = mtev_decompress_create_curl_helper(
      (curl_write_callback) print_data, NULL, MTEV_COMPRESS_LZ4F);
  curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, data_helper);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mtev_curl_write_callback);
  struct curl_slist *headers = curl_slist_append(NULL, "Accept-Encoding: lz4f");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  CURLcode code = curl_easy_perform(curl);
  long httpcode;
  if(CURLE_OK != code ||
     CURLE_OK != curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode) ||
     httpcode != 200) {
    fprintf(stderr, "[%ld] Error: %s\n", httpcode, curl_easy_strerror(code));
    rv = -1;
  }
  curl_easy_cleanup(curl);
  curl_slist_free_all(headers);
  mtev_decompress_destroy_curl_helper(data_helper);
  exit(rv);
}
