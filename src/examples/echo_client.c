/**
 * Takes a compression encoding and a string from params
 * and submits them to the echo_server for decompression testing
 * 
 * Verifies it gets back the same string as it sent.
 */

#include <mtev_http.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

size_t process_response(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  const char *original_string = (const char *)userdata;
  if (strncmp(ptr, original_string, size) != 0) {
    printf("FAIL! Orig: %s, response: %s\n", original_string, ptr);
    exit(1);
  } else {
    printf("SUCCESS! Orig: %s, response: %s\n", original_string, ptr);
  }
  return size;
}

int main(int argc, char **argv)
{
  if (argc != 3) {
    printf("Usage:\n\n\t./echo_client <compression> \"<string>\"\n\n");
    printf("\tWhere <compression> is either 'gzip', 'lz4f', or 'none'\n");
    printf("\tWhere <string> is what you want to echo (should be quoted)\n");
    exit(1);

  }
  char content_encoding_header[64];
  const char *compression = argv[1];
  const char *string = argv[2];
  unsigned char *payload = NULL;
  size_t len = 0;

  if (strcmp("gzip", compression) == 0) {
    mtev_http_gzip(string, strlen(string), &payload, &len);
  } else if (strcmp("lz4f", compression) == 0) {
    mtev_http_lz4f(string, strlen(string), &payload, &len);
  } else if (strcmp("none", compression) == 0) {
    payload = (unsigned char *)string;
    len = strlen(string);
  } else {
    printf("<compression> must be either 'gzip', 'lz4f' or 'none' \n");
    exit(1);
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  struct curl_slist *list = NULL;

  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1");
  curl_easy_setopt(curl, CURLOPT_PORT, 8888);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, string);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, process_response);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);  
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
  if (strcmp("none", compression) != 0) {
    sprintf(content_encoding_header, "Content-encoding: %s", compression);
    list = curl_slist_append(list, content_encoding_header);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
  }

  int code = curl_easy_perform(curl); 
  
  
  return code;
}
