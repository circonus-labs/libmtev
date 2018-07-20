/**
 * Takes a compression encoding and a string from params
 * and submits them to the echo_server for decompression testing
 * 
 * Verifies it gets back the same string as it sent.
 */

#include <mtev_compress.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

struct curl_response_buffer {
  size_t size;
  size_t allocd;
  char *data;
};

size_t process_response(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  size_t x = size * nmemb;
  struct curl_response_buffer *data = (struct curl_response_buffer *)userdata;
  if (data->size + x > data->allocd) {
    data->data = realloc(data->data, data->allocd + x + 1);
    data->allocd += x + 1;
  }
  memcpy(data->data + data->size, ptr, x);
  data->size += x;
  data->data[data->size] = '\0';
  return x;
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
  struct curl_response_buffer data = {0, 0, NULL};
  const char *compression = argv[1];
  const char *string = argv[2];
  unsigned char *payload = NULL;
  size_t len = 0;

  if (strcmp("gzip", compression) == 0) {
    mtev_compress_gzip(string, strlen(string), &payload, &len);
  } else if (strcmp("lz4f", compression) == 0) {
    mtev_compress_lz4f(string, strlen(string), &payload, &len);
  } else if (strcmp("none", compression) == 0) {
    payload = (unsigned char *)strdup(string);
    len = strlen(string);
  } else {
    printf("<compression> must be either 'gzip', 'lz4f' or 'none' \n");
    exit(1);
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);
  CURL *curl = curl_easy_init();
  struct curl_slist *list = NULL;

  mtev_decompress_curl_helper_t *data_helper = mtev_decompress_create_curl_helper((mtev_curl_write_func_t)process_response, &data, MTEV_COMPRESS_LZ4F);


  curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 0);
  curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1");
  curl_easy_setopt(curl, CURLOPT_PORT, 8888);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  if (strcmp("lz4f", compression) == 0) {
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, data_helper);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, mtev_curl_write_callback);
    snprintf(content_encoding_header, sizeof(content_encoding_header), "Accept-Encoding: %s", compression);
    list = curl_slist_append(list, content_encoding_header);
  }
  else {
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, process_response);
  }
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (char *)payload);
  if (strcmp("none", compression) != 0) {
    sprintf(content_encoding_header, "Content-encoding: %s", compression);
    list = curl_slist_append(list, content_encoding_header);
  }

  if (list) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
  }
  int code = curl_easy_perform(curl); 
  free(payload);
  mtev_decompress_destroy_curl_helper(data_helper);
  if (code != CURLE_OK) {
    printf("Curl returned error: %d: %s\n", code, curl_easy_strerror(code));
    exit(1);
  } else {

    printf("Received %lu bytes\n", data.size);
    if (data.size != strlen(string)) {
      printf("FAIL! Expected: %d bytes, got: %d bytes\n", (int)strlen(string), (int)data.size);
      exit(1);
    }

    if (strncmp(data.data, string, data.size) != 0) {
      printf("FAIL! Orig: %s, response: %s\n", string, data.data);
    } else {
      printf("SUCCESS! Orig: %s, response: %s\n", string, data.data);
    }
  }
  curl_easy_cleanup(curl);
  curl_global_cleanup();

  free(data.data);

  return code;
}
