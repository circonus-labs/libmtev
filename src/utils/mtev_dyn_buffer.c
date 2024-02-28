#include "mtev_dyn_buffer.h"
#include "mtev_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <yajl/yajl_gen.h>

extern void
yajl_string_encode(const yajl_print_t print, void * ctx,
                   const unsigned char * str, size_t len,
                   int escape_solidus);

static inline void
yajl_mtev_dyn_buff_append(void *ctx, const char *str, size_t len) {
  mtev_dyn_buffer_t *buff = (mtev_dyn_buffer_t *)ctx;
  mtev_dyn_buffer_add(buff, (uint8_t *)str, len);
}

inline void
mtev_dyn_buffer_init(mtev_dyn_buffer_t *buf)
{
  buf->data = buf->static_buffer;
  buf->pos = buf->data;
  buf->size = sizeof(buf->static_buffer);
}

inline void
mtev_dyn_buffer_add(mtev_dyn_buffer_t *buf, const void *data, size_t len)
{
  mtev_dyn_buffer_ensure(buf, len);
  memcpy(buf->pos, data, len);
  buf->pos += len;
}

inline void
mtev_dyn_buffer_add_json_string(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len, int sol) {
  yajl_string_encode(yajl_mtev_dyn_buff_append, buf, (void *)data, len, sol);
}

inline void
mtev_dyn_buffer_add_vprintf(mtev_dyn_buffer_t *buf, const char *format, va_list args)
{
  int needed, available;
  va_list arg_copy;

  // vsnprirntf can be called twice in this function and calling it alters the va_list
  // argument in a destructive manner, so we need to make a copy
  va_copy(arg_copy, args);
  available = mtev_dyn_buffer_size(buf) - mtev_dyn_buffer_used(buf);
  needed = vsnprintf((char *)buf->pos, available, format, args);
  if (needed > (available - 1)) {
    mtev_dyn_buffer_ensure(buf, needed + 1); /* ensure we have space for the trailing NUL too */
    needed = vsnprintf((char *)buf->pos, needed + 1, format, arg_copy);
  }
  buf->pos += needed;
  va_end(arg_copy);
}

inline int
mtev_dyn_buffer_maybe_add_vprintf(mtev_dyn_buffer_t *buf, const char *format, va_list args) {
  int available = mtev_dyn_buffer_size(buf) - mtev_dyn_buffer_used(buf);
  int needed = vsnprintf((char *)buf->pos, available, format, args);
  if (needed > (available - 1)) {
    if (available > 0) {
      *(buf->pos) = 0;
    }
    return needed + 1;
  }
  buf->pos += needed;
  return 0;
}

inline void
mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...)
{
  va_list args;
  va_start(args, format);
  int needed = mtev_dyn_buffer_maybe_add_vprintf(buf, format, args);
  if (needed) {
    mtev_dyn_buffer_ensure(buf, needed); /* ensure we have space for the trailing NUL too */
    va_end(args);
    va_start(args, format);
    mtevAssert(mtev_dyn_buffer_maybe_add_vprintf(buf, format, args) == 0);
  }
  va_end(args);
}

inline void
mtev_dyn_buffer_ensure(mtev_dyn_buffer_t *buf, size_t len)
{
  size_t used = mtev_dyn_buffer_used(buf);
  size_t new_size = 0;
  if (buf->size < (used + len)) {
    if (buf->data == buf->static_buffer) {
      new_size = (used + len) * 2;
      buf->data = malloc(new_size);
      memcpy(buf->data, buf->static_buffer, used);
    } else {
      new_size = MAX(buf->size * 2, used + len);
      buf->data = realloc(buf->data, new_size);
    }
    buf->pos = buf->data + used;
    buf->size = new_size;
  }
}

inline size_t
mtev_dyn_buffer_used(mtev_dyn_buffer_t *buf)
{
  return buf->pos - buf->data;
}

inline size_t
mtev_dyn_buffer_size(mtev_dyn_buffer_t *buf)
{
  return buf->size;
}

inline uint8_t *
mtev_dyn_buffer_data(mtev_dyn_buffer_t *buf) 
{
  return buf->data;
}

inline uint8_t *
mtev_dyn_buffer_write_pointer(mtev_dyn_buffer_t *buf) 
{
  return buf->pos;
}

inline void
mtev_dyn_buffer_advance(mtev_dyn_buffer_t *buf, size_t len) 
{
  buf->pos += len;
}

inline void 
mtev_dyn_buffer_reset(mtev_dyn_buffer_t *buf)
{
  buf->pos = buf->data;
}

inline void 
mtev_dyn_buffer_destroy(mtev_dyn_buffer_t *buf)
{
  if (buf->data != buf->static_buffer) {
    free(buf->data);
  }
  mtev_dyn_buffer_init(buf);
}

inline uint8_t *
mtev_dyn_buffer_destroy_detach_data(mtev_dyn_buffer_t *buf)
{
  uint8_t *data = buf->data;
  size_t length = buf->pos - data;
  if (data == buf->static_buffer || length == buf->size) {
    data = (uint8_t *)malloc(length + 1);
    memcpy(data, buf->data, length);
    if (buf->data != buf->static_buffer) { free(buf->data); }
  }
  mtev_dyn_buffer_init(buf);
  *(data + length) = 0;
  return data;
}

size_t
mtev_dyn_curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  mtev_dyn_buffer_add((mtev_dyn_buffer_t *)userdata, (uint8_t *)ptr, size * nmemb);
  return size *nmemb;
}
