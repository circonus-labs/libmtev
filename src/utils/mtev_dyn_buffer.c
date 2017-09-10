#include "mtev_dyn_buffer.h"

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>

inline void
mtev_dyn_buffer_init(mtev_dyn_buffer_t *buf)
{
  buf->data = buf->static_buffer;
  buf->pos = buf->data;
  buf->size = sizeof(buf->static_buffer);
}

inline void
mtev_dyn_buffer_add(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len)
{
  mtev_dyn_buffer_ensure(buf, len);
  memcpy(buf->pos, data, len);
  buf->pos += len;
}

inline void
mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...)
{
  va_list args;
  int needed, available;

  available = mtev_dyn_buffer_size(buf) - mtev_dyn_buffer_used(buf);

  va_start(args, format);
  needed = vsnprintf((char *)buf->pos, available, format, args);
  if (needed > (available - 1)) {
    mtev_dyn_buffer_ensure(buf, needed + 1); /* ensure we have space for the trailing NUL too */
    needed = vsnprintf((char *)buf->pos, needed + 1, format, args);
  }
  /* (v)snprintf ensures NUL termination */
  va_end(args);
  buf->pos += needed;
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
}
