#include "mtev_logbuf.h"
#include <ck_spinlock.h>
#include <inttypes.h>
#include <stdio.h>

#define ALIGN_DECL(name, type) \
  struct _align_decl_##name {  \
    char fst;                  \
    type snd;                  \
  }
#define ALIGN_OF(name) ((size_t) & ((struct _align_decl_##name *) 0)->snd)

#define MTEV_LOGBUF_LOG_BUSY ((mtev_logbuf_log_t *) 0x1)
#define MTEV_LOGBUF_LOG_END ((mtev_logbuf_log_t *) 0x2)

/* buffer organization:
 *
 * starts with mtev_logbuf_log_t *, MTEV_LOGBUF_LOG_BUSY, or
 * MTEV_LOGBUF_LOG_END.
 * when BUSY, data is currently being written to the log.
 * when MTEV_LOGBUF_LOG_END, skips remaining data from the circular buffer,
 * wrapping around to beginning.
 * mtev_logbuf_log_t * describes organization of subsequent data.
 *
 * buffer is a circular buffer, indexed by next_read_idx and next_write_idx.
 * when `next_read_idx == next_write_idx` the buffer is assumed to be empty,
 * and `next_read_idx` and `next_write_idx` should both be set to 0.
 *
 * possible states:
 *
 * EMPTY:
 * +----------------------------+
 * |                            |
 * +----------------------------+
 * ^
 * |
 * next_read_idx, next_write_idx are always set 0 when empty.
 *
 * NON_EMPTY 1
 * +----------------------------+
 * |  ////////////              |
 * +----------------------------+
 *    ^           ^
 *    |           |
 *    |           next_write_idx
 *    next_read_idx
 *
 * NON_EMPTY 2
 * +----------------------------+
 * |//            //////////////|
 * +----------------------------+
 *    ^           ^
 *    |           |
 *    |           next_read_idx
 *    next_write_idx
 *
 */
typedef struct _mtev_logbuf_log_header_t {
  const mtev_logbuf_log_t *log;
  struct timeval log_time;
} mtev_logbuf_log_header_t;

ALIGN_DECL(byte, char);
ALIGN_DECL(string, const char *);
ALIGN_DECL(pointer, void *);
ALIGN_DECL(int32, int32_t);
ALIGN_DECL(uint32, uint32_t);
ALIGN_DECL(int64, int64_t);
ALIGN_DECL(uint64, uint64_t);
ALIGN_DECL(logbuf_log_header, mtev_logbuf_log_header_t);

struct _mtev_logbuf_t {
  size_t next_read_idx;
  size_t next_write_idx;
  ck_spinlock_t lock;
  size_t size;
  mtev_logbuf_log_header_t buffer[];
};

mtev_logbuf_t *mtev_logbuf_create(size_t size, mtev_logbuf_onfull_t on_full)
{
  size = size / ALIGN_OF(logbuf_log_header) * ALIGN_OF(logbuf_log_header);
  if (!size) return 0;

  size += sizeof(mtev_logbuf_t);
  mtev_logbuf_t *rval = (mtev_logbuf_t *) calloc(1, size);
  rval->next_read_idx = 0;
  rval->next_write_idx = 0;
  ck_spinlock_init(&rval->lock);
  rval->size = size;
  return rval;
}
void mtev_logbuf_destroy(mtev_logbuf_t *logbuf)
{
  free((void *) logbuf);
}

mtev_logbuf_log_t *mtev_logbuf_create_log(const char *name, mtev_logbuf_el_t *args, size_t nargs)
{
  mtev_logbuf_log_t *rval = (mtev_logbuf_log_t *) calloc(1, sizeof(mtev_logbuf_log_t) +
                                                           nargs * sizeof(rval->arg_offsets[0]));
  rval->name = name;
  rval->size = 0;
  rval->align = ALIGN_OF(logbuf_log_header);
  rval->nargs = nargs;
  rval->args = calloc(nargs, sizeof(mtev_logbuf_el_t));
  for (size_t index = 0; index < nargs; index++) {
    rval->args[index].descr = args[index].descr;
    rval->args[index].type = args[index].type;
    size_t arg_size = 0;
    size_t arg_align = 0;
    switch (args[index].type) {
    case MTEV_LOGBUF_TYPE_EMPTY:
      /* no data stored in log buffer */
      rval->arg_offsets[index] = 0;
      continue;
    case MTEV_LOGBUF_TYPE_STRING:
      arg_size = sizeof(const char *);
      arg_align = ALIGN_OF(string);
      break;
    case MTEV_LOGBUF_TYPE_POINTER:
      arg_size = sizeof(void *);
      arg_align = ALIGN_OF(pointer);
      break;
    case MTEV_LOGBUF_TYPE_INT32:
      arg_size = sizeof(int32_t);
      arg_align = ALIGN_OF(int32);
      break;
    case MTEV_LOGBUF_TYPE_INT64:
      arg_size = sizeof(int64_t);
      arg_align = ALIGN_OF(int64);
      break;
    case MTEV_LOGBUF_TYPE_UINT32:
      arg_size = sizeof(uint32_t);
      arg_align = ALIGN_OF(uint32);
      break;
    case MTEV_LOGBUF_TYPE_UINT64:
      arg_size = sizeof(uint64_t);
      arg_align = ALIGN_OF(uint64);
    default:
      free((void *) rval);
      return 0;
    }
    mtevAssert(arg_size != 0);
    mtevAssert(arg_align != 0);

    if (arg_align > rval->align) rval->align = arg_align;
    rval->arg_offsets[index] = ((rval->size + arg_align - 1) / arg_align) * arg_align;
    rval->size = rval->arg_offsets[index] + arg_size;
  }
  rval->size = (rval->size + ALIGN_OF(logbuf_log_header)) / ALIGN_OF(logbuf_log_header) *
    ALIGN_OF(logbuf_log_header);
  return rval;
}

void mtev_logbuf_destroy_log(mtev_logbuf_log_t *log)
{
  free((void *) log->args);
  free((void *) log);
}

void *mtev_logbuf_log_start(mtev_logbuf_t *logbuf, const mtev_logbuf_log_t *log, struct timeval now)
{
  /* data starts with an mtev_logbuf_log_header_t *; then size data.
   * but we also need to make sure there's room for an
   * mtev_logbuf_log_t * at the end of the buffer. */
  size_t needed = sizeof(mtev_logbuf_log_header_t) + log->size + sizeof(mtev_logbuf_log_t *);
  ck_spinlock_lock(&logbuf->lock);
  /* calculate free space from logbuf. */
  size_t avail_fst;
  size_t avail_snd;
  if (logbuf->next_write_idx >= logbuf->next_read_idx) {
    avail_fst = logbuf->size - logbuf->next_write_idx;
    avail_snd = logbuf->next_read_idx;
  }
  else {
    avail_fst = logbuf->next_read_idx - logbuf->next_write_idx;
    avail_snd = 0;
  }

  mtev_logbuf_log_header_t *next_write_address =
    (mtev_logbuf_log_header_t *) (((char *) logbuf->buffer) + logbuf->next_write_idx);
  if (avail_fst < needed) {
    if (avail_snd < needed) {
      ck_spinlock_unlock(&logbuf->lock);
      return 0;
    }
    /* not enough room to write past the end of the write-index, so mark that as
     * "complete",
     * and start filling in from the beginning of the circular buffer. */
    next_write_address->log = MTEV_LOGBUF_LOG_END;
    logbuf->next_write_idx = needed - sizeof(mtev_logbuf_log_t *);
    next_write_address = logbuf->buffer;
    *((mtev_logbuf_log_t **) next_write_address) = MTEV_LOGBUF_LOG_BUSY;
  }
  else {
    *((mtev_logbuf_log_t **) next_write_address) = MTEV_LOGBUF_LOG_BUSY;
    logbuf->next_write_idx += needed - sizeof(mtev_logbuf_log_t *);
  }
  ck_spinlock_unlock(&logbuf->lock);
  next_write_address->log_time = now;
  /* data that gets written to immediately follows the write header. */
  return (void *) &next_write_address[1];
}

void mtev_logbuf_log_commit(const mtev_logbuf_log_t *log, void *buf)
{
  /* fill in the write header with the `mtev_logbuf_log_t *` for this log. */
  char *headeraddr = ((char *) buf) - sizeof(mtev_logbuf_log_header_t);
  ((mtev_logbuf_log_header_t *) headeraddr)->log = log;
}

mtev_logbuf_log_header_t *mtev_logbuf_read_one_locked(mtev_logbuf_t *logbuf)
{
  if (logbuf->next_read_idx == logbuf->next_write_idx) {
    mtevAssert(logbuf->next_read_idx == 0);
    return 0;
  }
  char *read_address = ((char *) logbuf->buffer) + logbuf->next_read_idx;
  /* the spin-lock protects against updates to the read / write
   * indices... the write operation releases the spin-lock before
   * completing the write, so we need to wait for the write to
   * complete before we can get figure out how much data to read
   * out. */
  mtev_logbuf_log_header_t *read_header = (mtev_logbuf_log_header_t *) read_address;
  const mtev_logbuf_log_t *log;
  while (true) {
    log = ((volatile mtev_logbuf_log_header_t *) read_header)->log;
    if (log == MTEV_LOGBUF_LOG_END) {
      logbuf->next_read_idx = 0;
      read_header = logbuf->buffer;
      if (logbuf->next_write_idx == 0) return 0;
    }
    else if (log != MTEV_LOGBUF_LOG_BUSY)
      break;
  }

  logbuf->next_read_idx += sizeof(mtev_logbuf_log_header_t) + log->size;
  if (logbuf->next_read_idx == logbuf->next_write_idx)
    logbuf->next_read_idx = logbuf->next_write_idx = 0;
  return read_header;
}

void mtev_logbuf_reset(mtev_logbuf_t *logbuf)
{
  ck_spinlock_lock(&logbuf->lock);
  while (mtev_logbuf_read_one_locked(logbuf) != 0) continue;
  ck_spinlock_unlock(&logbuf->lock);
}

void mtev_logbuf_display_log(mtev_log_stream_t ls, mtev_logbuf_log_header_t *log_header)
{
  char display_buf[16384];
  char *wr_pos = display_buf;
  size_t wr_left = sizeof(display_buf);
  size_t arg_index;
  const mtev_logbuf_log_t *log = log_header->log;
  for (arg_index = 0; arg_index < log->nargs; arg_index++) {
    int wrote =
      snprintf(wr_pos, wr_left, " %s ", log->args[arg_index].descr);
    wr_pos += wrote;
    wr_left -= wrote;

    void *arg_ptr = (void *) ((char *)(log_header + 1) + log->arg_offsets[arg_index]);
    wrote = 0;
    switch (log->args[arg_index].type) {
    case MTEV_LOGBUF_TYPE_EMPTY:
      break;
    case MTEV_LOGBUF_TYPE_STRING:
      wrote = snprintf(wr_pos, wr_left, "%s", *(char **) arg_ptr);
      break;
    case MTEV_LOGBUF_TYPE_POINTER:
      wrote = snprintf(wr_pos, wr_left, "%p", *(void **) arg_ptr);
      break;
    case MTEV_LOGBUF_TYPE_INT32:
      wrote = snprintf(wr_pos, wr_left, "%" PRIi32, *(int32_t *) arg_ptr);
      break;
    case MTEV_LOGBUF_TYPE_INT64:
      wrote = snprintf(wr_pos, wr_left, "%" PRIi64, *(int64_t *) arg_ptr);
      break;
    case MTEV_LOGBUF_TYPE_UINT32:
      wrote = snprintf(wr_pos, wr_left, "%" PRIu32, *(uint32_t *) arg_ptr);
      break;
    case MTEV_LOGBUF_TYPE_UINT64:
      wrote = snprintf(wr_pos, wr_left, "%" PRIu64, *(uint64_t *) arg_ptr);
      break;
    default:
      break;
    }
    if (wrote < 0) *wr_pos = '\0';
    wr_pos += wrote;
    wr_left -= wrote;
    if (wr_left <= 1) break;
  }
  mtevLT(ls, &log_header->log_time, "%s:%s\n", log->name, display_buf);
}

void mtev_logbuf_dump(mtev_log_stream_t ls, mtev_logbuf_t *logbuf)
{
  /* maximum data to copy out from an individual log */
  char logdata[16384];
  size_t log_size;
  mtev_logbuf_log_header_t *log_header;
  const mtev_logbuf_log_t *log;
  do {
    log = 0;
    ck_spinlock_lock(&logbuf->lock);
    log_header = mtev_logbuf_read_one_locked(logbuf);
    if (log_header) {
      log = log_header->log;
      log_size = log->size + sizeof(mtev_logbuf_log_header_t);
      if (log_size < sizeof(logdata)) {
        memcpy(logdata, log_header, log_size);
        log_header = (mtev_logbuf_log_header_t *) logdata;
      }
      else
        log_header = 0;
    }
    ck_spinlock_unlock(&logbuf->lock);

    /* now working with our own private copy of the log data. */
    if (log_header) mtev_logbuf_display_log(ls, log_header);
  } while (log_header);
}
