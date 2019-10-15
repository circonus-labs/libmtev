/*
 * Copyright (c) 2017, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *    * Neither the name Circonus, Inc. nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MTEV_DYN_BUFFER_H
#define MTEV_DYN_BUFFER_H

#include <mtev_defines.h>
#include <stdarg.h>

/* a struct that uses up 4K of stack space but then dynamically grows
 * into heap space as you add to it
 * 
 * These are meant to be used on the stack ala:
 * 
 * mtev_dyn_buffer_t buf;
 * mtev_dyn_buffer_init(&buf);
 * mtev_dyn_buffer_add(&buf, "12345", 5);
 * mtev_dyn_buffer_add(&buf, "67890", 5);
 * printf((const char *)mtev_dyn_buffer_data(&buf)); // prints "1234567890"
 * mtev_dyn_buffer_destroy(&buf);
 */
typedef struct mtev_dyn_buffer {
  uint8_t static_buffer[4096];
  size_t size;
  uint8_t *data;
  uint8_t *pos;
} mtev_dyn_buffer_t;

/*! \fn void mtev_dyn_buffer_init(mtev_dyn_buffer_t *buf)
    \brief initialize a dyn_buffer
    \param buf the buffer to init
  
   Provided for completeness or non-stack allocations.
 */
API_EXPORT(void)
  mtev_dyn_buffer_init(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_add(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len)
    \brief add data to the dyn_buffer.
    \param buf the buffer to add to.
    \param data the data to add.
    \param len the size of the data to add.
 */
API_EXPORT(void)
  mtev_dyn_buffer_add(mtev_dyn_buffer_t *buf, const void *data, size_t len);

/*! \fn void mtev_dyn_buffer_add_json_string(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len)
    \brief add data to the dyn_buffer as an unquoted json-encoded string.
    \param buf the buffer to add to.
    \param data the data to add.
    \param len the size of the data to add.
    \param sol 1 to escape the solipsis, 0 otherwise.
 */
API_EXPORT(void)
  mtev_dyn_buffer_add_json_string(mtev_dyn_buffer_t *buf, uint8_t *data, size_t len, int sol);

/*! \fn void mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...)
    \brief add data to the dyn_buffer using printf semantics.
    \param buf the buffer to add to.
    \param format the printf style format string
    \param args printf arguments
    
    This does NUL terminate the format string but does not advance the write_pointer past
    the NUL.  Basically, the last mtev_dyn_buffer_add_printf will leave the resultant
    data NUL terminated.
    
 */
API_EXPORT(void)
  mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...);


/*! \fn void mtev_dyn_buffer_add_printf(mtev_dyn_buffer_t *buf, const char *format, ...)
    \brief add data to the dyn_buffer using printf semantics.
    \param buf the buffer to add to.
    \param format the printf style format string
    \param args printf arguments
    
    This does NUL terminate the format string but does not advance the write_pointer past
    the NUL.  Basically, the last mtev_dyn_buffer_add_printf will leave the resultant
    data NUL terminated.
    
 */
API_EXPORT(void)
  mtev_dyn_buffer_add_vprintf(mtev_dyn_buffer_t *buf, const char *format, va_list arg);

/*! \fn void mtev_dyn_buffer_ensure(mtev_dyn_buffer_t *buf, size_t len)
    \brief possibly grow the dyn_buffer so it can fit len bytes
    \param buf the buffer to ensure
    \param len the size of the data about to be added
 */
API_EXPORT(void)
  mtev_dyn_buffer_ensure(mtev_dyn_buffer_t *buf, size_t len);

/*! \fn void mtev_dyn_buffer_data(mtev_dyn_buffer_t *buf)
    \brief return the front of the dyn_buffer
    \param buf the buffer to get the pointer from.
    \return the pointer to the front (beginning) of the dyn_buffer
 */
API_EXPORT(uint8_t *)
  mtev_dyn_buffer_data(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_write_pointer(mtev_dyn_buffer_t *buf)
    \brief return the end of the dyn_buffer
    \param buf the buffer to get the pointer from.
    \return the pointer to the end of the dyn_buffer
 */
API_EXPORT(uint8_t *)
  mtev_dyn_buffer_write_pointer(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_advance(mtev_dyn_buffer_t *buf)
    \brief move the write_pointer forward len bytes
    \param buf the buffer to advance
 */
API_EXPORT(void)
mtev_dyn_buffer_advance(mtev_dyn_buffer_t *buf, size_t len);

/*! \fn void mtev_dyn_buffer_used(mtev_dyn_buffer_t *buf)
    \brief return the total used space of the buffer
    \param buf the buffer to get the used space from.
    \return the total used space of the buffer
 */
API_EXPORT(size_t)
  mtev_dyn_buffer_used(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_size(mtev_dyn_buffer_t *buf)
    \brief return the total size of the buffer
    \param buf the buffer to get the size from.
    \return the total size of the buffer
 */
API_EXPORT(size_t)
  mtev_dyn_buffer_size(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_reset(mtev_dyn_buffer_t *buf)
    \brief move the write position to the beginning of the buffer
    \param buf the buffer to reset.
 */
API_EXPORT(void)
  mtev_dyn_buffer_reset(mtev_dyn_buffer_t *buf);

/*! \fn void mtev_dyn_buffer_destroy(mtev_dyn_buffer_t *buf)
    \brief destroy the dyn_buffer
    \param buf the buffer to destroy
  
   This must be called at the end of dyn_buffer interactions in case the
   buffer has overflowed into dynamic allocation space.
 */
API_EXPORT(void)
  mtev_dyn_buffer_destroy(mtev_dyn_buffer_t *buf);

/*! \fn size_t mtev_curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
 *  \brief A function to pass as curls CURLOPT_WRITEFUNCTION
 */
API_EXPORT(size_t)
  mtev_dyn_curl_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
#endif
