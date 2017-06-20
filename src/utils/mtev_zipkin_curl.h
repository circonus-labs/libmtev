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

#ifndef MTEV_ZIPKIN_CURL_H
#define MTEV_ZIPKIN_CURL_H

#include <mtev_defines.h>
#include <mtev_zipkin.h>
#include <curl/curl.h>

static inline struct curl_slist *
mtev_zipkin_inst_curl_headers_name(struct curl_slist *inheaders,
                                   const char *uri) {
  char name[1024];
  char hdr[128];
  snprintf(name, sizeof(name), "curl: %s", uri);
  mtev_zipkin_client_new(NULL, name, true);
  if(mtev_zipkin_client_trace_hdr(NULL, hdr, sizeof(hdr))) {
    inheaders = curl_slist_append(inheaders, hdr);
    inheaders = curl_slist_append(inheaders, HEADER_ZIPKIN_SAMPLED ": 1");
  }
  if(mtev_zipkin_client_parent_hdr(NULL, hdr, sizeof(hdr)))
    inheaders = curl_slist_append(inheaders, hdr);
  if(mtev_zipkin_client_span_hdr(NULL, hdr, sizeof(hdr)))
    inheaders = curl_slist_append(inheaders, hdr);
  return inheaders;
}
static inline struct curl_slist *
mtev_zipkin_inst_curl_headers(struct curl_slist *inheaders) {
  static const char *curl_name = "request";
  return mtev_zipkin_inst_curl_headers_name(inheaders, curl_name);
}

static inline CURLcode mtev_zipkin_curl_easy_perform(CURL *curl) {
  static const char *zipkin_http_uri = "http.uri";
  static const char *zipkin_http_status = "http.status_code";
  static const char *zipkin_peer_port = "peer.port";
  static const char *zipkin_peer_ipv4 = "peer.ipv4";
  static const char *zipkin_peer_ipv6 = "peer.ipv6";
  Zipkin_Span *span = mtev_zipkin_client_span(NULL);
  CURLcode rv;

  if(!span) return curl_easy_perform(curl);
 
  long httpcode = 0;
  long port = 0;
  char *ip = NULL;
  char *url = NULL;

  mtev_zipkin_span_annotate(span, NULL, ZIPKIN_CLIENT_SEND, false);
  rv = curl_easy_perform(curl);
  if(CURLE_OK == curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode)) {
    mtev_zipkin_span_bannotate_i32(span, zipkin_http_status, false, httpcode);
  }
  if(CURLE_OK == curl_easy_getinfo(curl, CURLINFO_PRIMARY_PORT, &port) && port) {
    mtev_zipkin_span_bannotate_i32(span, zipkin_peer_port, false, port);
  }
  if(CURLE_OK == curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &ip) && ip) {
    if(strchr(ip, ':'))
      mtev_zipkin_span_bannotate_str(span, zipkin_peer_ipv6, false, ip, true);
    else
      mtev_zipkin_span_bannotate_str(span, zipkin_peer_ipv4, false, ip, true);
  }
  if(CURLE_OK == curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &url) && url) {
    mtev_zipkin_span_bannotate_str(span, zipkin_http_uri, false, url, true);
  }
  mtev_zipkin_span_annotate(span, NULL, ZIPKIN_CLIENT_RECV, false);
  mtev_zipkin_client_publish(NULL);
  return rv;
}

#endif
