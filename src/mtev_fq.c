/*
 * Copyright (c) 2015, Circonus, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name OmniTI Computer Consulting, Inc. nor the names
 *       of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written
 *       permission.
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

#include "mtev_fq.h"

#include "mtev_log.h"
#include "mtev_conf.h"

#define CONFIG_FQ_IN "//network/in/mq"
#define CONFIG_FQ_HOST CONFIG_FQ_IN"/host"
#define CONFIG_FQ_PORT CONFIG_FQ_IN"/port"
#define CONFIG_FQ_USER CONFIG_FQ_IN"/user"
#define CONFIG_FQ_PASS CONFIG_FQ_IN"/pass"

void mtev_fq_init() {

  int cnt = 0;
  mtev_conf_section_t *mqs = mtev_conf_get_sections(NULL, CONFIG_FQ_IN, &cnt);

  if (cnt == 0) {
    mtevL(mtev_error, "No fq config found!\n");
    exit(2);
  }

  struct mtev_conf_description_t descs[] = { {
  CONFIG_FQ_HOST, MTEV_CONF_TYPE_STRING,
      "Hostname of the fq broker data should be received from" },

  { CONFIG_FQ_PORT, MTEV_CONF_TYPE_INT, "Port number of the fq broker" },

  { CONFIG_FQ_USER, MTEV_CONF_TYPE_STRING,
      "User name used to connect to the fq broker" },

  { CONFIG_FQ_PASS, MTEV_CONF_TYPE_STRING,
      "Password used to connect to the fq broker" } };

  if (mtev_conf_check(descs,
      sizeof(descs) / sizeof(struct mtev_conf_description_t)) != 0) {
    mtevL(mtev_error, "Incomplete fq config found!\n");
    exit(2);
  }

  char* type;
  mtev_conf_get_string(NULL, "//network/in/mq/@type",
          &type);


  mtevL(mtev_error, "Type: %s!\n", type);
      exit(2);


//
//  std::vector<std::string> strings(cnt);
//  for (int i = 0; i < cnt; i++) {
//    char *value = nullptr;
//    if (!mtev_conf_get_string(mqs[i], ("self::node()" + child_path).c_str(),
//        &value)) {
//      ERROR<< "Unable to read option entry: " <<parent_path<<child_path << endl;
//      exit(-1);
//    }
//    strings[i] = value;
//    free(value);
//  }



}
