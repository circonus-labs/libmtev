/*
 * Copyright (c) 2025, Circonus, Inc. All rights reserved.
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

#include "mtev_defines.h"
#include "mtev_log.h"
#include "mtev_hooks.h"
#include "mtev_dso.h"
#include "mtev_conf.h"
#include "mtev_rand.h"
#include "mtev_thread.h"

#define CONFIG_KAFKA_IN_MQ "//network//mq[@type='kafka']"

struct kafka_module_config {
  kafka_module_config() : number_of_conns{0} {}
  ~kafka_module_config() = default;

  int number_of_conns;
};

static mtev_log_stream_t nlerr = nullptr;
static mtev_log_stream_t nldeb = nullptr;
static kafka_module_config *the_conf = nullptr;

static kafka_module_config *get_config(mtev_dso_generic_t *self) {
  if(the_conf) {
    return the_conf;
  }
  the_conf = static_cast<kafka_module_config *>(mtev_image_get_userdata(&self->hdr));
  if(the_conf) {
    return the_conf;
  }
  the_conf = new kafka_module_config{};
  mtev_image_set_userdata(&self->hdr, the_conf);
  return the_conf;
}

static void
init_conns(void) {
  mtev_conf_section_t *mqs = mtev_conf_get_sections_read(MTEV_CONF_ROOT, CONFIG_KAFKA_IN_MQ,
      &the_conf->number_of_conns);

  if(the_conf->number_of_conns == 0) {
    mtev_conf_release_sections_read(mqs, the_conf->number_of_conns);
    return;
  }
  mtev_conf_release_sections_read(mqs, the_conf->number_of_conns);
}

static int
kafka_driver_config(mtev_dso_generic_t *img, mtev_hash_table *options) {
  return 0;
}

static int
kafka_driver_init(mtev_dso_generic_t *img) {
  auto conf = get_config(img);
  nlerr = mtev_log_stream_find("error/kafka");
  nldeb = mtev_log_stream_find("debug/kafka");

  init_conns();
  if (the_conf->number_of_conns == 0) {
    mtevL(nlerr, "No kafka reciever setting found in the config!\n");
    return 0;
  }
  return 0;
}

#include "kafka.xmlh"
mtev_dso_generic_t kafka = {
  {
    .magic = MTEV_GENERIC_MAGIC,
    .version = MTEV_GENERIC_ABI_VERSION,
    .name = "kafka",
    .description = "A Kafka subscriber and publisher",
    .xml_description = kafka_xml_description,
  },
  kafka_driver_config,
  kafka_driver_init
};