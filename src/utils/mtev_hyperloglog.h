#ifndef MTEV_HYPER_LOG_LOG_H
#define MTEV_HYPER_LOG_LOG_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mtev_hyperloglog mtev_hyperloglog_t;

mtev_hyperloglog_t *mtev_hyperloglog_alloc(int bitcount);
void mtev_hyperloglog_destroy(mtev_hyperloglog_t *hll);

void mtev_hyperloglog_add(mtev_hyperloglog_t *hll, const void *data, size_t len);
double mtev_hyperloglog_size(mtev_hyperloglog_t *hll);

#ifdef __cplusplus
}
#endif

#endif
