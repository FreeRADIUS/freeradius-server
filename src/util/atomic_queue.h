#include <talloc.h>
#include <stdbool.h>

typedef struct fr_atomic_queue_t fr_atomic_queue_t;

fr_atomic_queue_t *fr_atomic_queue_create(TALLOC_CTX *ctx, int size);
bool fr_atomic_queue_push(fr_atomic_queue_t *aq, void *data);
bool fr_atomic_queue_pop(fr_atomic_queue_t *aq, void **p_data);

#ifndef NDEBUG
void fr_atomic_queue_debug(fr_atomic_queue_t *aq, FILE *fp);
#endif
