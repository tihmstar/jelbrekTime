#ifndef V0RTEX_H
#define V0RTEX_H

#include <mach/mach.h>

#include "common.h"
#include "offsets.h"

typedef kern_return_t (*v0rtex_cb_t)(task_t tfp0, kptr_t kbase, void *data);

kern_return_t v0rtex(offsets_t *off, v0rtex_cb_t callback, void *cb_data);

#endif
