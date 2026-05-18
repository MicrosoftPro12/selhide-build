/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SELHIDE_PATCH_MEMORY_H
#define SELHIDE_PATCH_MEMORY_H

#include <linux/types.h>

#define SELHIDE_PATCH_FLUSH_DCACHE 1
#define SELHIDE_PATCH_FLUSH_ICACHE 2

int selhide_read_kernel_nofault(void *dst, const void *src, size_t size);
int selhide_write_kernel_nofault(void *dst, const void *src, size_t size);
int selhide_patch_text(void *dst, const void *src, size_t len, int flags);

#endif
