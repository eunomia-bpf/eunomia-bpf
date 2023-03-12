//* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BTF_HELPERS_H
#define __BTF_HELPERS_H

#include <sys/types.h>
#include <unistd.h>
#include <gelf.h>

char* get_btf_path(const char* path);

#endif /* __BTF_HELPERS_H */
