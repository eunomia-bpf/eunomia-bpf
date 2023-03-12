/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <zlib.h>
#include "btf_helpers.h"

#define FIELD_LEN 65

// sources: bcc btf_helpers
// https://github.com/iovisor/bcc/blob/master/libbpf-tools/btf_helpers.c

struct os_info {
    char id[FIELD_LEN];
    char version[FIELD_LEN];
    char arch[FIELD_LEN];
    char kernel_release[FIELD_LEN];
};

static struct os_info* get_os_info() {
    struct os_info* info = NULL;
    struct utsname u;
    size_t len = 0;
    ssize_t read;
    char* line = NULL;
    FILE* f;

    if (uname(&u) == -1)
        return NULL;

    f = fopen("/etc/os-release", "r");
    if (!f)
        return NULL;

    info = calloc(1, sizeof(*info));
    if (!info)
        goto out;

    strncpy(info->kernel_release, u.release, FIELD_LEN);
    strncpy(info->arch, u.machine, FIELD_LEN);

    while ((read = getline(&line, &len, f)) != -1) {
        if (sscanf(line, "ID=%64s", info->id) == 1)
            continue;

        if (sscanf(line, "VERSION_ID=\"%64s", info->version) == 1) {
            info->version[strlen(info->version) - 1] = 0;
            continue;
        }
    }
out:
    free(line);
    fclose(f);

    return info;
}

char* get_btf_path(const char* path) {
    struct os_info* info = NULL;
    char name_fmt[] = "%s/%s/%s/%s.btf";
    char name[100];
    int ret;

    info = get_os_info();
    if (!info)
        return NULL;

    ret = snprintf(name, sizeof(name), name_fmt, info->id, info->version,
                   info->arch, info->kernel_release);
    if (ret < 0 || ret == sizeof(name))
        return NULL;

    char* result = malloc(strlen(path) + strlen(name) + 2);
    if (!result) {
        free(info);
        return NULL;
    }
    sprintf(result, "%s/%s", path, name);

    free(info);
    return result;
}
