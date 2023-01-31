/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2023, eunomia-bpf
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "eunomia/eunomia-bpf.h"

const char *
read_file_data(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *data = malloc((size_t)size + 1);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    fread(data, (size_t)size, 1, fp);
    data[size] = '\0';
    fclose(fp);
    return data;
}

int
test_create_and_stop()
{
    const char *data = read_file_data("../../test/asserts/bootstrap.json");
    struct eunomia_bpf *ctx = open_eunomia_skel_from_json_package(data);
    assert(ctx);
    destroy_eunomia_skel(ctx);
    free((void *)data);
    return 0;
}

int
test_create_args_and_stop()
{
    char *args[] = { "boostraps", "value1", "--arg2", "value2" };
    const char *data = read_file_data("../../test/asserts/bootstrap.json");
    struct eunomia_bpf *ctx =
        open_eunomia_skel_from_json_package_with_args(data, args, 1);
    assert(ctx);
    destroy_eunomia_skel(ctx);
    ctx = open_eunomia_skel_from_json_package_with_args(data, args, 2);
    assert(!ctx);

    char outbuffer[1024];
    int res = parse_args_to_json_config(data, args, 1, outbuffer, 1024);
    assert(res < 0);
    free((void *)data);
    return 0;
}

int
test_create_and_run()
{
    const char *data = read_file_data("../../test/asserts/bootstrap.json");
    struct eunomia_bpf *ctx = open_eunomia_skel_from_json_package(data);
    assert(ctx);
    int res = load_and_attach_eunomia_skel(ctx);
    assert(res == 0);
    destroy_eunomia_skel(ctx);
    free((void *)data);
    return 0;
}

int
test_create_and_run_multi()
{
    const char *data = read_file_data("../../test/asserts/bootstrap.json");
    struct eunomia_bpf *ctx1 = open_eunomia_skel_from_json_package(data);
    assert(ctx1);
    int res = load_and_attach_eunomia_skel(ctx1);
    assert(res == 0);
    // run again, should fail
    res = load_and_attach_eunomia_skel(ctx1);
    assert(res == 0);

    struct eunomia_bpf *ctx2 = open_eunomia_skel_from_json_package(data);
    res = load_and_attach_eunomia_skel(ctx2);
    assert(res == 0);

    destroy_eunomia_skel(ctx1);
    destroy_eunomia_skel(ctx2);
    free((void *)data);
    return 0;
}

int
main(int argc, char **argv)
{
    test_create_and_stop();
    test_create_and_run();
    test_create_args_and_stop();
    test_create_and_run_multi();
    return 0;
}
