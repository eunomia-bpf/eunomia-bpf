#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "eunomia/eunomia-bpf.h"

const char *
read_file_data(const char *path)
{
    int res;
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    res = fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    res = fseek(fp, 0, SEEK_SET);
    char *data = malloc((size_t)size + 1);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    res = fread(data, (size_t)size, 1, fp);
    data[size] = '\0';
    res = fclose(fp);
    return data;
}

int
test_create_and_stop()
{
    const char *data = read_file_data("../../test/asserts/package.json");
    struct eunomia_bpf *ctx = open_eunomia_skel_from_json_package(data);
    assert(ctx);
    destroy_eunomia_skel(ctx);
    free((void *)data);
    return 0;
}

int
test_create_and_run()
{
    const char *data = read_file_data("../../test/asserts/package.json");
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
    const char *data = read_file_data("../../test/asserts/package.json");
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
    test_create_and_run_multi();
    return 0;
}
