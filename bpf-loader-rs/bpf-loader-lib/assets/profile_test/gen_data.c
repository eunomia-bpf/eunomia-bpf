#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
struct ST {
    uint32_t pid;
    uint32_t cpu_id;
    char comm[16];
    int32_t kstack_sz;
    int32_t ustack_sz;
    uint64_t kstack[128];
    uint64_t ustack[128];
};
int main() {
    struct ST data;
    memset(&data, 0, sizeof(data));
    assert(sizeof(data) == 2080);
    data.pid = 0x1234;
    data.cpu_id = 0x5678;
    strcpy(data.comm, "test-comm");
    data.kstack_sz = 16;
    data.ustack_sz = 128;
    for (int i = 0; i < data.kstack_sz; i++) {
        data.kstack[i] = (1 << 16) | i;
    }
    for (int i = 0; i < data.ustack_sz; i++) {
        data.ustack[i] = (1 << 16) | i;
    }
    FILE* fp = fopen("test.bin", "w");
    assert(fp);
    fwrite(&data, sizeof(data), 1, fp);
    fclose(fp);
    return 0;
}
