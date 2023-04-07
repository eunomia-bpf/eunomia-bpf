#include "dumper_test.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
int main() {
    struct S st;
    strcpy(st.str, "A-String");
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 0; k < 4; k++) {
                st.arr1[i][j][k] = (i << 16) + (j << 8) + k;
            }
        }
    }
    for (int i = 0; i < 10; i++) {
        char buf[20];
        sprintf(buf, "hello %d", i);
        strcpy(st.str_arr[i], buf);
    }
    st.ft = 1.23;
    st.dbl = 4.56;
    st.u8v = 0x12;
    st.u16v = 0x1234;
    st.u32v = 0x12345678;
    st.u64v = 0x123456789abcdef0;
    st.i8v = -0x12;
    st.i16v = -0x1234;
    st.i32v = -0x12345678;
    st.i64v = -0x123456789abcdef0;
    st.e = E_A;
    FILE* fp = fopen("dumper_test.bin", "w");
    assert(fp != NULL);
    fwrite(&st, sizeof(st), 1, fp);
    fclose(fp);

    return 0;
}
