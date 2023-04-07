enum E {
    E_A,
    E_B,
    E_C
};

struct S {
    int arr1[2][3][4];
    char str[20];
    char str_arr[10][20];
    float ft;
    double dbl;
    unsigned char u8v;
    signed char i8v;
    unsigned short u16v;
    signed short i16v;
    unsigned int u32v;
    signed int i32v;
    unsigned long long u64v;
    signed long long i64v;
    enum E e;
};

struct S* __dummy;
