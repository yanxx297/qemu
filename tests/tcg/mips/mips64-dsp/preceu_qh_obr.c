#include "io.h"

int main(void)
{
    long long rd, rt, result;

    rt = 0x123456789ABCDEF0;
    result = 0x009A00BC00DE00F0;

    __asm
        ("preceu.qh.obr %0, %1\n\t"
         : "=r"(rd)
         : "r"(rt)
        );

    if (result != rd) {
        printf("preceu.qh.obr error\n");

        return -1;
    }

    return 0;
}
