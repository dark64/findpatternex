#include <stdio.h>
#include "findpattern.h"

int main()
{
    BYTE bytes[] =
    {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x54,
        0xA3, 0xFC, 0x10, 0x20, 0x30, 0x40,
        0xF1, 0xAC, 0x20, 0x24, 0x64, 0xA4
    };

    DWORD dwOut;
    if (FindPattern<DWORD>((PBYTE)&bytes, ARRAYSIZE(bytes), "A3 FC ? ? ? ? F1 AC", 2, &dwOut))
        printf("FindPattern: %x\n", dwOut);

    if (FindPatternEx<DWORD>(GetCurrentProcess(), (PBYTE)&bytes, ARRAYSIZE(bytes), "A3 FC ? ? ? ? F1 AC", 2, &dwOut))
        printf("FindPatternEx: %x", dwOut);

    return 0;
}
