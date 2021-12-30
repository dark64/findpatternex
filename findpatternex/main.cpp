#include <Windows.h>
#include <stdio.h>

#define InRange(x, a, b)    (x >= a && x <= b) 
#define GetBits(x)		    (InRange(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define GetByte(x)	        (GetBits(x[0]) << 4 | GetBits(x[1]))

template <typename T>
BOOL FindPatternEx(HANDLE hProcess, PBYTE pBaseAddress, DWORD dwSize, LPCSTR CONST lpPattern, DWORD dwOffset, T* pOut)
{
    PBYTE pBuffer = new BYTE[dwSize];
    if (!ReadProcessMemory(hProcess, (LPVOID)pBaseAddress, pBuffer, dwSize, NULL))
    {
        delete[] pBuffer;
        return FALSE;
    }

    LPCSTR lpAcc = lpPattern;
    PBYTE  pMatch = NULL;

    for (PBYTE i = pBuffer; i < pBuffer + dwSize; ++i)
    {
        if (*lpAcc == '?' || *i == GetByte(lpAcc))
        {
            if (!pMatch) pMatch = i;
            lpAcc += (*lpAcc != '?') ? 3 : 2;
            if (!*lpAcc)
            {
                *pOut = *(T*)(pBaseAddress + (pMatch - pBuffer) + dwOffset);
                break;
            }
        }
        else if (pMatch)
        {
            i = pMatch;
            lpAcc = lpPattern;
            pMatch = NULL;
        }
    }

    delete[] pBuffer;
    return pMatch != NULL;
}

template <typename T>
BOOL FindPattern(PBYTE pBaseAddress, DWORD dwSize, LPCSTR CONST lpPattern, DWORD dwOffset, T* pOut)
{
    LPCSTR lpAcc = lpPattern;
    PBYTE  pMatch = NULL;

    for (PBYTE i = pBaseAddress; i < pBaseAddress + dwSize; ++i)
    {
        if (*lpAcc == '?' || *i == GetByte(lpAcc))
        {
            if (!pMatch) pMatch = i;
            lpAcc += (*lpAcc != '?') ? 3 : 2;
            if (!*lpAcc)
            {
                *pOut = *(T*)(pMatch + dwOffset);
                break;
            }
        }
        else if (pMatch)
        {
            i = pMatch;
            lpAcc = lpPattern;
            pMatch = NULL;
        }
    }
    return pMatch != NULL;
}

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
