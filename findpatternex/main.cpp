#include <Windows.h>
#include <stdio.h>

#define IN_RANGE( x, a, b )	  (x >= a && x <= b) 
#define GET_BITS( x )		  (IN_RANGE(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define GET_BYTE( x )		  (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))

typedef struct
{
    const char*     name;
    const char*     pattern;
    int             offset;
    int             extra;
} cl_signature_t;

template <typename T>
T FindPatternEx(HANDLE hProcess, PBYTE pBaseAddress, DWORD dwSize, cl_signature_t* signature)
{
    BYTE* buffer = new BYTE[dwSize];
    if (!ReadProcessMemory(hProcess, (LPVOID)pBaseAddress, buffer, dwSize, NULL))
    {
        printf_s("ReadProcessMemory failed (err: %d, line: %d)\n", GetLastError(), __LINE__);
        return NULL;
    }

    LPCBYTE pat = reinterpret_cast<LPCBYTE>(signature->pattern);
    PBYTE   match = NULL;

    for (PBYTE current = buffer; current < buffer + dwSize; ++current)
    {
        if (*(PBYTE)pat == (BYTE)'\?' || *current == GET_BYTE(pat))
        {
            if (!match) {
                match = current;
            }
            pat += (*(PBYTE)pat != (BYTE)'\?' && *(PBYTE)(pat + 2) != '\0') ? 3 : 2;
            if (!*pat)
            {
                match = pBaseAddress + (match - buffer) + signature->offset;
                break;
            }
        }
        else if (match)
        {
            current = match;
            pat = reinterpret_cast<LPCBYTE>(signature->pattern);
            match = NULL;
        }
    }

    delete[] buffer;
    return (match != NULL) ? *(T*)match + signature->extra : NULL;
}

int main()
{
    BYTE bytes[] =
    {
        0x20, 0x20, 0x20, 0x20, 0x20, 0x54,
        0xA3, 0xFC, 0x10, 0x20, 0x30, 0x40,
        0xF1, 0xAC, 0x20, 0x24, 0x64, 0xA4
    };

    cl_signature_t signature =
    {
        "Pattern1",
        "A3 FC ? ? ? ? F1 AC",
        2,
        0
    };

    DWORD result = FindPatternEx<DWORD>(GetCurrentProcess(), (PBYTE)&bytes, ARRAYSIZE(bytes), &signature);
    if (result)
        printf("%s -> 0x%x", signature.name, result);

    getchar();
    return FALSE;
}