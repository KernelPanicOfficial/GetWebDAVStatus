#include <windows.h>
#include "beacon.h"

WINBASEAPI BOOL WINAPI KERNEL32$WaitNamedPipeW(LPCWSTR lpNamedPipeName, DWORD nTimeOut);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);

void go(char* args, int length) 
{
    datap parser;
    wchar_t* host = NULL;
    wchar_t* fullPipeName = NULL;
    BOOL pipeStatus = 0;
    HANDLE hHeap = NULL;
    int totalHosts = 0;
    int enabledCount = 0;
    int disabledCount = 0;
    int hostLen = 0;
    int i = 0;
    int numHosts = 0;

    BeaconDataParse(&parser, args, length);
    hHeap = KERNEL32$GetProcessHeap();

    // First argument is the number of hosts
    numHosts = BeaconDataInt(&parser);

    if (numHosts <= 0)
    {
        BeaconPrintf(CALLBACK_ERROR, "[!] No targets specified");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "=== GetWebDAVStatus Check ===\n");

    for (totalHosts = 0; totalHosts < numHosts; totalHosts++)
    {
        host = (wchar_t*)BeaconDataExtract(&parser, NULL);
        
        if (host == NULL || host[0] == L'\0')
        {
            break;
        }

        // Calculate length manually
        hostLen = 0;
        while (host[hostLen] != L'\0')
        {
            hostLen++;
        }

        // Allocate buffer for full pipe name
        // \\host\pipe\DAV RPC SERVICE = 2 + hostLen + 21 + 1
        fullPipeName = (wchar_t*)KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, (2 + hostLen + 21 + 1) * sizeof(wchar_t));
        
        if (fullPipeName == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed for %S", host);
            continue;
        }

        // Build pipe name manually
        // Copy "\\\\"
        fullPipeName[0] = L'\\';
        fullPipeName[1] = L'\\';
        
        // Copy host
        for (i = 0; i < hostLen; i++)
        {
            fullPipeName[2 + i] = host[i];
        }
        
        // Copy "\\pipe\\DAV RPC SERVICE"
        fullPipeName[2 + hostLen] = L'\\';
        fullPipeName[3 + hostLen] = L'p';
        fullPipeName[4 + hostLen] = L'i';
        fullPipeName[5 + hostLen] = L'p';
        fullPipeName[6 + hostLen] = L'e';
        fullPipeName[7 + hostLen] = L'\\';
        fullPipeName[8 + hostLen] = L'D';
        fullPipeName[9 + hostLen] = L'A';
        fullPipeName[10 + hostLen] = L'V';
        fullPipeName[11 + hostLen] = L' ';
        fullPipeName[12 + hostLen] = L'R';
        fullPipeName[13 + hostLen] = L'P';
        fullPipeName[14 + hostLen] = L'C';
        fullPipeName[15 + hostLen] = L' ';
        fullPipeName[16 + hostLen] = L'S';
        fullPipeName[17 + hostLen] = L'E';
        fullPipeName[18 + hostLen] = L'R';
        fullPipeName[19 + hostLen] = L'V';
        fullPipeName[20 + hostLen] = L'I';
        fullPipeName[21 + hostLen] = L'C';
        fullPipeName[22 + hostLen] = L'E';
        fullPipeName[23 + hostLen] = L'\0';

        pipeStatus = KERNEL32$WaitNamedPipeW(fullPipeName, 3000);
        
        if (pipeStatus == 0)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[-] %S - WebClient NOT running or unreachable", host);
            disabledCount++;
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %S - WebClient ENABLED", host);
            enabledCount++;
        }

        KERNEL32$HeapFree(hHeap, 0, fullPipeName);
        fullPipeName = NULL;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Summary: %d hosts checked, %d enabled, %d disabled/unreachable", 
                 totalHosts, enabledCount, disabledCount);
}
