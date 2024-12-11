#pragma once
#include <Windows.h>
#include <iostream>
#include <memory>

// Declare function pointers for other NTAPI functions
typedef NTSTATUS(WINAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG NumberOfBytesRead);

typedef NTSTATUS(WINAPI* NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG Size,
    PULONG NumberOfBytesWritten);

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(WINAPI* NtFreeVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType);

typedef NTSTATUS(WINAPI* NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

// Declare function pointers for the NTAPI functions
extern NtReadVirtualMemory_t NtReadVirtualMemory;
extern NtWriteVirtualMemory_t NtWriteVirtualMemory;
extern NtAllocateVirtualMemory_t NtAllocateVirtualMemory;
extern NtFreeVirtualMemory_t NtFreeVirtualMemory;
extern NtProtectVirtualMemory_t NtProtectVirtualMemory;

// Function to initialize function pointers
bool InitializeNtdll();