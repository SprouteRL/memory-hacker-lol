#include "ntdll.h"
#include <Windows.h>
#include <memory>

NtReadVirtualMemory_t NtReadVirtualMemory = nullptr;
NtWriteVirtualMemory_t NtWriteVirtualMemory = nullptr;
NtAllocateVirtualMemory_t NtAllocateVirtualMemory = nullptr;
NtFreeVirtualMemory_t NtFreeVirtualMemory = nullptr;
NtProtectVirtualMemory_t NtProtectVirtualMemory = nullptr;

bool InitializeNtdll()
{
    // Load ntdll.dll
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {
        return false;
    }

    // Get addresses of functions in ntdll.dll
    NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(ntdll, "NtReadVirtualMemory"));
    NtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory_t>(GetProcAddress(ntdll, "NtWriteVirtualMemory"));
    NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
    NtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(GetProcAddress(ntdll, "NtFreeVirtualMemory"));
    NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));

    // Check if all functions are loaded correctly
    return NtReadVirtualMemory && NtWriteVirtualMemory && NtAllocateVirtualMemory &&
        NtFreeVirtualMemory && NtProtectVirtualMemory;
}
