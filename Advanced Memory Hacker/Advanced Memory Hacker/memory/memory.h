#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <vector>
#include <thread>
#include <string>
#include <memory>

#include "ntdll\ntdll.h"

class Memory
{
public:
	HANDLE handle;
	DWORD id;
	uintptr_t base;

	std::string procName;

public:
	std::vector<LPVOID> allocatedMemory;
	std::vector<HANDLE> heldMutex;

public:
	static DWORD GetIdByName(const char* procName);
	uintptr_t GetBaseAddress(const char* moduleName);

	bool Attach(const char* procName);
	void Detach();

	bool ChangeMemoryPage(const uintptr_t& address, const DWORD& newProtect, SIZE_T& size, DWORD* oldProtect);
	bool IsMemoryOk(const uintptr_t& address);

	LPVOID AllocateMemory(size_t size);
	bool FreeMemory(const uintptr_t& address);

	bool m_CreateMutex(const std::string& mutexName, const LPSECURITY_ATTRIBUTES& attributes=0, const bool& initialOwner=1);
		
	template <typename Ty>
	Ty ReadMemory(const uintptr_t& address, bool checkOk = false)
	{
		Ty buffer = {};
		if (!InitializeNtdll()) return buffer;
		if (!handle) return buffer;

		if (!IsMemoryOk(address) && checkOk) return buffer;

		LPVOID addy = reinterpret_cast<LPVOID>(address);

		NtReadVirtualMemory(handle, addy, &buffer, sizeof(buffer), nullptr);
		return buffer;
	}

	template <typename Ty>
	bool WriteMemory(const uintptr_t& address, const Ty& buffer)
	{
		if (!InitializeNtdll()) return false;
		if (!handle) return false;

		if (!IsMemoryOk(address)) return false;

		return NtWriteVirtualMemory(handle, reinterpret_cast<LPVOID>(address), (PVOID)&buffer, sizeof(buffer), nullptr) == 0;
	}

	static bool KillProcess(const char* processName = "this");

public:
	Memory(const char* procName = "");
	~Memory();
};
inline std::unique_ptr<Memory> memory;